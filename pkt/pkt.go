package pkt

import (
	"net/netip"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/types"
)

type Socket interface {
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
	WriteToUDPAddrPort(b []byte, addrPort netip.AddrPort) (n int, err error)
}

type RawPacket struct {
	Data     []byte
	AddrPort netip.AddrPort
}

type Packet struct {
	Msg      *types.Msg
	AddrPort netip.AddrPort
}

type PacketProcessor struct {
	packetsIn  chan *RawPacket
	packetsOut chan *Packet
	myAddrPort chan netip.AddrPort
	logger     *logger.Logger
}

func MapToIPv6(addr netip.AddrPort) netip.AddrPort {
	if !addr.Addr().Is4() {
		return addr
	}
	v4 := addr.Addr().As4()
	v6 := netip.AddrFrom16([16]byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF,
		v4[0], v4[1], v4[2], v4[3],
	})
	return netip.AddrPortFrom(v6, addr.Port())
}

func NewPacketProcessor(sock Socket, logger *logger.Logger) (*PacketProcessor, error) {
	pp := &PacketProcessor{
		packetsIn:  make(chan *RawPacket, 10000),
		packetsOut: make(chan *Packet, 100),
		logger:     logger,
		myAddrPort: make(chan netip.AddrPort),
	}
	go pp.readFromSocket(sock)
	go pp.writeToSocket(sock)
	return pp, nil
}

func (pp *PacketProcessor) In() <-chan *RawPacket { return pp.packetsIn }

func (pp *PacketProcessor) Out() chan<- *Packet { return pp.packetsOut }

func (pp *PacketProcessor) MyAddrPortChan() chan<- netip.AddrPort { return pp.myAddrPort }

func (pp *PacketProcessor) readFromSocket(socket Socket) {
	var myAddrPort netip.AddrPort
	buf := make([]byte, types.MaxMsgLen)
	for {
		select {
		case newAddrPort := <-pp.myAddrPort:
			myAddrPort = newAddrPort
			pp.log(logger.DEBUG, "updated my addrport to %s", myAddrPort)
		default:
			buf = buf[:cap(buf)]
			n, raddr, err := socket.ReadFromUDPAddrPort(buf)
			if err != nil {
				pp.log(logger.ERROR, "failed to read from socket: %s", err)
				continue
			}
			ipv6 := MapToIPv6(raddr)
			if ipv6 == myAddrPort {
				pp.log(logger.ERROR, "packet dropped: loopback")
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			pp.packetsIn <- &RawPacket{data, ipv6}
		}

	}
}

func (pp *PacketProcessor) writeToSocket(socket Socket) {
	buf := make([]byte, types.MaxMsgLen)
	for pkt := range pp.packetsOut {
		buf = buf[:cap(buf)]
		n, err := pkt.Msg.Marshal(buf)
		if err != nil {
			pp.log(logger.ERROR, "dispatch error: %s", err)
			continue
		}
		_, err = socket.WriteToUDPAddrPort(buf[:n], pkt.AddrPort)
		if err != nil {
			pp.log(logger.ERROR, "dispatch error: %s", err)
		}
	}
}

func (pp *PacketProcessor) log(level logger.LogLevel, msg string, args ...any) {
	if pp.logger != nil {
		pp.logger.Log(level, msg, args...)
	}
}
