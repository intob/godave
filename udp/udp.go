package udp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/network"
	"github.com/intob/godave/types"
)

type RawPacket struct {
	Data     []byte
	AddrPort netip.AddrPort
}

type Packet struct {
	Msg      *types.Msg
	AddrPort netip.AddrPort
}

type UDPService struct {
	packetsIn  chan *RawPacket
	packetsOut chan *Packet
	myAddrPort chan netip.AddrPort
	logger     logger.Logger
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

func NewUDPService(udpAddr *net.UDPAddr, logger logger.Logger) (*UDPService, error) {
	u := &UDPService{
		packetsIn:  make(chan *RawPacket, 100_000),
		packetsOut: make(chan *Packet, 100_000),
		logger:     logger,
		myAddrPort: make(chan netip.AddrPort),
	}
	sock, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen UDP: %w", err)
	}
	go u.readFromSocket(sock)
	go u.writeToSocket(sock)
	return u, nil
}

func (u *UDPService) In() <-chan *RawPacket { return u.packetsIn }

func (u *UDPService) Out() chan<- *Packet { return u.packetsOut }

func (u *UDPService) MyAddrPortChan() chan<- netip.AddrPort { return u.myAddrPort }

func (u *UDPService) readFromSocket(sock *net.UDPConn) {
	var myAddrPort netip.AddrPort
	buf := make([]byte, network.MAX_MSG_LEN)
	for {
		select {
		case newAddrPort := <-u.myAddrPort:
			myAddrPort = newAddrPort
			u.log(logger.DEBUG, "updated my addrport to %s", myAddrPort)
		default:
			buf = buf[:cap(buf)]
			n, raddr, err := sock.ReadFromUDPAddrPort(buf)
			if err != nil {
				u.log(logger.ERROR, "failed to read from socket: %s", err)
				continue
			}
			ipv6 := MapToIPv6(raddr)
			if ipv6 == myAddrPort {
				u.log(logger.ERROR, "packet dropped: loopback")
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			u.packetsIn <- &RawPacket{data, ipv6}
		}
	}
}

func (u *UDPService) writeToSocket(sock *net.UDPConn) {
	buf := make([]byte, network.MAX_MSG_LEN)
	for pkt := range u.packetsOut {
		buf = buf[:cap(buf)]
		n, err := pkt.Msg.Marshal(buf)
		if err != nil {
			u.log(logger.ERROR, "dispatch error: %s", err)
			continue
		}
		_, err = sock.WriteToUDPAddrPort(buf[:n], pkt.AddrPort)
		if err != nil {
			u.log(logger.ERROR, "dispatch error: %s", err)
		}
	}
}

func (u *UDPService) log(level logger.LogLevel, msg string, args ...any) {
	if u.logger != nil {
		u.logger.Log(level, msg, args...)
	}
}
