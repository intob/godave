package pkt

import (
	"errors"
	"net/netip"
	"sync"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/types"
)

type Socket interface {
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
	WriteToUDPAddrPort(b []byte, addrPort netip.AddrPort) (n int, err error)
}

type Packet struct {
	Msg      *types.Msg
	AddrPort netip.AddrPort
}

type PacketProcessor struct {
	resultChan chan *Packet
	bpool      *sync.Pool
	logger     *logger.Logger
	myAddrPort chan netip.AddrPort
}

type PacketProcessorCfg struct {
	Socket  Socket
	BufSize int
	Logger  *logger.Logger
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

func NewPacketProcessor(cfg *PacketProcessorCfg) (*PacketProcessor, error) {
	if cfg == nil || cfg.Logger == nil {
		return nil, errors.New("invalid config")
	}
	pp := &PacketProcessor{
		resultChan: make(chan *Packet, 1000),
		bpool:      &sync.Pool{New: func() any { return make([]byte, cfg.BufSize) }},
		logger:     cfg.Logger,
		myAddrPort: make(chan netip.AddrPort),
	}
	go func(socket Socket) {
		var myAddrPort netip.AddrPort
		for {
			select {
			case newAddrPort := <-pp.myAddrPort:
				myAddrPort = newAddrPort
				pp.logger.Debug("updated my addrport to %s", myAddrPort)
			default:
				buf := pp.bpool.Get().([]byte)
				n, raddr, err := socket.ReadFromUDPAddrPort(buf)
				if err != nil {
					pp.bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
					pp.logger.Error("failed to read from socket: %s", err)
					continue
				}
				if n > types.MaxMsgLen {
					pp.bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
					pp.logger.Debug("packet dropped: size greater than limit")
					continue
				}
				ipv6 := MapToIPv6(raddr)
				if ipv6 == myAddrPort {
					pp.bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
					pp.logger.Debug("packet dropped: loopback")
					continue
				}
				msg := &types.Msg{}
				err = msg.Unmarshal(buf[:n])
				if err != nil {
					pp.bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
					pp.logger.Error("unmarshal error: %s", err)
					continue
				}
				pp.resultChan <- &Packet{Msg: msg, AddrPort: ipv6}
				pp.bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
			}

		}
	}(cfg.Socket)
	return pp, nil
}

func (pp *PacketProcessor) Packets() <-chan *Packet { return pp.resultChan }

func (pp *PacketProcessor) MyAddrPortChan() chan<- netip.AddrPort { return pp.myAddrPort }
