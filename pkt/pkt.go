package pkt

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/intob/godave/dave"
	"github.com/intob/godave/logger"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

type Socket interface {
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
	WriteToUDPAddrPort(b []byte, addrPort netip.AddrPort) (n int, err error)
}

type rawPacket struct {
	data  []byte
	raddr netip.AddrPort
}

type Packet struct {
	Msg      *dave.M
	AddrPort netip.AddrPort
}

type PacketProcessor struct {
	workQueue  chan *rawPacket
	resultChan chan *Packet
	bpool      *sync.Pool
	filterFunc func(m *dave.M, h *blake3.Hasher) error
	logger     *logger.Logger
}

type PacketProcessorCfg struct {
	NumWorkers, BufSize int
	FilterFunc          func(m *dave.M, h *blake3.Hasher) error
	Socket              Socket
	Logger              *logger.Logger
}

func NewPacketProcessor(cfg *PacketProcessorCfg) *PacketProcessor {
	pp := &PacketProcessor{
		workQueue:  make(chan *rawPacket, 1000),
		resultChan: make(chan *Packet, 1000),
		bpool:      &sync.Pool{New: func() any { return make([]byte, cfg.BufSize) }},
		filterFunc: cfg.FilterFunc,
		logger:     cfg.Logger,
	}
	for i := 0; i < cfg.NumWorkers; i++ {
		go pp.worker()
	}
	go func(socket Socket) {
		for {
			buf := pp.bpool.Get().([]byte)
			n, raddr, err := socket.ReadFromUDPAddrPort(buf)
			if err != nil {
				pp.bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
				pp.logger.Error("failed to read from socket: %s", err)
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			pp.bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
			pp.workQueue <- &rawPacket{data, raddr}
		}
	}(cfg.Socket)
	return pp
}

func (pp *PacketProcessor) Packets() <-chan *Packet { return pp.resultChan }

func (pp *PacketProcessor) worker() {
	h := blake3.New(32, nil)
	for raw := range pp.workQueue {
		packet, err := pp.processPacket(raw, h)
		if err == nil {
			pp.resultChan <- packet
		} else {
			pp.logger.Error("failed to process packet: %s", err)
		}
	}
}

func (pp *PacketProcessor) processPacket(raw *rawPacket, h *blake3.Hasher) (*Packet, error) {
	m := &dave.M{}
	err := proto.Unmarshal(raw.data, m)
	if err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	if pp.filterFunc(m, h) != nil {
		return nil, fmt.Errorf("filter func error: %w", err)
	}
	return &Packet{m, raw.raddr}, nil
}
