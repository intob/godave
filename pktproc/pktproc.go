package pktproc

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/intob/godave/dave"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

type SocketReader interface {
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
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
}

type PacketProcessorCfg struct {
	NumWorkers, BufSize int
	FilterFunc          func(m *dave.M, h *blake3.Hasher) error
	SocketReader        SocketReader
}

func (pp *PacketProcessor) worker() {
	h := blake3.New(32, nil)
	for raw := range pp.workQueue {
		packet, err := pp.processPacket(raw, h)
		if err == nil {
			pp.resultChan <- packet
		}
	}
}

func (pp *PacketProcessor) ResultChan() <-chan *Packet { return pp.resultChan }

func NewPacketProcessor(cfg *PacketProcessorCfg) *PacketProcessor {
	pp := &PacketProcessor{
		workQueue:  make(chan *rawPacket, 1000),
		resultChan: make(chan *Packet, 1000),
		bpool:      &sync.Pool{New: func() any { return make([]byte, cfg.BufSize) }},
		filterFunc: cfg.FilterFunc,
	}
	for i := 0; i < cfg.NumWorkers; i++ {
		go pp.worker()
	}
	go func(socketReader SocketReader) {
		for {
			buf := pp.bpool.Get().([]byte)
			n, raddr, err := socketReader.ReadFromUDPAddrPort(buf)
			if err != nil {
				pp.bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
				continue
			}
			// TODO: use buf from pool directly if it performs better, as in current implementation
			data := make([]byte, n)
			copy(data, buf[:n])
			pp.bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
			pp.workQueue <- &rawPacket{data, raddr}
		}
	}(cfg.SocketReader)
	return pp
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
