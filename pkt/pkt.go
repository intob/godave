package pkt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/pow"
	"github.com/intob/godave/types"
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
	Msg      *types.Msg
	AddrPort netip.AddrPort
}

type PacketProcessor struct {
	workQueue     chan *rawPacket
	resultChan    chan *Packet
	bpool         *sync.Pool
	logger        *logger.Logger
	pongPeerLimit int
	minWork       uint8
}

type PacketProcessorCfg struct {
	NumWorkers, BufSize, PongPeerLimit int
	MinWork                            uint8
	Socket                             Socket
	Logger                             *logger.Logger
}

func NewPacketProcessor(cfg *PacketProcessorCfg) (*PacketProcessor, error) {
	if cfg == nil {
		return nil, errors.New("no cfg provided")
	}
	if cfg.Logger == nil {
		return nil, errors.New("logger is nil")
	}
	pp := &PacketProcessor{
		workQueue:     make(chan *rawPacket, 1000),
		resultChan:    make(chan *Packet, 1000),
		bpool:         &sync.Pool{New: func() any { return make([]byte, cfg.BufSize) }},
		logger:        cfg.Logger,
		pongPeerLimit: cfg.PongPeerLimit,
		minWork:       cfg.MinWork,
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
	return pp, nil
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
	msg := &types.Msg{}
	err := msg.Unmarshal(raw.data)
	if err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	if err = pp.packetFilter(msg, h); err != nil {
		return nil, fmt.Errorf("filter error: %w", err)
	}
	return &Packet{
		Msg:      msg,
		AddrPort: raw.raddr}, nil
}

func (pp *PacketProcessor) packetFilter(msg *types.Msg, h *blake3.Hasher) error {
	switch msg.Op {
	case types.Op_PUT:
		if pow.Nzerobit(msg.Dat.Work) < pp.minWork {
			return fmt.Errorf("work is insufficient: %x", msg.Dat.Work)
		}
		if err := pow.Check(h, msg.Dat); err != nil {
			return fmt.Errorf("work is invalid: %s", err)
		}
		if l := len(msg.Dat.PubKey); l != ed25519.PublicKeySize {
			return fmt.Errorf("pub key is invalid: len %d", l)
		}
		pubKey, err := unmarshalEd25519PublicKey(msg.Dat.PubKey)
		if err != nil {
			return fmt.Errorf("failed to unmarshal pub key: %s", err)
		}
		if !ed25519.Verify(pubKey, msg.Dat.Work[:], msg.Dat.Sig[:]) {
			return fmt.Errorf("signature is invalid")
		}
	case types.Op_PONG:
		if len(msg.AddrPorts) > pp.pongPeerLimit {
			return errors.New("packet exceeds pd limit")
		}
	}
	return nil
}

func unmarshalEd25519PublicKey(publicKeyBytes []byte) (ed25519.PublicKey, error) {
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519: public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(publicKeyBytes), nil
}
