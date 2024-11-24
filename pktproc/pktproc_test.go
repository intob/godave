package pktproc

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/intob/godave/dave"
	"github.com/intob/godave/pow"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

type mockReader struct {
	packet   []byte
	addrPort netip.AddrPort
}

func buildMockPacket() ([]byte, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	m := &dave.M{
		Op:     dave.Op_PUT,
		DatKey: []byte("test"),
		Val:    []byte("test_val"),
		Time:   pow.Ttb(time.Now().Add(-50 * time.Millisecond)),
		PubKey: pubKey,
	}
	m.Work, m.Salt = pow.DoWork(m.DatKey, m.Val, m.Time, 16)
	m.Sig = ed25519.Sign(privKey, m.Work)
	return proto.Marshal(m)
}

func (m *mockReader) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	copy(b, m.packet)
	return len(m.packet), m.addrPort, nil
}

func BenchmarkRdpkt(b *testing.B) {
	pkt, err := buildMockPacket()
	if err != nil {
		b.Error(err)
	}
	mr := &mockReader{pkt, netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1992)}
	bpool := sync.Pool{New: func() any { return make([]byte, 1424) }}
	h := blake3.New(32, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rdpkt(mr, h, &bpool)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkProcessor(b *testing.B) {
	pkt, err := buildMockPacket()
	if err != nil {
		b.Error(err)
	}
	proc := NewPacketProcessor(&PacketProcessorCfg{
		NumWorkers:   runtime.NumCPU(),
		BufSize:      1424,
		FilterFunc:   packetFilter,
		SocketReader: &mockReader{pkt, netip.MustParseAddrPort("127.0.0.1:6102")},
	})
	packetChan := proc.ResultChan()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		<-packetChan
	}
}

// copied from main, maybe move it to another package
func packetFilter(m *dave.M, h *blake3.Hasher) error {
	if m.Op == dave.Op_PUT {
		if pow.Nzerobit(m.Work) < 16 {
			return fmt.Errorf("work is insufficient: %x", m.Work)
		}
		err := pow.Check(h, m)
		if err != nil {
			return fmt.Errorf("work is invalid: %s", err)
		}
		pubKey, err := unmarshalEd25519(m.PubKey)
		if err != nil {
			return fmt.Errorf("failed to unmarshal pub key: %s", err)
		}
		if !ed25519.Verify(pubKey, m.Work, m.Sig) {
			return fmt.Errorf("signature is invalid")
		}
	} else if m.Op == dave.Op_PEER && len(m.Pds) > 3 {
		return errors.New("packet exceeds pd limit")
	}
	return nil
}

func unmarshalEd25519(publicKeyBytes []byte) (ed25519.PublicKey, error) {
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519: public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(publicKeyBytes), nil
}

// old implementation
func rdpkt(sock SocketReader, h *blake3.Hasher, bpool *sync.Pool) (*Packet, error) {
	buf := bpool.Get().([]byte)
	defer bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
	n, raddr, err := sock.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from socket: %s", err)
	}
	m := &dave.M{}
	err = proto.Unmarshal(buf[:n], m)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %s", err)
	}
	if m.Op == dave.Op_PUT {
		err := pow.Check(h, m)
		if err != nil {
			return nil, fmt.Errorf("failed work check: %s", err)
		}
		if pow.Nzerobit(m.Work) < 16 {
			return nil, fmt.Errorf("work is insufficient: %x from %s", m.Work, raddr)
		}
		pubKey, err := unmarshalEd25519(m.PubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal pub key: %s", err)
		}
		if !ed25519.Verify(pubKey, m.Work, m.Sig) {
			return nil, fmt.Errorf("invalid signature")
		}
	} else if m.Op == dave.Op_PEER && len(m.Pds) > 3 {
		return nil, errors.New("packet exceeds pd limit")
	}
	return &Packet{m, raddr}, nil
}
