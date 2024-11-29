package pkt

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

	"github.com/intob/godave/logger"
	"github.com/intob/godave/pow"
	"github.com/intob/godave/types"
	"lukechampine.com/blake3"
)

type mockReader struct {
	packet   []byte
	addrPort netip.AddrPort
}

func buildMockPacket(buf []byte) (int, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 0, err
	}
	msg := &types.Msg{
		Op: types.Op_PUT,
		Dat: &types.Dat{
			Key:    "test",
			Val:    []byte("test_val"),
			Time:   time.Now().Add(-50 * time.Millisecond),
			PubKey: pubKey,
		},
	}
	msg.Dat.Work, msg.Dat.Salt = pow.DoWork(msg.Dat.Key, msg.Dat.Val, msg.Dat.Time, 16)
	msg.Dat.Sig = types.Signature(ed25519.Sign(privKey, msg.Dat.Work[:]))
	return msg.Marshal(buf)
}

func (m *mockReader) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	return copy(b, m.packet), m.addrPort, nil
}

func (m *mockReader) WriteToUDPAddrPort(b []byte, addrPort netip.AddrPort) (n int, err error) {
	return copy(m.packet, b), nil
}

func BenchmarkRdpkt(b *testing.B) {
	buf := make([]byte, types.MaxMsgLen)
	n, err := buildMockPacket(buf)
	if err != nil {
		b.Error(err)
	}
	buf = buf[:n]
	mr := &mockReader{buf, netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1992)}
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
	buf := make([]byte, types.MaxMsgLen)
	n, err := buildMockPacket(buf)
	if err != nil {
		b.Error(err)
	}
	buf = buf[:n]
	proc, err := NewPacketProcessor(&PacketProcessorCfg{
		NumWorkers: runtime.NumCPU(),
		BufSize:    1424,
		Socket:     &mockReader{buf, netip.MustParseAddrPort("127.0.0.1:6102")},
		Logger:     logger.NewLogger(&logger.LoggerCfg{}),
	})
	if err != nil {
		b.Fatalf("failed to init packet processor: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		<-proc.Packets()
	}
}

// old implementation
func rdpkt(socket Socket, h *blake3.Hasher, bpool *sync.Pool) (*Packet, error) {
	buf := bpool.Get().([]byte)
	defer bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
	n, raddr, err := socket.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from socket: %s", err)
	}
	msg := &types.Msg{}
	msg.Unmarshal(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %s", err)
	}
	if msg.Op == types.Op_PUT {
		err := pow.Check(h, msg.Dat)
		if err != nil {
			return nil, fmt.Errorf("failed work check: %s", err)
		}
		if pow.Nzerobit(msg.Dat.Work) < 16 {
			return nil, fmt.Errorf("work is insufficient: %x from %s", msg.Dat.Work, raddr)
		}
		pubKey, err := unmarshalEd25519PublicKey(msg.Dat.PubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal pub key: %s", err)
		}
		if !ed25519.Verify(pubKey, msg.Dat.Work[:], msg.Dat.Sig[:]) {
			return nil, fmt.Errorf("invalid signature")
		}
	} else if msg.Op == types.Op_PONG && len(msg.AddrPorts) > 3 {
		return nil, errors.New("packet exceeds pd limit")
	}
	return &Packet{&types.Msg{}, raddr}, nil
}

/*
func BenchmarkProto(b *testing.B) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := &dave.M{
		Op:     dave.Op_PUT,
		DatKey: []byte("test"),
		Val:    []byte("test_val"),
		Time:   types.Ttb(time.Now()),
		PubKey: pubKey,
	}
	work, salt := pow.DoWork(string(msg.DatKey), msg.Val, types.Btt(msg.Time), 16)
	msg.Work = work[:]
	msg.Salt = salt[:]
	msg.Sig = ed25519.Sign(privKey, msg.Work)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, _ := proto.Marshal(msg)
		m := &dave.M{}
		proto.Unmarshal(buf, m)
	}
}
*/

/*
BenchmarkProto-12        	2904609	       412.0 ns/op	     600 B/op	       9 allocs/op
BenchmarkNewMsg-12    	 	9422624	       109.4 ns/op	     256 B/op	       4 allocs/op
*/
func BenchmarkNewMsg(b *testing.B) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := &types.Msg{
		Op: types.Op_PUT,
		Dat: &types.Dat{
			Key:    "test",
			Val:    []byte("test_val"),
			Time:   time.Now(),
			PubKey: pubKey,
		},
	}
	msg.Dat.Work, msg.Dat.Salt = pow.DoWork(msg.Dat.Key, msg.Dat.Val, msg.Dat.Time, 16)
	msg.Dat.Sig = types.Signature(ed25519.Sign(privKey, msg.Dat.Work[:]))
	buf := make([]byte, types.MaxMsgLen)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, _ := msg.Marshal(buf)
		m := &types.Msg{}
		m.Unmarshal(buf[:n])
	}
}
