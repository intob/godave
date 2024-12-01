package pkt

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/pow"
	"github.com/intob/godave/types"
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

func BenchmarkProcessor(b *testing.B) {
	buf := make([]byte, types.MaxMsgLen)
	n, err := buildMockPacket(buf)
	if err != nil {
		b.Error(err)
	}
	buf = buf[:n]
	proc, err := NewPacketProcessor(
		&mockReader{buf, netip.MustParseAddrPort("127.0.0.1:6102")},
		logger.NewLoggerToDevNull())
	if err != nil {
		b.Fatalf("failed to init packet processor: %s", err)
	}
	packets := proc.In()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		<-packets
	}
}

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
