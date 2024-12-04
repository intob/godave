package pkt

import (
	"crypto/ed25519"
	"net/netip"
	"testing"
	"time"

	"github.com/intob/godave/dat"
	"github.com/intob/godave/logger"
	"github.com/intob/godave/network"
	"github.com/intob/godave/store"
	"github.com/intob/godave/types"
)

type mockReader struct {
	packet   []byte
	addrPort netip.AddrPort
}

func buildMockPacket(buf []byte) (int, error) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return 0, err
	}
	msg := &types.Msg{Op: types.OP_PUT,
		Entry: &store.Entry{Dat: dat.Dat{
			Key:    "test",
			Val:    []byte("test_val"),
			Time:   time.Now().Add(-50 * time.Millisecond),
			PubKey: pubKey}}}
	msg.Entry.Dat.Sign(privKey)
	msg.Entry.Dat.Work, msg.Entry.Dat.Salt = dat.DoWork(msg.Entry.Dat.Sig, 16)
	return msg.Marshal(buf)
}

func (m *mockReader) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	return copy(b, m.packet), m.addrPort, nil
}

func (m *mockReader) WriteToUDPAddrPort(b []byte, addrPort netip.AddrPort) (n int, err error) {
	return copy(m.packet, b), nil
}

func BenchmarkProcessor(b *testing.B) {
	buf := make([]byte, network.MAX_MSG_LEN)
	n, err := buildMockPacket(buf)
	if err != nil {
		b.Error(err)
	}
	buf = buf[:n]
	proc, err := NewPacketProcessor(
		&mockReader{buf, netip.MustParseAddrPort("127.0.0.1:6102")},
		logger.NewDaveLoggerToDevNull())
	if err != nil {
		b.Fatalf("failed to init packet processor: %s", err)
	}
	packets := proc.In()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		<-packets
	}
}
