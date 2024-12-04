package store

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/intob/godave/dat"
	"github.com/intob/godave/network"
)

func TestMarshalEntry(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	e := Entry{
		Dat:      dat.Dat{Key: "test-key", Val: []byte("test-val"), PubKey: pubKey},
		Replicas: [network.FANOUT]uint64{0, 1, 2}}
	buf := make([]byte, network.MAX_MSG_LEN)
	n, err := e.Marshal(buf)
	if err != nil {
		t.Fatalf("failed to marshal: %s", err)
	}
	if n != 197 {
		t.Fatalf("expected len 197, got %d", n)
	}
}

func TestUnmarshalEntry(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	e := Entry{
		Dat:      dat.Dat{Key: "test-key", Val: []byte("test-val"), PubKey: pubKey},
		Replicas: [network.FANOUT]uint64{17, 257, 65537}}
	buf := make([]byte, network.MAX_MSG_LEN)
	n, err := e.Marshal(buf)
	if err != nil {
		t.Fatalf("failed to marshal: %s", err)
	}
	e2 := &Entry{}
	err = e2.Unmarshal(buf[:n])
	if err != nil {
		t.Fatalf("failed to unmarshal: %s", err)
	}
	if e2.Dat.Key != e.Dat.Key || !bytes.Equal(e2.Dat.Val, e.Dat.Val) || e2.Replicas != e.Replicas {
		t.Fatalf("something went wrong, entries should be equal: %+v %+v", e, e2)
	}
}

func BenchmarkMarshalUnmarshalEntry(b *testing.B) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	e := Entry{
		Dat:      dat.Dat{Key: "test-key", Val: []byte("test-val"), PubKey: pubKey},
		Replicas: [network.FANOUT]uint64{17, 257, 65537}}
	buf := make([]byte, network.MAX_MSG_LEN)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, _ := e.Marshal(buf)
		e2 := &Entry{}
		e2.Unmarshal(buf[:n])
	}
}
