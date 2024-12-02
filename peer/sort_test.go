package peer

import (
	"crypto/ed25519"
	"testing"
)

func BenchmarkSortPeersByDistance(b *testing.B) {
	myPubKey, _, _ := ed25519.GenerateKey(nil)
	myID := IDFromPublicKey(myPubKey)
	peers := make([]Peer, 0, 500)
	for i := 0; i < 500; i++ {
		pubKey, _, _ := ed25519.GenerateKey(nil)
		peers = append(peers, Peer{id: IDFromPublicKey(pubKey)})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SortPeersByDistance(myID, peers)
	}
}

func TestSortPeersByDistance(t *testing.T) {
	myPubKey, _, _ := ed25519.GenerateKey(nil)
	myID := IDFromPublicKey(myPubKey)
	peers := make([]Peer, 0, 500)
	for i := 0; i < 500; i++ {
		pubKey, _, _ := ed25519.GenerateKey(nil)
		peers = append(peers, Peer{id: IDFromPublicKey(pubKey)})
	}
	sorted := SortPeersByDistance(myID, peers)
	// Ensure peer distances ascend, closest first
	var prevDistance uint64
	for _, p := range sorted {
		if p.Distance < prevDistance {
			t.Fatalf("expected distance to be greater than previous: prev=%d current=%d", prevDistance, p.Distance)
		}
		prevDistance = p.Distance
	}
}
