package peer

import (
	"bytes"
	"crypto/ed25519"
	"sort"
	"testing"

	"github.com/intob/godave/xor"
)

type peerDistanceOld struct {
	peer     Peer
	distance []byte
}

func sortPeersByDistanceOld(target ed25519.PublicKey, peers []Peer) []peerDistanceOld {
	distances := make([]peerDistanceOld, 0, len(peers))
	for _, peer := range peers {
		if peer.publicKey == nil {
			continue
		}
		dist := make([]byte, ed25519.PublicKeySize)
		xor.Xor256Into(dist, peer.publicKey, target)
		distances = append(distances, peerDistanceOld{peer, dist})
	}
	sort.Slice(distances, func(i, j int) bool {
		return bytes.Compare(distances[i].distance, distances[j].distance) < 0
	})
	return distances
}

func BenchmarkSortPeersByDistanceOld(b *testing.B) {
	myPubKey, _, _ := ed25519.GenerateKey(nil)
	peers := make([]Peer, 0, 500)
	for i := 0; i < 500; i++ {
		pubKey, _, _ := ed25519.GenerateKey(nil)
		peers = append(peers, Peer{publicKey: pubKey})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sortPeersByDistanceOld(myPubKey, peers)
	}
}

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
