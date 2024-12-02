package peer

import "sort"

type PeerDistance struct {
	Peer     Peer
	Distance uint64
}

func SortPeersByDistance(target uint64, peers []Peer) []PeerDistance {
	distances := make([]PeerDistance, 0, len(peers))
	for _, peer := range peers {
		if peer.id == 0 {
			continue
		}
		distances = append(distances, PeerDistance{peer, target ^ peer.id})
	}
	sort.Slice(distances, func(i, j int) bool {
		return distances[i].Distance < distances[j].Distance
	})
	return distances
}
