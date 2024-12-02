package peer

import (
	"crypto/ed25519"
	"net/netip"
	"sync"
	"time"

	"github.com/intob/godave/types"
)

//const WEIGHTED_RELIABILITY_ALPHA = 0.5

type StorageChallenge struct {
	PublicKey ed25519.PublicKey
	DatKey    string
	Expires   time.Time
}

type peer struct {
	mu                         sync.RWMutex
	id                         uint64
	addrPort                   netip.AddrPort
	added                      time.Time
	edge                       bool
	authChallenge              types.AuthChallenge
	publicKey                  ed25519.PublicKey
	authChallengeSolved        time.Time
	storageChallenge           *StorageChallenge
	storageChallengesCompleted uint32
	storageChallengesFailed    uint32
	capacity, usedSpace        int64
}

type PeerCopy struct {
	ID                         uint64
	AddrPort                   netip.AddrPort
	Edge                       bool
	AuthChallengeSolved        time.Time
	StorageChallengesCompleted uint32
	StorageChallengesFailed    uint32
}

func copyFromPeer(peer *peer) PeerCopy {
	return PeerCopy{
		ID:                         peer.id,
		AddrPort:                   peer.addrPort,
		Edge:                       peer.edge,
		AuthChallengeSolved:        peer.authChallengeSolved,
		StorageChallengesCompleted: peer.storageChallengesCompleted,
		StorageChallengesFailed:    peer.storageChallengesFailed,
	}
}

/*
func (p Peer) Reliability() float64 {
	if p.pingsSent == 0 {
		return 0
	}
	baseScore := float64(p.pongsReceived) / float64(p.pingsSent)
	reliabilityScore := baseScore * (1 - math.Exp(-WEIGHTED_RELIABILITY_ALPHA*float64(p.pingsSent)))
	return reliabilityScore
}
*/
