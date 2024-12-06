package peer

import (
	"crypto/ed25519"
	"net/netip"
	"sync"
	"time"

	"github.com/intob/godave/auth"
)

type peer struct {
	mu                  sync.RWMutex
	id                  uint64
	addrPort            netip.AddrPort
	added               time.Time
	edge                bool
	authChallenge       auth.AuthChallenge
	publicKey           ed25519.PublicKey
	authChallengeSolved time.Time
	capacity, usedSpace int64
}

type PeerCopy struct {
	ID                  uint64
	AddrPort            netip.AddrPort
	PublicKey           ed25519.PublicKey
	AuthChallengeSolved time.Time
}

func copyFromPeer(peer *peer) PeerCopy {
	return PeerCopy{
		ID:                  peer.id,
		AddrPort:            peer.addrPort,
		PublicKey:           peer.publicKey,
		AuthChallengeSolved: peer.authChallengeSolved,
	}
}
