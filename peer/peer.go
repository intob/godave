package peer

import (
	"crypto/ed25519"
	"net/netip"
	"time"

	"github.com/intob/godave/types"
)

type Peer struct {
	// First 8 bytes of public key. Benchmarks show it's 2% more efficient
	// to compute once. In future, if the network grows large,
	// maybe we will compute this on the fly.
	id              uint64
	addrPort        netip.AddrPort
	added           time.Time
	edge            bool
	trust           float64
	challenge       types.Challenge
	publicKey       ed25519.PublicKey
	challengeSolved time.Time
	pingReceived    time.Time
}

func (p Peer) AddrPort() netip.AddrPort {
	return p.addrPort
}

func (p Peer) PublicKey() ed25519.PublicKey {
	return p.publicKey
}

func (p Peer) Trust() float64 {
	return p.trust
}

func (p Peer) ChallengeSolved() time.Time {
	return p.challengeSolved
}

func (p Peer) ID() uint64 {
	return p.id
}
