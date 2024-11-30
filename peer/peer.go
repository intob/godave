package peer

import (
	"crypto/ed25519"
	"net/netip"
	"time"

	"github.com/intob/godave/types"
)

type Peer struct {
	addrPort        netip.AddrPort
	added           time.Time
	edge            bool
	trust           uint8
	challenge       types.Challenge
	pubKey          ed25519.PublicKey
	challengeSolved time.Time
	pingReceived    time.Time
}

func (p Peer) AddrPort() netip.AddrPort {
	return p.addrPort
}

func (p Peer) PubKey() ed25519.PublicKey {
	return p.pubKey
}

func (p Peer) Trust() uint8 {
	return p.trust
}

func (p Peer) ChallengeSolved() time.Time {
	return p.challengeSolved
}
