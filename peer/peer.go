package peer

import (
	"crypto/ed25519"
	"net/netip"
	"time"

	"github.com/intob/godave/types"
)

type Peer struct {
	fp              uint64
	addrPort        netip.AddrPort
	added           time.Time
	edge            bool
	trust           float64
	challenge       types.Challenge
	pubKey          ed25519.PublicKey
	challengeSolved time.Time
	pingReceived    time.Time
}

func (p Peer) Fp() uint64 {
	return p.fp
}

func (p Peer) AddrPort() netip.AddrPort {
	return p.addrPort
}

func (p Peer) PubKey() ed25519.PublicKey {
	return p.pubKey
}
