package peer

import (
	"crypto/ed25519"
	"net/netip"
	"time"
)

type Peer struct {
	fp          uint64
	addrPort    netip.AddrPort
	added, seen time.Time
	edge        bool
	trust       float64
	challenge   []byte
	pubKey      ed25519.PublicKey
}

func (p Peer) Fp() uint64 {
	return p.fp
}

func (p Peer) AddrPort() netip.AddrPort {
	return p.addrPort
}
