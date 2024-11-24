package peer

import (
	"net/netip"
	"time"

	"github.com/intob/godave/dave"
)

type Peer struct {
	fp                       uint64
	addrPort                 netip.AddrPort
	pd                       *dave.Pd
	added, seen, lastPeerMsg time.Time
	edge                     bool
	trust                    float64
}

func (p *Peer) String() string {
	return p.addrPort.String()
}

func (p *Peer) AddTrust(delta, max float64) {
	p.trust += delta
	if p.trust > max {
		p.trust = max
	}
}

func (p *Peer) LastPeerMsg() time.Time {
	return p.lastPeerMsg
}

func (p *Peer) GotPeerMsg() {
	p.lastPeerMsg = time.Now()
}

func (p *Peer) Pd() *dave.Pd {
	return p.pd
}

func (p *Peer) AddrPort() netip.AddrPort {
	return p.addrPort
}

func (p *Peer) LastSeen() time.Time {
	return p.seen
}
func (p *Peer) Edge() bool {
	return p.edge
}
