package peer

import (
	"net/netip"
	"time"
)

type Peer struct {
	fp                               uint64
	addrPort                         netip.AddrPort
	added, seen, lastPeerMsgReceived time.Time
	edge                             bool
	trust                            float64
}

func (p Peer) String() string {
	return p.addrPort.String()
}

func (p Peer) LastPeerMsgReceived() time.Time {
	return p.lastPeerMsgReceived
}

func (p Peer) Seen() time.Time {
	return p.seen
}

func (p Peer) Edge() bool {
	return p.edge
}

func (p Peer) Fp() uint64 {
	return p.fp
}

func (p Peer) AddrPort() netip.AddrPort {
	return p.addrPort
}
