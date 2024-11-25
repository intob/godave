package peer

import (
	"encoding/binary"
	mrand "math/rand"
	"net/netip"
	"sort"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/intob/godave/dave"
	"github.com/intob/godave/logger"
)

type StoreCfg struct {
	Probe      int
	MaxTrust   float64
	PruneEvery time.Duration
	DropAfter  time.Duration
	Ping       time.Duration
	Logger     *logger.Logger
}

type Store struct {
	table              map[uint64]*Peer
	list               []*Peer // sorted by trust descending
	trustSum, maxTrust float64
	probe              int
	dropAfter          time.Duration
	logger             *logger.Logger
	ping               time.Duration
}

func NewStore(cfg *StoreCfg) *Store {
	s := &Store{
		table:     make(map[uint64]*Peer),
		list:      make([]*Peer, 0),
		probe:     cfg.Probe,
		maxTrust:  cfg.MaxTrust,
		dropAfter: cfg.DropAfter,
		ping:      cfg.Ping,
		logger:    cfg.Logger,
	}
	return s
}

func (s *Store) Count() int {
	return len(s.list)
}

// Adds or updates the peer
func (s *Store) Seen(addrPort netip.AddrPort) uint64 {
	fp := fingerprint(addrPort)
	peer, exists := s.table[fp]
	if exists {
		peer.seen = time.Now()
		return peer.fp
	}
	peer = &Peer{
		fp:       fp,
		addrPort: addrPort,
		added:    time.Now(),
		seen:     time.Now(), // otherwise, peer is dropped
	}
	s.table[fp] = peer
	s.list = append(s.list, peer)
	s.logger.Error("added peer %s", peer)
	return peer.fp
}

func (s *Store) AddEdge(addrPort netip.AddrPort) {
	fp := fingerprint(addrPort)
	peer := &Peer{
		edge:     true,
		fp:       fp,
		addrPort: addrPort,
		added:    time.Now(),
		seen:     time.Now(),
	}
	s.table[peer.fp] = peer
	s.list = append(s.list, peer)
}

func (s *Store) AddPd(pd *dave.Pd) {
	addrPort := addrPortFrom(pd)
	fp := fingerprint(addrPort)
	_, exists := s.table[fp]
	if exists {
		return
	}
	peer := &Peer{
		fp:       fp,
		addrPort: addrPort,
		added:    time.Now(),
		seen:     time.Now(),
	}
	s.table[fp] = peer
	s.list = append(s.list, peer)
	s.logger.Error("peer added from gossip %s", peer)
}

func (s *Store) AddTrust(fp uint64, delta float64) {
	peer, exists := s.table[fp]
	if !exists {
		return
	}
	peer.trust += delta
	if peer.trust > s.maxTrust {
		peer.trust = s.maxTrust
	}
}

// returns true if message is no sooner than expected
func (s *Store) IsPeerMessageExpected(fp uint64) bool {
	peer, exists := s.table[fp]
	if !exists {
		return false
	}
	if time.Since(peer.lastPeerMsgReceived) < s.ping-10*time.Millisecond {
		return false
	}
	peer.lastPeerMsgReceived = time.Now()
	return true
}

func (s *Store) List() []*Peer {
	return s.list
}

func (s *Store) RandPeer() *Peer {
	if len(s.list) == 0 {
		return nil
	}
	if mrand.Intn(s.probe) == 0 {
		peer := s.list[mrand.Intn(len(s.list))]
		return peer
	}
	r := mrand.Float64() * s.trustSum
	for _, peer := range s.list {
		r -= peer.trust
		if r <= 0 {
			return peer
		}
	}
	return nil
}

func (s *Store) RandPeers(limit int, excludeFp uint64, knownFor time.Duration) []Peer {
	if len(s.list) == 0 {
		return nil
	}
	selected := make([]Peer, 0, limit)
	r := mrand.Float64() * s.trustSum
	for _, peer := range s.list {
		r -= peer.trust
		if peer.fp == excludeFp || time.Since(peer.added) < knownFor || time.Since(peer.seen) > s.dropAfter {
			continue
		}
		if s.trustSum == 0 || r <= 0 || mrand.Intn(s.probe) == 0 {
			selected = append(selected, *peer)
			if len(selected) == limit {
				return selected
			}
		}
	}
	return selected
}

// drops inactive peers
func (s *Store) Prune() {
	activeCount := 0
	for _, p := range s.table {
		if time.Since(p.seen) < s.dropAfter || p.edge {
			activeCount++
		}
	}
	if activeCount == len(s.table) {
		s.logger.Error("pruning skipped, got %d peers", activeCount)
		return
	}
	newTable := make(map[uint64]*Peer, activeCount)
	newList := make([]*Peer, 0, activeCount)
	var trustSum float64
	for k, p := range s.table {
		if time.Since(p.seen) < s.dropAfter || p.edge {
			newTable[k] = p
			newList = append(newList, p)
			trustSum += p.trust
		} else {
			s.logger.Error("dropped %s", p.addrPort)
		}
	}
	sort.Slice(newList, func(i, j int) bool {
		return newList[i].trust > newList[j].trust
	})
	s.table = newTable
	s.list = newList
	s.trustSum = trustSum
	s.logger.Error("pruned %d peers", len(s.list))
}

func addrPortFrom(pd *dave.Pd) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(pd.Ip)), uint16(pd.Port))
}

func PdFrom(addrport netip.AddrPort) *dave.Pd {
	ip := addrport.Addr().As16()
	return &dave.Pd{Ip: ip[:], Port: uint32(addrport.Port())}
}

func fingerprint(addrPort netip.AddrPort) uint64 {
	port := make([]byte, 2)
	binary.LittleEndian.PutUint16(port, addrPort.Port())
	h := xxhash.New()
	h.Write(port)
	addrPortBytes := addrPort.Addr().As16()
	h.Write(addrPortBytes[:])
	return h.Sum64()
}
