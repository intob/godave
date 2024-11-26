package peer

import (
	"encoding/binary"
	"math"
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
	ListDelay  time.Duration
	Ping       time.Duration
	Logger     *logger.Logger
}

type Store struct {
	table              map[uint64]*Peer
	list               []*Peer // sorted by trust descending
	trustSum, maxTrust float64
	probe              int
	dropAfter          time.Duration
	listDelay          time.Duration
	ping               time.Duration
	logger             *logger.Logger
}

func NewStore(cfg *StoreCfg) *Store {
	s := &Store{
		table:     make(map[uint64]*Peer),
		list:      make([]*Peer, 0),
		probe:     cfg.Probe,
		maxTrust:  cfg.MaxTrust,
		dropAfter: cfg.DropAfter,
		listDelay: cfg.ListDelay,
		ping:      cfg.Ping,
		logger:    cfg.Logger,
	}
	return s
}

func (s *Store) CountActive() int {
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
	s.logger.Error("added %s", peer)
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
	// New peers from gossip are not added to the list directly.
	// During prune, if they've been known for SHARE_DELAY,
	// and seen recently active, they will be added to the list.
	//s.list = append(s.list, peer)
	s.logger.Error("added from gossip %s", peer)
}

func (s *Store) AddTrust(fp uint64, delta float64) {
	peer, exists := s.table[fp]
	if !exists {
		return
	}
	oldTrust := peer.trust
	peer.trust = math.Min(peer.trust+delta, s.maxTrust)
	s.trustSum += peer.trust - oldTrust
	s.logger.Debug("trust sum updated to %f", s.trustSum)
}

// Returns false if PEER message is received sooner than expected.
// This is important to prevent peer table poisoning.
func (s *Store) IsPeerMessageExpected(fp uint64) bool {
	peer, exists := s.table[fp]
	if !exists {
		return false
	}
	// Some margin is given to allow for latency, as maybe the previous PEER
	// message was late.
	sinceLast := time.Since(peer.lastPeerMsgReceived)
	if sinceLast < s.ping-s.ping/10 {
		s.logger.Error("unexpected PEER message from %s, %s since last", peer.addrPort, sinceLast)
		return false
	}
	peer.lastPeerMsgReceived = time.Now()
	return true
}

// Can't use list to ping because once-inactive edges may now be online
// but are omitted from the list.
func (s *Store) Table() map[uint64]*Peer {
	return s.table
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

func (s *Store) RandPeers(limit int, excludeFp uint64) []Peer {
	if len(s.list) == 0 {
		return nil
	}
	selected := make([]Peer, 0, limit)
	r := mrand.Float64() * s.trustSum
	for _, peer := range s.list {
		r -= peer.trust
		if peer.fp == excludeFp {
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

// Drops inactive peers. Inactive edges are not dropped, but excluded from seeding.
func (s *Store) Prune() {
	activeCount := 0
	for _, p := range s.table {
		if time.Since(p.seen) < s.dropAfter {
			activeCount++
		}
	}
	if activeCount == len(s.table) && activeCount == len(s.list) {
		s.logger.Error("prune skipped, active: %d/%d", activeCount, activeCount)
		return
	}
	newTable := make(map[uint64]*Peer, activeCount)
	newList := make([]*Peer, 0, activeCount)
	var trustSum float64
	for k, p := range s.table {
		if p.edge { // Never drop edges, even if they go offline
			newTable[k] = p
			if time.Since(p.seen) < s.dropAfter { // Only share with them if they're online
				newList = append(newList, p)
				trustSum += p.trust
			}
		} else {
			if time.Since(p.seen) < s.dropAfter {
				newTable[k] = p
				if time.Since(p.added) > s.listDelay { // Peers must wait to be added to the list
					newList = append(newList, p)
					trustSum += p.trust
				}
			} else {
				s.logger.Error("dropped %s", p.addrPort)
			}
		}
	}
	sort.Slice(newList, func(i, j int) bool {
		return newList[i].trust > newList[j].trust
	})
	s.table = newTable
	s.list = newList
	s.trustSum = trustSum
	s.logger.Error("pruned, active: %d/%d", len(s.list), len(s.table))
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
