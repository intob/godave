package peer

import (
	"encoding/binary"
	mrand "math/rand"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/intob/godave/dave"
	"github.com/intob/godave/logger"
)

type StoreCfg struct {
	Probe      int
	MaxTrust   float64
	PruneEvery time.Duration
	Logger     *logger.Logger
}

func NewStore(cfg *StoreCfg) *Store {
	s := &Store{
		table:  make(map[uint64]*Peer),
		list:   make([]*Peer, 0),
		probe:  cfg.Probe,
		logger: cfg.Logger,
	}
	go func() {
		tick := time.NewTicker(cfg.PruneEvery)
		for range tick.C {
			s.prune()
		}
	}()
	return s
}

type Store struct {
	table    map[uint64]*Peer
	mu       sync.RWMutex
	list     []*Peer // sorted by trust descending
	trustSum float64
	probe    int
	logger   *logger.Logger
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.table)
}

// Adds or updates the peer
func (s *Store) Seen(addrPort netip.AddrPort) *Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	fp := fingerprint(addrPort)
	peer, exists := s.table[fp]
	if exists {
		peer.seen = time.Now()
		return peer
	}
	s.table[fp] = &Peer{
		fp:       fp,
		addrPort: addrPort,
		pd:       pdFrom(addrPort),
		added:    time.Now(),
	}
	return s.table[fp]
}

func (s *Store) AddEdge(addrPort netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fp := fingerprint(addrPort)
	s.table[fp] = &Peer{
		edge:     true,
		fp:       fp,
		addrPort: addrPort,
		pd:       pdFrom(addrPort),
		added:    time.Now(),
	}
}

func (s *Store) AddPd(pd *dave.Pd) (*Peer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	addrPort := addrPortFrom(pd)
	fp := fingerprint(addrPort)
	peer, exists := s.table[fp]
	if exists {
		return peer, false
	}
	s.table[fp] = &Peer{
		fp:       fp,
		addrPort: addrPort,
		pd:       pd,
		added:    time.Now(),
	}
	return s.table[fp], true
}

func (s *Store) Drop(peer *Peer) {
	s.mu.Lock()
	delete(s.table, peer.fp)
	s.mu.Unlock()
	s.prune()
}

func (s *Store) List() []*Peer {
	return s.list
}

func (s *Store) RandPeer() *Peer {
	if len(s.list) == 0 {
		return nil
	}
	if mrand.Intn(s.probe) == 0 {
		return s.list[mrand.Intn(len(s.list))]
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

func (s *Store) RandPeers(limit int, exclude *Peer, knownFor time.Duration) []*Peer {
	if len(s.list) == 0 {
		return nil
	}
	selected := make([]*Peer, 0, limit)
	r := mrand.Float64() * s.trustSum
	for _, peer := range s.list {
		r -= peer.trust
		if peer.fp == exclude.fp || time.Since(peer.added) < knownFor {
			continue
		}
		if s.trustSum == 0 || r <= 0 || mrand.Intn(s.probe) == 0 {
			selected = append(selected, peer)
			if len(selected) == limit {
				return selected
			}
		}
	}
	return selected
}

func (s *Store) prune() {
	start := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	newTable := make(map[uint64]*Peer, len(s.table))
	newList := make([]*Peer, 0, len(s.table))
	var trustSum float64
	for k, p := range s.table {
		newTable[k] = p
		newList = append(newList, p)
		trustSum += p.trust
	}
	sort.Slice(newList, func(i, j int) bool { return newList[i].trust > newList[j].trust })
	s.table = newTable
	s.list = newList
	s.trustSum = trustSum
	s.logger.Error("pruned %d peers in %s", len(newList), time.Since(start))
}

func addrPortFrom(pd *dave.Pd) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(pd.Ip)), uint16(pd.Port))
}

func pdFrom(addrport netip.AddrPort) *dave.Pd {
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
