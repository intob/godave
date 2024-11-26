package peer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
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
	Probe      int     // Inverse of probability that an untrusted peer is chosen
	MaxTrust   float64 // Maximum trust a peer can earn. Ensures fair resource distribution.
	PruneEvery time.Duration
	DropAfter  time.Duration // Time until unresponsive peers are dropped
	ListDelay  time.Duration // Time until new peers are candidates for selection
	Logger     *logger.Logger
}

type Store struct {
	table              map[uint64]*Peer
	list               []*Peer // sorted by trust descending
	trustSum, maxTrust float64
	probe              int
	dropAfter          time.Duration
	listDelay          time.Duration
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
	s.logger.Error("added %s", peer.addrPort)
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
	s.logger.Error("added from gossip %s", peer.addrPort)
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

func (s *Store) CreateChallenge(fp uint64) ([]byte, error) {
	peer, exists := s.table[fp]
	if !exists {
		return nil, errors.New("peer not found")
	}
	peer.challenge = make([]byte, 8)
	_, err := rand.Read(peer.challenge)
	if err != nil {
		return nil, err
	}
	return peer.challenge, nil
}

func (s *Store) CurrentChallengeAndPubKey(fp uint64) ([]byte, ed25519.PublicKey, error) {
	peer, exists := s.table[fp]
	if !exists {
		return nil, nil, errors.New("peer not found")
	}
	if len(peer.challenge) == 0 {
		return nil, nil, errors.New("challenge is empty")
	}
	return peer.challenge, peer.pubKey, nil
}

func (s *Store) SetPubKey(fp uint64, pubKey ed25519.PublicKey) error {
	peer, exists := s.table[fp]
	if !exists {
		return errors.New("peer not found")
	}
	if peer.pubKey != nil {
		return errors.New("pub key is already set")
	}
	peer.pubKey = pubKey
	return nil
}

func (s *Store) ClearChallenge(fp uint64) {
	peer, exists := s.table[fp]
	if !exists {
		return
	}
	peer.challenge = nil
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
