package peer

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/types"
)

type StoreCfg struct {
	Probe            int           // Inverse of probability that an untrusted peer is chosen
	ActivationDelay  time.Duration // Time until new peers are candidates for selection
	DeactivateAfter  time.Duration // Time until unresponsive peers are deactivated
	DropAfter        time.Duration // Time until unresponsive peers are dropped
	TrustDecayFactor float64
	PruneEvery       time.Duration
	DecayEvery       time.Duration
	Logger           logger.Logger
}

type Store struct {
	mu              sync.RWMutex
	table           map[netip.AddrPort]*Peer
	active          []*Peer // sorted by trust descending
	edges           []*Peer
	trustSum        float64
	probe           int
	activationDelay time.Duration
	deactivateAfter time.Duration
	dropAfter       time.Duration
	logger          logger.Logger
}

func NewStore(cfg *StoreCfg) *Store {
	s := &Store{
		table:           make(map[netip.AddrPort]*Peer),
		active:          make([]*Peer, 0),
		edges:           make([]*Peer, 0),
		probe:           cfg.Probe,
		activationDelay: cfg.ActivationDelay,
		deactivateAfter: cfg.DeactivateAfter,
		dropAfter:       cfg.DropAfter,
		logger:          cfg.Logger,
	}
	go func() {
		pruneTick := time.NewTicker(cfg.PruneEvery)
		decayTick := time.NewTicker(cfg.DecayEvery)
		for {
			select {
			case <-pruneTick.C:
				s.prune()
			case <-decayTick.C:
				s.decayTrust(cfg.TrustDecayFactor)
			}
		}
	}()
	return s
}

// Peer is added if not found.
func (s *Store) AddPeer(addrPort netip.AddrPort, isEdge bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.table[addrPort]
	if exists {
		return
	}
	peer := &Peer{
		addrPort:        addrPort,
		added:           time.Now(),
		challengeSolved: time.Now(),
		edge:            isEdge,
	}
	s.table[addrPort] = peer
	if isEdge {
		s.edges = append(s.edges, peer)
	}
	s.log(logger.ERROR, "added %s", peer.addrPort)
}

func (s *Store) UpdateTrust(addrPort netip.AddrPort, delta float64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return
	}
	oldTrust := peer.trust
	peer.trust = peer.trust + delta
	s.trustSum += peer.trust - oldTrust
}

func (s *Store) CreateChallenge(addrPort netip.AddrPort) (types.Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return types.Challenge{}, errors.New("peer not found")
	}
	_, err := rand.Read(peer.challenge[:])
	if err != nil {
		return types.Challenge{}, err
	}
	return peer.challenge, nil
}

func (s *Store) CurrentChallengeAndPubKey(addrPort netip.AddrPort) (types.Challenge, ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return types.Challenge{}, nil, errors.New("peer not found")
	}
	if peer.challenge == (types.Challenge{}) {
		return types.Challenge{}, nil, errors.New("challenge is empty")
	}
	currentChallenge := peer.challenge
	peer.challenge = types.Challenge{}
	return currentChallenge, peer.publicKey, nil
}

func (s *Store) SetPublicKeyAndID(addrPort netip.AddrPort, publicKey ed25519.PublicKey) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return errors.New("peer not found")
	}
	if peer.publicKey != nil {
		return errors.New("public key is already set")
	}
	peer.publicKey = publicKey
	peer.id = IDFromPublicKey(publicKey)
	return nil
}

func (s *Store) ChallengeSolved(addrPort netip.AddrPort) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return
	}
	peer.challengeSolved = time.Now()
}

func (s *Store) IsPingExpected(addrPort netip.AddrPort, ping time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return false
	}
	return time.Since(peer.pingReceived) >= ping-200*time.Millisecond
}

func (s *Store) UpdatePingReceived(addrPort netip.AddrPort) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return
	}
	peer.pingReceived = time.Now()
}

func (s *Store) IsEdge(addrPort netip.AddrPort) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, ok := s.table[addrPort]
	if !ok {
		return false
	}
	return peer.edge
}

func (s *Store) CountActive() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.active)
}

func (s *Store) ListActive(exclude *netip.AddrPort) []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]Peer, len(s.active))
	if exclude != nil {
		deref := *exclude
		for i, p := range s.active {
			if deref != p.addrPort {
				list[i] = *p
			}
		}
	} else {
		for i, p := range s.active {
			list[i] = *p
		}
	}
	return list
}

func (s *Store) ListAll() []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]Peer, 0, len(s.table))
	for _, p := range s.table {
		list = append(list, *p)
	}
	return list
}

func (s *Store) Edges() []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]Peer, len(s.edges))
	for i, p := range s.edges {
		list[i] = *p
	}
	return list
}

// As the active peer slice is sorted by trust score, we can simply range over it,
// decrementing a counter initialised to a random value between 0 and the trust sum.
// This naturally favours peers with higher trust scores.
func (s *Store) TrustWeightedRandPeers(limit int, exclude *netip.AddrPort) []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.active) == 0 {
		return nil
	}
	if s.trustSum == 0 {
		return s.RandPeers(limit, exclude)
	}
	selected := make([]Peer, 0, min(limit, len(s.active)))
	r := mrand.Float64() * s.trustSum
	for _, peer := range s.active {
		r -= peer.trust
		if exclude != nil && peer.addrPort == *exclude {
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

// For such a simple problem, I found it surprisingly tough to make
// an efficient implementation.
func (s *Store) RandPeers(limit int, exclude *netip.AddrPort) []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.active) == 0 {
		return nil
	}
	// Create slice of valid indices (excluding the excluded peer)
	// TODO: consider caching this for a short time.
	indices := make([]int, 0, len(s.active))
	for i, p := range s.active {
		if exclude == nil || p.addrPort != *exclude {
			indices = append(indices, i)
		}
	}
	targetCount := min(limit, len(indices))
	selected := make([]Peer, 0, targetCount)
	// Partial Fisher-Yates shuffle on valid indices
	for i := 0; i < targetCount; i++ {
		j := i + mrand.Intn(len(indices)-i)
		indices[i], indices[j] = indices[j], indices[i]
		selected = append(selected, *s.active[indices[i]])
	}
	return selected
}

// Drops/deactivates inactive peers. Inactive edges are not dropped, but deactivated..
func (s *Store) prune() {
	s.mu.RLock()
	activeCount := 0
	for _, p := range s.table {
		if time.Since(p.challengeSolved) < s.deactivateAfter {
			activeCount++
		}
	}
	if activeCount == len(s.table) && activeCount == len(s.active) {
		s.log(logger.ERROR, "prune skipped, active: %d/%d", activeCount, activeCount)
		s.mu.RUnlock()
		return
	}
	newTable := make(map[netip.AddrPort]*Peer, activeCount)
	newActive := make([]*Peer, 0, activeCount)
	var trustSum float64
	for k, p := range s.table {
		if p.edge { // Never drop edges, even if they go offline
			newTable[k] = p
			if time.Since(p.challengeSolved) < s.deactivateAfter {
				newActive = append(newActive, p)
				trustSum += p.trust
			}
		} else {
			if time.Since(p.challengeSolved) < s.dropAfter {
				newTable[k] = p
				if time.Since(p.added) > s.activationDelay &&
					time.Since(p.challengeSolved) < s.deactivateAfter {
					newActive = append(newActive, p)
					trustSum += p.trust
				}
			} else {
				s.log(logger.ERROR, "dropped %s", p.addrPort)
			}
		}
	}
	s.mu.RUnlock()
	sort.Slice(newActive, func(i, j int) bool {
		return newActive[i].trust > newActive[j].trust
	})
	s.mu.Lock()
	s.table = newTable
	s.active = newActive
	s.trustSum = trustSum
	s.log(logger.ERROR, "pruned, active: %d/%d", len(s.active), len(s.table))
	s.mu.Unlock()
}

func (s *Store) decayTrust(decayFactor float64) {
	for _, peer := range s.active {
		if peer.trust > 0 {
			oldTrust := peer.trust
			peer.trust = peer.trust * decayFactor
			s.trustSum -= oldTrust - peer.trust
		}
	}
}

func (s *Store) log(level logger.LogLevel, msg string, args ...any) {
	if s.logger != nil {
		s.logger.Log(level, msg, args...)
	}
}
