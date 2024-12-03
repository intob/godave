package peer

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/types"
)

var ErrPeerNotFound = errors.New("peer not found")

type StoreCfg struct {
	Probe           int           // Inverse of probability that an untrusted peer is chosen
	ActivateAfter   time.Duration // Time until new peers are candidates for selection
	DeactivateAfter time.Duration // Time until unresponsive peers are deactivated
	DropAfter       time.Duration // Time until unresponsive peers are dropped
	PruneEvery      time.Duration
	Logger          logger.Logger
}

type Store struct {
	mu              sync.RWMutex
	table           map[netip.AddrPort]*peer
	active          []*peer // Sorted by trust descending
	edges           []*peer
	probe           int
	activateAfter   time.Duration
	deactivateAfter time.Duration
	dropAfter       time.Duration
	logger          logger.Logger
}

func NewStore(cfg *StoreCfg) *Store {
	s := &Store{
		table:           make(map[netip.AddrPort]*peer),
		active:          make([]*peer, 0),
		edges:           make([]*peer, 0),
		probe:           cfg.Probe,
		activateAfter:   cfg.ActivateAfter,
		deactivateAfter: cfg.DeactivateAfter,
		dropAfter:       cfg.DropAfter,
		logger:          cfg.Logger,
	}
	go func() {
		pruneTick := time.NewTicker(cfg.PruneEvery)
		for range pruneTick.C {
			s.prune()
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
	p := &peer{
		addrPort:            addrPort,
		added:               time.Now(),
		authChallengeSolved: time.Now(),
		edge:                isEdge,
	}
	s.table[addrPort] = p
	if isEdge {
		s.edges = append(s.edges, p)
	}
	s.log(logger.ERROR, "added %s", addrPort)
}

func (s *Store) SetPeerUsedSpaceAndCapacity(addrPort netip.AddrPort, usedSpace, capacity int64) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return ErrPeerNotFound
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	peer.usedSpace = usedSpace
	peer.capacity = capacity
	return nil
}

// Currently this is flawed, as a peer can lie about their resources.
// Maybe remove this entirely, or set bounds for acceptable figures.
// The larger the network, the more accurate this becomes.
func (s *Store) TotalUsedSpaceAndCapacity() (usedSpace, capacity uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.active {
		p.mu.RLock()
		usedSpace += uint64(p.usedSpace)
		capacity += uint64(p.capacity)
		p.mu.RUnlock()
	}
	return usedSpace, capacity
}

func (s *Store) CreateAuthChallenge(addrPort netip.AddrPort) (types.AuthChallenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return types.AuthChallenge{}, ErrPeerNotFound
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	_, err := rand.Read(peer.authChallenge[:])
	if err != nil {
		return types.AuthChallenge{}, err
	}
	return peer.authChallenge, nil
}

func (s *Store) CurrentAuthChallengeAndPubKey(addrPort netip.AddrPort) (types.AuthChallenge, ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return types.AuthChallenge{}, nil, ErrPeerNotFound
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.authChallenge == (types.AuthChallenge{}) {
		return types.AuthChallenge{}, nil, errors.New("challenge is empty")
	}
	currentChallenge := peer.authChallenge
	peer.authChallenge = types.AuthChallenge{}
	return currentChallenge, peer.publicKey, nil
}

func (s *Store) SetPublicKeyAndID(addrPort netip.AddrPort, publicKey ed25519.PublicKey) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return ErrPeerNotFound
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.publicKey != nil {
		return errors.New("public key is already set")
	}
	peer.publicKey = publicKey
	peer.id = IDFromPublicKey(publicKey)
	return nil
}

func (s *Store) AuthChallengeSolved(addrPort netip.AddrPort) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	peer.authChallengeSolved = time.Now()
}

func (s *Store) GetStorageChallenge(addrPort netip.AddrPort) (StorageChallenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return StorageChallenge{}, ErrPeerNotFound
	}
	peer.mu.RLock()
	defer peer.mu.RUnlock()
	challenge := peer.storageChallenge
	if challenge == nil || challenge.Expires.Before(time.Now()) {
		return StorageChallenge{}, errors.New("challenge nil or expired")
	}
	return *challenge, nil
}

func (s *Store) SetStorageChallenge(addrPort netip.AddrPort, challenge *StorageChallenge) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return ErrPeerNotFound
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.storageChallenge != nil && peer.storageChallenge.Expires.After(time.Now()) {
		return errors.New("peer already has a valid challenge")
	}
	peer.storageChallenge = challenge
	return nil
}

func (s *Store) StorageChallengeSent(addrPort netip.AddrPort) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return ErrPeerNotFound
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.storageChallenge == nil {
		return errors.New("peer has no storage challenge")
	}
	peer.storageChallenge.Sent = time.Now()
	return nil
}

func (s *Store) StorageChallengeCompleted(addrPort netip.AddrPort) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return ErrPeerNotFound
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	peer.storageChallenge = nil
	peer.storageChallengesCompleted++
	return nil
}

func (s *Store) StorageChallengeFailed(addrPort netip.AddrPort) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return ErrPeerNotFound
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	peer.storageChallenge = nil
	peer.storageChallengesFailed++
	return nil
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

func (s *Store) ListActive(exclude *netip.AddrPort) []PeerCopy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]PeerCopy, len(s.active))
	if exclude != nil {
		deref := *exclude
		for i, p := range s.active {
			if deref != p.addrPort {
				list[i] = copyFromPeer(p)
			}
		}
	} else {
		for i, p := range s.active {
			list[i] = copyFromPeer(p)
		}
	}
	return list
}

func (s *Store) ListAll() []PeerCopy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]PeerCopy, 0, len(s.table))
	for _, p := range s.table {
		list = append(list, copyFromPeer(p))
	}
	return list
}

func (s *Store) Edges() []PeerCopy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]PeerCopy, len(s.edges))
	for i, p := range s.edges {
		list[i] = copyFromPeer(p)
	}
	return list
}

// As the active peer slice is sorted by trust score, we can simply range over it,
// decrementing a counter initialised to a random value between 0 and the trust sum.
// This naturally favours peers with higher trust scores.
/*
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
*/

// For such a simple problem, I found it surprisingly tough to make
// an efficient implementation.
func (s *Store) RandPeers(limit int, exclude *netip.AddrPort) []PeerCopy {
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
	selected := make([]PeerCopy, 0, targetCount)
	// Partial Fisher-Yates shuffle on valid indices
	for i := 0; i < targetCount; i++ {
		j := i + mrand.Intn(len(indices)-i)
		indices[i], indices[j] = indices[j], indices[i]
		selected = append(selected, copyFromPeer(s.active[indices[i]]))
	}
	return selected
}

// Drops/deactivates inactive peers. Inactive edges are not dropped, but deactivated.
func (s *Store) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	newActive := make([]*peer, 0, len(s.active))
	for k, p := range s.table {
		if p.edge { // Never drop edges, even if they go offline
			if time.Since(p.authChallengeSolved) < s.deactivateAfter {
				newActive = append(newActive, p)
			}
		} else {
			if time.Since(p.authChallengeSolved) < s.dropAfter {
				if time.Since(p.added) > s.activateAfter &&
					time.Since(p.authChallengeSolved) < s.deactivateAfter {
					newActive = append(newActive, p)
				}
			} else {
				delete(s.table, k)
				s.log(logger.ERROR, "dropped %s", p.addrPort)
			}
		}
	}
	s.active = newActive
	s.log(logger.DEBUG, "pruned, active: %d/%d", len(s.active), len(s.table))
}

func (s *Store) log(level logger.LogLevel, msg string, args ...any) {
	if s.logger != nil {
		s.logger.Log(level, msg, args...)
	}
}
