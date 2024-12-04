package peer

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/intob/godave/auth"
	"github.com/intob/godave/logger"
	"github.com/intob/godave/network"
	"github.com/intob/godave/sub"
)

var ErrPeerNotFound = errors.New("peer not found")

type StoreCfg struct {
	SubSvc *sub.SubscriptionService
	Logger logger.Logger
}

type Store struct {
	mu          sync.RWMutex
	table       map[netip.AddrPort]*peer
	active      map[netip.AddrPort]*peer
	activeSlice []*peer
	edges       []*peer
	subSvc      *sub.SubscriptionService
	logger      logger.Logger
}

func NewStore(cfg *StoreCfg) *Store {
	s := &Store{
		table:       make(map[netip.AddrPort]*peer),
		active:      make(map[netip.AddrPort]*peer),
		activeSlice: make([]*peer, 0),
		edges:       make([]*peer, 0),
		subSvc:      cfg.SubSvc,
		logger:      cfg.Logger,
	}
	go func() {
		pruneTick := time.NewTicker(network.DEACTIVATE_AFTER)
		for range pruneTick.C {
			s.prune()
		}
	}()
	return s
}

// Peer is added if not found.
func (s *Store) AddPeer(addrPort netip.AddrPort, isEdge bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.table[addrPort]
	if exists {
		return errors.New("peer already added")
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
	s.log(logger.DEBUG, "added %s", addrPort)
	return nil
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

func (s *Store) CreateAuthChallenge(addrPort netip.AddrPort) (auth.AuthChallenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return auth.AuthChallenge{}, ErrPeerNotFound
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	_, err := rand.Read(peer.authChallenge[:])
	if err != nil {
		return auth.AuthChallenge{}, err
	}
	return peer.authChallenge, nil
}

func (s *Store) CurrentAuthChallengeAndPubKey(addrPort netip.AddrPort) (auth.AuthChallenge, ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, exists := s.table[addrPort]
	if !exists {
		return auth.AuthChallenge{}, nil, ErrPeerNotFound
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.authChallenge == (auth.AuthChallenge{}) {
		return auth.AuthChallenge{}, nil, errors.New("challenge is empty")
	}
	currentChallenge := peer.authChallenge
	peer.authChallenge = auth.AuthChallenge{}
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
	if challenge == nil {
		return StorageChallenge{}, errors.New("challenge is nil")
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
		for i, p := range s.activeSlice {
			if deref != p.addrPort {
				list[i] = copyFromPeer(p)
			}
		}
	} else {
		for i, p := range s.activeSlice {
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
	if len(s.activeSlice) == 0 {
		return nil
	}
	// Create slice of valid indices (excluding the excluded peer)
	// TODO: consider caching this for a short time.
	indices := make([]int, 0, len(s.activeSlice))
	for i, p := range s.activeSlice {
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
		selected = append(selected, copyFromPeer(s.activeSlice[indices[i]]))
	}
	return selected
}

// Drops/deactivates inactive peers. Inactive edges are not dropped, but deactivated.
func (s *Store) prune() {
	s.mu.Lock()
	dropped := make([]PeerCopy, 0)
	now := time.Now()
	for k, p := range s.table {
		isActive := now.Sub(p.authChallengeSolved) < network.DEACTIVATE_AFTER
		_, alreadyActive := s.active[k]
		if p.edge {
			if isActive && !alreadyActive {
				s.active[k] = p
				s.subSvc.Publish(sub.PEER_ADDED, copyFromPeer(p))
			} else if !isActive {
				delete(s.active, k)
			}
			continue
		}
		if now.Sub(p.authChallengeSolved) >= network.DROP_AFTER {
			dropped = append(dropped, copyFromPeer(p))
			delete(s.table, k)
			delete(s.active, k)
			s.log(logger.ERROR, "dropped %s", p.addrPort)
			continue
		}
		shouldBeActive := isActive && now.Sub(p.added) > network.ACTIVATE_AFTER
		if shouldBeActive && !alreadyActive {
			s.active[k] = p
			s.subSvc.Publish(sub.PEER_ADDED, copyFromPeer(p))
		} else if !shouldBeActive {
			delete(s.active, k)
		}
	}
	s.activeSlice = make([]*peer, 0, len(s.active))
	for _, p := range s.active {
		s.activeSlice = append(s.activeSlice, p)
	}
	activeCount, totalCount := len(s.active), len(s.table)
	s.mu.Unlock()
	for _, d := range dropped {
		s.subSvc.Publish(sub.PEER_DROPPED, d)
	}
	s.subSvc.Publish(sub.PEERS_PRUNED, struct{}{})
	s.log(logger.DEBUG, "pruned, active: %d/%d", activeCount, totalCount)
}

func (s *Store) log(level logger.LogLevel, msg string, args ...any) {
	if s.logger != nil {
		s.logger.Log(level, msg, args...)
	}
}
