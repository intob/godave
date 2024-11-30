package ratelimit

import (
	"net/netip"
	"sync"
	"time"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/peer"
)

const startingTokens = uint16(100)
const startingIssueRate = uint8(100)
const tokenLimit = uint16(1000)

type RateLimiter struct {
	mu           sync.Mutex
	peerBalances map[netip.AddrPort]*peerBalance
	getPeers     chan<- bool
	peers        <-chan []peer.Peer
	logger       *logger.Logger
}

type peerBalance struct {
	tokens    uint16
	issueRate uint8
}

type RateLimiterCfg struct {
	GetPeers chan<- bool
	Peers    <-chan []peer.Peer
	Logger   *logger.Logger
}

func NewRateLimiter(cfg *RateLimiterCfg) *RateLimiter {
	r := &RateLimiter{
		peerBalances: make(map[netip.AddrPort]*peerBalance),
		getPeers:     cfg.GetPeers,
		peers:        cfg.Peers,
		logger:       cfg.Logger,
	}
	go func() {
		updateTick := time.NewTicker(30 * time.Second)
		addTokensTick := time.NewTicker(10 * time.Second)
		pruneTick := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-updateTick.C:
				r.updateIssueRates()
			case <-addTokensTick.C:
				r.addTokens()
			case <-pruneTick.C:
				r.prune()
			}
		}
	}()
	return r
}

func (r *RateLimiter) IsPacketAllowed(addrPort netip.AddrPort) bool {
	r.mu.Lock()
	balance, ok := r.peerBalances[addrPort]
	if !ok {
		r.peerBalances[addrPort] = &peerBalance{startingTokens, startingIssueRate}
		r.mu.Unlock()
		return true
	}
	if balance.tokens == 0 {
		r.mu.Unlock()
		return false
	}
	balance.tokens--
	r.mu.Unlock()
	return balance.tokens > 0
}

func (r *RateLimiter) updateIssueRates() {
	r.mu.Lock()
	r.getPeers <- true // true = get active only
	for _, peer := range <-r.peers {
		balance, ok := r.peerBalances[peer.AddrPort()]
		if !ok {
			continue
		}
		balance.issueRate = max(startingIssueRate, peer.Trust())
		r.logger.Debug("%s's issue rate updated to %d", peer.AddrPort(), balance.issueRate)
	}
	r.mu.Unlock()
}

func (r *RateLimiter) addTokens() {
	r.mu.Lock()
	for addr, balance := range r.peerBalances {
		if balance.tokens > tokenLimit-uint16(balance.issueRate) {
			balance.tokens = tokenLimit
		} else {
			balance.tokens += uint16(balance.issueRate)
			r.logger.Debug("%d tokens added to %s (%d)", balance.issueRate, addr, balance.tokens)
		}
	}
	r.mu.Unlock()
}

// Make a new map of peerBalances containing only balances
// for peers that still exist in the peer table.
func (r *RateLimiter) prune() {
	r.mu.Lock()
	oldLen := len(r.peerBalances)
	r.getPeers <- false // false = get all peers
	peers := <-r.peers
	newBalances := make(map[netip.AddrPort]*peerBalance)
	for _, peer := range peers {
		currentBalance, ok := r.peerBalances[peer.AddrPort()]
		if ok {
			newBalances[peer.AddrPort()] = currentBalance
		}
	}
	r.peerBalances = newBalances
	r.logger.Debug("pruned, removed %d stale entries", oldLen-len(r.peerBalances))
	r.mu.Unlock()
}
