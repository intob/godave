package ratelimiter

import (
	"math"
	"net/netip"
	"time"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/peer"
)

const startingTokens = uint16(20)
const startingIssueRate = uint8(20)

type RateLimiter struct {
	peerBalances   map[netip.AddrPort]*peerBalance
	getActivePeers chan<- struct{}
	activePeers    <-chan []peer.Peer
	logger         *logger.Logger
}

type peerBalance struct {
	tokens    uint16
	issueRate uint8
}

type RateLimiterCfg struct {
	GetActivePeers chan<- struct{}
	ActivePeers    <-chan []peer.Peer
	Logger         *logger.Logger
}

func NewRateLimiter(cfg *RateLimiterCfg) *RateLimiter {
	r := &RateLimiter{
		peerBalances:   make(map[netip.AddrPort]*peerBalance),
		getActivePeers: cfg.GetActivePeers,
		activePeers:    cfg.ActivePeers,
		logger:         cfg.Logger,
	}
	go func() {
		updateTick := time.NewTicker(30 * time.Second)
		addTokensTick := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-updateTick.C:
				r.updateIssueRates()
			case <-addTokensTick.C:
				r.addTokens()
			}
		}
	}()
	return r
}

func (r *RateLimiter) IsPacketAllowed(addrPort netip.AddrPort) bool {
	balance, ok := r.peerBalances[addrPort]
	if !ok {
		r.peerBalances[addrPort] = &peerBalance{startingTokens, startingIssueRate}
		return true
	}
	if balance.tokens == 0 {
		return false
	}
	balance.tokens--
	return balance.tokens > 0
}

func (r *RateLimiter) updateIssueRates() {
	r.getActivePeers <- struct{}{}
	activePeers := <-r.activePeers
	for _, peer := range activePeers {
		balance, ok := r.peerBalances[peer.AddrPort()]
		if !ok {
			continue
		}
		balance.issueRate = max(startingIssueRate, peer.Trust())
	}
}

func (r *RateLimiter) addTokens() {
	for addr, balance := range r.peerBalances {
		if balance.tokens > math.MaxUint16-uint16(balance.issueRate) {
			balance.tokens = math.MaxUint16
		} else {
			balance.tokens += uint16(balance.issueRate)
			r.logger.Debug("%d tokens added to %s (%d)", balance.issueRate, addr, balance.tokens)
		}
	}
}
