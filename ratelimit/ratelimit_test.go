package ratelimit

import (
	"net/netip"
	"testing"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/peer"
)

func BenchmarkIsPacketAllowed(b *testing.B) {
	getPeers := make(chan bool)
	peers := make(chan []peer.Peer)
	go func() {
		for range getPeers {
			peers <- []peer.Peer{}
		}
	}()
	limiter := NewRateLimiter(&RateLimiterCfg{
		GetPeers: getPeers,
		Peers:    peers,
		Logger:   logger.NewLoggerToDevNull(),
	})
	addr := netip.MustParseAddrPort("127.0.0.1:1234")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.IsPacketAllowed(addr)
	}
}
