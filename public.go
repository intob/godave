// This file contains the publicly exposed methods and types of the main package.
package godave

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"github.com/intob/godave/dat"
	"github.com/intob/godave/logger"
	"github.com/intob/godave/network"
	"github.com/intob/godave/peer"
	"github.com/intob/godave/store"
	"github.com/intob/godave/sub"
	"github.com/intob/godave/tcp"
	"github.com/intob/godave/types"
	"github.com/intob/godave/udp"
	"lukechampine.com/blake3"
)

type Dave struct {
	privateKey               ed25519.PrivateKey
	publicKey                ed25519.PublicKey
	myID                     uint64
	killStore, killStoreDone chan struct{}
	peers                    *peer.Store
	store                    *store.Store
	udp                      *udp.UDPService
	tcp                      *tcp.TCPService
	logger                   logger.Logger
	subSvc                   *sub.SubscriptionService
}

type DaveCfg struct {
	// UDP listen address:port. IP must be a pure IPv6 address. For localhost, use [::1].
	// A TCP listener will be created on the next port, for example if this is on port 40,
	// dave will listen for TCP connections on port 41.
	UdpListenAddr *net.UDPAddr
	// Node private key. The last 32 bytes are the public key. The node ID is
	// derived from the first 8 bytes of the public key.
	PrivateKey     ed25519.PrivateKey
	Edges          []netip.AddrPort // Bootstrap peers.
	ShardCapacity  int64            // Capacity of each of 256 shards in bytes.
	BackupFilename string           // Filename of backup file. Leave blank to disable backup.
	// Set to nil to disable logging, although this is not reccomended. Currently
	// logging is the best way to monitor. In future, the API will be better.
	Logger logger.Logger
}

// NewDave returns a running instance of Dave, or an error.
func NewDave(cfg *DaveCfg) (*Dave, error) {
	subSvc := sub.NewSubscriptionService(100)
	tcpSvc, err := tcp.NewTCPService(cfg.UdpListenAddr, cfg.Logger.WithPrefix("/tcp"))
	if err != nil {
		return nil, fmt.Errorf("failed to init TCP service: %w", err)
	}
	udpSvc, err := udp.NewUDPService(cfg.UdpListenAddr, cfg.Logger.WithPrefix("/udp"))
	if err != nil {
		return nil, fmt.Errorf("failed to init UDP service: %w", err)
	}
	d := &Dave{
		privateKey: cfg.PrivateKey, publicKey: cfg.PrivateKey.Public().(ed25519.PublicKey),
		myID:      peer.IDFromPublicKey(cfg.PrivateKey.Public().(ed25519.PublicKey)),
		killStore: make(chan struct{}), killStoreDone: make(chan struct{}),
		peers: peer.NewStore(&peer.StoreCfg{
			SubSvc: subSvc,
			Logger: cfg.Logger.WithPrefix("/peers")}),
		subSvc: subSvc,
		udp:    udpSvc,
		tcp:    tcpSvc,
		logger: cfg.Logger}
	d.log(logger.ERROR, "MY ID: %d", d.myID)
	for _, addrPort := range cfg.Edges {
		d.peers.AddPeer(udp.MapToIPv6(addrPort), true)
	}
	d.store = store.NewStore(&store.StoreCfg{
		MyID:           peer.IDFromPublicKey(cfg.PrivateKey.Public().(ed25519.PublicKey)),
		Capacity:       cfg.ShardCapacity,
		BackupFilename: cfg.BackupFilename, Kill: d.killStore, Done: d.killStoreDone,
		Logger: cfg.Logger.WithPrefix("/dats")})
	if cfg.BackupFilename != "" {
		err = d.store.ReadBackup()
		if err != nil {
			d.log(logger.ERROR, "failed to read backup: %s", err)
		}
	}
	go d.handleMessages()
	go d.manageReplicas()
	go d.managePeerDiscovery()
	return d, nil
}

// Kill initiates a graceful shutdown. This is important, as the store uses a buffer
// to write to the filesystem. This buffer must be flushed to prevent loss of the data
// in the buffer.
func (d *Dave) Kill() {
	close(d.killStore)
	<-d.killStoreDone
}

// BatchWriter finds the peers closest to the given public key, and creates TCP
// connections to them. A channel is returned on which the caller can send signed
// and proven Dats. The caller must close the channel, which will flush the buffers,
// and close the TCP connections.
func (d *Dave) BatchWriter(publicKey ed25519.PublicKey) (chan<- dat.Dat, <-chan error, error) {
	activePeers := append(d.peers.ListActive(nil), peer.PeerCopy{ID: d.myID})
	if len(activePeers) == 1 {
		return nil, nil, errors.New("no active peers")
	}
	dats := make(chan dat.Dat, runtime.NumCPU())
	errors := make(chan error, 1)
	go func() {
		defer close(errors)
		sorted := peer.SortPeersByDistance(peer.IDFromPublicKey(publicKey), activePeers)
		replicas := [network.FANOUT]uint64{}
		writers := make([]*tcp.ConnWriter, 0, network.FANOUT)
		for i := 0; i < network.FANOUT && i < len(sorted); i++ {
			if sorted[i].Peer.ID != d.myID {
				w, err := tcp.Dial(sorted[i].Peer.AddrPort)
				if err != nil {
					d.log(logger.ERROR, "failed to dial: %s", err)
					continue
				}
				writers = append(writers, w)
			}
			replicas[i] = sorted[i].Peer.ID
		}
		defer func(writers []*tcp.ConnWriter) {
			for _, w := range writers {
				w.Writer.Flush()
				w.Conn.Close()
			}
		}(writers)
		mbuf := make([]byte, network.MAX_MSG_LEN+2)
		for dat := range dats {
			e := &store.Entry{Dat: dat, Replicas: replicas}
			err := d.store.Write(e)
			if err != nil {
				select {
				case errors <- fmt.Errorf("failed to write entry to local store: %s", err):
				default:
				}
				return
			}
			m := &types.Msg{Op: types.OP_PUT, Entry: e}
			n, err := m.Marshal(mbuf[2:])
			binary.LittleEndian.PutUint16(mbuf, uint16(n))
			if err != nil {
				errors <- fmt.Errorf("failed to marshal message: %w", err)
				return
			}
			for _, w := range writers {
				w.Writer.Write(mbuf[:n+2])
			}
		}
	}()
	return dats, errors, nil
}

// Get returns a store entry, or an error. If not found locally, requests will be
// sent to the peers that are closest to the given public key. Use the context
// to implement a timeout.
func (d *Dave) Get(ctx context.Context, get *types.Get) (*store.Entry, error) {
	if get == nil {
		return nil, errors.New("get is nil")
	}
	stored, err := d.store.Read(get.PublicKey, get.DatKey)
	if err == nil {
		d.log(logger.DEBUG, "found locally: %s", stored.Dat.Key)
		return &stored, nil
	}
	activePeers := d.peers.ListActive(nil)
	if len(activePeers) == 0 {
		return nil, errors.New("no active peers")
	}
	evch := d.subSvc.Subscribe(sub.RECV_GET_ACK)
	defer d.subSvc.Unsubscribe(sub.RECV_GET_ACK, evch)
	sorted := peer.SortPeersByDistance(peer.IDFromPublicKey(get.PublicKey), activePeers)
	count := min(network.FANOUT, len(sorted))
	for i := 0; i < count; i++ {
		d.udp.Out() <- &udp.Packet{Msg: &types.Msg{Op: types.OP_GET, Get: get},
			AddrPort: sorted[i].Peer.AddrPort}
	}
	hasher := blake3.New(32, nil)
	var received int
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case e := <-evch:
			pkt, ok := e.(*udp.Packet)
			if !ok {
				d.log(logger.ERROR, "expected event type *pkt.Packet, got %T", pkt)
				continue
			}
			msgDat := pkt.Msg.Entry.Dat
			if !bytes.Equal(msgDat.PubKey, get.PublicKey) || msgDat.Key != get.DatKey {
				continue
			}
			received++
			if msgDat.Sig == (dat.Signature{}) {
				d.log(logger.DEBUG, "not found from %d/%d", received, count)
				if received == count {
					return nil, errors.New("not found")
				} else {
					continue
				}
			}
			hasher.Reset()
			err = msgDat.Verify(hasher)
			if err != nil {
				d.log(logger.ERROR, "verification failed: %s", err)
				continue
			}
			err = d.store.Write(pkt.Msg.Entry)
			if err != nil {
				d.log(logger.ERROR, "failed to store: %s", err)
				continue
			}
			return pkt.Msg.Entry, nil
		}
	}
}

// WaitForActivePeers returns a nil error when the desired number of peers
// is reached. Use the context to implement a timeout.
func (d *Dave) WaitForActivePeers(ctx context.Context, count int) error {
	ev := d.subSvc.Subscribe(sub.PEERS_PRUNED)
	defer d.subSvc.Unsubscribe(sub.PEERS_PRUNED, ev)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ev:
			if d.peers.CountActive() >= count {
				return nil
			}
		}
	}
}

// UsedSpace returns the approximate memory in bytes used by the local store.
func (d *Dave) UsedSpace() int64 {
	return d.store.Used()
}

// Capacity returns the maximum memory allowance that the local store may use.
func (d *Dave) Capacity() int64 {
	return d.store.Capacity()
}

// ActivePeerCount returns the number of peers that are currently activated.
func (d *Dave) ActivePeerCount() int {
	return d.peers.CountActive()
}

// NetworkUsedSpaceAndCapacity returns the used space and capacity of the network.
// This value is only an approximation. There is currently no way to know if nodes
// are lying. Nodes are not incentivised to lie, because there is no reward or
// penalty either way.
func (d *Dave) NetworkUsedSpaceAndCapacity() (usedSpace, capacity uint64) {
	return d.peers.TotalUsedSpaceAndCapacity()
}
