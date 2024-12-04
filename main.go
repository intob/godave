package godave

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/intob/godave/auth"
	"github.com/intob/godave/dat"
	"github.com/intob/godave/logger"
	"github.com/intob/godave/network"
	"github.com/intob/godave/peer"
	"github.com/intob/godave/pkt"
	"github.com/intob/godave/store"
	"github.com/intob/godave/sub"
	"github.com/intob/godave/types"
	"lukechampine.com/blake3"
)

type Dave struct {
	privateKey               ed25519.PrivateKey
	publicKey                ed25519.PublicKey
	myID                     uint64
	killStore, killStoreDone chan struct{}
	peers                    *peer.Store
	store                    *store.Store
	pproc                    *pkt.PacketProcessor
	logger                   logger.Logger
	subSvc                   *sub.SubscriptionService
}

type DaveCfg struct {
	// A UDP socket. Normally from net.ListenUDP. This interface can be mocked
	// to build simulations.
	Socket pkt.Socket
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

func NewDave(cfg *DaveCfg) (*Dave, error) {
	subSvc := sub.NewSubscriptionService(100)
	d := &Dave{
		privateKey: cfg.PrivateKey, publicKey: cfg.PrivateKey.Public().(ed25519.PublicKey),
		myID:      peer.IDFromPublicKey(cfg.PrivateKey.Public().(ed25519.PublicKey)),
		killStore: make(chan struct{}), killStoreDone: make(chan struct{}),
		peers: peer.NewStore(&peer.StoreCfg{
			SubSvc: subSvc,
			Logger: cfg.Logger.WithPrefix("/peers")}),
		subSvc: subSvc,
		logger: cfg.Logger}
	for _, addrPort := range cfg.Edges {
		d.peers.AddPeer(pkt.MapToIPv6(addrPort), true)
	}
	d.store = store.NewStore(&store.StoreCfg{
		MyID:           peer.IDFromPublicKey(cfg.PrivateKey.Public().(ed25519.PublicKey)),
		Capacity:       cfg.ShardCapacity,
		BackupFilename: cfg.BackupFilename, Kill: d.killStore, Done: d.killStoreDone,
		Logger: cfg.Logger.WithPrefix("/dats")})
	err := d.store.ReadBackup()
	if err != nil {
		d.log(logger.ERROR, "failed to read backup: %s", err)
	}
	d.pproc, err = pkt.NewPacketProcessor(cfg.Socket, cfg.Logger.WithPrefix("/pproc"))
	if err != nil {
		return nil, fmt.Errorf("failed to init packet processor: %s", err)
	}
	go d.handlePackets()
	go d.manageReplicas()
	go d.run()
	return d, nil
}

func (d *Dave) Kill() {
	close(d.killStore)
	<-d.killStoreDone
}

func (d *Dave) Put(dat dat.Dat) error {
	activePeers := d.peers.ListActive(nil)
	if len(activePeers) == 0 {
		return errors.New("no active peers")
	}
	sorted := peer.SortPeersByDistance(peer.IDFromPublicKey(dat.PubKey), activePeers)
	entry := &store.Entry{Dat: dat}
	for i := 0; i < network.FANOUT && i < len(sorted); i++ {
		entry.Replicas[i] = sorted[i].Peer.ID
	}
	for i := 0; i < network.FANOUT && i < len(sorted); i++ {
		if mrand.Float64() <= network.STORAGE_CHALLENGE_PROBABILITY {
			d.peers.SetStorageChallenge(sorted[i].Peer.AddrPort, &peer.StorageChallenge{
				PublicKey: dat.PubKey, DatKey: dat.Key,
				Expires: time.Now().Add(network.TTL - time.Second)})
		}
		d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_PUT, Entry: entry},
			AddrPort: sorted[i].Peer.AddrPort}
		d.log(logger.DEBUG, "sent to %s (%v)", sorted[i].Peer.AddrPort, sorted[i].Peer.ID)
	}
	err := d.store.Write(entry)
	if err != nil {
		return fmt.Errorf("failed to write entry to local store: %s", err)
	}
	return nil
}

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
		d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_GET, Get: get},
			AddrPort: sorted[i].Peer.AddrPort}
	}
	hasher := blake3.New(32, nil)
	var received int
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case e := <-evch:
			pkt, ok := e.(*pkt.Packet)
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
			// TODO: send to nodes that responded with "not found"
			return pkt.Msg.Entry, nil
		}
	}
}

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

func (d *Dave) UsedSpace() int64 {
	return d.store.Used()
}

func (d *Dave) Capacity() int64 {
	return d.store.Capacity()
}

func (d *Dave) ActivePeerCount() int {
	return d.peers.CountActive()
}

func (d *Dave) NetworkUsedSpaceAndCapacity() (usedSpace, capacity uint64) {
	return d.peers.TotalUsedSpaceAndCapacity()
}

func (d *Dave) handlePackets() {
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			hasher := blake3.New(32, nil)
			var myAddrPort netip.AddrPort
			for packet := range d.pproc.In() {
				msg := &types.Msg{}
				err := msg.Unmarshal(packet.Data)
				if err != nil {
					d.log(logger.ERROR, "failed to unmarshal packet: %s", err)
				}
				switch msg.Op {
				case types.OP_PONG:
					hasher.Reset()
					err := d.handlePong(hasher, msg, packet.AddrPort, myAddrPort)
					if err != nil {
						d.log(logger.ERROR, "failed to handle PONG: %s", err)
					}
				case types.OP_PING:
					hasher.Reset()
					d.handlePing(hasher, msg, packet.AddrPort)
				case types.OP_PUT:
					hasher.Reset()
					err = d.handlePut(hasher, msg.Entry)
					if err != nil {
						d.log(logger.ERROR, "failed to handle PUT: %s", err)
					}
				case types.OP_GET:
					err = d.handleGet(msg.Get, packet.AddrPort)
					if err != nil {
						d.log(logger.DEBUG, "failed to handle GET: %s", err)
					}
				case types.OP_GET_ACK:
					d.subSvc.Publish(sub.RECV_GET_ACK, &pkt.Packet{Msg: msg, AddrPort: packet.AddrPort})
				case types.OP_GETMYADDRPORT:
					d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_GETMYADDRPORT_ACK,
						AddrPorts: []netip.AddrPort{packet.AddrPort}}, AddrPort: packet.AddrPort}
				case types.OP_GETMYADDRPORT_ACK:
					// Only accept from edge peers
					if d.peers.IsEdge(packet.AddrPort) && len(msg.AddrPorts) == 1 {
						myAddrPort = msg.AddrPorts[0]
						d.pproc.MyAddrPortChan() <- myAddrPort
					} else {
						d.log(logger.ERROR, "rejected MYADDRPORT_ACK from %s", packet.AddrPort)
					}
				}
			}
		}()
	}
}

func (d *Dave) manageReplicas() {
	peerDroppedEv := d.subSvc.Subscribe(sub.PEER_DROPPED)
	peerAddedEv := d.subSvc.Subscribe(sub.PEER_ADDED)
	for {
		select {
		case ev := <-peerDroppedEv:
			peer, ok := ev.(peer.PeerCopy)
			if !ok {
				d.log(logger.ERROR, "expected type peer.PeerCopy, got %T", peer)
				continue
			}
			d.replaceReplicasForDroppedPeer(peer)
		case ev := <-peerAddedEv:
			peer, ok := ev.(peer.PeerCopy)
			if !ok {
				d.log(logger.ERROR, "expected type peer.PeerCopy, got %T", peer)
				continue
			}
			d.replaceReplicasForNewPeer(peer)
		}
	}
}

func (d *Dave) run() {
	pingTick := time.NewTicker(network.PING)
	storageChallengeTick := time.NewTicker(network.STORAGE_CHALLENGE_EVERY)
	getMyAddrPortTick := time.NewTicker(network.GETMYADDRPORT_EVERY)
	if len(d.peers.Edges()) == 0 {
		getMyAddrPortTick.Stop()
	} else { // also send now
		err := d.sendGetMyAddrPort()
		if err != nil {
			d.log(logger.ERROR, "failed to send GETMYADDRPORT: no edge is online")
		}
	}
	for {
		select {
		case <-pingTick.C:
			for _, peer := range d.peers.ListAll() {
				challenge, err := d.peers.CreateAuthChallenge(peer.AddrPort)
				if err != nil {
					d.log(logger.ERROR, "failed to create challenge: %s", err)
					continue
				}
				d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_PING,
					AuthChallenge: challenge, Status: &types.Status{
						UsedSpace: d.UsedSpace(), Capacity: d.Capacity()},
				}, AddrPort: peer.AddrPort}
			}
		case <-storageChallengeTick.C:
			for _, p := range d.peers.RandPeers(network.FANOUT, nil) {
				challenge, err := d.peers.GetStorageChallenge(p.AddrPort)
				if err != nil {
					continue
				}
				if challenge.Expires.Before(time.Now()) {
					d.log(logger.DEBUG, "storage challenge expired")
					continue
				}
				go func() {
					evch := d.subSvc.Subscribe(sub.RECV_GET_ACK)
					defer d.subSvc.Unsubscribe(sub.RECV_GET_ACK, evch)
					timer := time.NewTimer(network.STORAGE_CHALLENGE_DEADLINE)
					h := blake3.New(32, nil)
					for {
						select {
						case <-timer.C:
							d.peers.StorageChallengeFailed(p.AddrPort)
							d.log(logger.ERROR, "storage challenge failed: deadline exceeded %s", p.AddrPort)
						case ev := <-evch:
							pkt, ok := ev.(*pkt.Packet)
							if !ok {
								d.log(logger.ERROR, "expected event *pkt.Packet, got %T", ev)
							}
							if !bytes.Equal(challenge.PublicKey, pkt.Msg.Entry.Dat.PubKey) {
								continue
							}
							if challenge.DatKey != pkt.Msg.Entry.Dat.Key {
								continue
							}
							h.Reset()
							err = pkt.Msg.Entry.Dat.Verify(h)
							if err != nil {
								d.peers.StorageChallengeFailed(p.AddrPort)
								d.log(logger.ERROR, "storage challenge failed %s", p.AddrPort)
							} else {
								d.peers.StorageChallengeCompleted(p.AddrPort)
								d.log(logger.DEBUG, "storage challenge completed %s", p.AddrPort)
							}
							return
						}
					}
				}()
				d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_GET,
					Get: &types.Get{PublicKey: challenge.PublicKey, DatKey: challenge.DatKey}},
					AddrPort: p.AddrPort}
			}
		case <-getMyAddrPortTick.C:
			err := d.sendGetMyAddrPort()
			if err != nil {
				d.log(logger.ERROR, "failed to send GETMYADDRPORT: no edge is online")
			}
		}
	}
}

func (d *Dave) replaceReplicasForDroppedPeer(p peer.PeerCopy) {
	entries := d.store.ListWithReplicaID(p.ID)
	wg := sync.WaitGroup{}
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			active := d.peers.ListActive(nil)
			for e := range entries {
				// Choose replicas
				sorted := peer.SortPeersByDistance(peer.IDFromPublicKey(e.Dat.PubKey), active)
				for j := range e.Replicas {
					if j >= len(sorted) {
						break
					}
					e.Replicas[j] = sorted[j].Peer.ID
					d.log(logger.ERROR, "selected replica: %s", sorted[j].Peer.AddrPort)
				}
				// Send entry to replicas
				for i := 0; i < network.FANOUT && i < len(sorted); i++ {
					replica := sorted[i].Peer
					/*if mrand.Float64() <= network.STORAGE_CHALLENGE_PROBABILITY {
						d.peers.SetStorageChallenge(replica.AddrPort, &peer.StorageChallenge{
							PublicKey: e.Dat.PubKey, DatKey: e.Dat.Key,
							Expires: e.Dat.Time.Add(network.TTL - time.Second)})
					}*/
					d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_PUT, Entry: &e},
						AddrPort: replica.AddrPort}
				}
				d.log(logger.ERROR, "updated replicas: %+v", e.Replicas)
				// Update store
				err := d.store.Write(&e)
				if err != nil {
					d.log(logger.ERROR, "reassign replicas: failed to update store: %s", err)
				}
			}
		}()
	}
	wg.Wait()
}

func (d *Dave) replaceReplicasForNewPeer(p peer.PeerCopy) {
	entries := d.store.ListAll()
	wg := sync.WaitGroup{}
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range entries {
				newPeerDist := p.ID ^ peer.IDFromPublicKey(e.Dat.PubKey)
				replaced := false
				for j, replicaID := range e.Replicas {
					if newPeerDist < replicaID^peer.IDFromPublicKey(e.Dat.PubKey) {
						e.Replicas[j] = p.ID
						replaced = true
						d.log(logger.DEBUG, "%v replaced with %v", replicaID, p.ID)
						break
					}
				}
				if replaced {
					d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_PUT, Entry: &e},
						AddrPort: p.AddrPort}
					if err := d.store.Write(&e); err != nil {
						d.log(logger.ERROR, "reassign replicas: failed to update store: %s", err)
					}
				}
			}
		}()
	}
	wg.Wait()
}

func (d *Dave) sendGetMyAddrPort() error {
	for _, p := range d.peers.Edges() {
		if time.Since(p.AuthChallengeSolved) < network.DEACTIVATE_AFTER {
			d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_GETMYADDRPORT},
				AddrPort: p.AddrPort}
			d.log(logger.DEBUG, "sent GETMYADDRPORT to %s", p.AddrPort)
			return nil
		}
	}
	return errors.New("failed to send MYADDRPORT")
}

func (d *Dave) handlePing(hasher *blake3.Hasher, msg *types.Msg, raddr netip.AddrPort) {
	d.peers.AddPeer(raddr, false)
	randPeers := d.peers.RandPeers(network.NPEER_LIMIT, &raddr)
	addrPorts := make([]netip.AddrPort, len(randPeers))
	for i, p := range randPeers {
		addrPorts[i] = p.AddrPort
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	hasher.Write(msg.AuthChallenge[:])
	hasher.Write(salt)
	sig := ed25519.Sign(d.privateKey, hasher.Sum(nil))
	d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_PONG,
		AuthSolution: &auth.AuthSolution{Challenge: msg.AuthChallenge,
			Salt:      auth.Salt(salt),
			PublicKey: d.publicKey,
			Signature: auth.Signature(sig)},
		AddrPorts: addrPorts}, AddrPort: raddr}
	err := d.peers.SetPeerUsedSpaceAndCapacity(raddr, msg.Status.UsedSpace, msg.Status.Capacity)
	if err != nil {
		d.log(logger.ERROR, "failed to set peer used space & capacity: %s", err)
	}
}

/*
func (d *Dave) sendToClosestPeers(activePeers []peer.PeerCopy, dat *dat.Dat) {
	sorted := peer.SortPeersByDistance(peer.IDFromPublicKey(dat.PubKey), activePeers)
	for i := 0; i < network.FANOUT && i < len(sorted); i++ {
		p := sorted[i].Peer
		if mrand.Float64() <= network.STORAGE_CHALLENGE_PROBABILITY {
			d.peers.SetStorageChallenge(p.AddrPort, &peer.StorageChallenge{
				PublicKey: entry.Dat.PubKey, DatKey: entry.Dat.Key,
				Expires: time.Now().Add(network.TTL - time.Second)})
		}
		d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_PUT, Entry: entry},
			AddrPort: p.AddrPort}
	}
}
*/

func (d *Dave) handlePong(h *blake3.Hasher, msg *types.Msg, raddr, myAddr netip.AddrPort) error {
	challenge, storedPubKey, err := d.peers.CurrentAuthChallengeAndPubKey(raddr)
	if err != nil {
		return err
	}
	if msg.AuthSolution.Challenge != challenge {
		return errors.New("challenge is incorrect")
	}
	if len(msg.AuthSolution.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("pub key is invalid: %s", err)
	}
	if storedPubKey != nil && !storedPubKey.Equal(msg.AuthSolution.PublicKey) {
		return fmt.Errorf("msg pub key does not match stored pub key")
	}
	h.Write(challenge[:])
	h.Write(msg.AuthSolution.Salt[:])
	hash := h.Sum(nil)
	if !ed25519.Verify(msg.AuthSolution.PublicKey, hash, msg.AuthSolution.Signature[:]) {
		return fmt.Errorf("signature is invalid")
	}
	if storedPubKey == nil {
		d.peers.SetPublicKeyAndID(raddr, msg.AuthSolution.PublicKey)
	}
	if len(msg.AddrPorts) > network.NPEER_LIMIT {
		return fmt.Errorf("message contains more than %d addrports", network.NPEER_LIMIT)
	}
	for _, addrPort := range msg.AddrPorts {
		if addrPort != myAddr {
			d.peers.AddPeer(addrPort, false)
		} else {
			return fmt.Errorf("my own addrport was given")
		}
	}
	d.peers.AuthChallengeSolved(raddr)
	return nil
}

func (d *Dave) handlePut(hasher *blake3.Hasher, entry *store.Entry) error {
	err := entry.Dat.Verify(hasher)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	err = d.store.Write(entry)
	if err != nil {
		return fmt.Errorf("failed to store: %w", err)
	}
	d.log(logger.DEBUG, "stored %s, replicas: %+v", entry.Dat.Key, entry.Replicas)
	return nil
}

func (d *Dave) handleGet(get *types.Get, raddr netip.AddrPort) error {
	entry, err := d.store.Read(get.PublicKey, get.DatKey)
	if err != nil {
		d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_GET_ACK,
			Entry: &store.Entry{Dat: dat.Dat{PubKey: get.PublicKey, Key: get.DatKey}}},
			AddrPort: raddr}
		return fmt.Errorf("failed to read from store: %s", err)
	}
	d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_GET_ACK, Entry: &entry}, AddrPort: raddr}
	return nil
}

func (d *Dave) log(level logger.LogLevel, msg string, args ...any) {
	if d.logger != nil {
		d.logger.Log(level, msg, args...)
	}
}
