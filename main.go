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
	"time"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/peer"
	"github.com/intob/godave/pkt"
	"github.com/intob/godave/pow"
	"github.com/intob/godave/store"
	"github.com/intob/godave/types"
	"lukechampine.com/blake3"
)

const (
	FANOUT              = 3                // Number of peers selected when sending dats.
	PROBE               = 12               // Inverse of probability that a peer is selected regardless of trust.
	NPEER_LIMIT         = 5                // Maximum number of peer descriptors in a PONG message.
	MIN_WORK            = 20               // Minimum amount of acceptable work in number of leading zero bits.
	PING                = 1 * time.Second  // Period between pinging peers.
	ACTIVATE_AFTER      = 5 * PING         // Time until new peers are activated.
	DEACTIVATE_AFTER    = 3 * PING         // Time until protocol-deviating peers are deactivated.
	DROP_AFTER          = 12 * PING        // Time until protocol-deviating peers are dropped.
	GETMYADDRPORT_EVERY = 10 * time.Minute // Period between getting my addrport from an edge.
	// Time-to-live of data. Data older than this will be replaced as needed,
	// if new data has a higher priority. Priority is a function of age and
	// XOR distance.
	TTL                           = 365 * 24 * time.Hour
	STORAGE_CHALLENGE_PROBABILITY = 0.1 // Probability that a dat will be used as a storage challenge.
	STORAGE_CHALLENGE_EVERY       = 10 * time.Second
)

type Dave struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	myID       uint64
	kill, done chan struct{}
	peers      *peer.Store
	store      *store.Store
	pproc      *pkt.PacketProcessor
	getAck     chan types.Dat
	logger     logger.Logger
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
	dave := &Dave{
		privateKey: cfg.PrivateKey, publicKey: cfg.PrivateKey.Public().(ed25519.PublicKey),
		myID: peer.IDFromPublicKey(cfg.PrivateKey.Public().(ed25519.PublicKey)),
		kill: make(chan struct{}), done: make(chan struct{}),
		peers: peer.NewStore(&peer.StoreCfg{
			Probe:           PROBE,
			ActivateAfter:   ACTIVATE_AFTER,
			DeactivateAfter: DEACTIVATE_AFTER,
			DropAfter:       DROP_AFTER,
			PruneEvery:      DEACTIVATE_AFTER,
			Logger:          cfg.Logger.WithPrefix("/peers")}),
		logger: cfg.Logger,
		getAck: make(chan types.Dat, FANOUT),
	}
	for _, addrPort := range cfg.Edges {
		dave.peers.AddPeer(pkt.MapToIPv6(addrPort), true)
	}
	dave.store = store.NewStore(&store.StoreCfg{
		MyID:     peer.IDFromPublicKey(cfg.PrivateKey.Public().(ed25519.PublicKey)),
		Capacity: cfg.ShardCapacity, TTL: TTL,
		BackupFilename: cfg.BackupFilename, Kill: dave.kill, Done: dave.done,
		Logger: cfg.Logger.WithPrefix("/dats")})
	err := dave.store.ReadBackup()
	if err != nil {
		dave.log(logger.ERROR, "failed to read backup: %s", err)
	}
	dave.pproc, err = pkt.NewPacketProcessor(cfg.Socket, cfg.Logger.WithPrefix("/pproc"))
	if err != nil {
		return nil, fmt.Errorf("failed to init packet processor: %s", err)
	}
	go dave.run()
	go dave.handlePackets()
	return dave, nil
}

func (d *Dave) Kill() {
	close(d.kill)
	<-d.done
}

func (d *Dave) Put(dat types.Dat) error {
	err := d.store.Write(&dat)
	if err != nil {
		return fmt.Errorf("failed to put dat in local store: %s", err)
	}
	activePeers := d.peers.ListActive(nil)
	if len(activePeers) == 0 {
		return errors.New("no active peers")
	}
	d.sendToClosestPeers(activePeers, &dat)
	return nil
}

func (d *Dave) Get(ctx context.Context, get *types.Get) (*types.Dat, error) {
	if get == nil {
		return nil, errors.New("get is nil")
	}
	dat, err := d.store.Read(get.PublicKey, get.DatKey)
	if err == nil {
		d.log(logger.DEBUG, "found locally: %s", dat.Key)
		return &dat, nil
	}
	activePeers := d.peers.ListActive(nil)
	if len(activePeers) == 0 {
		return nil, errors.New("no active peers")
	}
	sorted := peer.SortPeersByDistance(peer.IDFromPublicKey(get.PublicKey), activePeers)
	count := min(FANOUT, len(sorted))
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
		case dat := <-d.getAck:
			if !bytes.Equal(dat.PubKey, get.PublicKey) || dat.Key != get.DatKey {
				continue
			}
			received++
			if dat.Sig == (types.Signature{}) {
				d.log(logger.DEBUG, "not found from %d/%d", received, count)
				if received == count {
					return nil, errors.New("not found")
				} else {
					continue
				}
			}
			err = d.verifyDat(hasher, &dat)
			if err != nil {
				d.log(logger.ERROR, "verification failed: %s", err)
				continue
			}
			err = d.store.Write(&dat)
			if err != nil {
				d.log(logger.ERROR, "failed to store: %s", err)
				continue
			}
			return &dat, nil
		}
	}
}

func (d *Dave) WaitForActivePeers(ctx context.Context, count int) error {
	check := time.NewTicker(200 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-check.C:
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
					err := d.handlePong(hasher, msg, packet.AddrPort, myAddrPort)
					if err != nil {
						d.log(logger.ERROR, "failed to handle PONG: %s", err)
					}
				case types.OP_PING:
					d.handlePing(hasher, msg, packet.AddrPort)
				case types.OP_PUT:
					d.handlePut(hasher, msg.Dat, packet.AddrPort)
				case types.OP_GET:
					err = d.handleGet(msg.Get, packet.AddrPort)
					if err != nil {
						d.log(logger.DEBUG, "failed to handle GET: %s", err)
					}
				case types.OP_GET_ACK:
					err = d.handleGetAck(hasher, msg.Dat, packet.AddrPort)
					if err != nil {
						d.log(logger.ERROR, "failed to handle GET_ACK: %s", err)
					}
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

func (d *Dave) run() {
	pingTick := time.NewTicker(PING)
	storageChallengeTick := time.NewTicker(STORAGE_CHALLENGE_EVERY)
	getMyAddrPortTick := time.NewTicker(GETMYADDRPORT_EVERY)
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
			for _, peer := range d.peers.RandPeers(FANOUT, nil) {
				challenge, err := d.peers.GetStorageChallenge(peer.AddrPort)
				if err == nil {
					d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_GET,
						Get: &types.Get{PublicKey: challenge.PublicKey, DatKey: challenge.DatKey}},
						AddrPort: peer.AddrPort}
				}
			}
		case <-getMyAddrPortTick.C:
			err := d.sendGetMyAddrPort()
			if err != nil {
				d.log(logger.ERROR, "failed to send GETMYADDRPORT: no edge is online")
			}
		}
	}
}

func (d *Dave) sendGetMyAddrPort() error {
	for _, p := range d.peers.Edges() {
		if time.Since(p.AuthChallengeSolved) < DEACTIVATE_AFTER {
			d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_GETMYADDRPORT},
				AddrPort: p.AddrPort}
			d.log(logger.DEBUG, "sent GETMYADDRPORT to %s", p.AddrPort)
			return nil
		}
	}
	return errors.New("failed to send MYADDRPORT")
}

func (d *Dave) verifyDat(hasher *blake3.Hasher, dat *types.Dat) error {
	if dat == nil {
		return errors.New("dat is nil")
	}
	if pow.Nzerobit(dat.Work) < MIN_WORK {
		return fmt.Errorf("work is insufficient: %x", dat.Work)
	}
	if err := pow.Check(hasher, dat); err != nil {
		return fmt.Errorf("work is invalid: %s", err)
	}
	if l := len(dat.PubKey); l != ed25519.PublicKeySize {
		return fmt.Errorf("pub key is invalid: len %d", l)
	}
	pubKey, err := unmarshalEd25519PublicKey(dat.PubKey)
	if err != nil {
		return fmt.Errorf("failed to unmarshal pub key: %s", err)
	}
	if !ed25519.Verify(pubKey, dat.Work[:], dat.Sig[:]) {
		return fmt.Errorf("signature is invalid")
	}
	return nil
}

func (d *Dave) handlePing(hasher *blake3.Hasher, msg *types.Msg, raddr netip.AddrPort) {
	d.peers.AddPeer(raddr, false)
	randPeers := d.peers.RandPeers(NPEER_LIMIT, &raddr)
	addrPorts := make([]netip.AddrPort, len(randPeers))
	for i, p := range randPeers {
		addrPorts[i] = p.AddrPort
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	hasher.Reset()
	hasher.Write(msg.AuthChallenge[:])
	hasher.Write(salt)
	sig := ed25519.Sign(d.privateKey, hasher.Sum(nil))
	d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_PONG,
		AuthSolution: &types.AuthSolution{Challenge: msg.AuthChallenge,
			Salt:      types.Salt(salt),
			PublicKey: d.publicKey,
			Signature: types.Signature(sig)},
		AddrPorts: addrPorts}, AddrPort: raddr}
	err := d.peers.SetPeerUsedSpaceAndCapacity(raddr, msg.Status.UsedSpace, msg.Status.Capacity)
	if err != nil {
		d.log(logger.ERROR, "failed to set peer used space & capacity: %s", err)
	}
}

func (d *Dave) sendToClosestPeers(activePeers []peer.PeerCopy, dat *types.Dat) {
	sorted := peer.SortPeersByDistance(peer.IDFromPublicKey(dat.PubKey), activePeers)
	for i := 0; i < FANOUT && i < len(sorted); i++ {
		p := sorted[i].Peer
		if mrand.Float64() <= STORAGE_CHALLENGE_PROBABILITY {
			d.peers.SetStorageChallenge(p.AddrPort, &peer.StorageChallenge{
				PublicKey: dat.PubKey, DatKey: dat.Key,
				Expires: time.Now().Add(TTL - time.Second)})
		}
		d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_PUT, Dat: dat},
			AddrPort: p.AddrPort}
	}
}

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
	h.Reset()
	h.Write(challenge[:])
	h.Write(msg.AuthSolution.Salt[:])
	hash := h.Sum(nil)
	if !ed25519.Verify(msg.AuthSolution.PublicKey, hash, msg.AuthSolution.Signature[:]) {
		return fmt.Errorf("signature is invalid")
	}
	if storedPubKey == nil {
		d.peers.SetPublicKeyAndID(raddr, msg.AuthSolution.PublicKey)
	}
	if len(msg.AddrPorts) > NPEER_LIMIT {
		return fmt.Errorf("message contains more than %d addrports", NPEER_LIMIT)
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

func (d *Dave) handlePut(hasher *blake3.Hasher, dat *types.Dat, raddr netip.AddrPort) error {
	err := d.verifyDat(hasher, dat)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	err = d.store.Write(dat)
	if err != nil {
		return fmt.Errorf("failed to store: %w", err)
	}
	d.log(logger.DEBUG, "stored %s", dat.Key)
	activePeers := d.peers.ListActive(&raddr)
	// Maybe make this depend on trust, or maybe leave this up to the originator.
	// This improves reliability, as we may know a closer peer that the originator
	// is unaware of. This also improves anonymity, as we don't know which peer was
	// the originator.
	if len(activePeers) >= FANOUT {
		d.sendToClosestPeers(activePeers, dat)
	}
	return nil
}

func (d *Dave) handleGet(get *types.Get, raddr netip.AddrPort) error {
	dat, err := d.store.Read(get.PublicKey, get.DatKey)
	if err != nil {
		d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_GET_ACK,
			Dat: &types.Dat{PubKey: get.PublicKey, Key: get.DatKey}},
			AddrPort: raddr}
		return fmt.Errorf("failed to read from store: %s", err)
	}
	d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.OP_GET_ACK, Dat: &dat}, AddrPort: raddr}
	return nil
}

func (d *Dave) handleGetAck(hasher *blake3.Hasher, dat *types.Dat, raddr netip.AddrPort) error {
	select {
	case d.getAck <- *dat:
	default: // don't block if no reciever is waiting
	}
	challenge, err := d.peers.GetStorageChallenge(raddr)
	if err != nil {
		return nil
	}
	if !bytes.Equal(challenge.PublicKey, dat.PubKey) {
		return nil
	}
	if challenge.DatKey != dat.Key {
		return nil
	}
	if pow.Nzerobit(dat.Work) < MIN_WORK {
		d.peers.StorageChallengeFailed(raddr)
		return fmt.Errorf("work is insufficient: %x", dat.Work)
	}
	if err := pow.Check(hasher, dat); err != nil {
		d.peers.StorageChallengeFailed(raddr)
		return fmt.Errorf("work is invalid: %s", err)
	}
	if l := len(dat.PubKey); l != ed25519.PublicKeySize {
		d.peers.StorageChallengeFailed(raddr)
		return fmt.Errorf("pub key is invalid: len %d", l)
	}
	pubKey, err := unmarshalEd25519PublicKey(dat.PubKey)
	if err != nil {
		d.peers.StorageChallengeFailed(raddr)
		return fmt.Errorf("failed to unmarshal pub key: %s", err)
	}
	if !ed25519.Verify(pubKey, dat.Work[:], dat.Sig[:]) {
		d.peers.StorageChallengeFailed(raddr)
		return fmt.Errorf("signature is invalid")
	}
	err = d.peers.StorageChallengeCompleted(raddr)
	if err != nil {
		return fmt.Errorf("failed to set storage challenge completed: %s", err)
	}
	d.log(logger.ERROR, "YAYY!! STORAGE CHALLENGE COMPLETED")
	return nil
}

func unmarshalEd25519PublicKey(publicKeyBytes []byte) (ed25519.PublicKey, error) {
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519: public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(publicKeyBytes), nil
}

func (d *Dave) log(level logger.LogLevel, msg string, args ...any) {
	if d.logger != nil {
		d.logger.Log(level, msg, args...)
	}
}
