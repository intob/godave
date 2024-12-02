package godave

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"time"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/peer"
	"github.com/intob/godave/pkt"
	"github.com/intob/godave/pow"
	"github.com/intob/godave/ringbuffer"
	"github.com/intob/godave/store"
	"github.com/intob/godave/types"
	"lukechampine.com/blake3"
)

const (
	EPOCH               = 500 * time.Microsecond // Period between seeding rounds.
	FANOUT              = 2                      // Number of peers selected when sending dats.
	PROBE               = 12                     // Inverse of probability that a peer is selected regardless of trust.
	NPEER_LIMIT         = 3                      // Maximum number of peer descriptors in a PONG message.
	MIN_WORK            = 16                     // Minimum amount of acceptable work in number of leading zero bits.
	PING                = 1 * time.Second        // Period between pinging peers.
	DEACTIVATE_AFTER    = 3 * PING               // Time until protocol-deviating peers are deactivated.
	DROP                = 12 * PING              // Time until protocol-deviating peers are dropped.
	ACTIVATION_DELAY    = 5 * PING               // Time until new peers are activated.
	PRUNE_DATS          = 30 * time.Second       // Period between pruning dats.
	TRUST_DECAY_FACTOR  = 0.99                   // Factor used to decay peer trust.
	TRUST_DECAY_RATE    = time.Minute            // Rate at which trust decays.
	GETMYADDRPORT_EVERY = 10 * time.Minute       // Period between getting my addrport from an edge.
)

type Dave struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	myID       uint64
	kill, done chan struct{}
	peers      *peer.Store
	store      *store.Store
	pproc      *pkt.PacketProcessor
	ring       *ringbuffer.RingBuffer[*types.Dat]
	logger     *logger.Logger
}

type DaveCfg struct {
	Socket             pkt.Socket
	PrivateKey         ed25519.PrivateKey
	Edges              []netip.AddrPort
	ShardCapacity      uint64 // Bytes
	RingBufferCapacity int    // Number of Dats
	TTL                time.Duration
	BackupFilename     string
	Logger             *logger.Logger
}

func NewDave(cfg *DaveCfg) (*Dave, error) {
	if cfg.PrivateKey == nil || len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("no valid private key provided")
	}
	dave := &Dave{
		privateKey: cfg.PrivateKey, publicKey: cfg.PrivateKey.Public().(ed25519.PublicKey),
		myID: peer.IDFromPublicKey(cfg.PrivateKey.Public().(ed25519.PublicKey)),
		kill: make(chan struct{}), done: make(chan struct{}),
		ring: ringbuffer.NewRingBuffer[*types.Dat](cfg.RingBufferCapacity),
		peers: peer.NewStore(&peer.StoreCfg{
			Probe:            PROBE,
			ActivationDelay:  ACTIVATION_DELAY,
			DeactivateAfter:  DEACTIVATE_AFTER,
			DropAfter:        DROP,
			TrustDecayFactor: TRUST_DECAY_FACTOR,
			DecayEvery:       TRUST_DECAY_RATE,
			PruneEvery:       DEACTIVATE_AFTER,
			Logger:           cfg.Logger.WithPrefix("/peers")}),
		logger: cfg.Logger}
	for _, addrPort := range cfg.Edges {
		dave.peers.AddPeer(pkt.MapToIPv6(addrPort), true)
	}
	dave.store = store.NewStore(&store.StoreCfg{
		MyID:           peer.IDFromPublicKey(cfg.PrivateKey.Public().(ed25519.PublicKey)),
		BackupFilename: cfg.BackupFilename, Kill: dave.kill, Done: dave.done,
		Logger: cfg.Logger.WithPrefix("/dats")})
	var err error
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
	activePeers := d.peers.ListActive()
	if len(activePeers) == 0 {
		return errors.New("no active peers")
	}
	d.sendToClosestPeers(activePeers, &dat)
	d.logger.Error("sent to %s")
	return nil
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

func (d *Dave) handlePackets() {
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			hasher := blake3.New(32, nil)
			var myAddrPort netip.AddrPort
			for packet := range d.pproc.In() {
				msg := &types.Msg{}
				err := msg.Unmarshal(packet.Data)
				if err != nil {
					d.logger.Error("failed to unmarshal packet: %s", err)
				}
				switch msg.Op {
				case types.Op_PONG: // VALIDATE SOLUTION & STORE PEERS
					err := d.handlePong(msg, packet.AddrPort, myAddrPort)
					if err != nil {
						d.logger.Error("failed to handle pong: %s", err)
					}
				case types.Op_PING: // SOLVE CHALLENGE & GIVE PEERS
					d.handlePing(msg, packet.AddrPort)
				case types.Op_PUT: // STORE DAT
					err = d.handlePut(hasher, msg.Dat, packet.AddrPort)
					if err != nil {
						d.logger.Debug("failed to handle put: %s", err)
					}
				case types.Op_GETMYADDRPORT:
					d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.Op_GETMYADDRPORT_ACK,
						AddrPorts: []netip.AddrPort{packet.AddrPort}}, AddrPort: packet.AddrPort}
				case types.Op_GETMYADDRPORT_ACK:
					// Only accept from edge peers
					if d.peers.IsEdge(packet.AddrPort) && len(msg.AddrPorts) == 1 {
						myAddrPort = msg.AddrPorts[0]
						d.pproc.MyAddrPortChan() <- myAddrPort
					} else {
						d.logger.Error("rejected MYADDRPORT_ACK from %s", packet.AddrPort)
					}
				}
			}
		}()
	}
}

func (d *Dave) run() {
	pingTick := time.NewTicker(PING)
	epochTick := time.NewTicker(EPOCH)
	getMyAddrPortTick := time.NewTicker(GETMYADDRPORT_EVERY)
	if len(d.peers.Edges()) == 0 {
		getMyAddrPortTick.Stop()
	} else { // also send now
		err := d.sendGetMyAddrPort()
		if err != nil {
			d.logger.Error("failed to send GETMYADDRPORT: no edge is online")
		}
	}
	for {
		select {
		case <-epochTick.C: // SEED
			activePeers := d.peers.ListActive()
			if len(activePeers) < FANOUT {
				continue
			}
			ringDat, ok := d.ring.Read()
			if ok {
				d.sendToClosestPeers(activePeers, ringDat)
			} else {
				nextDat, ok := d.store.Next()
				if ok {
					d.sendToClosestPeers(activePeers, &nextDat)
				}
			}
		case <-pingTick.C: // PING PEERS WITH A CHALLENGE
			for _, peer := range d.peers.ListAll() {
				challenge, err := d.peers.CreateChallenge(peer.AddrPort())
				if err != nil {
					d.logger.Error("failed to create challenge: %s", err)
					continue
				}
				d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{
					Op: types.Op_PING, Challenge: challenge},
					AddrPort: peer.AddrPort()}
			}
		case <-getMyAddrPortTick.C: // REQUEST MY ADDRPORT
			err := d.sendGetMyAddrPort()
			if err != nil {
				d.logger.Error("failed to send GETMYADDRPORT: no edge is online")
			}
		}
	}
}

func (d *Dave) sendGetMyAddrPort() error {
	for _, p := range d.peers.Edges() {
		if time.Since(p.ChallengeSolved()) < DEACTIVATE_AFTER {
			d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.Op_GETMYADDRPORT},
				AddrPort: p.AddrPort()}
			d.logger.Debug("sent GETMYADDRPORT to %s", p.AddrPort())
			return nil
		}
	}
	return errors.New("failed to send MYADDRPORT")
}

func (d *Dave) handlePut(hasher *blake3.Hasher, dat *types.Dat, raddr netip.AddrPort) error {
	d.peers.AddPeer(raddr, false)
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
	err = d.store.Write(dat)
	if err != nil {
		return nil
	}
	d.ring.Write(dat)
	normDistance := float64(d.myID^peer.IDFromPublicKey(dat.PubKey)) / float64(^uint64(0))
	d.peers.UpdateTrust(raddr, 1-normDistance)
	d.logger.Debug("stored %s", dat.Key)
	return nil
}

func (d *Dave) handlePing(msg *types.Msg, raddr netip.AddrPort) {
	d.peers.AddPeer(raddr, false)
	if !d.peers.IsPingExpected(raddr, PING) {
		d.logger.Error("unexpected ping from %s", raddr)
		return
	}
	d.peers.UpdatePingReceived(raddr)
	randPeers := d.peers.TrustWeightedRandPeers(NPEER_LIMIT, &raddr)
	addrPorts := make([]netip.AddrPort, len(randPeers))
	for i, p := range randPeers {
		addrPorts[i] = p.AddrPort()
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := blake3.New(32, nil)
	hash.Write(msg.Challenge[:])
	hash.Write(salt)
	sig := ed25519.Sign(d.privateKey, hash.Sum(nil))
	d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.Op_PONG,
		Solution: &types.Solution{Challenge: msg.Challenge,
			Salt:      types.Salt(salt),
			PublicKey: d.publicKey,
			Signature: types.Signature(sig)},
		AddrPorts: addrPorts}, AddrPort: raddr}
}

func (d *Dave) sendToClosestPeers(activePeers []peer.Peer, dat *types.Dat) {
	sorted := peer.SortPeersByDistance(peer.IDFromPublicKey(dat.PubKey), activePeers)
	for i := 0; i < FANOUT && i < len(sorted); i++ {
		d.pproc.Out() <- &pkt.Packet{Msg: &types.Msg{Op: types.Op_PUT, Dat: dat},
			AddrPort: sorted[i].Peer.AddrPort()}
	}
}

func (d *Dave) handlePong(msg *types.Msg, raddr, myAddrPort netip.AddrPort) error {
	d.peers.AddPeer(raddr, false)
	challenge, storedPubKey, err := d.peers.CurrentChallengeAndPubKey(raddr)
	if err != nil {
		return err
	}
	if msg.Solution.Challenge != challenge {
		return errors.New("challenge is incorrect")
	}
	if len(msg.Solution.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("pub key is invalid: %s", err)
	}
	if storedPubKey != nil && !storedPubKey.Equal(msg.Solution.PublicKey) {
		return fmt.Errorf("msg pub key does not match stored pub key")
	}
	h := blake3.New(32, nil)
	h.Write(challenge[:])
	h.Write(msg.Solution.Salt[:])
	hash := h.Sum(nil)
	if !ed25519.Verify(msg.Solution.PublicKey, hash, msg.Solution.Signature[:]) {
		return fmt.Errorf("signature is invalid")
	}
	if storedPubKey == nil {
		d.peers.SetPublicKeyAndID(raddr, msg.Solution.PublicKey)
	}
	if len(msg.AddrPorts) > NPEER_LIMIT {
		return fmt.Errorf("message contains more than %d addrports", NPEER_LIMIT)
	}
	for _, addrPort := range msg.AddrPorts {
		if addrPort != myAddrPort {
			d.peers.AddPeer(addrPort, false)
		} else {
			return fmt.Errorf("my own addrport was given")
		}
	}
	d.peers.ChallengeSolved(raddr)
	return nil
}

func unmarshalEd25519PublicKey(publicKeyBytes []byte) (ed25519.PublicKey, error) {
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519: public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(publicKeyBytes), nil
}
