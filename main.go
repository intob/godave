package godave

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sort"
	"time"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/peer"
	"github.com/intob/godave/pkt"
	"github.com/intob/godave/pow"
	"github.com/intob/godave/ringbuffer"
	"github.com/intob/godave/store"
	"github.com/intob/godave/types"
	"github.com/intob/godave/xor"
	"lukechampine.com/blake3"
)

const (
	EPOCH               = time.Millisecond // Period between seeding rounds.
	FANOUT              = 2                // Number of peers selected when sending dats.
	PROBE               = 12               // Inverse of probability that a peer is selected regardless of trust.
	NPEER_LIMIT         = 3                // Maximum number of peer descriptors in a PONG message.
	MIN_WORK            = 16               // Minimum amount of acceptable work in number of leading zero bits.
	PING                = 1 * time.Second  // Period between pinging peers.
	DEACTIVATE_AFTER    = 3 * PING         // Time until protocol-deviating peers are deactivated.
	DROP                = 12 * PING        // Time until protocol-deviating peers are dropped.
	ACTIVATION_DELAY    = 5 * PING         // Time until new peers are activated.
	PRUNE_DATS          = 10 * time.Second // Period between pruning dats.
	TRUST_DECAY_FACTOR  = 0.99             // Factor used to decay peer trust.
	TRUST_DECAY_RATE    = time.Minute      // Rate at which trust decays.
	GETMYADDRPORT_EVERY = 10 * time.Minute // Period between getting my addrport from an edge.
)

type Dave struct {
	privateKey      ed25519.PrivateKey
	publicKey       ed25519.PublicKey
	kill, done      chan struct{}
	packetOut       chan *pkt.Packet
	peers           *peer.Store
	store           *store.Store
	packetProcessor *pkt.PacketProcessor
	ring            *ringbuffer.RingBuffer[*types.Dat]
	logger          *logger.Logger
}

type Cfg struct {
	Socket         pkt.Socket
	PrivateKey     ed25519.PrivateKey
	Edges          []netip.AddrPort
	ShardCap       int
	BackupFilename string
	Logger         *logger.Logger
}

func NewDave(cfg *Cfg) (*Dave, error) {
	if cfg.PrivateKey == nil || len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("no valid private key provided")
	}
	dave := &Dave{
		privateKey: cfg.PrivateKey,
		publicKey:  cfg.PrivateKey.Public().(ed25519.PublicKey),
		kill:       make(chan struct{}),
		done:       make(chan struct{}),
		packetOut:  make(chan *pkt.Packet, 1),
		ring:       ringbuffer.NewRingBuffer[*types.Dat](cfg.ShardCap),
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
	var err error
	dave.store, err = store.NewStore(&store.StoreCfg{
		ShardCap:       cfg.ShardCap,
		PruneEvery:     PRUNE_DATS,
		BackupFilename: cfg.BackupFilename,
		PublicKey:      cfg.PrivateKey.Public().(ed25519.PublicKey),
		Kill:           dave.kill,
		Done:           dave.done,
		Logger:         cfg.Logger.WithPrefix("/dats")})
	if err != nil {
		return nil, fmt.Errorf("failed to init store: %w", err)
	}
	dave.packetProcessor, err = pkt.NewPacketProcessor(&pkt.PacketProcessorCfg{
		BufSize: types.MaxMsgLen,
		Socket:  cfg.Socket,
		Logger:  cfg.Logger.WithPrefix("/packet_proc")})
	if err != nil {
		return nil, fmt.Errorf("failed to init packet processor: %s", err)
	}
	go dave.run()
	go dave.handlePackets()
	go dave.writePackets(cfg.Socket)
	return dave, nil
}

func (d *Dave) Kill() {
	close(d.kill)
	<-d.done
}

func (d *Dave) Put(dat types.Dat) error {
	err := d.store.Put(&dat)
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
			for packet := range d.packetProcessor.Packets() {
				switch packet.Msg.Op {
				case types.Op_PONG: // VALIDATE SOLUTION & STORE PEERS
					err := d.handlePong(packet, myAddrPort)
					if err != nil {
						d.logger.Error("failed to handle pong: %s", err)
					}
				case types.Op_PING: // SOLVE CHALLENGE & GIVE PEERS
					d.handlePing(packet)
				case types.Op_PUT: // STORE DAT
					d.handlePut(hasher, packet)
				case types.Op_GETMYADDRPORT:
					d.packetOut <- &pkt.Packet{Msg: &types.Msg{Op: types.Op_GETMYADDRPORT_ACK,
						AddrPorts: []netip.AddrPort{packet.AddrPort}}, AddrPort: packet.AddrPort}
				case types.Op_GETMYADDRPORT_ACK:
					// Only accept from edge peers
					if d.peers.IsEdge(packet.AddrPort) && len(packet.Msg.AddrPorts) == 1 {
						myAddrPort = packet.Msg.AddrPorts[0]
						d.packetProcessor.MyAddrPortChan() <- myAddrPort
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
				d.packetOut <- &pkt.Packet{Msg: &types.Msg{
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
			d.packetOut <- &pkt.Packet{Msg: &types.Msg{Op: types.Op_GETMYADDRPORT},
				AddrPort: p.AddrPort()}
			d.logger.Debug("sent GETMYADDRPORT to %s", p.AddrPort())
			return nil
		}
	}
	return errors.New("failed to send MYADDRPORT")
}

func (d *Dave) handlePut(hasher *blake3.Hasher, packet *pkt.Packet) error {
	d.peers.AddPeer(packet.AddrPort, false)
	dat := packet.Msg.Dat
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
	err = d.store.Put(dat)
	if err != nil {
		return err
	}
	d.ring.Write(packet.Msg.Dat)
	distance, err := xor.Xor256Uint8(d.publicKey, packet.Msg.Dat.PubKey)
	if err != nil {
		return err
	}
	d.peers.UpdateTrust(packet.AddrPort, 255-distance)
	d.logger.Debug("stored %s", packet.Msg.Dat.Key)
	return nil
}

func (d *Dave) handlePing(packet *pkt.Packet) {
	d.peers.AddPeer(packet.AddrPort, false)
	if !d.peers.IsPingExpected(packet.AddrPort, PING) {
		d.logger.Error("unexpected ping from %s", packet.AddrPort)
		return
	}
	d.peers.UpdatePingReceived(packet.AddrPort)
	randPeers := d.peers.TrustWeightedRandPeers(NPEER_LIMIT, &packet.AddrPort)
	addrPorts := make([]netip.AddrPort, len(randPeers))
	for i, p := range randPeers {
		addrPorts[i] = p.AddrPort()
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := blake3.New(32, nil)
	hash.Write(packet.Msg.Challenge[:])
	hash.Write(salt)
	sig := ed25519.Sign(d.privateKey, hash.Sum(nil))
	d.packetOut <- &pkt.Packet{Msg: &types.Msg{Op: types.Op_PONG,
		Solution: &types.Solution{Challenge: packet.Msg.Challenge,
			Salt:      types.Salt(salt),
			PublicKey: d.publicKey,
			Signature: types.Signature(sig)},
		AddrPorts: addrPorts}, AddrPort: packet.AddrPort}
}

func (d *Dave) sendToClosestPeers(activePeers []peer.Peer, dat *types.Dat) {
	sorted := sortPeersByDistance(dat.PubKey, activePeers)
	for i := 0; i < FANOUT && i < len(sorted); i++ {
		d.packetOut <- &pkt.Packet{Msg: &types.Msg{Op: types.Op_PUT, Dat: dat},
			AddrPort: sorted[i].peer.AddrPort()}
	}
}

func (d *Dave) writePackets(socket pkt.Socket) {
	buf := make([]byte, types.MaxMsgLen)
	for pkt := range d.packetOut {
		buf = buf[:cap(buf)]
		n, err := pkt.Msg.Marshal(buf)
		if err != nil {
			d.logger.Error("dispatch error: %s", err)
			continue
		}
		_, err = socket.WriteToUDPAddrPort(buf[:n], pkt.AddrPort)
		if err != nil {
			d.logger.Error("dispatch error: %s", err)
		}
	}
}

func (d *Dave) handlePong(packet *pkt.Packet, myAddrPort netip.AddrPort) error {
	d.peers.AddPeer(packet.AddrPort, false)
	challenge, storedPubKey, err := d.peers.CurrentChallengeAndPubKey(packet.AddrPort)
	if err != nil {
		return err
	}
	if packet.Msg.Solution.Challenge != challenge {
		return errors.New("challenge is incorrect")
	}
	if len(packet.Msg.Solution.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("pub key is invalid: %s", err)
	}
	if storedPubKey != nil && !storedPubKey.Equal(packet.Msg.Solution.PublicKey) {
		return fmt.Errorf("msg pub key does not match stored pub key")
	}
	h := blake3.New(32, nil)
	h.Write(challenge[:])
	h.Write(packet.Msg.Solution.Salt[:])
	hash := h.Sum(nil)
	if !ed25519.Verify(packet.Msg.Solution.PublicKey, hash, packet.Msg.Solution.Signature[:]) {
		return fmt.Errorf("signature is invalid")
	}
	if storedPubKey == nil {
		d.peers.SetPubKey(packet.AddrPort, packet.Msg.Solution.PublicKey)
	}
	if len(packet.Msg.AddrPorts) > NPEER_LIMIT {
		return fmt.Errorf("message contains more than %d addrports", NPEER_LIMIT)
	}
	for _, addrPort := range packet.Msg.AddrPorts {
		if addrPort != myAddrPort {
			d.peers.AddPeer(addrPort, false)
		} else {
			return fmt.Errorf("my own addrport was given")
		}
	}
	d.peers.ChallengeSolved(packet.AddrPort)
	return nil
}

func unmarshalEd25519PublicKey(publicKeyBytes []byte) (ed25519.PublicKey, error) {
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519: public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(publicKeyBytes), nil
}

type peerDistance struct {
	peer     peer.Peer
	distance []byte
}

// Returns a copy of the peer slice sorted by distance, closest first
func sortPeersByDistance(target ed25519.PublicKey, peers []peer.Peer) []peerDistance {
	distances := make([]peerDistance, 0, len(peers))
	for _, peer := range peers {
		if peer.PubKey() == nil {
			continue
		}
		dist := make([]byte, ed25519.PublicKeySize)
		xor.Xor256Into(dist, peer.PubKey(), target)
		distances = append(distances, peerDistance{peer, dist})
	}
	sort.Slice(distances, func(i, j int) bool {
		return bytes.Compare(distances[i].distance, distances[j].distance) < 0
	})
	return distances
}
