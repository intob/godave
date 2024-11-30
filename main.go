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
	getPeers        chan bool // true = active only, false = all peers
	peers           chan []peer.Peer
	store           *store.Store
	packetProcessor *pkt.PacketProcessor
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
		packetOut:  make(chan *pkt.Packet, 100),
		getPeers:   make(chan bool),
		peers:      make(chan []peer.Peer),
		logger:     cfg.Logger}
	var err error
	dave.store, err = store.New(&store.StoreCfg{
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
	peers := peer.NewStore(&peer.StoreCfg{
		Probe:            PROBE,
		ActivationDelay:  ACTIVATION_DELAY,
		DeactivateAfter:  DEACTIVATE_AFTER,
		DropAfter:        DROP,
		TrustDecayFactor: TRUST_DECAY_FACTOR,
		Logger:           cfg.Logger.WithPrefix("/peers")})
	for _, addrPort := range cfg.Edges {
		peers.AddPeer(pkt.MapToIPv6(addrPort), true)
	}
	dave.packetProcessor, err = pkt.NewPacketProcessor(&pkt.PacketProcessorCfg{
		NumWorkers:    runtime.NumCPU(),
		BufSize:       types.MaxMsgLen,
		Socket:        cfg.Socket,
		PongPeerLimit: NPEER_LIMIT,
		GetPeers:      dave.getPeers,
		Peers:         dave.peers,
		Logger:        cfg.Logger.WithPrefix("/packet_proc")})
	if err != nil {
		return nil, fmt.Errorf("failed to init packet processor: %s", err)
	}
	go dave.run(peers, cfg.ShardCap)
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
	d.getPeers <- true // true = active only
	activePeers := <-d.peers
	if len(activePeers) == 0 {
		return errors.New("no active peers")
	}
	d.sendToClosestPeers(activePeers, &dat)
	d.logger.Error("sent to %s")
	return nil
}

func (d *Dave) WaitForActivePeers(ctx context.Context, count int) error {
	check := time.NewTicker(100 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-check.C:
			d.getPeers <- true // true = active only
			activePeers := <-d.peers
			if len(activePeers) >= count {
				return nil
			}
		}
	}
}

func (d *Dave) run(peers *peer.Store, ringSize int) {
	pingTick := time.NewTicker(PING)
	epochTick := time.NewTicker(EPOCH)
	trustDecayTick := time.NewTicker(TRUST_DECAY_RATE)
	getMyAddrPortTick := time.NewTicker(GETMYADDRPORT_EVERY)
	if len(peers.Edges()) == 0 {
		getMyAddrPortTick.Stop()
	} else { // also send now
		err := d.sendGetMyAddrPort(peers)
		if err != nil {
			d.logger.Error("failed to send GETMYADDRPORT: no edge is online")
		}
	}
	ring := ringbuffer.NewRingBuffer[*types.Dat](ringSize)
	packetIn := d.packetProcessor.Packets()
	myAddrPortChans := d.packetProcessor.MyAddrPortChans()
	var myAddrPort netip.AddrPort
	for {
		select {
		case packet := <-packetIn: // HANDLE INCOMING PACKET
			switch packet.Msg.Op {
			case types.Op_PONG: // VALIDATE SOLUTION & STORE PEERS
				err := handlePong(peers, packet, myAddrPort)
				if err != nil {
					d.logger.Error("failed to handle pong: %s", err)
				}
			case types.Op_PING: // SOLVE CHALLENGE & GIVE PEERS
				d.handlePing(peers, packet)
			case types.Op_PUT: // STORE DAT
				d.handlePut(peers, ring, packet)
			case types.Op_GETMYADDRPORT:
				d.packetOut <- &pkt.Packet{Msg: &types.Msg{
					Op:        types.Op_GETMYADDRPORT_ACK,
					AddrPorts: []netip.AddrPort{packet.AddrPort}},
					AddrPort: packet.AddrPort}
			case types.Op_GETMYADDRPORT_ACK:
				// Only accept from edge peers
				if peers.IsEdge(packet.AddrPort) && len(packet.Msg.AddrPorts) == 1 {
					myAddrPort = packet.Msg.AddrPorts[0]
					for _, c := range myAddrPortChans {
						c <- myAddrPort
					}
				} else {
					d.logger.Error("rejected MYADDRPORT_ACK from %s", packet.AddrPort)
				}
			}
		case <-epochTick.C: // SEED
			activePeers := peers.ListActive()
			if len(activePeers) < FANOUT {
				continue
			}
			ringDat, ok := ring.Read()
			if ok {
				d.sendToClosestPeers(activePeers, ringDat)
			} else {
				nextDat, ok := d.store.Next()
				if ok {
					d.sendToClosestPeers(activePeers, &nextDat)
				}
			}
		case <-pingTick.C: // PING PEERS WITH A CHALLENGE
			peers.Prune()
			for _, peer := range peers.ListAll() {
				challenge, err := peers.CreateChallenge(peer.AddrPort())
				if err != nil {
					d.logger.Error("failed to create challenge: %s", err)
					continue
				}
				d.packetOut <- &pkt.Packet{Msg: &types.Msg{
					Op: types.Op_PING, Challenge: challenge},
					AddrPort: peer.AddrPort()}
			}
		case <-trustDecayTick.C:
			peers.DecayTrust()
		case activeOnly := <-d.getPeers:
			if activeOnly {
				d.peers <- peers.ListActive()
			} else {
				d.peers <- peers.ListAll()
			}
		case <-getMyAddrPortTick.C:
			err := d.sendGetMyAddrPort(peers)
			if err != nil {
				d.logger.Error("failed to send GETMYADDRPORT: no edge is online")
			}
		}
	}
}

func (d *Dave) sendGetMyAddrPort(peers *peer.Store) error {
	for _, p := range peers.Edges() {
		if time.Since(p.ChallengeSolved()) < DEACTIVATE_AFTER {
			d.packetOut <- &pkt.Packet{
				Msg:      &types.Msg{Op: types.Op_GETMYADDRPORT},
				AddrPort: p.AddrPort()}
			d.logger.Debug("sent GETMYADDRPORT to %s", p.AddrPort())
			return nil
		}
	}
	return errors.New("failed to send MYADDRPORT")
}

func (d *Dave) handlePut(peers *peer.Store, ring *ringbuffer.RingBuffer[*types.Dat], packet *pkt.Packet) {
	peers.AddPeer(packet.AddrPort, false)
	err := d.store.Put(packet.Msg.Dat)
	if err != nil {
		//d.logger.Debug("failed to store dat: %s", err)
		return
	}
	ring.Write(packet.Msg.Dat)
	distance, err := xor.Xor256Uint8(d.publicKey, packet.Msg.Dat.PubKey)
	if err != nil {
		d.logger.Error("failed to calculate distance: %s", err)
		return
	}
	peers.UpdateTrust(packet.AddrPort, 255-distance)
	d.logger.Debug("stored %s", packet.Msg.Dat.Key)
}

func (d *Dave) handlePing(peers *peer.Store, packet *pkt.Packet) {
	peers.AddPeer(packet.AddrPort, false)
	if !peers.IsPingExpected(packet.AddrPort, PING) {
		d.logger.Error("unexpected ping from %s", packet.AddrPort)
		return
	}
	peers.UpdatePingReceived(packet.AddrPort)
	randPeers := peers.TrustWeightedRandPeers(NPEER_LIMIT, &packet.AddrPort)
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
	d.packetOut <- &pkt.Packet{
		Msg: &types.Msg{
			Op: types.Op_PONG,
			Solution: &types.Solution{
				Challenge: packet.Msg.Challenge,
				Salt:      types.Salt(salt),
				PublicKey: d.publicKey,
				Signature: types.Signature(sig)},
			AddrPorts: addrPorts},
		AddrPort: packet.AddrPort}
}

func (d *Dave) sendToClosestPeers(activePeers []peer.Peer, dat *types.Dat) {
	sorted := sortPeersByDistance(dat.PubKey, activePeers)
	for i := 0; i < FANOUT && i < len(sorted); i++ {
		d.packetOut <- &pkt.Packet{
			Msg:      &types.Msg{Op: types.Op_PUT, Dat: dat},
			AddrPort: sorted[i].peer.AddrPort()}
	}
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

func handlePong(peers *peer.Store, packet *pkt.Packet, myAddrPort netip.AddrPort) error {
	peers.AddPeer(packet.AddrPort, false)
	challenge, storedPubKey, err := peers.CurrentChallengeAndPubKey(packet.AddrPort)
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
		peers.SetPubKey(packet.AddrPort, packet.Msg.Solution.PublicKey)
	}
	for _, addrPort := range packet.Msg.AddrPorts {
		if addrPort != myAddrPort {
			peers.AddPeer(addrPort, false)
		} else {
			return fmt.Errorf("my own addrport was given")
		}
	}
	peers.ChallengeSolved(packet.AddrPort)
	return nil
}
