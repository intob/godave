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
	EPOCH = time.Millisecond // Period between seeding rounds.
	//BUF_SIZE         = types.MaxMsgLen  // (1424) Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT           = 2                // Number of peers selected when sending dats.
	PROBE            = 12               // Inverse of probability that a peer is selected regardless of trust.
	NPEER_LIMIT      = 3                // Maximum number of peer descriptors in a PONG message.
	MIN_WORK         = 16               // Minimum amount of acceptable work in number of leading zero bits.
	MAX_TRUST        = 25               // Maximum trust score, ensuring fair trust distribution from feedback.
	PING             = 1 * time.Second  // Period between pinging peers.
	DROP             = 3 * PING         // Time until protocol-deviating peers are dropped.
	ACTIVATION_DELAY = 2 * DROP         // Time until new peers are activated. Must be greater than DROP.
	PRUNE_DATS       = 10 * time.Second // Period between pruning dats.
)

type Dave struct {
	Store                      *store.Store
	privateKey                 ed25519.PrivateKey
	publicKey                  ed25519.PublicKey
	kill, done, getActivePeers chan struct{}
	packetOut                  chan *pkt.Packet
	activePeers                chan []peer.Peer
	logger                     *logger.Logger
}

type Cfg struct {
	Socket         pkt.Socket
	PrivateKey     ed25519.PrivateKey
	Edges          []netip.AddrPort // Bootstrap peers
	ShardCap       int
	BackupFilename string
	Logger         *logger.Logger
}

func NewDave(cfg *Cfg) (*Dave, error) {
	if cfg.PrivateKey == nil || len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("no valid private key provided")
	}
	dave := &Dave{
		privateKey:     cfg.PrivateKey,
		publicKey:      cfg.PrivateKey.Public().(ed25519.PublicKey),
		kill:           make(chan struct{}, 1),
		done:           make(chan struct{}, 1),
		packetOut:      make(chan *pkt.Packet, 100),
		getActivePeers: make(chan struct{}),
		activePeers:    make(chan []peer.Peer),
		logger:         cfg.Logger,
	}
	var err error
	dave.Store, err = store.New(&store.StoreCfg{
		ShardCap:       cfg.ShardCap,
		PruneEvery:     PRUNE_DATS,
		BackupFilename: cfg.BackupFilename,
		PublicKey:      cfg.PrivateKey.Public().(ed25519.PublicKey),
		Logger:         cfg.Logger.WithPrefix("/dats"),
		Kill:           dave.kill,
		Done:           dave.done,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init store: %w", err)
	}
	peers := peer.NewStore(&peer.StoreCfg{
		Probe:           PROBE,
		MaxTrust:        MAX_TRUST,
		DropAfter:       DROP,
		ActivationDelay: ACTIVATION_DELAY,
		Logger:          cfg.Logger.WithPrefix("/peers"),
	})
	for _, addrPort := range cfg.Edges {
		peers.AddPeer(addrPort, true)
	}
	packetProcessor, err := pkt.NewPacketProcessor(&pkt.PacketProcessorCfg{
		NumWorkers:    runtime.NumCPU(),
		BufSize:       types.MaxMsgLen,
		Socket:        cfg.Socket,
		Logger:        cfg.Logger.WithPrefix("/packet_proc"),
		PongPeerLimit: NPEER_LIMIT,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init packet processor: %s", err)
	}
	go dave.run(peers, packetProcessor.Packets(), cfg.ShardCap)
	go dave.writePackets(cfg.Socket)
	return dave, nil
}

func (d *Dave) Kill() <-chan struct{} {
	close(d.kill)
	return d.done
}

func (d *Dave) Put(dat types.Dat) error {
	err := d.Store.Put(&dat)
	if err != nil {
		return fmt.Errorf("failed to put dat in local store: %s", err)
	}
	var activePeers []peer.Peer
	d.getActivePeers <- struct{}{}
	activePeers = <-d.activePeers
	if len(activePeers) == 0 {
		return errors.New("no active peers")
	}
	d.sendToClosestPeers(activePeers, &dat)
	d.logger.Error("sent to %s")
	return nil
}

func (d *Dave) WaitForPeers(ctx context.Context, count int) error {
	check := time.NewTicker(100 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-check.C:
			d.getActivePeers <- struct{}{}
			activePeers := <-d.activePeers
			if len(activePeers) >= count {
				return nil
			}
		}
	}
}

func (d *Dave) run(peers *peer.Store, packetIn <-chan *pkt.Packet, ringSize int) {
	pingTick := time.NewTicker(PING)
	epochTick := time.NewTicker(EPOCH)
	ring := ringbuffer.NewRingBuffer[*types.Dat](ringSize)
	for {
		select {
		case packet := <-packetIn: // HANDLE INCOMING PACKET
			switch packet.Msg.Op {
			case types.Op_PONG: // VALIDATE SOLUTION & STORE PEERS
				err := handlePong(peers, packet)
				if err != nil {
					d.logger.Error("failed to handle pong: %s", err)
				}
			case types.Op_PING: // SOLVE CHALLENGE & GIVE PEERS
				d.handlePing(peers, packet)
			case types.Op_PUT: // STORE DAT
				d.handlePut(peers, ring, packet)
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
				nextDat, ok := d.Store.Next()
				if ok {
					d.sendToClosestPeers(activePeers, &nextDat)
				}
			}
		case <-pingTick.C: // PING PEERS WITH A CHALLENGE
			peers.Prune()
			for _, peer := range peers.Table() {
				challenge, err := peers.CreateChallenge(peer.Fp())
				if err != nil {
					d.logger.Error("failed to create challenge: %s", err)
					continue
				}
				d.packetOut <- &pkt.Packet{
					Msg:      &types.Msg{Op: types.Op_PING, Challenge: challenge},
					AddrPort: peer.AddrPort()}
				//d.logger.Debug("ping sent to %s", peer.AddrPort())
			}
		case <-d.getActivePeers:
			d.activePeers <- peers.ListActive()
		}
	}
}

func (d *Dave) handlePut(peers *peer.Store, ring *ringbuffer.RingBuffer[*types.Dat], packet *pkt.Packet) {
	remoteFp := peers.AddPeer(packet.AddrPort, false)
	err := d.Store.Put(packet.Msg.Dat)
	if err != nil {
		//d.logger.Debug("failed to store dat: %s", err)
		return
	}
	ring.Write(packet.Msg.Dat)
	dist, err := xor.XorFloat(d.publicKey, packet.Msg.Dat.PubKey)
	if err != nil {
		d.logger.Error("failed to calculate distance: %s", err)
		return
	}
	peers.UpdateTrust(remoteFp, 1/dist)
	//d.logger.Debug("stored %x %s", packet.Msg.Work, packet.AddrPort)
}

func (d *Dave) handlePing(peers *peer.Store, packet *pkt.Packet) {
	remoteFp := peers.AddPeer(packet.AddrPort, false)
	if !peers.IsPingExpected(remoteFp, PING) {
		d.logger.Error("unexpected ping from %x", remoteFp)
		return
	}
	peers.UpdatePingReceived(remoteFp)
	randPeers := peers.TrustWeightedRandPeers(NPEER_LIMIT, remoteFp)
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
				Signature: types.Signature(sig),
			},
			AddrPorts: addrPorts,
		},
		AddrPort: packet.AddrPort,
	}

	//d.logger.Debug("replied to ping from %d", remoteFp)
}

func (d *Dave) sendToClosestPeers(activePeers []peer.Peer, dat *types.Dat) {
	sorted := sortPeersByDistance(dat.PubKey, activePeers)
	for i := 0; i < FANOUT && i < len(sorted); i++ {
		d.packetOut <- &pkt.Packet{
			Msg: &types.Msg{
				Op:  types.Op_PUT,
				Dat: dat,
			},
			AddrPort: sorted[i].peer.AddrPort(),
		}
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

func handlePong(peers *peer.Store, packet *pkt.Packet) error {
	remoteFp := peers.AddPeer(packet.AddrPort, false)
	challenge, storedPubKey, err := peers.CurrentChallengeAndPubKey(remoteFp)
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
		peers.SetPubKey(remoteFp, packet.Msg.Solution.PublicKey)
	}
	peers.ChallengeSolved(remoteFp)
	for _, addrPort := range packet.Msg.AddrPorts {
		peers.AddPeer(addrPort, false)
	}
	return nil
}
