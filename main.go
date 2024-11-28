package godave

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sort"
	"time"

	"github.com/intob/godave/dave"
	"github.com/intob/godave/logger"
	"github.com/intob/godave/peer"
	"github.com/intob/godave/pkt"
	"github.com/intob/godave/pow"
	"github.com/intob/godave/ringbuffer"
	"github.com/intob/godave/store"
	"github.com/intob/godave/xor"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

const (
	EPOCH            = time.Millisecond
	BUF_SIZE         = 1424             // Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT           = 2                // Number of peers selected when sending dats.
	PROBE            = 12               // Inverse of probability that a peer is selected regardless of trust.
	NPEER_LIMIT      = 3                // Maximum number of peer descriptors in a PONG message.
	MIN_WORK         = 16               // Minimum amount of acceptable work in number of leading zero bits.
	MAX_TRUST        = 25               // Maximum trust score, ensuring fair trust distribution from feedback.
	PING             = 3 * time.Second  // Period between pinging peers.
	DROP             = 3 * PING         // Time until protocol-deviating peers are dropped.
	ACTIVATION_DELAY = 2 * DROP         // Time until new peers are activated. Must be greater than DROP.
	PRUNE_DATS       = 10 * time.Second // Period between pruning dats.
	PRUNE_PEERS      = PING             // Period between pruning peers.
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
		PruneEvery:      PRUNE_PEERS,
		DropAfter:       DROP,
		ActivationDelay: ACTIVATION_DELAY,
		Logger:          cfg.Logger.WithPrefix("/peers"),
	})
	for _, addrPort := range cfg.Edges {
		peers.AddPeer(addrPort, true)
	}
	incoming := pkt.NewPacketProcessor(&pkt.PacketProcessorCfg{
		NumWorkers: runtime.NumCPU(),
		BufSize:    BUF_SIZE,
		FilterFunc: packetFilter,
		Socket:     cfg.Socket,
		Logger:     cfg.Logger.WithPrefix("/packet_proc"),
	})
	go dave.run(peers, incoming.Packets(), cfg.ShardCap)
	go dave.writePackets(cfg.Socket)
	return dave, nil
}

func (d *Dave) Kill() <-chan struct{} {
	close(d.kill)
	return d.done
}

func (d *Dave) Put(dat store.Dat) error {
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
	ring := ringbuffer.NewRingBuffer[*store.Dat](ringSize)
	for {
		select {
		case packet := <-packetIn: // HANDLE INCOMING PACKET
			switch packet.Msg.Op {
			case dave.Op_PONG: // VALIDATE SOLUTION & STORE PEERS
				err := handlePong(peers, packet)
				if err != nil {
					d.logger.Error("failed to handle pong: %s", err)
				}
			case dave.Op_PING: // SOLVE CHALLENGE & GIVE PEERS
				d.handlePing(peers, packet)
			case dave.Op_PUT: // STORE DAT
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
					Msg:      &dave.M{Op: dave.Op_PING, Val: challenge},
					AddrPort: peer.AddrPort()}
				//d.logger.Debug("ping sent to %s", peer.AddrPort())
			}
		case <-d.getActivePeers:
			d.activePeers <- peers.ListActive()
		}
	}
}

func (d *Dave) handlePut(peers *peer.Store, ring *ringbuffer.RingBuffer[*store.Dat], packet *pkt.Packet) {
	remoteFp := peers.AddPeer(packet.AddrPort, false)
	dat := &store.Dat{
		Key:    packet.Msg.DatKey,
		Val:    packet.Msg.Val,
		Time:   pow.Btt(packet.Msg.Time),
		Salt:   packet.Msg.Salt,
		Work:   packet.Msg.Work,
		Sig:    packet.Msg.Sig,
		PubKey: packet.Msg.PubKey,
	}
	err := d.Store.Put(dat)
	if err != nil {
		//d.logger.Debug("failed to store dat: %s", err)
		return
	}
	ring.Write(dat)
	dist, err := xor.XorFloat(d.publicKey, dat.PubKey)
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
	pds := make([]*dave.Pd, len(randPeers))
	for i, p := range randPeers {
		pds[i] = peer.PdFrom(p.AddrPort())
	}
	d.packetOut <- &pkt.Packet{
		Msg: &dave.M{
			Op:     dave.Op_PONG,
			Val:    packet.Msg.Val,
			Pds:    pds,
			PubKey: d.publicKey,
			Sig:    ed25519.Sign(d.privateKey, packet.Msg.Val),
		},
		AddrPort: packet.AddrPort,
	}
	//d.logger.Debug("replied to ping from %d", remoteFp)
}

func (d *Dave) sendToClosestPeers(activePeers []peer.Peer, dat *store.Dat) {
	msg := buildDatMessage(dat)
	sorted := sortPeersByDistance(dat.PubKey, activePeers)
	for i := 0; i < FANOUT && i < len(sorted); i++ {
		d.packetOut <- &pkt.Packet{
			Msg:      msg,
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
	for pkt := range d.packetOut {
		bin, err := proto.Marshal(pkt.Msg)
		if err != nil {
			d.logger.Error("dispatch error: %s", err)
			continue
		}
		_, err = socket.WriteToUDPAddrPort(bin, pkt.AddrPort)
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
	if !bytes.Equal(challenge, packet.Msg.Val) {
		return errors.New("challenge is incorrect")
	}
	msgPubKey, err := unmarshalEd25519(packet.Msg.PubKey)
	if err != nil {
		return fmt.Errorf("failed to unmarshal pub key: %s", err)
	}
	if storedPubKey != nil && !storedPubKey.Equal(msgPubKey) {
		return fmt.Errorf("msg pub key does not match stored pub key")
	}
	if !ed25519.Verify(msgPubKey, challenge, packet.Msg.Sig) {
		return fmt.Errorf("signature is invalid")
	}
	if storedPubKey == nil {
		peers.SetPubKey(remoteFp, msgPubKey)
	}
	peers.ChallengeSolved(remoteFp)
	for _, pd := range packet.Msg.Pds {
		peers.AddPd(pd)
	}
	return nil
}

// TODO: consider using a cuckoo filter or rate limiter for PUT
// messages to prevent DoS. Verifying the signature is expensive.
func packetFilter(m *dave.M, h *blake3.Hasher) error {
	switch m.Op {
	case dave.Op_PUT:
		if pow.Nzerobit(m.Work) < MIN_WORK {
			return fmt.Errorf("work is insufficient: %x", m.Work)
		}
		if err := pow.Check(h, m); err != nil {
			return fmt.Errorf("work is invalid: %s", err)
		}
		if l := len(m.PubKey); l != ed25519.PublicKeySize {
			return fmt.Errorf("pub key is invalid: len %d", l)
		}
		pubKey, err := unmarshalEd25519(m.PubKey)
		if err != nil {
			return fmt.Errorf("failed to unmarshal pub key: %s", err)
		}
		if !ed25519.Verify(pubKey, m.Work, m.Sig) {
			return fmt.Errorf("signature is invalid")
		}
	case dave.Op_PONG:
		if len(m.Pds) > NPEER_LIMIT {
			return errors.New("packet exceeds pd limit")
		}
	}
	return nil
}

func unmarshalEd25519(publicKeyBytes []byte) (ed25519.PublicKey, error) {
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519: public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(publicKeyBytes), nil
}

func buildDatMessage(dat *store.Dat) *dave.M {
	return &dave.M{
		Op:     dave.Op_PUT,
		DatKey: dat.Key,
		Val:    dat.Val,
		Time:   pow.Ttb(dat.Time),
		Salt:   dat.Salt,
		Work:   dat.Work,
		PubKey: dat.PubKey,
		Sig:    dat.Sig,
	}
}
