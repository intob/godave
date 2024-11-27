package godave

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"time"

	"github.com/intob/godave/dave"
	"github.com/intob/godave/logger"
	"github.com/intob/godave/peer"
	"github.com/intob/godave/pkt"
	"github.com/intob/godave/pow"
	"github.com/intob/godave/ringbuffer"
	"github.com/intob/godave/store"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

const (
	EPOCH            = time.Millisecond
	BUF_SIZE         = 1424             // Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT           = 5                // Number of peers randomly selected when sending new dats.
	PROBE            = 12               // Inverse of probability that a peer is selected regardless of trust.
	NPEER_LIMIT      = 3                // Maximum number of peer descriptors in a PONG message.
	MIN_WORK         = 16               // Minimum amount of acceptable work in number of leading zero bits.
	MAX_TRUST        = 25               // Maximum trust score, ensuring fair trust distribution from feedback.
	PING             = 10 * time.Second // Period between pinging peers.
	DROP             = 3 * PING         // Time until protocol-deviating peers are dropped.
	ACTIVATION_DELAY = 2 * DROP         // Time until new peers are activated. Must be greater than DROP.
	PRUNE_DATS       = 20 * time.Second // Period between pruning dats.
	PRUNE_PEERS      = PING             // Period between pruning peers.
	RING_SIZE        = 1000             // Number of dats to store in ring buffer.
	LOGLEVEL_ERROR   = LogLevel(0)      // Base log level, for errors & status.
	LOGLEVEL_DEBUG   = LogLevel(1)      // Debugging log level.
)

type LogLevel int

type Dave struct {
	Store      *store.Store
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	kill, done chan struct{}
	packetOut  chan *pkt.Packet
	toSend     chan *store.Dat
	logger     *logger.Logger
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
		privateKey: cfg.PrivateKey,
		publicKey:  cfg.PrivateKey.Public().(ed25519.PublicKey),
		kill:       make(chan struct{}, 1),
		done:       make(chan struct{}, 1),
		packetOut:  make(chan *pkt.Packet, 100),
		toSend:     make(chan *store.Dat),
		logger:     cfg.Logger,
	}
	var err error
	dave.Store, err = store.New(&store.StoreCfg{
		ShardCap:       cfg.ShardCap,
		PruneEvery:     PRUNE_DATS,
		BackupFilename: cfg.BackupFilename,
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
	go dave.run(peers, incoming.Packets())
	go dave.writePackets(cfg.Socket)
	return dave, nil
}

func (d *Dave) Kill() <-chan struct{} {
	close(d.kill)
	return d.done
}

func (d *Dave) Put(dat store.Dat) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := d.Store.Put(&dat)
		if err != nil {
			return
		}
		d.toSend <- &dat
	}()
	return done
}

func (d *Dave) run(peers *peer.Store, packetIn <-chan *pkt.Packet) {
	pingTick := time.NewTicker(PING)
	epochTick := time.NewTicker(EPOCH)
	ring := ringbuffer.NewRingBuffer[*store.Dat](RING_SIZE)
	var cshard uint8
	for {
		select {
		case packet := <-packetIn: // HANDLE INCOMING PACKET
			remoteFp := peers.AddPeer(packet.AddrPort, false)
			switch packet.Msg.Op {
			case dave.Op_PONG: // VALIDATE SOLUTION & STORE PEERS
				d.logger.Debug("got PONG message from %d", remoteFp)
				err := handlePong(peers, remoteFp, packet)
				if err != nil {
					d.logger.Error("encountered error handling PONG: %s", err)
				}
			case dave.Op_PING: // SOLVE CHALLENGE & GIVE PEERS
				randPeers := peers.RandPeers(NPEER_LIMIT, remoteFp)
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
				d.logger.Debug("replied to PING from %d", remoteFp)
			case dave.Op_PUT: // STORE DAT
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
					d.logger.Debug("failed to store dat: %s", err)
					continue
				}
				peers.UpdateTrust(remoteFp, store.Mass(packet.Msg.Work, pow.Btt(packet.Msg.Time)))
				ring.Write(dat)
				d.logger.Debug("stored %x %s", packet.Msg.Work, packet.AddrPort)
			}
		case <-epochTick.C: // SEED
			d.seed(peers, ring, cshard)
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
				d.logger.Debug("ping sent to %s", peer.AddrPort())
			}
		case dat := <-d.toSend:
			d.sendDat(peers, dat)
		}
	}
}

func (d *Dave) seed(peers *peer.Store, ring *ringbuffer.RingBuffer[*store.Dat], cshard uint8) {
	randPeer := peers.RandPeer()
	if randPeer == nil {
		return
	}
	dat := d.Store.Rand(cshard)
	if dat != nil {
		d.packetOut <- &pkt.Packet{Msg: buildDatMessage(dat), AddrPort: randPeer.AddrPort()}
	}
	dat, ok := ring.Read()
	if ok {
		d.packetOut <- &pkt.Packet{Msg: buildDatMessage(dat), AddrPort: randPeer.AddrPort()}
	}
	cshard++ // overflows to 0
}

func (d *Dave) sendDat(peers *peer.Store, dat *store.Dat) {
	sentTo := make(map[uint64]struct{})
	targetPeers := min(FANOUT, peers.CountActive())
	for len(sentTo) < targetPeers {
		randPeers := peers.RandPeers(FANOUT, 0)
		for _, peer := range randPeers {
			_, sentAlready := sentTo[peer.Fp()]
			if !sentAlready {
				d.packetOut <- &pkt.Packet{Msg: buildDatMessage(dat), AddrPort: peer.AddrPort()}
				sentTo[peer.Fp()] = struct{}{}
				d.logger.Error("sent to %s", peer)
			}
		}
	}
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

func handlePong(peers *peer.Store, remoteFp uint64, packet *pkt.Packet) error {
	challenge, storedPubKey, err := peers.CurrentChallengeAndPubKey(remoteFp)
	if err != nil {
		return err
	}
	if !bytes.Equal(challenge, packet.Msg.Val) {
		return fmt.Errorf("PONG from %s: challenge is incorrect, expected %x, got %x", packet.AddrPort, challenge, packet.Msg.Val)
	}
	msgPubKey, err := unmarshalEd25519(packet.Msg.PubKey)
	if err != nil {
		return fmt.Errorf("failed to unmarshal pub key: %s", err)
	}
	if storedPubKey == nil {
		peers.SetPubKey(remoteFp, msgPubKey)
	} else if !storedPubKey.Equal(msgPubKey) {
		return fmt.Errorf("msg pub key does not match stored pub key")
	}
	if !ed25519.Verify(msgPubKey, challenge, packet.Msg.Sig) {
		return fmt.Errorf("signature is invalid")
	}
	peers.ClearChallenge(remoteFp)
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
		err := pow.Check(h, m)
		if err != nil {
			return fmt.Errorf("work is invalid: %s", err)
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
