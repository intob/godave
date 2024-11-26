package godave

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
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
	EPOCH          = time.Millisecond
	BUF_SIZE       = 1424             // Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT         = 5                // Number of peers randomly selected when sending new dats.
	PROBE          = 12               // Inverse of probability that a peer is selected regardless of trust.
	NPEER_LIMIT    = 3                // Maximum number of peer descriptors in a PEER message.
	MIN_WORK       = 16               // Minimum amount of acceptable work in number of leading zero bits.
	MAX_TRUST      = 25               // Maximum trust score, ensuring fair trust distribution from feedback.
	PING           = 8 * time.Second  // Time until peers are pinged with a GETPEER message.
	DROP           = 16 * time.Second // Time until silent peers are dropped from the peer table.
	SHARE_DELAY    = 2 * DROP         // Time until new peers are shared. Must be greater than DROP.
	PRUNE_DATS     = 20 * time.Second // Period between pruning dats.
	PRUNE_PEERS    = PING             // Period between pruning peers.
	RINGSIZE       = 1000             // Number of dats to store in ring buffer.
	LOGLEVEL_ERROR = LogLevel(0)      // Base log level, for errors & status.
	LOGLEVEL_DEBUG = LogLevel(1)      // Debugging log level.
)

type LogLevel int

type Dave struct {
	Store      *store.Store
	kill, done chan struct{}
	packetOut  chan *pkt.Packet
	send       chan *store.Dat
	logger     *logger.Logger
}

type Cfg struct {
	UdpListenAddr  *net.UDPAddr
	Edges          []netip.AddrPort // Bootstrap peers
	ShardCap       int
	BackupFilename string
	Logger         *logger.Logger
}

func NewDave(cfg *Cfg) (*Dave, error) {
	socket, err := net.ListenUDP("udp", cfg.UdpListenAddr)
	if err != nil {
		return nil, err
	}
	dave := &Dave{
		kill:      make(chan struct{}, 1),
		done:      make(chan struct{}, 1),
		packetOut: make(chan *pkt.Packet, 100),
		send:      make(chan *store.Dat),
		logger:    cfg.Logger,
	}
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
		Probe:      PROBE,
		MaxTrust:   MAX_TRUST,
		PruneEvery: PRUNE_PEERS,
		DropAfter:  DROP,
		ListDelay:  SHARE_DELAY,
		Ping:       PING,
		Logger:     cfg.Logger.WithPrefix("/peers"),
	})
	for _, edge := range cfg.Edges {
		peers.AddEdge(edge)
	}
	incoming := pkt.NewPacketProcessor(&pkt.PacketProcessorCfg{
		NumWorkers: runtime.NumCPU(),
		BufSize:    BUF_SIZE,
		FilterFunc: packetFilter,
		Socket:     socket,
		Logger:     cfg.Logger.WithPrefix("/packet_proc"),
	})
	go dave.run(peers, incoming.Packets())
	go dave.writePackets(socket)
	return dave, nil
}

func (d *Dave) Kill() <-chan struct{} {
	d.kill <- struct{}{}
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
		d.send <- &dat
	}()
	return done
}

func (d *Dave) run(peers *peer.Store, packetIn <-chan *pkt.Packet) {
	pingTick := time.NewTicker(PING)
	epochTick := time.NewTicker(EPOCH)
	ring := ringbuffer.NewRingBuffer[*store.Dat](RINGSIZE)
	var cshard uint8
	for {
		select {
		case packet := <-packetIn: // HANDLE INCOMING PACKET
			remoteFp := peers.Seen(packet.AddrPort)
			switch packet.Msg.Op {
			case dave.Op_PEER: // STORE PEERS
				d.logger.Debug("got PEER message from %d", remoteFp)
				if peers.IsPeerMessageExpected(remoteFp) {
					for _, pd := range packet.Msg.Pds {
						peers.AddPd(pd)
					}
				}
			case dave.Op_GETPEER: // GIVE PEERS
				randPeers := peers.RandPeers(NPEER_LIMIT, remoteFp)
				pds := make([]*dave.Pd, len(randPeers))
				for i, p := range randPeers {
					pds[i] = peer.PdFrom(p.AddrPort())
				}
				d.packetOut <- &pkt.Packet{
					Msg:      &dave.M{Op: dave.Op_PEER, Pds: pds},
					AddrPort: packet.AddrPort,
				}
				d.logger.Debug("replied to GETPEER from %d", remoteFp)
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
				peers.AddTrust(remoteFp, store.Mass(packet.Msg.Work, pow.Btt(packet.Msg.Time)))
				ring.Write(dat)
				d.logger.Debug("stored %x %s", packet.Msg.Work, packet.AddrPort)
			}
		case <-epochTick.C: // SEED
			randPeer := peers.RandPeer()
			if randPeer == nil {
				continue
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
		case <-pingTick.C:
			peers.Prune()
			for _, peer := range peers.Table() {
				d.packetOut <- &pkt.Packet{Msg: &dave.M{Op: dave.Op_GETPEER}, AddrPort: peer.AddrPort()}
				d.logger.Debug("ping sent to %s", peer.AddrPort())
			}
		case dat := <-d.send:
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
	}
}

func (d *Dave) writePackets(socket *net.UDPConn) {
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

func packetFilter(m *dave.M, h *blake3.Hasher) error {
	if m.Op == dave.Op_PUT {
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
	} else if m.Op == dave.Op_PEER && len(m.Pds) > NPEER_LIMIT {
		return errors.New("packet exceeds pd limit")
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
