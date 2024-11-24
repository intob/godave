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
	EPOCH          = 200 * time.Microsecond
	BUF_SIZE       = 1424             // Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT         = 5                // Number of peers randomly selected when selecting more than one.
	PROBE          = 8                // Inverse of probability that an untrusted peer is randomly selected.
	NPEER_LIMIT    = 2                // Maximum number of peer descriptors in a PEER message.
	MIN_WORK       = 16               // Minimum amount of acceptable work in number of leading zero bits.
	MAX_TRUST      = 25               // Maximum trust score, ensuring fair trust distribution from feedback.
	PING           = 8 * time.Second  // Time until peers are pinged with a GETPEER message.
	DROP           = 16 * time.Second // Time until silent peers are dropped from the peer table.
	SHARE_DELAY    = 20 * time.Second // Time until new peers are shared. Must be greater than DROP.
	PRUNE          = 10 * time.Second // Period between pruning dats & peers.
	RINGSIZE       = 1000             // Number of dats to store in ring buffer.
	LOGLEVEL_ERROR = LogLevel(0)      // Base log level, for errors & status.
	LOGLEVEL_DEBUG = LogLevel(1)      // Debugging log level.
)

type LogLevel int

type Dave struct {
	Store      *store.Store
	Peers      *peer.Store
	kill, done chan struct{}
	packetOut  chan *pkt.Packet
	logger     *logger.Logger
}

type Cfg struct {
	UdpListenAddr *net.UDPAddr
	Edges         []netip.AddrPort // Bootstrap peers
	ShardCap      int
	BackupFname   string
	Logger        *logger.Logger
}

func NewDave(cfg *Cfg) (*Dave, error) {
	socket, err := net.ListenUDP("udp", cfg.UdpListenAddr)
	if err != nil {
		return nil, err
	}
	dave := &Dave{
		Peers: peer.NewStore(&peer.StoreCfg{
			Probe:      PROBE,
			MaxTrust:   MAX_TRUST,
			PruneEvery: PRUNE,
			Logger:     cfg.Logger.WithPrefix("/peer_store"),
		}),
		packetOut: make(chan *pkt.Packet, 100),
		kill:      make(chan struct{}, 1),
		done:      make(chan struct{}, 1),
		logger:    cfg.Logger.WithPrefix("/main"),
	}
	dave.Store, err = store.New(&store.StoreCfg{
		ShardCap:       cfg.ShardCap,
		PruneEvery:     10 * time.Second,
		BackupFilename: cfg.BackupFname,
		Logger:         cfg.Logger.WithPrefix("/dat_store"),
		Kill:           dave.kill,
		Done:           dave.done,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init store: %w", err)
	}
	for _, edge := range cfg.Edges {
		dave.Peers.AddEdge(edge)
	}
	incoming := pkt.NewPacketProcessor(&pkt.PacketProcessorCfg{
		NumWorkers: runtime.NumCPU(),
		BufSize:    BUF_SIZE,
		FilterFunc: packetFilter,
		Socket:     socket,
		Logger:     cfg.Logger.WithPrefix("/packet_proc"),
	})
	go dave.run(incoming.Packets(), dave.packetOut)
	go dave.writePackets(socket, dave.packetOut)
	return dave, nil
}

func (d *Dave) Kill() <-chan struct{} {
	d.kill <- struct{}{}
	return d.done
}

func (d *Dave) Put(dat *store.Dat) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		// TODO: refactor peer table and use here
		// send messages to d.packetOut
		//d.send <- &dave.M{Op: dave.Op_PUT, DatKey: dat.Key, Val: dat.Val, Salt: dat.Salt, Work: dat.Work, Time: pow.Ttb(dat.Time), PubKey: dat.PubKey, Sig: dat.Sig}
		defer close(done)
	}()
	return done
}

/*
func (d *Dave) sendForApp(m *dave.M, peerList []*peer, trustSum float64, pktout chan<- *pkt.Packet, cfg *Cfg) {
	if m == nil {
		return
	}
	switch m.Op {
	case dave.Op_PUT:
		d.Store.Put(&store.Dat{Key: m.DatKey, Val: m.Val, Salt: m.Salt, Work: m.Work, Sig: m.Sig, Time: pow.Btt(m.Time), PubKey: m.PubKey})
		for _, p := range rndpeers(peerList, trustSum, FANOUT, 0, 0) {
			addr := addrfrom(p.pd)
			pktout <- &pkt.Packet{Msg: m, AddrPort: addr}
			lg(cfg, LOGLEVEL_DEBUG, "/send_for_app dat sent to %s", addr)
		}
	default:
		lg(cfg, LOGLEVEL_ERROR, "/send_for_app unsupported operation: %s", m.Op)
	}
}
*/

func (d *Dave) run(packetIn <-chan *pkt.Packet, packetOut chan<- *pkt.Packet) {
	epochTick := time.NewTicker(EPOCH)
	pingTick := time.NewTicker(PING)
	ring := ringbuffer.NewRingBuffer[*store.Dat](RINGSIZE)
	var cshard uint8
	for {
		select {
		case packet := <-packetIn: // HANDLE INCOMING PACKET
			peer := d.Peers.Seen(packet.AddrPort)
			switch packet.Msg.Op {
			case dave.Op_PEER: // STORE PEERS
				if time.Since(peer.LastPeerMsg()) >= PING-10*time.Millisecond {
					peer.GotPeerMsg()
					for _, pd := range packet.Msg.Pds {
						newPeer, added := d.Peers.AddPd(pd)
						if added {
							d.logger.Error("peer added from gossip %s from %s", newPeer, peer)
						}
					}
				} else {
					d.logger.Error("unexpected PEER message from %s", packet.AddrPort)
				}
			case dave.Op_GETPEER: // GIVE PEERS
				randPeers := d.Peers.RandPeers(NPEER_LIMIT, peer, SHARE_DELAY)
				pds := make([]*dave.Pd, len(randPeers))
				for i, p := range randPeers {
					pds[i] = p.Pd()
				}
				packetOut <- &pkt.Packet{Msg: &dave.M{Op: dave.Op_PEER, Pds: pds}, AddrPort: packet.AddrPort}
				d.logger.Debug("replied to GETPEER from %s", packet.AddrPort)
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
				novel, err := d.Store.Put(dat)
				if err != nil {
					d.logger.Debug("failed to store dat: %s", err)
					continue
				}
				if novel {
					peer.AddTrust(store.Mass(packet.Msg.Work, pow.Btt(packet.Msg.Time)), MAX_TRUST)
				}
				ring.Write(dat) // even if not novel, if there is no error from call to Store.Put, it's a valid update
				d.logger.Debug("stored %x %s", packet.Msg.Work, packet.AddrPort)
			}
		case <-epochTick.C: // SEED
			randPeer := d.Peers.RandPeer()
			if randPeer != nil {
				dat := d.Store.Rand(cshard)
				if dat != nil {
					packetOut <- &pkt.Packet{Msg: &dave.M{Op: dave.Op_PUT, DatKey: dat.Key, Val: dat.Val, Time: pow.Ttb(dat.Time), Salt: dat.Salt, Work: dat.Work, PubKey: dat.PubKey, Sig: dat.Sig}, AddrPort: randPeer.AddrPort()}
				}
				dat, ok := ring.Read()
				if ok {
					packetOut <- &pkt.Packet{Msg: &dave.M{Op: dave.Op_PUT, DatKey: dat.Key, Val: dat.Val, Time: pow.Ttb(dat.Time), Salt: dat.Salt, Work: dat.Work, PubKey: dat.PubKey, Sig: dat.Sig}, AddrPort: randPeer.AddrPort()}
				}
				cshard++ // overflows to 0
			}
		case <-pingTick.C: // PING & DROP PEERS
			for _, p := range d.Peers.List() {
				if !p.Edge() && time.Since(p.LastSeen()) > DROP {
					d.logger.Error("dropped %s, not seen for %s", p, time.Since(p.LastSeen()))
					d.Peers.Drop(p)
					continue
				}
				if time.Since(p.LastPeerMsg()) > PING { // Send ping
					packetOut <- &pkt.Packet{Msg: &dave.M{Op: dave.Op_GETPEER}, AddrPort: p.AddrPort()}
					d.logger.Debug("ping sent to %s", p)
				}
			}
		}
	}
}

func (d *Dave) writePackets(socket *net.UDPConn, packets <-chan *pkt.Packet) {
	for pkt := range packets {
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
