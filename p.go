package godave

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	mrand "math/rand"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/intob/godave/dave"
	ckoo "github.com/panmari/cuckoofilter"
	"github.com/twmb/murmur3"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	BUF      = 1424   // Max packet size, 1500 MTU is typical, avoids packet fragmentation.
	FANOUT   = 2      // Number of peers randomly selected when selecting more than one.
	PROBE    = 8      // Inverse of probability that an untrusted peer is randomly selected.
	GETNPEER = 2      // Limit of peers in a PEER message.
	DELAY    = 5039   // Epochs until new peers may be randomly selected.
	PING     = 14197  // Epochs until silent peers are pinged with a GETPEER message.
	DROP     = 131071 // Epochs until silent peers are dropped from the peer table.
	SEED     = 3      // Epochs between sending one random dat to one random peer, excluding edges.
	PUSH     = 127    // Epcohs between sending the newest dat to one random peer, excluding edges.
	EDGE     = 3889   // Epochs between sending one random dat to one random edge peer.
	PULL     = 9377   // Interval between pulling a random dat from a random peer. Increases anonymity.
)

var zeroTable = [256]int{ // Lookup table for the number of leading zero bits in a byte
	8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

type Dave struct {
	Recv  <-chan *dave.M
	Send  chan<- *dave.M
	epoch time.Duration
}

type Cfg struct {
	LstnAddr  *net.UDPAddr     // Listening address:port
	Edges     []netip.AddrPort // Bootstrap peers
	Epoch     time.Duration    // Base cycle, lower runs faster, using more bandwidth
	DatCap    int              // Cuckoo filter capacity
	Prune     int              // Interval between refreshing dat & peer maps
	FilterCap uint             // Dat map capacity
	Log       chan<- []byte    // Log messages
	Test      bool             // Allow multiple ports per IP
}

type Dat struct {
	V, S, W []byte // Val, Salt, Work
	Ti      time.Time
}

type peer struct {
	pd                 *dave.Pd // Peer descriptor
	id                 uint64   // Address:port hash
	added, seen, peers time.Time
	edge               bool
	trust              float64
}

type pkt struct {
	msg *dave.M
	ip  netip.AddrPort
}

func NewDave(cfg *Cfg) (*Dave, error) {
	if cfg.Epoch == 0 {
		return nil, errors.New("Cfg.Epoch must not be zero. Try 20us")
	}
	if cfg.DatCap < 1 {
		return nil, errors.New("Cfg.DatCap must be at least 1")
	}
	if cfg.FilterCap < 1 {
		return nil, errors.New("Cfg.FilterCap must not be at least 1. 1K, 10K or 100K is probably good for you ;)")
	}
	if cfg.Prune < 1 {
		return nil, errors.New("Cfg.Prune must be at least 1. 50K or 100K is should be fine")
	}
	lg(cfg.Log, "/newdave/creating %+v\n", *cfg)
	c, err := net.ListenUDP("udp", cfg.LstnAddr)
	if err != nil {
		return nil, err
	}
	lg(cfg.Log, "/newdave/listening %s\n", c.LocalAddr())
	edges := make(map[uint64]*peer)
	h := murmur3.New64()
	for _, e := range cfg.Edges {
		pd := pdfrom(e)
		edges[pdid(h, pd)] = &peer{pd: pd, id: pdid(h, pd), added: time.Now(), seen: time.Now(), edge: true}
	}
	pktout := make(chan *pkt, 1)
	go func(c *net.UDPConn, pkts <-chan *pkt) {
		for pkt := range pkts {
			wraddr(c, marshal(pkt.msg), pkt.ip, cfg.Log)
		}
	}(c, pktout)
	send := make(chan *dave.M)
	recv := make(chan *dave.M, 1)
	go d(pktout, edges, cfg.Epoch, cfg.DatCap, cfg.Prune, lstn(c, cfg.Epoch, cfg.FilterCap, cfg.Test, cfg.Log), send, recv, cfg.Log)
	for _, e := range cfg.Edges {
		wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), e, cfg.Log)
	}
	return &Dave{Recv: recv, Send: send, epoch: cfg.Epoch}, nil
}

func (d *Dave) Get(work []byte, timeout, retry time.Duration) <-chan *Dat {
	c := make(chan *Dat, 1)
	go func() {
		d.Send <- &dave.M{Op: dave.Op_GET, W: work}
		defer close(c)
		sendy := time.NewTicker(retry)
		to := time.NewTimer(timeout)
		for {
			select {
			case <-to.C:
				return
			case m := <-d.Recv:
				if bytes.Equal(m.W, work) {
					c <- &Dat{m.V, m.S, m.W, Btt(m.T)}
					return
				}
			case <-sendy.C:
				d.Send <- &dave.M{Op: dave.Op_GET, W: work}
			}
		}
	}()
	return c
}

func (d *Dave) Set(dat Dat, rounds, npeer int) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		var p, r int
		tick := time.NewTicker(PUSH * d.epoch)
		for {
			select {
			case <-tick.C:
				if p < npeer {
					d.Send <- &dave.M{Op: dave.Op_GETPEER}
				} else {
					d.Send <- &dave.M{Op: dave.Op_DAT, V: dat.V, S: dat.S, W: dat.W, T: Ttb(dat.Ti)}
					r++
				}
				if r >= rounds && p >= npeer {
					done <- struct{}{}
					return
				}
			case m := <-d.Recv:
				if m.Op == dave.Op_PEER {
					p += len(m.Pds)
				}
			}
		}
	}()
	return done
}

func Work(val, tim []byte, d int) (work, salt []byte) {
	if d < 0 || d > 256 {
		return nil, nil
	}
	salt = make([]byte, 32)
	h, err := blake2b.New256(nil)
	if err != nil {
		return nil, nil
	}
	h.Write(val)
	h.Write(tim)
	load := h.Sum(nil)
	for {
		crand.Read(salt)
		h.Reset()
		h.Write(salt)
		h.Write(load)
		work = h.Sum(nil)
		if nzerobit(work) >= d {
			return work, salt
		}
	}
}

func Check(val, tim, salt, work []byte) int {
	if len(tim) != 8 || Btt(tim).After(time.Now()) {
		return -2
	}
	h, err := blake2b.New256(nil)
	if err != nil {
		return -3
	}
	return check(h, val, tim, salt, work)
}

func Mass(work []byte, t time.Time) float64 {
	return float64(nzerobit(work)) * (1 / float64(time.Since(t).Milliseconds()))
}

func Ttb(t time.Time) []byte {
	milli := t.UnixNano() / 1000000
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(milli))
	return bytes
}

func Btt(b []byte) time.Time {
	return time.Unix(0, int64(binary.LittleEndian.Uint64(b))*1000000)
}

func d(pktout chan<- *pkt, prs map[uint64]*peer, epoch time.Duration, dcap, prune int, pktin <-chan *pkt, appsend <-chan *dave.M, apprecv chan<- *dave.M, log chan<- []byte) {
	nedge := len(prs)
	dats := make(map[uint64]map[uint64]Dat)
	var nepoch, npeer int
	var newest *Dat
	etick := time.NewTicker(epoch)
	h := murmur3.New64()
	for {
		select {
		case <-etick.C:
			nepoch++
			if nepoch%prune == 0 { // MEMORY MANAGEMENT
				memstat := &runtime.MemStats{}
				runtime.ReadMemStats(memstat)
				dats, prs = mem(dats, prs, dcap)
				npeer = len(prs)
				lg(log, "/d/prune/keep %d peers, %d dat shards, %.2fGB mem alloc\n", len(prs), len(dats), float64(memstat.Alloc)/(1<<30))
			}
			if newest != nil && npeer > 0 && nepoch%PUSH == 0 { // SEND NEWEST DAT TO RANDOM PEER, EXCLUDING EDGES
				for _, rp := range rndpeers(prs, nil, 1, func(p *peer, l *peer) bool { return !p.edge && available(p, epoch) && dotrust(p, l) }) {
					pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: newest.V, T: Ttb(newest.Ti), S: newest.S, W: newest.W}, addrfrom(rp.pd)}
					lg(log, "/d/push %x %x\n", rp.id, newest.W)
				}
			}
			if npeer > 0 && nepoch%SEED == 0 { // SEND RANDOM DAT TO RANDOM PEER, EXCLUDING EDGES
				for _, rp := range rndpeers(prs, nil, 1, func(p *peer, l *peer) bool { return !p.edge && available(p, epoch) && dotrust(p, l) }) {
					rd := rnd(dats)
					if rd != nil {
						pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: rd.V, T: Ttb(rd.Ti), S: rd.S, W: rd.W}, addrfrom(rp.pd)}
						lg(log, "/d/seed %x %x\n", rp.id, rd.W)
					}
				}
			}
			if npeer > 0 && nedge > 0 && nepoch%(EDGE*(npeer/nedge)) == 0 { // SEND RANDOM DAT TO RANDOM EDGE PEER, MODULATED WITH PEER/EDGE RATIO
				rd := rnd(dats)
				if rd != nil {
					for _, redge := range rndpeers(prs, nil, 1, func(p *peer, l *peer) bool { return p.edge && available(p, epoch) }) {
						pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: rd.V, T: Ttb(rd.Ti), S: rd.S, W: rd.W}, addrfrom(redge.pd)}
						lg(log, "/d/seed_edge %x %x\n", redge.id, rd.W)
					}
				}
			}
			if npeer > 0 && nepoch%PULL == 0 { // PULL RANDOM DAT FROM RANDOM PEER, EXCLUDING EDGES
				rd := rnd(dats)
				if rd != nil {
					for _, rp := range rndpeers(prs, nil, 1, func(p *peer, l *peer) bool { return !p.edge && available(p, epoch) }) {
						pktout <- &pkt{&dave.M{Op: dave.Op_GET, W: rd.W}, addrfrom(rp.pd)}
						lg(log, "/d/pull %x %x\n", rp.id, rd.W)
					}
				}
			}
			if nepoch%PING == 0 { // PING AND DROP
				for pid, p := range prs {
					if !p.edge && time.Since(p.seen) > epoch*DROP { // DROP UNRESPONSIVE PEER
						delete(prs, pid)
						lg(log, "/d/ping/deleted %x\n", p.id)
					} else if time.Since(p.seen) > epoch*PING { // SEND PING
						pktout <- &pkt{&dave.M{Op: dave.Op_GETPEER}, addrfrom(p.pd)}
						lg(log, "/d/ping/sent %x\n", p.id)
					}
				}
			}
		case m := <-appsend: // SEND PACKET FOR APP
			sendForApp(m, dats, h, prs, pktout, apprecv, npeer, nedge, epoch, log)
		case pk := <-pktin: // HANDLE INCOMING PACKET
			pkpd := pdfrom(pk.ip)
			pkpid := pdid(h, pkpd)
			p, ok := prs[pkpid]
			if !ok {
				p = &peer{pd: pkpd, id: pkpid, added: time.Now(), seen: time.Now()}
				prs[pkpid] = p
				lg(log, "/d/h/add_peer %s %x\n", pk.ip.String(), pkpid)
			} else {
				p.seen = time.Now()
			}
			m := pk.msg
			select {
			case apprecv <- m:
			default:
				lg(log, "/d/h/app_missed\n")
			}
			switch m.Op {
			case dave.Op_PEER: // STORE PEERS
				if time.Since(p.peers) >= PING*epoch-epoch {
					p.peers = time.Now()
					for _, pd := range m.Pds {
						pid := pdid(h, pd)
						_, ok := prs[pid]
						if !ok {
							p := &peer{pd: pd, id: pdid(h, pd), added: time.Now(), seen: time.Now()}
							prs[pid] = p
							lg(log, "/d/h/peer_msg/add_from_gossip %s %x\n", pk.ip.String(), p.id)
						}
					}
				} else {
					lg(log, "/d/h/peer_msg/unexpected dropped %s %x\n", pk.ip.String(), p.id)
				}
			case dave.Op_GETPEER: // GIVE PEERS
				rpeers := rndpeers(prs, map[uint64]*peer{pkpid: p}, GETNPEER, func(p *peer, l *peer) bool { return available(p, epoch) })
				pds := make([]*dave.Pd, len(rpeers))
				for i, rp := range rpeers {
					pds[i] = rp.pd
				}
				pktout <- &pkt{&dave.M{Op: dave.Op_PEER, Pds: pds}, pk.ip}
				lg(log, "/d/h/getpeer_msg/reply %s %x\n", pk.ip.String(), p.id)
			case dave.Op_DAT: // FORWARD ON RECV CHAN AND STORE
				dat := &Dat{m.V, m.S, m.W, Btt(m.T)}
				novel, _ := store(dats, dat, h)
				label := "known"
				if novel {
					newest = dat
					label = "novel"
					p.trust += Mass(m.W, Btt(m.T))
				}
				lg(log, "/d/h/dat_msg/%s %x %x %f\n", label, m.W, p.id, p.trust)
			case dave.Op_GET: // REPLY WITH DAT
				shardi, dati, err := workid(h, m.W)
				if err == nil {
					shard, ok := dats[shardi]
					if ok { // GOT SHARD
						dat, ok := shard[dati]
						if ok { // GOT DAT
							pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}, pk.ip}
							lg(log, "/d/h/get_msg/reply %s %x\n", pk.ip.String(), dat.W)
						}
					}
				}
			}
		}
	}
}

func mem(dats map[uint64]map[uint64]Dat, prs map[uint64]*peer, dcap int) (map[uint64]map[uint64]Dat, map[uint64]*peer) {
	type hdat struct {
		shard, key uint64
		dat        Dat
	}
	heaviest := make([]hdat, dcap)
	for shardId, shard := range dats {
		for key, dat := range shard {
			if len(heaviest) < dcap {
				heaviest = append(heaviest, hdat{shardId, key, dat})
				if len(heaviest) == dcap {
					sort.Slice(heaviest, func(i, j int) bool {
						return Mass(heaviest[i].dat.W, heaviest[i].dat.Ti) < Mass(heaviest[j].dat.W, heaviest[j].dat.Ti)
					})
				}
			} else if Mass(dat.W, dat.Ti) > Mass(heaviest[0].dat.W, heaviest[0].dat.Ti) {
				heaviest[0] = hdat{shardId, key, dat}
				sort.Slice(heaviest, func(i, j int) bool {
					return Mass(heaviest[i].dat.W, heaviest[i].dat.Ti) < Mass(heaviest[j].dat.W, heaviest[j].dat.Ti)
				})
			}
		}
	}
	newdats := make(map[uint64]map[uint64]Dat, len(heaviest))
	for _, hdat := range heaviest {
		if hdat.shard != 0 && hdat.key != 0 {
			_, shardExists := newdats[hdat.shard]
			if !shardExists {
				newdats[hdat.shard] = make(map[uint64]Dat)
			}
			newdats[hdat.shard][hdat.key] = hdat.dat
		}
	}
	newpeers := make(map[uint64]*peer)
	for k, p := range prs {
		newpeers[k] = p
	}
	return newdats, newpeers
}

func sendForApp(m *dave.M, dats map[uint64]map[uint64]Dat, h hash.Hash64, prs map[uint64]*peer, pktout chan<- *pkt, apprecv chan<- *dave.M, npeer, nedge int, epoch time.Duration, log chan<- []byte) {
	if m != nil {
		switch m.Op {
		case dave.Op_DAT:
			store(dats, &Dat{m.V, m.S, m.W, Btt(m.T)}, h)
			go func(rps []*peer) {
				for _, rp := range rps {
					pktout <- &pkt{m, addrfrom(rp.pd)}
					lg(log, "/d/send/dat %x %x\n", rp.id, m.W)
				}
			}(rndpeers(prs, nil, FANOUT, func(p *peer, l *peer) bool { return (!p.edge || npeer < 2*nedge) && available(p, epoch) }))
		case dave.Op_GET:
			shardi, dati, err := workid(h, m.W)
			if err == nil {
				var found bool
				shard, ok := dats[shardi]
				if ok {
					dat, ok := shard[dati]
					if ok {
						found = true
						apprecv <- &dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}
						lg(log, "/d/send/get found locally %x\n", dat.W)
					}
				}
				if !found {
					go func(rps []*peer) {
						for _, rp := range rps {
							pktout <- &pkt{&dave.M{Op: dave.Op_GET, W: m.W}, addrfrom(rp.pd)}
							lg(log, "/d/send/get sent %x %x\n", rp.id, m.W)
						}
					}(rndpeers(prs, nil, FANOUT, func(p *peer, l *peer) bool { return available(p, epoch) }))
				}
			}
		case dave.Op_GETPEER:
			for _, rp := range rndpeers(prs, nil, 1, func(p *peer, l *peer) bool { return available(p, epoch) }) {
				pktout <- &pkt{m, addrfrom(rp.pd)}
				lg(log, "/d/send/getpeer %x\n", rp.id)
			}
		default:
			panic(fmt.Sprintf("unsupported operation: send %s", m.Op))
		}
	}
}

func rnd(dats map[uint64]map[uint64]Dat) *Dat {
	if len(dats) == 0 {
		return nil
	}
	rshardpos := mrand.Uint64() % (uint64(len(dats)) + 1)
	var cshardpos uint64
	for _, shard := range dats {
		if cshardpos == rshardpos {
			rdattop := uint64(len(shard))
			rdatpos := mrand.Uint64() % (rdattop + 1)
			var cdatpos uint64
			for _, dat := range shard {
				if cdatpos == rdatpos {
					return &dat
				}
				cdatpos++
			}
		}
		cshardpos++
	}
	return nil
}

func store(dats map[uint64]map[uint64]Dat, d *Dat, h hash.Hash64) (bool, error) {
	shardi, dati, err := workid(h, d.W)
	if err != nil {
		return false, err
	}
	shard, ok := dats[shardi]
	if !ok {
		dats[shardi] = make(map[uint64]Dat)
		dats[shardi][dati] = *d
		return true, nil
	} else {
		_, ok := shard[dati]
		if !ok {
			shard[dati] = *d
			return true, nil
		}
		return false, nil
	}
}

func lstn(c *net.UDPConn, epoch time.Duration, fcap uint, test bool, log chan<- []byte) <-chan *pkt {
	pkts := make(chan *pkt, 100)
	go func() {
		bpool := sync.Pool{New: func() any { return make([]byte, BUF) }}
		mpool := sync.Pool{New: func() any { return &dave.M{} }}
		fh := murmur3.New64()
		ch, err := blake2b.New256(nil)
		if err != nil {
			panic(fmt.Sprintf("failed to init hash: %s", err))
		}
		f := ckoo.NewFilter(fcap)
		rtick := time.NewTicker(epoch)
		defer c.Close()
		for {
			select {
			case <-rtick.C:
				f.Reset()
				lg(log, "/lstn/filter_reset\n")
			default:
				p := rdpkt(c, fh, f, ch, &bpool, &mpool, test, log)
				if p != nil {
					pkts <- p
				}
			}
		}
	}()
	return pkts
}

func rdpkt(c *net.UDPConn, fh hash.Hash, f *ckoo.Filter, ch hash.Hash, bpool, mpool *sync.Pool, test bool, log chan<- []byte) *pkt {
	buf := bpool.Get().([]byte)
	defer bpool.Put(buf) //lint:ignore SA6002 slice is already a reference
	n, raddr, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		panic(err)
	}
	m := mpool.Get().(*dave.M)
	defer mpool.Put(m)
	err = proto.Unmarshal(buf[:n], m)
	if err != nil {
		lg(log, "/lstn/rdpkt/drop unmarshal err\n")
		return nil
	}
	fh.Reset()
	op := make([]byte, 2)
	binary.LittleEndian.PutUint16(op, uint16(m.Op.Number()))
	fh.Write(op)
	addr := raddr.Addr().As16()
	fh.Write(addr[:])
	if test {
		port := make([]byte, 2)
		binary.LittleEndian.PutUint16(port, raddr.Port())
		fh.Write(port)
	}
	sum := fh.Sum(nil)
	if f.Lookup(sum) {
		lg(log, "/lstn/rdpkt/drop/filter %s %x\n", m.Op, m.W)
		return nil
	}
	f.Insert(sum)
	if m.Op == dave.Op_PEER && len(m.Pds) > GETNPEER {
		lg(log, "/lstn/rdpkt/drop/npeer too many peers\n")
		return nil
	} else if m.Op == dave.Op_DAT && check(ch, m.V, m.T, m.S, m.W) < 1 {
		lg(log, "/lstn/rdpkt/drop/workcheck failed\n")
		return nil
	}
	cpy := &dave.M{Op: m.Op, Pds: make([]*dave.Pd, len(m.Pds)), V: m.V, T: m.T, S: m.S, W: m.W}
	for i, pd := range m.Pds {
		cpy.Pds[i] = &dave.Pd{Ip: pd.Ip, Port: pd.Port}
	}
	return &pkt{cpy, raddr}
}

func rndpeers(prs map[uint64]*peer, excl map[uint64]*peer, lim int, match func(p, legend *peer) bool) []*peer {
	candidates := make([]*peer, 0, len(prs))
	for k, p := range prs {
		_, exclude := excl[k]
		if !exclude && match(p, legend(prs)) {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) <= lim {
		return candidates
	}
	ans := make([]*peer, lim)
	for i := 0; i < lim; i++ {
		r := i + mrand.Intn(len(candidates)-i)
		ans[i] = candidates[r]
	}
	return ans
}

func legend(prs map[uint64]*peer) (legend *peer) {
	for _, p := range prs {
		if legend == nil || p.trust > legend.trust {
			legend = p
		}
	}
	return legend
}

func available(k *peer, epoch time.Duration) bool {
	return time.Since(k.seen) < epoch*PING && (time.Since(k.added) > epoch*DELAY || k.edge)
}

func dotrust(k *peer, legend *peer) bool {
	return mrand.Intn(PROBE) == 1 || k.trust >= mrand.Float64()*legend.trust
}

func addrfrom(pd *dave.Pd) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(pd.Ip)), uint16(pd.Port))
}

func pdfrom(addrport netip.AddrPort) *dave.Pd {
	ip := addrport.Addr().As16()
	return &dave.Pd{Ip: ip[:], Port: uint32(addrport.Port())}
}

func pdid(h hash.Hash64, pd *dave.Pd) uint64 {
	port := make([]byte, 2)
	binary.LittleEndian.PutUint16(port, uint16(pd.Port))
	h.Reset()
	h.Write(port)
	h.Write(pd.Ip)
	return h.Sum64()
}

func workid(h hash.Hash64, v []byte) (shardi uint64, dati uint64, err error) {
	if len(v) != 32 {
		return 0, 0, errors.New("value is not of length 32 bytes")
	}
	h.Reset()
	h.Write(v[:16])
	shardi = h.Sum64()
	h.Reset()
	h.Write(v[16:])
	dati = h.Sum64()
	return
}

func check(h hash.Hash, val, tim, salt, work []byte) int {
	if len(tim) != 8 || Btt(tim).After(time.Now()) {
		return -2
	}
	h.Reset()
	h.Write(val)
	h.Write(tim)
	load := h.Sum(nil)
	h.Reset()
	h.Write(salt)
	h.Write(load)
	if !bytes.Equal(h.Sum(nil), work) {
		return -1
	}
	return nzerobit(work)
}

func nzerobit(key []byte) int {
	count := 0
	for _, b := range key {
		count += zeroTable[b]
		if b != 0 {
			return count
		}
	}
	return count
}

func wraddr(c *net.UDPConn, payload []byte, addr netip.AddrPort, log chan<- []byte) {
	_, err := c.WriteToUDPAddrPort(payload, addr)
	if err != nil {
		lg(log, "/wraddr %s\n", err)
	}
}

func marshal(m protoreflect.ProtoMessage) []byte {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func lg(ch chan<- []byte, msg string, args ...any) {
	select {
	case ch <- []byte(fmt.Sprintf(msg, args...)):
	default:
	}
}
