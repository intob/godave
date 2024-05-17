package godave

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	mrand "math/rand"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/intob/godave/dave"
	ckoo "github.com/panmari/cuckoofilter"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	MTU      = 1500   // Max packet size, 1500 is typical for home WiFi, preventing packet fragmentation.
	FANOUT   = 2      // Number of peers randomly selected when selecting more than one.
	PROBE    = 8      // Inverse of probability that an untrusted peer is randomly selected.
	GETNPEER = 2      // Limit of peers in a PEER message. Prevents Eclipse attack.
	DELAY    = 5039   // Epochs until new peers may be randomly selected. Prevents Sybil attack.
	PING     = 14197  // Epochs until silent peers are pinged with a GETPEER message.
	DROP     = 131071 // Epochs until silent peers are dropped from the peer table.
	SEED     = 3      // Epochs between sending one random dat to one random peer, excluding edges.
	PUSH     = 127    // Epcohs between sending the newest dat to one random peer, excluding edges.
	EDGE     = 3889   // Epochs between sending one random dat to one random edge peer.
)

var debruijn64 = [64]byte{ // Precomputed De Bruijn sequence to efficiently count leading zero bits
	0, 1, 2, 53, 3, 7, 54, 27, 4, 38, 41, 8, 34, 55, 48, 28,
	62, 5, 39, 46, 44, 42, 22, 9, 24, 35, 59, 56, 49, 18, 29, 11,
	63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
	51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12,
}

type Dave struct {
	Recv  <-chan *dave.M
	send  chan<- *dave.M
	epoch time.Duration
}

type Cfg struct {
	LstnAddr          *net.UDPAddr     // Listening address:port
	Edges             []netip.AddrPort // Bootstrap peers
	Epoch             time.Duration    // Base cycle, lower runs faster, using more bandwidth
	DatCap, FilterCap uint             // Dat map & cuckoo filter capacity
	Pull              uint64           // Interval between pulling a random dat from a random peer (optional anonymity)
	Prune             uint64           // Interval between refreshing dat & peer maps
	Log               chan<- []byte    // Log messages
}

type Dat struct {
	V, S, W []byte // Val, Salt, Work
	Ti      time.Time
}

type peer struct {
	pd          *dave.Pd // Peer descriptor
	fp          uint64   // Address hash
	added, seen time.Time
	edge        bool    // Set for edge (bootstrap) peers
	trust       float64 // Accumulated mass of new dats from peer
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
	lg(cfg.Log, "/newdave/listening %s hash4(port):%x\n", c.LocalAddr(), hash4(uint16(cfg.LstnAddr.Port)))
	edges := make(map[string]*peer)
	for _, e := range cfg.Edges {
		pd := pdfrom(e)
		edges[pdstr(pd)] = &peer{pd: pd, fp: pdfp(fnv.New64a(), pd), added: time.Now(), seen: time.Now(), edge: true}
	}
	pktout := make(chan *pkt, 1)
	go func(c *net.UDPConn, pkts <-chan *pkt) {
		for pkt := range pkts {
			wraddr(c, marshal(pkt.msg), pkt.ip)
		}
	}(c, pktout)
	send := make(chan *dave.M)
	recv := make(chan *dave.M, 1)
	go d(pktout, edges, cfg.Epoch, int(cfg.DatCap), cfg.Prune, cfg.Pull, lstn(c, cfg.Epoch, cfg.FilterCap, cfg.Log), send, recv, cfg.Log)
	for _, e := range cfg.Edges {
		wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), e)
	}
	return &Dave{Recv: recv, send: send, epoch: cfg.Epoch}, nil
}

func (d *Dave) Get(work []byte, timeout, retry time.Duration) <-chan *Dat {
	c := make(chan *Dat, 1)
	go func() {
		d.send <- &dave.M{Op: dave.Op_GETPEER}
		d.send <- &dave.M{Op: dave.Op_GET, W: work}
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
				d.send <- &dave.M{Op: dave.Op_GETPEER}
				d.send <- &dave.M{Op: dave.Op_GET, W: work}
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
					d.send <- &dave.M{Op: dave.Op_GETPEER}
				}
				d.send <- &dave.M{Op: dave.Op_DAT, V: dat.V, S: dat.S, W: dat.W, T: Ttb(dat.Ti)}
				r++
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

func d(pktout chan<- *pkt, prs map[string]*peer, epoch time.Duration, dcap int, prune, pull uint64, pktin <-chan *pkt, appsend <-chan *dave.M, apprecv chan<- *dave.M, log chan<- []byte) {
	nedge := len(prs)
	dats := make(map[uint64]map[uint64]Dat)
	var nepoch, npeer uint64
	var newest *Dat
	etick := time.NewTicker(epoch)
	h := fnv.New64a()
	for {
		select {
		case <-etick.C:
			nepoch++
			if nepoch%prune == 0 { // MEMORY MANAGEMENT
				memstat := &runtime.MemStats{}
				runtime.ReadMemStats(memstat)
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
					if _, ok := newdats[hdat.shard]; !ok {
						newdats[hdat.shard] = make(map[uint64]Dat)
					}
					newdats[hdat.shard][hdat.key] = hdat.dat
				}
				dats = newdats
				newpeers := make(map[string]*peer)
				for k, p := range prs {
					newpeers[k] = p
				}
				prs = newpeers
				npeer = uint64(len(newpeers))
				lg(log, "/d/prune/keep %d peers, %d dat shards, %.2fGB mem alloc\n", len(newpeers), len(newdats), float64(memstat.Alloc)/(1<<30))
			}
			if newest != nil && npeer > 0 && nepoch%(max(PUSH, PUSH/npeer)) == 0 { // SEND NEWEST DAT TO RANDOM PEER, EXCLUDING EDGES
				for _, rp := range rndpeers(prs, nil, 1, func(p *peer, l *peer) bool { return !p.edge && available(p, epoch) && dotrust(p, l) }) {
					pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: newest.V, T: Ttb(newest.Ti), S: newest.S, W: newest.W}, addrfrom(rp.pd)}
					lg(log, "/d/push %x %x\n", rp.fp, newest.W)
				}
			}
			if npeer > 0 && nepoch%(max(SEED, SEED/npeer)) == 0 { // SEND RANDOM DAT TO RANDOM PEER, EXCLUDING EDGES
				for _, rp := range rndpeers(prs, nil, 1, func(p *peer, l *peer) bool { return !p.edge && available(p, epoch) && dotrust(p, l) }) {
					rd := rnd(dats)
					if rd != nil {
						pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: rd.V, T: Ttb(rd.Ti), S: rd.S, W: rd.W}, addrfrom(rp.pd)}
						lg(log, "/d/seed %x %x\n", rp.fp, rd.W)
					}
				}
			}
			if npeer > 0 && nepoch%(EDGE*npeer) == 0 { // SEND RANDOM DAT TO RANDOM EDGE PEER
				rd := rnd(dats)
				if rd != nil {
					for _, redge := range rndpeers(prs, nil, 1, func(p *peer, l *peer) bool { return p.edge && available(p, epoch) }) {
						pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: rd.V, T: Ttb(rd.Ti), S: rd.S, W: rd.W}, addrfrom(redge.pd)}
						lg(log, "/d/seededge %x %x\n", redge.fp, rd.W)
					}
				}
			}
			if pull > 0 && npeer > 0 && nepoch%(max(pull, pull/npeer)) == 0 { // PULL RANDOM DAT FROM RANDOM PEER, EXCLUDING EDGES
				rd := rnd(dats)
				if rd != nil {
					for _, rp := range rndpeers(prs, nil, 1, func(p *peer, l *peer) bool { return !p.edge && available(p, epoch) }) {
						pktout <- &pkt{&dave.M{Op: dave.Op_GET, W: rd.W}, addrfrom(rp.pd)}
						lg(log, "/d/pull %x %x\n", rp.fp, rd.W)
					}
				}
			}
			if nepoch%PING == 0 { // PING AND DROP
				for pid, p := range prs {
					if !p.edge && time.Since(p.seen) > epoch*DROP { // DROP UNRESPONSIVE PEER
						delete(prs, pid)
						lg(log, "/d/ping/delete %x\n", p.fp)
					} else if time.Since(p.seen) > epoch*PING { // SEND PING
						pktout <- &pkt{&dave.M{Op: dave.Op_GETPEER}, addrfrom(p.pd)}
						lg(log, "/d/ping/ping %x\n", p.fp)
					}
				}
			}
		case m := <-appsend: // SEND PACKET FOR APP
			if m != nil {
				switch m.Op {
				case dave.Op_DAT:
					store(dats, &Dat{m.V, m.S, m.W, Btt(m.T)}, h)
					go func(rps []*peer) {
						for _, rp := range rps {
							pktout <- &pkt{m, addrfrom(rp.pd)}
							lg(log, "/d/send/dat %x %x\n", rp.fp, m.W)
						}
					}(rndpeers(prs, nil, FANOUT, func(p *peer, l *peer) bool { return (!p.edge || int(npeer) < 2*nedge) && available(p, epoch) }))
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
								lg(log, "/d/send/get/found_locally %x\n", dat.W)
							}
						}
						if !found {
							go func(rps []*peer) {
								for _, rp := range rps {
									pktout <- &pkt{&dave.M{Op: dave.Op_GET, W: m.W}, addrfrom(rp.pd)}
									lg(log, "/d/send/get/sent %x %x\n", rp.fp, m.W)
								}
							}(rndpeers(prs, nil, FANOUT, func(p *peer, l *peer) bool { return available(p, epoch) }))
						}
					}
				case dave.Op_GETPEER:
					for _, rp := range rndpeers(prs, nil, 1, func(p *peer, l *peer) bool { return available(p, epoch) }) {
						pktout <- &pkt{m, addrfrom(rp.pd)}
						lg(log, "/d/send/getpeer %x\n", rp.fp)
					}
				default:
					panic("unsupported operation")
				}
			}
		case pk := <-pktin: // HANDLE INCOMING PACKET
			pkpd := pdfrom(pk.ip)
			pkpid := pdstr(pkpd)
			p, ok := prs[pkpid]
			if !ok {
				p = &peer{pd: pkpd, fp: pdfp(h, pkpd), added: time.Now()}
				prs[pkpid] = p
				lg(log, "/d/h/peer/add %x\n", p.fp)
			}
			p.seen = time.Now()
			m := pk.msg
			select {
			case apprecv <- m:
			default:
			}
			switch m.Op {
			case dave.Op_PEER: // STORE PEERS
				for _, pd := range m.Pds {
					pid := pdstr(pd)
					_, ok := prs[pid]
					if !ok {
						p := &peer{pd: pd, fp: pdfp(h, pd), added: time.Now(), seen: time.Now()}
						prs[pid] = p
						lg(log, "/d/h/peer/add_from_gossip %x\n", p.fp)
					}
				}
			case dave.Op_GETPEER: // GIVE PEERS
				rpeers := rndpeers(prs, map[string]*peer{pkpid: p}, GETNPEER, func(p *peer, l *peer) bool { return available(p, epoch) })
				pds := make([]*dave.Pd, len(rpeers))
				for i, rp := range rpeers {
					pds[i] = rp.pd
				}
				pktout <- &pkt{&dave.M{Op: dave.Op_PEER, Pds: pds}, pk.ip}
				lg(log, "/d/h/peer/reply %x\n", p.fp)
			case dave.Op_DAT: // FORWARD ON RECV CHAN AND STORE
				dat := &Dat{m.V, m.S, m.W, Btt(m.T)}
				novel, _ := store(dats, dat, h)
				label := "known"
				if novel {
					newest = dat
					label = "novel"
					p.trust += Mass(m.W, Btt(m.T))
				}
				lg(log, "/d/h/dat/%s %x %x %f\n", label, m.W, p.fp, p.trust)
			case dave.Op_GET: // REPLY WITH DAT
				shardi, dati, err := workid(h, m.W)
				if err == nil {
					shard, ok := dats[shardi]
					if ok { // GOT SHARD
						dat, ok := shard[dati]
						if ok { // GOT DAT
							pktout <- &pkt{&dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}, pk.ip}
							lg(log, "/d/h/get/reply %x\n", dat.W)
						}
					}
				}
			}
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

func lstn(c *net.UDPConn, epoch time.Duration, fcap uint, log chan<- []byte) <-chan *pkt {
	pkts := make(chan *pkt, 100)
	go func() {
		bufpool := sync.Pool{New: func() any { return make([]byte, MTU) }}
		mpool := sync.Pool{New: func() any { return &dave.M{} }}
		f := ckoo.NewFilter(fcap)
		rtick := time.NewTicker(epoch)
		defer c.Close()
		for {
			select {
			case <-rtick.C:
				f.Reset()
				lg(log, "/lstn/filter_reset\n")
			default:
				p := rdpkt(c, f, &bufpool, &mpool, log)
				if p != nil {
					pkts <- p
				}
			}
		}
	}()
	return pkts
}

func rdpkt(c *net.UDPConn, f *ckoo.Filter, bufpool, mpool *sync.Pool, log chan<- []byte) *pkt {
	buf := bufpool.Get().([]byte)
	defer bufpool.Put(buf) //lint:ignore SA6002 slice is already a reference
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
	h := fnv.New64a()
	op := make([]byte, 8)
	binary.LittleEndian.PutUint32(op, uint32(m.Op.Number()))
	h.Write(op)
	h.Write([]byte{hash4(raddr.Port())})
	addr := raddr.Addr().As16()
	h.Write(addr[:])
	sum := h.Sum(nil)
	if f.Lookup(sum) {
		lg(log, "/lstn/rdpkt/drop/filter %s %x\n", m.Op, sum)
		return nil
	}
	f.Insert(sum)
	if m.Op == dave.Op_PEER && len(m.Pds) > GETNPEER {
		lg(log, "/lstn/rdpkt/drop/npeer too many peers\n")
		return nil
	} else if m.Op == dave.Op_DAT && Check(m.V, m.T, m.S, m.W) < 1 {
		lg(log, "/lstn/rdpkt/drop/workcheck failed\n")
		return nil
	}
	cpy := &dave.M{Op: m.Op, Pds: make([]*dave.Pd, len(m.Pds)), V: m.V, T: m.T, S: m.S, W: m.W}
	for i, pd := range m.Pds {
		cpy.Pds[i] = &dave.Pd{Ip: pd.Ip, Port: pd.Port}
	}
	return &pkt{cpy, raddr}
}

func rndpeers(prs map[string]*peer, excl map[string]*peer, lim int, match func(p, legend *peer) bool) []*peer {
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

func legend(prs map[string]*peer) (legend *peer) {
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

func pdstr(p *dave.Pd) string {
	return fmt.Sprintf("%x:%x", p.Ip, []byte{hash4(uint16(p.Port))})
}

func pdfp(h hash.Hash64, pd *dave.Pd) uint64 {
	port := make([]byte, 8)
	binary.LittleEndian.PutUint32(port, pd.Port)
	h.Reset()
	h.Write(port)
	h.Write(pd.Ip)
	return h.Sum64()
}

func hash4(port uint16) byte {
	return byte((port * 41) >> 12)
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

func nzerobit(key []byte) int {
	for i, b := range key {
		if b != 0 {
			return i*8 + int(debruijn64[uint64(b&-b)*0x03f79d71b4ca8b09>>58])
		}
	}
	return len(key) * 8
}

func wraddr(c *net.UDPConn, payload []byte, addr netip.AddrPort) {
	_, err := c.WriteToUDPAddrPort(payload, addr)
	if err != nil {
		panic(err)
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
