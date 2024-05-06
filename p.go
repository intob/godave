// Copyright 2024 Joey Innes <joey@inneslabs.uk>
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
	"sync"
	"time"

	"github.com/intob/godave/dave"
	ckoo "github.com/panmari/cuckoofilter"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	MTU       = 1500
	FILTERCAP = 100000
	FANOUT    = 3
	ROUNDS    = 9
	NPEER     = 2
	PROBE     = 16
	EPOCH     = 65537 * time.Nanosecond
	DELAY     = 28657
	PING      = 8191
	DROP      = 524287
	PRUNE     = 60649
	SEED      = 3
	EDGE      = 131071
	PULL      = 32993
)

type Dave struct {
	Recv <-chan *dave.M
	send chan<- *dave.M
}

type Cfg struct {
	Listen *net.UDPAddr
	Edges  []netip.AddrPort
	DatCap uint
	Log    chan<- string
}

type Dat struct {
	V, S, W []byte // Val, Salt, Work
	Ti      time.Time
}

type peer struct {
	pd                *dave.Pd
	added, seen, ping time.Time
	edge              bool
	trust             float64
}

type pkt struct {
	msg *dave.M
	ip  netip.AddrPort
}

func NewDave(cfg *Cfg) (*Dave, error) {
	if cfg.DatCap == 0 {
		return nil, errors.New("Cfg.DatCap must not be 0")
	}
	lg(cfg.Log, "/newdave/creating %+v\n", *cfg)
	c, err := net.ListenUDP("udp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	lg(cfg.Log, "/newdave/listening %s\n", c.LocalAddr())
	edges := make(map[string]*peer)
	for _, e := range cfg.Edges {
		pd := pdfrom(e)
		edges[pdstr(pd)] = &peer{pd: pd, added: time.Now(), seen: time.Now(), edge: true}
	}
	send := make(chan *dave.M)
	recv := make(chan *dave.M, 1)
	go d(c, edges, int(cfg.DatCap), lstn(c, cfg.Log), send, recv, cfg.Log)
	for _, e := range cfg.Edges {
		wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), e)
	}
	return &Dave{Recv: recv, send: send}, nil
}

func (d *Dave) Get(work []byte, timeout time.Duration, pass chan<- *dave.M) <-chan *Dat {
	c := make(chan *Dat, 1)
	go func() {
		defer close(c)
		sendy := time.NewTicker(EPOCH * SEED)
		to := time.NewTimer(timeout)
		for {
			select {
			case <-to.C:
				return
			case m := <-d.Recv:
				select {
				case pass <- m:
				default:
				}
				if bytes.Equal(m.W, work) {
					c <- &Dat{m.V, m.S, m.W, Btt(m.T)}
					return
				}
			case <-sendy.C:
				d.send <- &dave.M{Op: dave.Op_GET, W: work}
			}
		}
	}()
	return c
}

func (d *Dave) Set(dat Dat) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		for i := 0; i < ROUNDS; i++ {
			d.send <- &dave.M{Op: dave.Op_DAT, V: dat.V, S: dat.S, W: dat.W, T: Ttb(dat.Ti)}
		}
		done <- struct{}{}
		close(done)
	}()
	return done
}

func Work(val, tim []byte, d int) (work, salt []byte) {
	if d < 0 || d > 32 {
		return nil, nil
	}
	zeros := make([]byte, d)
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
		h.Write(load)
		h.Write(salt)
		work = h.Sum(nil)
		if bytes.HasPrefix(work, zeros) {
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
	h.Write(load)
	h.Write(salt)
	if !bytes.Equal(h.Sum(nil), work) {
		return -1
	}
	return nzero(work)
}

func Mass(work []byte, t time.Time) float64 {
	return float64(nzero(work)) * (1 / float64(time.Since(t).Milliseconds()))
}

func Ttb(t time.Time) []byte {
	milli := t.UnixNano() / 1000000
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(milli))
	return bytes
}

func Btt(b []byte) time.Time {
	if len(b) != 8 {
		return time.Time{}
	}
	milli := int64(binary.LittleEndian.Uint64(b))
	return time.Unix(0, milli*1000000)
}

func Pdfp(h hash.Hash, pd *dave.Pd) []byte {
	port := make([]byte, 8)
	binary.LittleEndian.PutUint32(port, pd.Port)
	h.Reset()
	h.Write(port)
	h.Write(pd.Ip)
	return h.Sum(nil)
}

func d(c *net.UDPConn, prs map[string]*peer, dcap int, pch <-chan *pkt, send <-chan *dave.M, recv chan<- *dave.M, log chan<- string) {
	dats := make(map[uint64]map[uint64]Dat)
	var nepoch, npeer uint64
	et := time.NewTicker(EPOCH)
	pdhfn := fnv.New64a()
	for {
		select {
		case <-et.C:
			nepoch++
			if nepoch%PRUNE == 0 { // PRUNING MEMORY, KEEP <=CAP MASSIVE DATS
				memstat := &runtime.MemStats{}
				runtime.ReadMemStats(memstat)
				newdats := make(map[uint64]map[uint64]Dat)
				var minmass float64
				var ld, count uint64
				for shardid, shard := range dats {
					for key, dat := range shard {
						count++
						mass := Mass(dat.W, dat.Ti)
						if len(shard) >= dcap-1 { // BEYOND CAP, REPLACE BY MASS
							if mass > minmass {
								delete(newdats[shardid], ld)
								lg(log, "/d/prune/delete %f\n", minmass)
								newdats[shardid][key] = dat
								ld = key
								minmass = mass
							}
						} else {
							if mass < minmass {
								minmass = mass
							}
							_, ok := newdats[shardid]
							if !ok {
								newdats[shardid] = make(map[uint64]Dat)
							}
							newdats[shardid][key] = dat
						}
					}
				}
				dats = newdats
				newpeers := make(map[string]*peer)
				for k, p := range prs {
					newpeers[k] = p
				}
				prs = newpeers
				npeer = uint64(len(newpeers))
				lg(log, "/d/prune/keep %d peers, %d dats across %d shards, %.2fMB mem alloc\n", len(newpeers), count, len(newdats), float32(memstat.Alloc)/1024/1024)
			}
			if npeer > 0 && nepoch%(max(1, SEED/npeer)) == 0 { // RANDOM DAT TO RANDOM PEER, EXCLUDING EDGE
				rd := rnd(dats)
				if rd != nil {
					for _, rp := range randpds(prs, nil, 1, func(p *peer, l *peer) bool { return !p.edge && available(p) && dotrust(p, l) }) {
						wraddr(c, marshal(&dave.M{Op: dave.Op_DAT, V: rd.V, T: Ttb(rd.Ti), S: rd.S, W: rd.W}), addrfrom(rp))
						lg(log, "/d/seed %x %x\n", Pdfp(pdhfn, rp), rd.W)
					}
				}
			}
			if npeer > 0 && nepoch%(EDGE*npeer) == 0 { // RANDOM DAT TO RANDOM EDGE PEER
				rd := rnd(dats)
				if rd != nil {
					for _, rboot := range randpds(prs, nil, 1, func(p *peer, l *peer) bool { return p.edge && available(p) }) {
						wraddr(c, marshal(&dave.M{Op: dave.Op_DAT, V: rd.V, T: Ttb(rd.Ti), S: rd.S, W: rd.W}), addrfrom(rboot))
						lg(log, "/d/seedboot %x %x\n", Pdfp(pdhfn, rboot), rd.W)
					}
				}
			}
			if npeer > 0 && nepoch%(max(1, PULL/npeer)) == 0 { // REQUEST RANDOM DAT FROM RANDOM PEER, EXCLUDING EDGE
				rd := rnd(dats)
				if rd != nil {
					for _, rp := range randpds(prs, nil, 1, func(p *peer, l *peer) bool { return !p.edge && available(p) }) {
						wraddr(c, marshal(&dave.M{Op: dave.Op_GET, W: rd.W}), addrfrom(rp))
						lg(log, "/d/pull %x %x\n", Pdfp(pdhfn, rp), rd.W)
					}
				}
			}
			if nepoch%PING == 0 { // PING AND DROP
				for pid, p := range prs {
					if !p.edge && time.Since(p.seen) > EPOCH*DROP { // DROP UNRESPONSIVE PEER
						delete(prs, pid)
						lg(log, "/d/ping/delete %x\n", Pdfp(pdhfn, p.pd))
					} else if time.Since(p.seen) > EPOCH*PING && time.Since(p.ping) > EPOCH*PING { // SEND PING
						wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), addrfrom(p.pd))
						p.ping = time.Now()
						lg(log, "/d/ping/ping %x\n", Pdfp(pdhfn, p.pd))
					}
				}
			}
		case m := <-send: // SEND PACKET
			if m != nil {
				switch m.Op {
				case dave.Op_DAT:
					store(dats, &Dat{m.V, m.S, m.W, Btt(m.T)})
					go func(rpds []*dave.Pd) {
						for _, rp := range rpds {
							wraddr(c, marshal(m), addrfrom(rp))
							lg(log, "/d/send/dat %x %x\n", Pdfp(pdhfn, rp), m.W)
						}
					}(randpds(prs, nil, FANOUT, func(p *peer, l *peer) bool { return !p.edge && available(p) }))
				case dave.Op_GET:
					shardi, dati, err := id(m.W)
					if err == nil {
						var found bool
						shard, ok := dats[shardi]
						if ok {
							dat, ok := shard[dati]
							if ok {
								found = true
								recv <- &dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}
								lg(log, "/d/send/get/found_locally %x\n", dat.W)
							}
						}
						if !found {
							go func(rpds []*dave.Pd) {
								for _, rp := range rpds {
									wraddr(c, marshal(&dave.M{Op: dave.Op_GET, W: m.W}), addrfrom(rp))
									lg(log, "/d/send/get/sent %x %x\n", Pdfp(pdhfn, rp), m.W)
								}
							}(randpds(prs, nil, FANOUT, func(p *peer, l *peer) bool { return !p.edge && available(p) }))
						}
					}
				default:
					panic("unsupported operation")
				}
			}
		case pkt := <-pch: // HANDLE INCOMING PACKET
			pktpd := pdfrom(pkt.ip)
			pktpid := pdstr(pktpd)
			p, ok := prs[pktpid]
			if !ok {
				p = &peer{pd: pktpd, added: time.Now()}
				prs[pktpid] = p
				lg(log, "/d/h/peer/add %x\n", Pdfp(pdhfn, pktpd))
			}
			p.seen = time.Now()
			m := pkt.msg
			switch m.Op {
			case dave.Op_PEER: // STORE PEERS
				for _, pd := range m.Pds {
					pid := pdstr(pd)
					_, ok := prs[pid]
					if !ok {
						prs[pid] = &peer{pd: pd, added: time.Now(), seen: time.Now()}
						lg(log, "/d/h/peer/add_from_gossip %x\n", Pdfp(pdhfn, pd))
					}
				}
			case dave.Op_GETPEER: // GIVE PEERS
				randpds := randpds(prs, map[string]*peer{pktpid: p}, NPEER, func(p *peer, l *peer) bool { return available(p) })
				wraddr(c, marshal(&dave.M{Op: dave.Op_PEER, Pds: randpds}), pkt.ip)
				lg(log, "/d/h/peer/reply %x\n", Pdfp(pdhfn, pktpd))
			case dave.Op_DAT: // FORWARD ON RECV CHAN AND STORE
				select {
				case recv <- pkt.msg:
				default:
				}
				novel, _ := store(dats, &Dat{m.V, m.S, m.W, Btt(m.T)})
				label := "known"
				if novel {
					label = "novel"
					p.trust += Mass(m.W, Btt(m.T))
				}
				lg(log, "/d/h/dat/%s %x %x %f\n", label, m.W, Pdfp(pdhfn, p.pd), p.trust)
			case dave.Op_GET: // REPLY WITH DAT
				shardi, dati, err := id(m.W)
				if err == nil {
					shard, ok := dats[shardi]
					if ok { // GOT SHARD
						dat, ok := shard[dati]
						if ok { // GOT DAT
							wraddr(c, marshal(&dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}), pkt.ip)
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
	rshardtop := uint64(len(dats))
	rshardpos := mrand.Uint64() % (rshardtop + 1)
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

func store(dats map[uint64]map[uint64]Dat, d *Dat) (bool, error) {
	shardi, dati, err := id(d.W)
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

func lstn(c *net.UDPConn, log chan<- string) <-chan *pkt {
	pkts := make(chan *pkt, 1)
	go func() {
		bufpool := sync.Pool{New: func() any { return make([]byte, MTU) }}
		mpool := sync.Pool{New: func() any { return &dave.M{} }}
		f := ckoo.NewFilter(FILTERCAP)
		rtick := time.NewTicker(EPOCH)
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

func rdpkt(c *net.UDPConn, f *ckoo.Filter, bufpool, mpool *sync.Pool, log chan<- string) *pkt {
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
	h := fnv.New128a()
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
	if m.Op == dave.Op_PEER && len(m.Pds) > NPEER {
		lg(log, "/lstn/rdpkt/drop/npeer too many peers\n")
		return nil
	} else if m.Op == dave.Op_DAT && Check(m.V, m.T, m.S, m.W) < 1 { // ZERO WORK WOULD HAVE ZERO MASS
		lg(log, "/lstn/rdpkt/drop/workcheck invalid\n")
		return nil
	}
	cpy := &dave.M{Op: m.Op, Pds: make([]*dave.Pd, len(m.Pds)), V: m.V, T: m.T, S: m.S, W: m.W}
	for i, pd := range m.Pds {
		cpy.Pds[i] = &dave.Pd{Ip: pd.Ip, Port: pd.Port}
	}
	return &pkt{cpy, raddr}
}

func randpds(prs map[string]*peer, excl map[string]*peer, lim int, match func(p, legend *peer) bool) []*dave.Pd {
	candidates := make([]*dave.Pd, 0, len(prs))
	for k, p := range prs {
		_, exclude := excl[k]
		if !exclude && match(p, legend(prs)) {
			candidates = append(candidates, p.pd)
		}
	}
	if len(candidates) <= lim {
		return candidates
	}
	ans := make([]*dave.Pd, lim)
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

func available(k *peer) bool {
	return time.Since(k.seen) < EPOCH*PING && (time.Since(k.added) > EPOCH*DELAY || k.edge)
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

func hash4(port uint16) byte {
	return byte((port * 41) >> 12)
}

func id(v []byte) (shardi uint64, dati uint64, err error) {
	if len(v) != 32 {
		return 0, 0, errors.New("value is not of length 32 bytes")
	}
	h := fnv.New64a()
	h.Write(v[:16])
	shardi = h.Sum64()
	h.Reset()
	h.Write(v[16:])
	dati = h.Sum64()
	return
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

func nzero(key []byte) int {
	for i, j := range key {
		if j != 0 {
			return i
		}
	}
	return len(key)
}

func lg(ch chan<- string, msg string, args ...any) {
	select {
	case ch <- fmt.Sprintf(msg, args...):
	default:
	}
}
