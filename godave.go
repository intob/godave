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
	MTU    = 1500
	FANOUT = 64
	NPEER  = 2
	PROBE  = 1000
	EPOCH  = 65537 * time.Nanosecond
	DELAY  = 1993
	PING   = 5039
	DROP   = 106033
	PRUNE  = 32768
	SEED   = 2
	PULL   = 53
)

type Dave struct {
	Recv <-chan *dave.M
	send chan<- *dave.M
}

type Cfg struct {
	Listen            *net.UDPAddr
	Bootstraps        []netip.AddrPort
	DatCap, FilterCap uint
	Log               chan<- string
}

type Dat struct {
	V, S, W []byte // Val, Salt, Work
	Ti      time.Time
}

type peer struct {
	pd                *dave.Pd
	added, seen, ping time.Time
	bootstrap         bool
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
	if cfg.FilterCap == 0 {
		return nil, errors.New("Cfg.FilterCap must not be 0")
	}
	lg(cfg.Log, "creating dave: %+v\n", *cfg)
	c, err := net.ListenUDP("udp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	lg(cfg.Log, "dave listening %s\n", c.LocalAddr())
	boot := make(map[string]*peer)
	for _, bap := range cfg.Bootstraps {
		bp := pdfrom(bap)
		boot[pdstr(bp)] = &peer{pd: bp, added: time.Now(), seen: time.Now(), bootstrap: true}
	}
	send := make(chan *dave.M, 1)
	recv := make(chan *dave.M, 1)
	go d(c, boot, int(cfg.DatCap), lstn(c, cfg.FilterCap, cfg.Log), send, recv, cfg.Log)
	for _, bap := range cfg.Bootstraps {
		wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), bap)
	}
	return &Dave{Recv: recv, send: send}, nil
}

func (d *Dave) Get(work []byte, timeout time.Duration) <-chan *Dat {
	c := make(chan *Dat)
	go func() {
		defer close(c)
		to := time.NewTimer(timeout)
		sendy := time.NewTicker(PING)
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
				d.send <- &dave.M{Op: dave.Op_GET, W: work}
			}
		}
	}()
	return c
}

func (d *Dave) Set(dat Dat) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		d.send <- &dave.M{Op: dave.Op_DAT, V: dat.V, S: dat.S, W: dat.W, T: Ttb(dat.Ti)}
		done <- struct{}{}
		close(done)
	}()
	return done
}

func Work(val, ti []byte, d int) (work, salt []byte) {
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
	h.Write(ti)
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

func Check(val, ti, salt, work []byte) int {
	if len(ti) != 8 || Btt(ti).After(time.Now()) {
		return -2
	}
	h, err := blake2b.New256(nil)
	if err != nil {
		return -3
	}
	h.Write(val)
	h.Write(ti)
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
	var nepoch uint64
	et := time.NewTicker(EPOCH)
	pdhfn := fnv.New64a()
	for {
		select {
		case <-et.C:
			nepoch++
			if nepoch%PRUNE == 0 { // PRUNING MEMORY, KEEP <=CAP MASSIVE DATS
				prune(dats, dcap, prs, log)
			}
			if nepoch%SEED == 0 && len(dats) > 0 && len(prs) > 0 { // SEND NEW OR RANDOM DAT TO RANDOM PEER
				select {
				case msend := <-send:
					for _, rp := range randpds(prs, nil, NPEER, usable) {
						wraddr(c, marshal(msend), addrfrom(rp))
						lg(log, "/d/send/sent %x to %x\n", msend.W, Pdfp(pdhfn, rp))
					}
				default:
					rd := rnd(dats)
					if rd != nil {
						for _, rp := range randpds(prs, nil, 1, usable) {
							wraddr(c, marshal(&dave.M{Op: dave.Op_DAT, V: rd.V, T: Ttb(rd.Ti), S: rd.S, W: rd.W}), addrfrom(rp))
							lg(log, "/d/rand/seed sent to %x %x\n", Pdfp(pdhfn, rp), rd.W)
						}
					}
				}
			}
			if nepoch%PULL == 0 { // REQUEST RANDOM DAT FROM RANDOM PEER
				rd := rnd(dats)
				if rd != nil {
					for _, rp := range randpds(prs, nil, 1, usable) {
						wraddr(c, marshal(&dave.M{Op: dave.Op_GET, W: rd.W}), addrfrom(rp))
						lg(log, "/d/rand/pull sent %x to %x\n", Pdfp(pdhfn, rp), rd.W)
					}
				}
			}
			if nepoch%PING == 0 { // ONCE PER PING EPOCHS, RELATIVELY SHORT CYCLE
				for pid, p := range prs {
					if !p.bootstrap && time.Since(p.seen) > EPOCH*DROP { // DROP UNRESPONSIVE PEER
						delete(prs, pid)
						lg(log, "/d/peer/remove %x\n", Pdfp(pdhfn, p.pd))
					} else if time.Since(p.seen) > EPOCH*PING && time.Since(p.ping) > EPOCH*PING { // SEND PING
						wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), addrfrom(p.pd))
						p.ping = time.Now()
						lg(log, "/d/peer/ping sent to %x\n", Pdfp(pdhfn, p.pd))
					}
				}
			}
		case m := <-send: // SEND PACKET
			if m != nil {
				switch m.Op {
				case dave.Op_DAT:
					store(dats, &Dat{m.V, m.S, m.W, Btt(m.T)})
					go func() {
						for _, rp := range randpds(prs, nil, FANOUT, usable) {
							wraddr(c, marshal(m), addrfrom(rp))
							lg(log, "/d/send/dat sent to %x\n", Pdfp(pdhfn, rp))
							time.Sleep(PULL * EPOCH)
						}
					}()
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
								lg(log, "/d/send/get found locally %x\n", dat.W)
							}
						}
						if !found {
							go func() {
								for _, rp := range randpds(prs, nil, FANOUT, usable) {
									wraddr(c, marshal(&dave.M{Op: dave.Op_GET, W: m.W}), addrfrom(rp))
									lg(log, "/d/send/get sent to %x %x\n", Pdfp(pdhfn, rp), m.W)
									time.Sleep(PULL * EPOCH)
								}
							}()
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
				lg(log, "/d/ph/peer/add from packet %x\n", Pdfp(pdhfn, pktpd))
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
						lg(log, "/d/ph/peer/add from gossip %x\n", Pdfp(pdhfn, pd))
					}
				}
			case dave.Op_GETPEER: // GIVE PEERS
				randpds := randpds(prs, map[string]*peer{pktpid: p}, NPEER, usable)
				wraddr(c, marshal(&dave.M{Op: dave.Op_PEER, Pds: randpds}), pkt.ip)
				lg(log, "/d/ph/getpeer/reply with PEER to %x\n", Pdfp(pdhfn, pktpd))
			case dave.Op_DAT: // FORWARD ON RECV CHAN AND STORE
				recv <- pkt.msg
				novel, _ := store(dats, &Dat{m.V, m.S, m.W, Btt(m.T)})
				if novel {
					p.trust += Mass(m.W, Btt(m.T))
				}
				lg(log, "/d/ph/dat/store %x novel: %v from: %x trust: %f\n", m.W, novel, Pdfp(pdhfn, p.pd), p.trust)
			case dave.Op_GET: // REPLY WITH DAT
				shardi, dati, err := id(m.W)
				if err == nil {
					shard, ok := dats[shardi]
					if ok { // GOT SHARD
						dat, ok := shard[dati]
						if ok { // GOT DAT
							wraddr(c, marshal(&dave.M{Op: dave.Op_DAT, V: dat.V, T: Ttb(dat.Ti), S: dat.S, W: dat.W}), pkt.ip)
							lg(log, "/d/ph/get/reply sent %x\n", dat.W)
						}
					}
				}
			}
		}
	}
}

func prune(dats map[uint64]map[uint64]Dat, dcap int, prs map[string]*peer, log chan<- string) {
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
					lg(log, "/d/prune/delete %d with weight %f\n", ld, minmass)
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
	lg(log, "/d/prune/keep %d peers, %d dats across %d shards, %.2fMB mem alloc\n", len(newpeers), count, len(newdats), float32(memstat.Alloc)/1024/1024)
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

func lstn(c *net.UDPConn, fcap uint, log chan<- string) <-chan *pkt {
	pkts := make(chan *pkt, 1)
	go func() {
		bufpool := sync.Pool{New: func() any { return make([]byte, MTU) }}
		mpool := sync.Pool{New: func() any { return &dave.M{} }}
		f := ckoo.NewFilter(fcap)
		rtick := time.NewTicker(EPOCH)
		defer c.Close()
		for {
			select {
			case <-rtick.C:
				f.Reset()
				lg(log, "/lstn/filter/reset\n")
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
		lg(log, "/rdpkt/drop unmarshal err\n")
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
		lg(log, "/rdpkt/drop/filter collision %s %x\n", m.Op, sum)
		return nil
	}
	f.Insert(sum)
	if m.Op == dave.Op_PEER && len(m.Pds) > NPEER {
		lg(log, "/rdpkt/drop/npeer too many peers\n")
		return nil
	} else if m.Op == dave.Op_DAT && Check(m.V, m.T, m.S, m.W) < 0 {
		lg(log, "/rdpkt/drop/workcheck invalid\n")
		return nil
	}
	lg(log, "ok %s", m.Op)
	cpy := &dave.M{Op: m.Op, Pds: make([]*dave.Pd, len(m.Pds)), V: m.V, T: m.T, S: m.S, W: m.W}
	for i, pd := range m.Pds {
		cpy.Pds[i] = &dave.Pd{Ip: pd.Ip, Port: pd.Port}
	}
	return &pkt{cpy, raddr}
}

func randpds(prs map[string]*peer, excl map[string]*peer, lim int, match func(p, legend *peer) bool) []*dave.Pd {
	candidates := make([]*dave.Pd, 0, len(prs))
	l := legend(prs)
	for k, p := range prs {
		_, exclude := excl[k]
		if !exclude && match(p, l) {
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

func usable(k, legend *peer) bool {
	if k.bootstrap || mrand.Intn(PROBE) == 1 || k.trust >= mrand.Float64()*legend.trust {
		return time.Since(k.seen) < EPOCH*PING && (time.Since(k.added) > EPOCH*DELAY || k.bootstrap)
	}
	return false
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

func hash4(port uint16) byte { // 4-bit hash
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
	ch <- fmt.Sprintf(msg, args...)
}
