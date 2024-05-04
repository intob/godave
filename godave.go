// Copyright 2024 Joey Innes <joey@inneslabs.uk>
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package godave

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
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
	ckoo "github.com/seiflotfy/cuckoofilter"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	MTU      = 1500
	NPEER    = 2
	EPOCH    = 65537 * time.Nanosecond
	DELAY    = 5039
	OPEN     = 257
	PING     = 719
	DROP     = 1597
	PRUNE    = 32768
	SEED     = 2
	PULL     = 3
	SEEDSEED = 911
)

type Dave struct {
	Send chan<- *dave.M
	Recv <-chan *dave.M
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
		lg(cfg.Log, "Cfg.FilterCap set to default 1M")
		cfg.FilterCap = 1000000
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
	send := make(chan *dave.M)
	recv := make(chan *dave.M, 1)
	go d(c, boot, lstn(c, cfg.FilterCap, cfg.Log), send, recv, cfg.Log, int(cfg.DatCap), len(cfg.Bootstraps) == 0)
	for _, bap := range cfg.Bootstraps {
		wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), bap)
	}
	return &Dave{send, recv}, nil
}

func Work(val, ti []byte, difficulty int) (work, salt []byte) {
	zeros := make([]byte, difficulty)
	salt = make([]byte, 32)
	h := sha256.New()
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
	h := sha256.New()
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
	binary.BigEndian.PutUint64(bytes, uint64(milli))
	return bytes
}

func Btt(b []byte) time.Time {
	if len(b) != 8 {
		return time.Time{}
	}
	milli := int64(binary.BigEndian.Uint64(b))
	return time.Unix(0, milli*1000000)
}

func Pdfp(h hash.Hash, pd *dave.Pd) []byte {
	port := make([]byte, 8)
	binary.BigEndian.PutUint32(port, pd.Port)
	h.Reset()
	h.Write(port)
	h.Write(pd.Ip)
	return h.Sum(nil)
}

func d(c *net.UDPConn, prs map[string]*peer, pch <-chan *pkt, send <-chan *dave.M, recv chan<- *dave.M, log chan<- string, cap int, seed bool) {
	dats := make(map[uint8]map[uint64]Dat)
	var nepoch uint64
	et := time.NewTicker(EPOCH)
	pdhfn := fnv.New64a()
	for {
		select {
		case <-et.C: // PERIODICALLY PER EPOCH
			nepoch++
			if nepoch%PRUNE == 0 { // PRUNING MEMORY, KEEP <=CAP MASSIVE DATS
				memstat := &runtime.MemStats{}
				runtime.ReadMemStats(memstat)
				newdats := make(map[uint8]map[uint64]Dat)
				var minmass float64
				var ld, count uint64
				for shardid, shard := range dats {
					for key, dat := range shard {
						count++
						mass := Mass(dat.W, dat.Ti)
						if len(shard) >= cap-1 { // BEYOND CAP, REPLACE BY MASS
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
			if ((seed && nepoch%SEEDSEED == 0) || (!seed && nepoch%SEED == 0)) && len(dats) > 0 && len(prs) > 0 { // SEND RANDOM DAT TO RANDOM PEER, SEEDS MAY PRIORITISE PEER MESSAGES
				rshard := uint8(mrand.Intn(256))
				if len(dats[rshard]) > 0 {
					rindex := mrand.Intn(len(dats[rshard]))
					var x int
					for s := range dats[rshard] {
						if x == rindex {
							rd := dats[rshard][s]
							m := marshal(&dave.M{Op: dave.Op_DAT, V: rd.V, T: Ttb(rd.Ti), S: rd.S, W: rd.W})
							for _, rp := range randpds(prs, nil, 1, usable) {
								wraddr(c, m, addrfrom(rp))
								lg(log, "/d/rand/seed sent to %x %s\n", Pdfp(pdhfn, rp), rd.V)
							}
							break
						}
						x++
					}
				}
			}
			if nepoch%PULL == 0 && len(dats) > 0 && len(prs) > 0 {
				rshard := uint8(mrand.Intn(256))
				if len(dats[rshard]) > 0 {
					rindex := mrand.Intn(len(dats[rshard]))
					var x int
					for s := range dats[rshard] {
						if x == rindex {
							rd := dats[rshard][s]
							for _, rp := range randpds(prs, nil, 1, usable) {
								wraddr(c, marshal(&dave.M{Op: dave.Op_GET, W: rd.W}), addrfrom(rp))
								lg(log, "/d/rand/pull sent to %x %s\n", Pdfp(pdhfn, rp), rd.V)
							}
							break
						}
						x++
					}
				}

			}
			if nepoch%OPEN == 0 { // ONCE PER SHARE EPOCHS, RELATIVELY SHORT CYCLE
				for pid, p := range prs {
					if !p.bootstrap && time.Since(p.seen) > EPOCH*DROP { // DROP UNRESPONSIVE PEER
						delete(prs, pid)
						lg(log, "/d/peer/remove %x\n", Pdfp(pdhfn, p.pd))
					} else if time.Since(p.seen) > EPOCH*OPEN && time.Since(p.ping) > EPOCH*PING { // SEND PING
						wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), addrfrom(p.pd))
						p.ping = time.Now()
						lg(log, "/d/peer/ping sent GETPEER to %x\n", Pdfp(pdhfn, p.pd))
					}
				}
			}
		case m := <-send: // SEND PACKET
			if m != nil {
				switch m.Op {
				case dave.Op_DAT:
					store(dats, &Dat{m.V, m.S, m.W, Btt(m.T)})
					for _, rp := range randpds(prs, nil, 1, usable) {
						wraddr(c, marshal(m), addrfrom(rp))
						lg(log, "/d/send DAT to %x\n", Pdfp(pdhfn, rp))
					}
				case dave.Op_GET:
					var found bool
					var d Dat
					shard, ok := dats[uint8(m.W[31])]
					if ok { // GOT SHARD
						d, found = shard[id(m.W)]
					}
					if found {
						recv <- &dave.M{Op: dave.Op_DAT, V: d.V, T: Ttb(d.Ti), S: d.S, W: d.W}
						lg(log, "/d/send/get found locally %x\n", d.W)
					} else {
						for _, rp := range randpds(prs, nil, NPEER, usable) {
							wraddr(c, marshal(&dave.M{Op: dave.Op_GET, W: m.W}), addrfrom(rp))
							lg(log, "/d/send/get sent to %x %x\n", Pdfp(pdhfn, rp), m.W)
						}

					}
				default:
					panic("unsupported operation")
				}
			}
		case pkt := <-pch: // HANDLE INCOMING PACKET
			recv <- pkt.msg
			pktpd := pdfrom(pkt.ip)
			pktpid := pdstr(pktpd)
			_, ok := prs[pktpid]
			if !ok {
				prs[pktpid] = &peer{pd: pktpd, added: time.Now()}
				lg(log, "/d/ph/peer/add from packet %x\n", Pdfp(pdhfn, pktpd))
			}
			prs[pktpid].seen = time.Now()
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
				randpds := randpds(prs, []*dave.Pd{pktpd}, NPEER, usable)
				wraddr(c, marshal(&dave.M{Op: dave.Op_PEER, Pds: randpds}), pkt.ip)
				lg(log, "/d/ph/getpeer/reply with PEER to %x\n", Pdfp(pdhfn, pktpd))
			case dave.Op_DAT: // STORE DAT
				store(dats, &Dat{m.V, m.S, m.W, Btt(m.T)})
				lg(log, "/d/ph/dat/store %x\n", m.W)
			case dave.Op_GET: // REPLY WITH DAT
				shard, ok := dats[uint8(m.W[31])]
				if ok { // GOT SHARD
					d, ok := shard[id(m.W)]
					if ok { // GOT DAT
						wraddr(c, marshal(&dave.M{Op: dave.Op_DAT, V: d.V, T: Ttb(d.Ti), S: d.S, W: d.W}), pkt.ip)
						lg(log, "/d/ph/get/reply sent %x\n", d.W)
					}
				}
			}
		}
	}
}

func store(dats map[uint8]map[uint64]Dat, d *Dat) {
	_, ok := dats[uint8(d.W[31])]
	if !ok {
		dats[uint8(d.W[31])] = make(map[uint64]Dat)
	}
	dats[uint8(d.W[31])][id(d.W)] = *d
}

func lstn(c *net.UDPConn, fcap uint, log chan<- string) <-chan *pkt {
	pkts := make(chan *pkt, 1)
	go func() {
		mpool := sync.Pool{New: func() any { return &dave.M{} }}
		bufpool := sync.Pool{New: func() any { return make([]byte, MTU) }}
		f := ckoo.NewFilter(fcap)
		rt := time.NewTimer(EPOCH)
		h := fnv.New128a()
		defer c.Close()
		for {
			select {
			case <-rt.C:
				f.Reset()
				rt.Reset(EPOCH)
				lg(log, "/lstn/filter/reset\n")
			default:
				p := rdpkt(c, f, h, &bufpool, &mpool, log)
				if p != nil {
					pkts <- p
				}
			}
		}
	}()
	return pkts
}

func rdpkt(c *net.UDPConn, f *ckoo.Filter, h hash.Hash, bufpool, mpool *sync.Pool, log chan<- string) *pkt {
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
	h.Reset()
	rab := raddr.Addr().As16()
	h.Write(rab[:])
	h.Write([]byte{hash4(raddr.Port())}) // allow nibble of ports per IP for now
	op := make([]byte, 8)
	binary.BigEndian.PutUint32(op, uint32(m.Op.Number()))
	h.Write(op)
	if !f.InsertUnique(h.Sum(nil)) {
		lg(log, "/rdpkt/drop/filter collision: IP-HASH4(PORT)-OP %s\n", m.Op)
		return nil
	}
	if m.Op == dave.Op_PEER && len(m.Pds) > NPEER {
		lg(log, "/rdpkt/drop/npeer too many peers\n")
		return nil
	} else if m.Op == dave.Op_DAT && Check(m.V, m.T, m.S, m.W) < 0 {
		lg(log, "/rdpkt/drop/workcheck invalid\n")
		return nil
	}
	cpy := &dave.M{Op: m.Op, Pds: make([]*dave.Pd, len(m.Pds)), V: m.V, T: m.T, S: m.S, W: m.W}
	for i, pd := range m.Pds {
		cpy.Pds[i] = &dave.Pd{Ip: pd.Ip, Port: pd.Port}
	}
	return &pkt{cpy, raddr}
}

func randpds(prs map[string]*peer, excl []*dave.Pd, lim int, match func(*peer) bool) []*dave.Pd {
	exclmap := make(map[string]struct{}, len(excl))
	for _, pexcl := range excl {
		exclmap[pdstr(pexcl)] = struct{}{}
	}
	candidates := make([]*dave.Pd, 0, len(prs))
	for _, k := range prs {
		if match(k) {
			if _, ok := exclmap[pdstr(k.pd)]; !ok {
				candidates = append(candidates, k.pd)
			}
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

func usable(k *peer) bool {
	return k.bootstrap || time.Since(k.seen) < EPOCH*OPEN && time.Since(k.added) > EPOCH*DELAY
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

func id(v []byte) uint64 {
	h := fnv.New64a()
	h.Write(v)
	return h.Sum64()
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
