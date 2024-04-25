// Copyright 2024 Joey Innes <joey@inneslabs.uk>

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package godave

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	mrand "math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/intob/dave/godave/dave"
	ckoo "github.com/seiflotfy/cuckoofilter"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	EPOCH       = 127713921 * time.Nanosecond
	MTU         = 1500
	NPEER       = 2
	SHARE_DELAY = time.Minute
	TOLERANCE   = 9
	DISTANCE    = 9
	FANOUT      = 2
	MINWORK     = 2
	PRUNE       = 256
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
	Val, Nonce, Work []byte
	Ti               time.Time
}

type peer struct {
	pd          *dave.Pd
	added, seen time.Time
	bootstrap   bool
}

type packet struct {
	msg *dave.M
	ip  netip.AddrPort
}

func NewDave(cfg *Cfg) (*Dave, error) {
	if cfg.DatCap == 0 {
		return nil, errors.New("DatCap must not be 0")
	}
	if cfg.FilterCap == 0 {
		return nil, errors.New("FilterCap must not be 0, 1M is recommended")
	}
	l(cfg.Log, "creating dave: %+v\n", *cfg)
	conn, err := net.ListenUDP("udp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	l(cfg.Log, "dave listening %s\n", conn.LocalAddr())
	boot := make(map[string]*peer)
	for _, bap := range cfg.Bootstraps {
		bp := pdfrom(bap)
		boot[pdstr(bp)] = &peer{pd: bp, added: time.Now(), seen: time.Now(), bootstrap: true}
	}
	send := make(chan *dave.M)
	recv := make(chan *dave.M, 1)
	go d(conn, boot, lstn(conn, cfg.FilterCap, cfg.Log), send, recv, cfg.Log, int(cfg.DatCap))
	for _, bap := range cfg.Bootstraps {
		wraddr(conn, marshal(&dave.M{Op: dave.Op_GETPEER}), bap)
	}
	return &Dave{send, recv}, nil
}

func Work(val, time []byte, difficulty int) (work, nonce []byte) {
	zeros := make([]byte, difficulty)
	nonce = make([]byte, 32)
	h := sha256.New()
	h.Write(val)
	h.Write(time)
	load := h.Sum(nil)
	for {
		crand.Read(nonce)
		h.Reset()
		h.Write(load)
		h.Write(nonce)
		work = h.Sum(nil)
		if bytes.HasPrefix(work, zeros) {
			return work, nonce
		}
	}
}

func Check(val, time, nonce, work []byte) int {
	h := sha256.New()
	h.Write(val)
	h.Write(time)
	load := h.Sum(nil)
	h.Reset()
	h.Write(load)
	h.Write(nonce)
	if !bytes.Equal(h.Sum(nil), work) {
		return -1
	}
	return nzero(work)
}

func Weight(work []byte, t time.Time) float64 {
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

func d(c *net.UDPConn, prs map[string]*peer, pch <-chan *packet, send <-chan *dave.M, recv chan<- *dave.M, log chan<- string, cap int) {
	dats := make(map[uint64]Dat)
	var nepoch uint64
	et := time.NewTimer(EPOCH)
	pdh := fnv.New64a()
	for {
		select {
		case <-et.C: // PERIODICALLY
			et.Reset(EPOCH)
			nepoch++
			if nepoch%PRUNE == 0 { // KEEP CAP HEAVIEST DATS
				newdats := make(map[uint64]Dat)
				var minw float64
				var ld uint64
				for k, d := range dats {
					w := Weight(d.Work, d.Ti)
					if len(newdats) >= cap-1 { // BEYOND CAP, REPLACE BY WEIGHT
						if w > minw {
							delete(newdats, ld)
							newdats[k] = d
							ld = k
							minw = w
						}
					} else {
						if w < minw {
							minw = w
						}
						newdats[k] = d
					}
				}
				dats = newdats
				newpeers := make(map[string]*peer)
				for k, p := range prs {
					newpeers[k] = p
				}
				prs = newpeers
				l(log, "got %d peers, %d dats\n", len(newpeers), len(newdats))
			}
			if len(dats) > 0 && len(prs) > 0 { // SEND RANDOM DAT TO FANOUT PEERS
				rdati := mrand.Intn(len(dats))
				var x int
				for s := range dats {
					if x == rdati {
						rd := dats[s]
						m := marshal(&dave.M{Op: dave.Op_DAT, Val: rd.Val, Time: Ttb(rd.Ti), Nonce: rd.Nonce, Work: rd.Work})
						for _, rp := range randpds(prs, nil, FANOUT, shareable) {
							wraddr(c, m, addrPortFrom(rp))
							l(log, "sent random dat %x to %x\n", rd.Work, Pdfp(pdh, rp))
						}
						break
					}
					x++
				}
			}
			for pid, p := range prs {
				if !p.bootstrap && time.Since(p.seen) > EPOCH*TOLERANCE { // KICK UNRESPONSIVE PEER
					delete(prs, pid)
					l(log, "removed peer %x\n", Pdfp(pdh, p.pd))
				} else if time.Since(p.seen) > EPOCH {
					wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), addrPortFrom(p.pd))
				}
			}
		case m := <-send: // SEND PACKET
			if m != nil {
				switch m.Op {
				case dave.Op_SET:
					store(dats, &Dat{m.Val, m.Nonce, m.Work, time.Now()})
					for _, rp := range randpds(prs, nil, FANOUT, shareable) {
						wraddr(c, marshal(m), addrPortFrom(rp))
					}
				case dave.Op_GET:
					loc, ok := dats[id(m.Work)]
					if ok {
						recv <- &dave.M{Op: dave.Op_DAT, Val: loc.Val, Time: Ttb(loc.Ti), Nonce: loc.Nonce, Work: loc.Work}
					} else {
						for _, rp := range randpds(prs, nil, FANOUT, shareable) {
							wraddr(c, marshal(m), addrPortFrom(rp))
						}
					}
				}
			}
		case pkt := <-pch: // HANDLE INCOMING PACKET
			recv <- pkt.msg
			pd := pdfrom(pkt.ip)
			pktpid := pdstr(pd)
			_, ok := prs[pktpid]
			if !ok {
				prs[pktpid] = &peer{pd: pd, added: time.Now()}
				l(log, "peer added: %x\n", Pdfp(pdh, pd))
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
						l(log, "peer added: gossip %x\n", Pdfp(pdh, pd))
					}
				}
			case dave.Op_GETPEER: // GIVE PEERS
				randpds := randpds(prs, []*dave.Pd{pd}, NPEER, shareable)
				wraddr(c, marshal(&dave.M{Op: dave.Op_PEER, Pds: randpds}), pkt.ip)
			case dave.Op_SET:
				dats[id(m.Work)] = Dat{m.Val, m.Nonce, m.Work, Btt(m.Time)}
				if len(m.Pds) < DISTANCE {
					for _, fp := range randpds(prs, m.Pds, FANOUT, shareable) {
						wraddr(c, marshal(m), addrPortFrom(fp))
					}
				}
			case dave.Op_GET: // RETURN DAT OR FORWARD
				d, ok := dats[id(m.Work)]
				if ok {
					for _, mp := range m.Pds {
						wraddr(c, marshal(&dave.M{Op: dave.Op_DAT, Val: d.Val, Time: Ttb(d.Ti), Nonce: d.Nonce, Work: m.Work}), addrPortFrom(mp))
					}
				} else if len(m.Pds) < DISTANCE {
					for _, fp := range randpds(prs, m.Pds, FANOUT, shareable) {
						wraddr(c, marshal(m), addrPortFrom(fp))
					}
				}
			case dave.Op_DAT: // STORE DAT
				if store(dats, &Dat{m.Val, m.Nonce, m.Work, Btt(m.Time)}) {
					l(log, "stored: %x\n", m.Work)
				}
			}
		}
	}
}

func lstn(conn *net.UDPConn, fcap uint, log chan<- string) <-chan *packet {
	pkts := make(chan *packet, 1)
	go func() {
		mpool := sync.Pool{New: func() any { return &dave.M{} }}
		bufpool := sync.Pool{New: func() any { return make([]byte, MTU) }}
		f := ckoo.NewFilter(fcap)
		rt := time.NewTimer(EPOCH)
		h := fnv.New128a()
		defer conn.Close()
		for {
			select {
			case <-rt.C:
				f.Reset()
				rt.Reset(EPOCH)
			default:
				p := rdpacket(conn, f, h, &bufpool, &mpool, log)
				if p != nil {
					pkts <- p
				}
			}
		}
	}()
	return pkts
}

func rdpacket(conn *net.UDPConn, f *ckoo.Filter, h hash.Hash, bufpool, mpool *sync.Pool, log chan<- string) *packet {
	buf := bufpool.Get().([]byte)
	defer bufpool.Put(buf) //lint:ignore SA6002 slice is already a reference
	n, raddr, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		panic(err)
	}
	m := mpool.Get().(*dave.M)
	defer mpool.Put(m)
	err = proto.Unmarshal(buf[:n], m)
	if err != nil {
		l(log, "dropped: unmarshal err\n")
		return nil
	}
	h.Reset()
	rab := raddr.Addr().As16()
	h.Write(rab[:])
	op := make([]byte, 8)
	binary.BigEndian.PutUint32(op, uint32(m.Op.Number()))
	h.Write(op)
	if !f.InsertUnique(h.Sum(nil)) {
		l(log, "dropped: filter collision: IP-OP\n")
		return nil
	}
	if m.Op == dave.Op_PEER && len(m.Pds) > NPEER {
		l(log, "dropped: too many peers\n")
		return nil
	} else if m.Op == dave.Op_DAT || m.Op == dave.Op_SET {
		if !f.InsertUnique(m.Work) {
			l(log, "dropped: filter collision: work\n")
			return nil
		}
		check := Check(m.Val, m.Time, m.Nonce, m.Work)
		if check < MINWORK {
			l(log, "dropped: invalid work: %s, %d, %x\n", m.Op, check, m.Work)
			return nil
		}
	}
	if m.Op == dave.Op_GET || m.Op == dave.Op_SET {
		if len(m.Pds) == 0 {
			m.Pds = []*dave.Pd{pdfrom(raddr)}
		} else {
			m.Pds = append(m.Pds, pdfrom(raddr))
		}
	}
	copy := &dave.M{Op: m.Op, Pds: make([]*dave.Pd, len(m.Pds)), Val: m.Val, Time: m.Time, Nonce: m.Nonce, Work: m.Work}
	for i, pd := range m.Pds {
		copy.Pds[i] = &dave.Pd{Ip: pd.Ip, Port: pd.Port}
	}
	return &packet{copy, raddr}
}

func randpds(peers map[string]*peer, exclude []*dave.Pd, limit int, match func(*peer) bool) []*dave.Pd {
	excludeMap := make(map[string]struct{}, len(exclude))
	for _, pexcl := range exclude {
		excludeMap[pdstr(pexcl)] = struct{}{}
	}
	candidates := make([]*dave.Pd, 0, len(peers))
	for _, k := range peers {
		if match(k) {
			if _, ok := excludeMap[pdstr(k.pd)]; !ok {
				candidates = append(candidates, k.pd)
			}
		}
	}
	if len(candidates) <= limit {
		return candidates
	}
	ans := make([]*dave.Pd, limit)
	for i := 0; i < limit; i++ {
		r := i + mrand.Intn(len(candidates)-i)
		ans[i] = candidates[r]
	}
	return ans
}

func shareable(k *peer) bool {
	return k.bootstrap || time.Since(k.seen) < EPOCH && time.Since(k.added) > SHARE_DELAY
}

func addrPortFrom(pd *dave.Pd) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(pd.Ip)), uint16(pd.Port))
}

func pdfrom(addrport netip.AddrPort) *dave.Pd {
	ip := addrport.Addr().As16()
	return &dave.Pd{Ip: ip[:], Port: uint32(addrport.Port())}
}

func pdstr(p *dave.Pd) string {
	return strings.TrimLeft(hex.EncodeToString(p.Ip), "0") + ":" + strconv.Itoa(int(p.Port))
}

func id(v []byte) uint64 {
	h := fnv.New64a()
	h.Write(v)
	return h.Sum64()
}

func wraddr(conn *net.UDPConn, payload []byte, addr netip.AddrPort) {
	_, err := conn.WriteToUDPAddrPort(payload, addr)
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

func store(dats map[uint64]Dat, dat *Dat) bool {
	_, ok := dats[id(dat.Work)]
	if !ok {
		dats[id(dat.Work)] = *dat
	}
	return !ok
}

func l(ch chan<- string, msg string, args ...any) {
	ch <- fmt.Sprintf(msg, args...)
}
