// Copyright 2024 Joey Innes <joey@inneslabs.uk>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package godave

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
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
	FILTER_CAP  = 1000000
)

type Dave struct {
	Send chan<- *dave.M
	Recv <-chan *dave.M
	stat chan *Stat
}

type Cfg struct {
	Listen     *net.UDPAddr
	Bootstraps []netip.AddrPort
	Size       int
	Log        io.Writer
}

func (d *Dave) Stat() *Stat {
	return <-d.stat
}

type Dat struct {
	Val, Tag, Nonce, Work []byte
	added                 time.Time
}

type Stat struct {
	NPeer, NDat uint32
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
	conn, err := net.ListenUDP("udp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	fmt.Printf("listening %s\n", conn.LocalAddr())
	boot := make(map[string]*peer)
	for _, bap := range cfg.Bootstraps {
		bp := pdfrom(bap)
		boot[pdstr(bp)] = &peer{pd: bp, added: time.Now(), seen: time.Now(), bootstrap: true}
	}
	send := make(chan *dave.M)
	recv := make(chan *dave.M, 1)
	stat := make(chan *Stat)
	go d(conn, boot, lstn(conn, cfg.Log), send, recv, stat, cfg.Log, cfg.Size)
	for _, bap := range cfg.Bootstraps {
		wraddr(conn, marshal(&dave.M{Op: dave.Op_GETPEER}), bap)
	}
	return &Dave{send, recv, stat}, nil
}

func Work(msg *dave.M, difficulty int) (<-chan *dave.M, error) {
	result := make(chan *dave.M)
	go func() {
		zeros := make([]byte, difficulty)
		msg.Nonce = make([]byte, 32)
		h := sha256.New()
		h.Write(msg.Val)
		h.Write(msg.Tag)
		load := h.Sum(nil)
		for {
			crand.Read(msg.Nonce)
			h.Reset()
			h.Write(load)
			h.Write(msg.Nonce)
			msg.Work = h.Sum(nil)
			if bytes.HasPrefix(msg.Work, zeros) {
				result <- msg
				return
			}
		}
	}()
	return result, nil
}

func Check(val, tag, nonce, work []byte) int {
	h := sha256.New()
	h.Write(val)
	h.Write(tag)
	load := h.Sum(nil)
	h.Reset()
	h.Write(load)
	h.Write(nonce)
	if !bytes.Equal(h.Sum(nil), work) {
		return -1
	}
	return nzero(work)
}

func d(c *net.UDPConn, prs map[string]*peer, pch <-chan *packet, send <-chan *dave.M, recv chan<- *dave.M, stat chan<- *Stat, log io.Writer, size int) {
	dats := make(map[uint64]Dat)
	for {
		select {
		case m := <-send: // SEND PACKET
			if m != nil {
				switch m.Op {
				case dave.Op_SET:
					store(dats, size, &Dat{m.Val, m.Tag, m.Nonce, m.Work, time.Now()}, log)
					for _, rp := range randpds(prs, nil, FANOUT, shareable) {
						wraddr(c, marshal(m), addrPortFrom(rp))
					}
				case dave.Op_GET:
					loc, ok := dats[id(m.Work)]
					if ok {
						recv <- &dave.M{Op: dave.Op_DAT, Val: loc.Val, Tag: loc.Tag, Nonce: loc.Nonce, Work: loc.Work}
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
				fmt.Fprintf(log, "peer added: %x\n", pdfp(pd))
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
						fmt.Fprintf(log, "peer added: gossip %x\n", pdfp(pd))
					}
				}
			case dave.Op_GETPEER: // GIVE PEERS
				randpds := randpds(prs, []*dave.Pd{pd}, NPEER, shareable)
				wraddr(c, marshal(&dave.M{Op: dave.Op_PEER, Pds: randpds}), pkt.ip)
			case dave.Op_SET:
				dats[id(m.Work)] = Dat{m.Val, m.Tag, m.Nonce, m.Work, time.Now()}
				if len(m.Pds) < DISTANCE {
					for _, fp := range randpds(prs, m.Pds, FANOUT, shareable) {
						wraddr(c, marshal(m), addrPortFrom(fp))
					}
				}
			case dave.Op_GET: // RETURN DAT OR FORWARD
				d, ok := dats[id(m.Work)]
				if ok {
					for _, mp := range m.Pds {
						wraddr(c, marshal(&dave.M{Op: dave.Op_DAT, Val: d.Val, Tag: d.Tag, Nonce: d.Nonce, Work: m.Work}), addrPortFrom(mp))
					}
				} else if len(m.Pds) < DISTANCE {
					for _, fp := range randpds(prs, m.Pds, FANOUT, shareable) {
						wraddr(c, marshal(m), addrPortFrom(fp))
					}
				}
			case dave.Op_DAT: // STORE DAT
				store(dats, size, &Dat{m.Val, m.Tag, m.Nonce, m.Work, time.Now()}, log)
				fmt.Fprintf(log, "stored: %x\n", m.Work)
			case dave.Op_RAND: // STORE RAND DAT
				store(dats, size, &Dat{m.Val, m.Tag, m.Nonce, m.Work, time.Now()}, log)
				fmt.Fprintf(log, "stored rand: %x\n", m.Work)
			}
		case <-time.After(EPOCH): // PERIODICALLY
			var rdat *Dat
			var x, rdatpeer int
			if len(dats) > 0 && len(prs) > 0 {
				rdati := mrand.Intn(len(dats))
				for s := range dats {
					if x == rdati {
						rd := dats[s]
						rdat = &rd
						rdatpeer = mrand.Intn(len(prs))
						x = 0
						break
					}
					x++
				}
			}
			for pid, p := range prs {
				if rdat != nil && x == rdatpeer { // PUSH RAND DAT
					wraddr(c, marshal(&dave.M{Op: dave.Op_RAND, Tag: rdat.Tag, Val: rdat.Val, Nonce: rdat.Nonce, Work: rdat.Work}), addrPortFrom(p.pd))
					fmt.Fprintf(log, "sent random dat %x to %x\n", rdat.Work, pdfp(p.pd))
				}
				x++
				if !p.bootstrap && time.Since(p.seen) > EPOCH*TOLERANCE { // KICK UNRESPONSIVE PEER
					delete(prs, pid)
					fmt.Fprintf(log, "removed peer %x\n", pdfp(p.pd))
				} else if time.Since(p.seen) > EPOCH {
					wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), addrPortFrom(p.pd))
				}
			}
		case stat <- &Stat{uint32(len(prs)), uint32(len(dats))}: // STATUS
		}
	}
}

func lstn(conn *net.UDPConn, log io.Writer) <-chan *packet {
	pkts := make(chan *packet, 1)
	go func() {
		mpool := sync.Pool{New: func() any { return &dave.M{} }}
		opool := sync.Pool{New: func() any { return make([]byte, 8) }}
		f := ckoo.NewFilter(FILTER_CAP)
		reset := time.After(EPOCH)
		h := fnv.New128a()
		defer conn.Close()
		for {
			select {
			case <-reset:
				reset = time.After(EPOCH)
				f.Reset()
			default:
				p := readPacket(conn, f, h, &mpool, &opool, log)
				if p != nil {
					pkts <- p
				}
			}
		}
	}()
	return pkts
}

func readPacket(conn *net.UDPConn, f *ckoo.Filter, h hash.Hash, mpool *sync.Pool, opool *sync.Pool, log io.Writer) *packet {
	buf := make([]byte, MTU)
	n, raddr, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		panic(err)
	}
	m := mpool.Get().(*dave.M)
	defer mpool.Put(m)
	err = proto.Unmarshal(buf[:n], m)
	if err != nil {
		fmt.Fprintf(log, "dropped: unmarshal err\n")
		return nil
	}
	if m.Op == dave.Op_PEER && len(m.Pds) > NPEER {
		fmt.Fprintf(log, "dropped %s: too many peers\n", m.Op)
		return nil
	}
	h.Reset()
	rab := raddr.Addr().As16()
	h.Write(rab[:])
	op := opool.Get().([]byte)
	binary.BigEndian.PutUint32(op, uint32(m.Op.Number()))
	h.Write(op)
	if m.Op == dave.Op_PEER || m.Op == dave.Op_GETPEER {
		if !f.InsertUnique(h.Sum(nil)) {
			fmt.Fprintf(log, "dropped %s: filter collision: %x\n", m.Op, pdfp(pdfrom(raddr)))
			return nil
		}
	} else { // DAT, GET, SET, RAND
		h.Write(m.Work)
		if !f.InsertUnique(h.Sum(nil)) {
			fmt.Fprintf(log, "dropped %s: filter collision: %x\n", m.Op, pdfp(pdfrom(raddr)))
			return nil
		}
		check := Check(m.Val, m.Tag, m.Nonce, m.Work)
		if (m.Op == dave.Op_DAT || m.Op == dave.Op_SET || m.Op == dave.Op_RAND) && check < MINWORK {
			fmt.Fprintf(log, "dropped %s: invalid work: %d, %x, %x\n", m.Op, check, m.Work, pdfp(pdfrom(raddr)))
			return nil
		}
		if m.Op == dave.Op_GET || m.Op == dave.Op_SET {
			pd := pdfrom(raddr)
			if len(m.Pds) == 0 {
				m.Pds = []*dave.Pd{pd}
			} else {
				m.Pds = append(m.Pds, pd)
			}
		}
	}
	copy := &dave.M{Op: m.Op, Pds: make([]*dave.Pd, len(m.Pds)), Val: m.Val, Tag: m.Tag, Nonce: m.Nonce, Work: m.Work}
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

func pdfp(pd *dave.Pd) []byte {
	port := make([]byte, 8)
	binary.BigEndian.PutUint32(port, pd.Port)
	h := fnv.New64a()
	h.Write(port)
	h.Write(pd.Ip)
	return h.Sum(nil)
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

func store(dats map[uint64]Dat, size int, dat *Dat, log io.Writer) {
	if len(dats) >= size {
		lightest := lightest(dats)
		fmt.Fprintf(log, "replaced lightest: %x\n", dats[lightest].Work)
		delete(dats, lightest)
	}
	dats[id(dat.Work)] = *dat
}

func lightest(dats map[uint64]Dat) uint64 {
	var lw float64
	var l uint64
	for key, dat := range dats {
		wd := weight(&dat)
		if lw == 0 || wd < lw {
			lw = wd
			l = key
		}
	}
	return l
}

func weight(dat *Dat) float64 {
	// Use linear zero count to accurately reflect exponential difficulty
	return float64(nzero(dat.Work)) * (1 / time.Since(dat.added).Seconds())
}
