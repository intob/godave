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
	PERIOD        = time.Second
	MTU           = 1500
	NPEER         = 2
	SHARE_DELAY   = time.Minute
	TOLERANCE     = 3
	DISTANCE      = 7
	FANOUT_GETDAT = 2
	FANOUT_SETDAT = 2
	MINWORK       = 2
	FILTER_CAP    = 1000000
)

type Dave struct {
	Send chan<- *dave.M
	Recv <-chan *dave.M
	stat chan *Stat
}

type Dat struct {
	Val   []byte
	Tag   []byte
	Nonce []byte
}

type Stat struct {
	NPeer uint32
}

type peer struct {
	pd        *dave.Pd
	added     time.Time
	seen      time.Time
	bootstrap bool
}

type packet struct {
	msg *dave.M
	ip  netip.AddrPort
}

func (d *Dave) Stat() *Stat {
	return <-d.stat
}

func NewDave(laddr *net.UDPAddr, baps []netip.AddrPort) (*Dave, error) {
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	fmt.Printf("listening %s\n", conn.LocalAddr())
	boot := make(map[string]*peer)
	for _, bap := range baps {
		bp := pdFrom(bap)
		boot[pdStr(bp)] = &peer{pd: bp, added: time.Now(), seen: time.Now(), bootstrap: true}
	}
	send := make(chan *dave.M)
	recv := make(chan *dave.M, 1)
	stat := make(chan *Stat)
	go d(conn, boot, lstn(conn), send, recv, stat)
	for _, bap := range baps {
		wraddr(conn, marshal(&dave.M{Op: dave.Op_GETPEER}), bap)
	}
	return &Dave{send, recv, stat}, nil
}

func Work(msg *dave.M, work int) (<-chan *dave.M, error) {
	result := make(chan *dave.M)
	go func() {
		zeros := make([]byte, work)
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

func CheckMsg(msg *dave.M) int {
	h := sha256.New()
	h.Write(msg.Val)
	h.Write(msg.Tag)
	load := h.Sum(nil)
	h.Reset()
	h.Write(load)
	h.Write(msg.Nonce)
	if !bytes.Equal(h.Sum(nil), msg.Work) {
		return -1
	}
	return nzero(msg.Work)
}

func d(c *net.UDPConn, prs map[string]*peer, pch <-chan packet, send <-chan *dave.M, recv chan<- *dave.M, stat chan<- *Stat) {
	data := make(map[string]Dat)
	for {
		select {
		case msend := <-send: // SEND PACKET
			if msend != nil {
				switch msend.Op {
				case dave.Op_SETDAT:
					for _, rp := range rndPds(prs, nil, FANOUT_SETDAT, shareable) {
						wraddr(c, marshal(msend), addrPortFrom(rp))
					}
				case dave.Op_GETDAT:
					for _, rp := range rndPds(prs, nil, FANOUT_GETDAT, shareable) {
						wraddr(c, marshal(msend), addrPortFrom(rp))
					}
				}
			}
		case pkt := <-pch: // HANDLE INCOMING PACKET
			recv <- pkt.msg
			pd := pdFrom(pkt.ip)
			pktpid := pdStr(pd)
			_, ok := prs[pktpid]
			if !ok {
				prs[pktpid] = &peer{pd: pd, added: time.Now()}

				fmt.Println("<-pkts added", pktpid)
			}
			prs[pktpid].seen = time.Now()
			m := pkt.msg
			switch m.Op {
			case dave.Op_PEER: // STORE PEERS
				for _, pd := range m.Pds {
					pid := pdStr(pd)
					_, ok := prs[pid]
					if !ok {
						prs[pid] = &peer{pd: pd, added: time.Now(), seen: time.Now()}
						fmt.Println("<-pkts added gossip", pid)
					}
				}
			case dave.Op_GETPEER: // GIVE PEERS
				randpds := rndPds(prs, []*dave.Pd{pd}, NPEER, shareable)
				wraddr(c, marshal(&dave.M{Op: dave.Op_PEER, Pds: randpds}), pkt.ip)
			case dave.Op_SETDAT:
				data[hex.EncodeToString(m.Work)] = Dat{m.Val, m.Tag, m.Nonce}
				if len(m.Pds) < DISTANCE {
					for _, fp := range rndPds(prs, m.Pds, FANOUT_SETDAT, shareable) {
						wraddr(c, marshal(m), addrPortFrom(fp))
					}
				}
			case dave.Op_GETDAT: // RETURN DAT OR FORWARD
				d, ok := data[hex.EncodeToString(m.Work)]
				if ok {
					for _, mp := range m.Pds {
						wraddr(c, marshal(&dave.M{Op: dave.Op_DAT, Val: d.Val,
							Tag: d.Tag, Nonce: d.Nonce, Work: m.Work}), addrPortFrom(mp))
					}
				} else if len(m.Pds) < DISTANCE {
					for _, fp := range rndPds(prs, m.Pds, FANOUT_GETDAT, shareable) {
						wraddr(c, marshal(m), addrPortFrom(fp))
					}
				}
			case dave.Op_DAT: // STORE INCOMING
				data[hex.EncodeToString(m.Work)] = Dat{m.Val, m.Tag, m.Nonce}
			}
		case <-time.After(PERIOD): // PEER LIVENESS & DISCOVERY
			for kid, k := range prs {
				if !k.bootstrap && time.Since(k.seen) > PERIOD*TOLERANCE*TOLERANCE {
					delete(prs, kid)
					fmt.Println("dropped", kid)
				} else if time.Since(k.seen) > PERIOD {
					wraddr(c, marshal(&dave.M{Op: dave.Op_GETPEER}), addrPortFrom(k.pd))
				}
			}
		case stat <- &Stat{uint32(len(prs))}: // STATUS
		}
	}
}

func lstn(conn *net.UDPConn) <-chan packet {
	pkts := make(chan packet, 100)
	go func() {
		pool := sync.Pool{New: func() interface{} { return &dave.M{} }}
		f := ckoo.NewFilter(FILTER_CAP)
		reset := time.Now()
		h := sha256.New()
		defer conn.Close()
		for {
			if time.Since(reset) > PERIOD {
				f.Reset()
				reset = time.Now()
			}
			buf := make([]byte, MTU)
			n, raddr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				panic(err)
			}
			m := pool.Get().(*dave.M)
			err = proto.Unmarshal(buf[:n], m)
			if err != nil {
				fmt.Println("lstn unmarshal err:", err)
				pool.Put(m)
				continue
			}
			if m.Op == dave.Op_PEER && len(m.Pds) > NPEER {
				pool.Put(m)
				continue
			}
			h.Reset()
			h.Write([]byte(m.Op.String()))
			if m.Op == dave.Op_PEER || m.Op == dave.Op_GETPEER {
				eb := make([]byte, 8)
				binary.BigEndian.PutUint64(eb, uint64(time.Now().Unix())) // PERIOD=1s
				h.Write(eb)
				rab := raddr.Addr().As16()
				h.Write(rab[:])
				s := h.Sum(nil)
				if !f.InsertUnique(s) {
					pool.Put(m)
					continue
				}
			} else { // DAT, GETDAT, SETDAT
				rab := raddr.Addr().As16()
				h.Write(rab[:])
				h.Write(m.Work)
				if !f.InsertUnique(h.Sum(nil)) {
					fmt.Println(m.Op, "dat seen, dropped")
					pool.Put(m)
					continue
				}
				if m.Op == dave.Op_SETDAT && CheckMsg(m) < MINWORK {
					fmt.Println("work invalid, dropped")
					pool.Put(m)
					continue
				}
				if m.Op == dave.Op_GETDAT || m.Op == dave.Op_SETDAT {
					pd := pdFrom(raddr)
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
			pkts <- packet{copy, raddr}
			pool.Put(m)
		}
	}()
	return pkts
}

func rndPds(peers map[string]*peer, exclude []*dave.Pd, limit int, match func(*peer) bool) []*dave.Pd {
	excludeMap := make(map[string]struct{}, len(exclude))
	for _, pexcl := range exclude {
		excludeMap[pdStr(pexcl)] = struct{}{}
	}
	candidates := make([]*dave.Pd, 0, len(peers))
	for _, k := range peers {
		if match(k) {
			if _, ok := excludeMap[pdStr(k.pd)]; !ok {
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
	return k.bootstrap || time.Since(k.seen) < PERIOD && time.Since(k.added) > SHARE_DELAY
}

func addrPortFrom(pd *dave.Pd) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(pd.Ip)), uint16(pd.Port))
}

func pdFrom(addrport netip.AddrPort) *dave.Pd {
	ip := addrport.Addr().As16()
	return &dave.Pd{Ip: ip[:], Port: uint32(addrport.Port())}
}

func pdStr(p *dave.Pd) string {
	return strings.TrimLeft(hex.EncodeToString(p.Ip), "0") + ":" + strconv.Itoa(int(p.Port))
}

func wraddr(conn *net.UDPConn, payload []byte, addr netip.AddrPort) {
	time.Sleep(time.Microsecond * 250)
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
