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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	PERIOD        = time.Second
	MTU           = 1500
	LEN_VAL       = 1200 /* When DISTANCE=7, 1230 is max */
	NPEER         = 2
	TOLERANCE     = 3
	DISTANCE      = 7
	FANOUT_GETDAT = 2
	FANOUT_SETDAT = 2
	MINWORK       = 2
)

type Dave struct {
	Send chan<- *dave.Msg
	Recv <-chan *dave.Msg
}

type Dat struct {
	Prev  []byte
	Val   []byte
	Tag   []byte
	Nonce []byte
}

type peer struct {
	pd        *dave.Pd
	added     time.Time
	seen      time.Time
	bootstrap bool
}

type packet struct {
	msg *dave.Msg
	ip  netip.AddrPort
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
	send := make(chan *dave.Msg)
	recv := make(chan *dave.Msg, 1)
	go d(conn, boot, lstn(conn), send, recv)
	for _, bap := range baps {
		wraddr(conn, marshal(&dave.Msg{Op: dave.Op_GETPEER}), bap)
	}
	return &Dave{send, recv}, nil
}

func Work(msg *dave.Msg, work int) (<-chan *dave.Msg, error) {
	result := make(chan *dave.Msg)
	go func() {
		zeros := make([]byte, work)
		msg.Nonce = make([]byte, 32)
		h := sha256.New()
		h.Write(msg.Prev)
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

func CheckWork(msg *dave.Msg) int {
	h := sha256.New()
	h.Write(msg.Prev)
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

func seenRecently(k *peer) bool {
	return time.Since(k.seen) < PERIOD
}

func d(c *net.UDPConn, ks map[string]*peer, pch <-chan packet, send <-chan *dave.Msg, recv chan<- *dave.Msg) {
	data := make(map[string]Dat)
	for {
		select {
		case msend := <-send: // SEND PACKET
			if msend != nil {
				switch msend.Op {
				case dave.Op_SETDAT:
					for _, rp := range rndPds(ks, nil, FANOUT_SETDAT, seenRecently) {
						wraddr(c, marshal(msend), addrPortFrom(rp))
						fmt.Println("SENT TO", pdStr(rp))
					}
				case dave.Op_GETDAT:
					for _, rp := range rndPds(ks, nil, FANOUT_GETDAT, seenRecently) {
						wraddr(c, marshal(msend), addrPortFrom(rp))
						fmt.Println("SENT TO", pdStr(rp))
					}
				}
			}
		case pkt := <-pch: // HANDLE INCOMING PACKET
			recv <- pkt.msg
			pd := pdFrom(pkt.ip)
			pktpid := pdStr(pd)
			_, ok := ks[pktpid]
			if !ok {
				ks[pktpid] = &peer{pd: pd, added: time.Now()}
				fmt.Println("<-pkts added", pktpid)
			}
			ks[pktpid].seen = time.Now()
			m := pkt.msg
			switch m.Op {
			case dave.Op_PEER: // STORE PEERS
				for i, pd := range m.Pds {
					if i >= NPEER {
						break // don't get poisoned
					}
					pid := pdStr(pd)
					_, ok := ks[pid]
					if !ok {
						ks[pid] = &peer{pd: pd, added: time.Now(), seen: time.Now()}
						fmt.Println("<-pkts added gossip", pid)
					}
				}
			case dave.Op_GETPEER: // GIVE PEERS
				randpds := rndPds(ks, []*dave.Pd{pd}, NPEER, seenRecently)
				wraddr(c, marshal(&dave.Msg{Op: dave.Op_PEER, Pds: randpds}), pkt.ip)
			case dave.Op_SETDAT:
				check := CheckWork(m)
				if check < MINWORK {
					fmt.Printf("dropped SETDAT: require %d, has %d\n", MINWORK, check)
					continue
				}
				data[hex.EncodeToString(m.Work)] = Dat{m.Prev, m.Val, m.Tag, m.Nonce}
				if len(m.Pds) < DISTANCE {
					for _, fp := range rndPds(ks, m.Pds, FANOUT_SETDAT, seenRecently) {
						wraddr(c, marshal(m), addrPortFrom(fp))
					}
				}
			case dave.Op_GETDAT: // RETURN DAT OR FORWARD
				if nzero(m.Work) < MINWORK {
					fmt.Printf("dropped GETDAT: require %d, has %d\n", MINWORK, nzero(m.Work))
					continue
				}
				d, ok := data[hex.EncodeToString(m.Work)]
				if ok {
					for _, mp := range m.Pds {
						wraddr(c, marshal(&dave.Msg{Op: dave.Op_DAT, Prev: d.Prev, Val: d.Val,
							Tag: d.Tag, Nonce: d.Nonce, Work: m.Work}), addrPortFrom(mp))
					}
				} else if len(m.Pds) < DISTANCE {
					for _, fp := range rndPds(ks, m.Pds, FANOUT_GETDAT, seenRecently) {
						wraddr(c, marshal(m), addrPortFrom(fp))
					}
				}
			case dave.Op_DAT: // STORE INCOMING
				check := CheckWork(m)
				if check < MINWORK {
					fmt.Printf("dropped DAT: require %d, has %d\n", MINWORK, check)
					continue
				}
				data[hex.EncodeToString(m.Work)] = Dat{m.Prev, m.Val, m.Tag, m.Nonce}
			}
		case <-time.After(PERIOD):
			for kid, k := range ks {
				if !k.bootstrap && time.Since(k.seen) > PERIOD*TOLERANCE*TOLERANCE {
					delete(ks, kid)
					fmt.Println("dropped", kid)
				} else if time.Since(k.seen) > PERIOD {
					wraddr(c, marshal(&dave.Msg{Op: dave.Op_GETPEER}), addrPortFrom(k.pd))
				}
			}
		}
	}
}

func lstn(conn *net.UDPConn) <-chan packet {
	pkts := make(chan packet, 100)
	go func() {
		msgPool := sync.Pool{New: func() interface{} { return &dave.Msg{} }}
		defer conn.Close()
		for {
			buf := make([]byte, MTU)
			n, raddr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				panic(err)
			}
			msg := msgPool.Get().(*dave.Msg)
			err = proto.Unmarshal(buf[:n], msg)
			if err != nil {
				fmt.Println("lstn unmarshal err:", err)
				msgPool.Put(msg)
				continue
			}
			if msg.Op == dave.Op_SETDAT || msg.Op == dave.Op_GETDAT {
				pd := pdFrom(raddr)
				if len(msg.Pds) == 0 {
					msg.Pds = []*dave.Pd{pd}
				} else {
					msg.Pds = append(msg.Pds, pd)
				}
			}
			pkts <- packet{msg, raddr}
			msgPool.Put(msg)
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
