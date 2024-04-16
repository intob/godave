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
	"time"

	"github.com/intob/dave/godave/dave"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	PERIOD          = 333333 * time.Microsecond
	LEN_PACKET      = 1500
	LEN_VAL         = 1024
	NPEER           = 2
	TOLERANCE       = 1
	DROP            = 5
	DISTANCE        = 5
	FANOUT_GETDAT   = 2
	FANOUT_SETDAT   = 2
	SEND_FACTOR     = 2
	WORK_MIN_FANOUT = 2
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
	seen      time.Time
	nping     int
	bootstrap bool
	drop      int
}

type packet struct {
	msg *dave.Msg
	ip  netip.AddrPort
}

func NewDave(work int, laddr *net.UDPAddr, bootstrap []netip.AddrPort) (*Dave, error) {
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	fmt.Printf("listening %s\n", conn.LocalAddr())
	peers := make(map[netip.AddrPort]*peer)
	for _, ip := range bootstrap {
		peers[ip] = &peer{time.Time{}, 0, true, 0}
	}
	send := make(chan *dave.Msg)
	return &Dave{send, d(conn, peers, lstn(conn), send, work)}, nil
}

func Work(msg *dave.Msg, work int) (<-chan *dave.Msg, error) {
	if CheckWork(msg) < -1 {
		return nil, fmt.Errorf("msg is invalid")
	}
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
	if len(msg.Prev) != 0 && len(msg.Prev) != 32 {
		return -2
	}
	if len(msg.Val) != 0 && len(msg.Val) > LEN_VAL {
		return -3
	}
	if len(msg.Tag) > 32 {
		return -4
	}
	if len(msg.Nonce) != 0 && len(msg.Nonce) != 32 {
		return -5
	}
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

func d(conn *net.UDPConn, peers map[netip.AddrPort]*peer,
	pkts <-chan packet, send <-chan *dave.Msg, work int) <-chan *dave.Msg {
	recv := make(chan *dave.Msg, 1)
	go func() {
		data := make(map[string]*Dat)
		for {
			select {
			case msend := <-send:
				if msend != nil {
					switch msend.Op {
					case dave.Op_SETDAT:
						for _, rad := range rndAddr(peers, nil, FANOUT_SETDAT*SEND_FACTOR) {
							wraddr(conn, marshal(msend), parseAddr(rad))
							fmt.Println("sent to", rad)
						}
					case dave.Op_GETDAT:
						for _, rad := range rndAddr(peers, nil, FANOUT_GETDAT*SEND_FACTOR) {
							wraddr(conn, marshal(msend), parseAddr(rad))
							fmt.Println("sent to", rad)
						}
					}
				}
			case pkt := <-pkts:
				p, ok := peers[pkt.ip]
				if ok {
					p.seen = time.Now()
					p.nping = 0
					p.drop = 0
				} else {
					peers[pkt.ip] = &peer{}
					fmt.Println("added", pkt.ip)
				}
				m := pkt.msg
				switch m.Op {
				case dave.Op_PEER:
					for _, addrstr := range m.Peers {
						addr := parseAddr(addrstr)
						_, ok := peers[addr]
						if !ok {
							peers[addr] = &peer{}
						}
					}
				case dave.Op_GETPEER:
					peers := rndAddr(peers, []string{pkt.ip.String()}, NPEER)
					wraddr(conn, marshal(&dave.Msg{Op: dave.Op_PEER, Peers: peers}), pkt.ip)
				case dave.Op_SETDAT:
					check := CheckWork(m)
					if check >= work {
						data[hex.EncodeToString(m.Work)] = &Dat{m.Prev, m.Val, m.Tag, m.Nonce}
					} else {
						panic(fmt.Sprintf("work invalid: %d", check))
					}
					if check >= WORK_MIN_FANOUT && len(m.Peers) < DISTANCE {
						for _, rad := range rndAddr(peers, m.Peers, FANOUT_SETDAT) {
							wraddr(conn, marshal(m), parseAddr(rad))
						}
					}
				case dave.Op_GETDAT:
					d, ok := data[hex.EncodeToString(m.Work)]
					if ok {
						for _, addr := range m.Peers {
							wraddr(conn, marshal(&dave.Msg{Op: dave.Op_DAT, Prev: d.Prev, Val: d.Val,
								Tag: d.Tag, Nonce: d.Nonce, Work: m.Work}), parseAddr(addr))
						}
					} else if len(m.Peers) < DISTANCE {
						for _, rad := range rndAddr(peers, m.Peers, FANOUT_GETDAT) {
							wraddr(conn, marshal(m), parseAddr(rad))
						}
					}
				}
				recv <- m
			case <-time.After(PERIOD):
				q, qip := rndPeer(peers)
				ping(conn, q, qip)
				for ip, p := range peers {
					if !p.bootstrap && p.nping > TOLERANCE {
						p.drop += 1
						p.nping = 0
						if p.drop > DROP*TOLERANCE {
							delete(peers, ip)
						}
					}
				}
			}
		}
	}()
	return recv
}

func lstn(conn *net.UDPConn) <-chan packet {
	pkts := make(chan packet, 1)
	go func() {
		defer conn.Close()
		for {
			buf := make([]byte, LEN_PACKET)
			n, raddr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				panic(err)
			}
			msg := &dave.Msg{}
			err = proto.Unmarshal(buf[:n], msg)
			if err != nil {
				panic(err)
			}
			if msg.Op == dave.Op_SETDAT || msg.Op == dave.Op_GETDAT {
				if len(msg.Peers) == 0 {
					msg.Peers = []string{raddr.String()}
				} else {
					msg.Peers = append(msg.Peers, raddr.String())
				}
			}
			pkts <- packet{msg, raddr}
		}
	}()
	return pkts
}

func ping(conn *net.UDPConn, q *peer, qip netip.AddrPort) {
	if q != nil && time.Since(q.seen) > PERIOD {
		q.nping += 1
		wraddr(conn, marshal(&dave.Msg{Op: dave.Op_GETPEER}), qip)
	}
}

// buggy as shit
func rndAddr(peers map[netip.AddrPort]*peer, exclude []string, limit int) []string {
	candidates := make([]string, 0, len(peers)-len(exclude))
	for ip, p := range peers {
		// don't overload bootstrap peers
		if !p.bootstrap && p.drop == 0 && p.nping <= TOLERANCE && !in(ip.String(), exclude) {
			candidates = append(candidates, ip.String())
		}
	}
	if len(candidates) == 0 {
		return []string{}
	}
	if len(candidates) == 1 {
		return []string{candidates[0]}
	}
	mygs := make(map[string]struct{})
	ans := make([]string, 0)
	for len(ans) < len(candidates) && len(ans) < limit {
		r := mrand.Intn(len(candidates) - 1)
		_, already := mygs[candidates[r]]
		if !already {
			ans = append(ans, candidates[r])
		}
	}
	return ans
}

func rndPeer(peers map[netip.AddrPort]*peer) (*peer, netip.AddrPort) {
	var r, j int
	if len(peers) > 1 {
		r = mrand.Intn(len(peers) - 1)
	}
	for ip, p := range peers {
		if r == j {
			return p, ip
		}
		j++
	}
	return nil, netip.AddrPort{}
}

func wraddr(conn *net.UDPConn, payload []byte, addr netip.AddrPort) error {
	_, err := conn.WriteToUDPAddrPort(payload, addr)
	return err
}

func parseAddr(addr string) netip.AddrPort {
	bap, err := netip.ParseAddrPort(addr)
	if err != nil {
		panic(err)
	}
	return bap
}

func marshal(m protoreflect.ProtoMessage) []byte {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func in(m string, n []string) bool {
	for _, nn := range n {
		if nn == m {
			return true
		}
	}
	return false
}

func nzero(key []byte) int {
	for i, j := range key {
		if j != 0 {
			return i
		}
	}
	return len(key)
}
