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
	"sync"
	"time"

	"github.com/intob/dave/godave/dave"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	PERIOD          = 333333 * time.Microsecond
	LEN_PACKET      = 1500
	LEN_VAL         = 1250
	NPEER           = 2
	TOLERANCE       = 1
	DROP            = 5
	DISTANCE        = 6
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

type known struct {
	peer      *dave.Peer
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
	peers := make(map[string]*known)
	for _, ap := range bootstrap {
		p := peerFrom(ap)
		peers[peerId(p)] = &known{p, time.Time{}, 0, true, 0}
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

func d(conn *net.UDPConn, peers map[string]*known,
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
						for _, rp := range rndPeers(peers, nil, FANOUT_SETDAT*SEND_FACTOR) {
							wraddr(conn, marshal(msend), parsePeer(rp))
						}
					case dave.Op_GETDAT:
						for _, rp := range rndPeers(peers, nil, FANOUT_GETDAT*SEND_FACTOR) {
							wraddr(conn, marshal(msend), parsePeer(rp))
						}
					}
				}
			case pkt := <-pkts:
				pktpeer := peerFrom(pkt.ip)
				pktpid := peerId(pktpeer)
				kp, ok := peers[pktpid]
				if ok {
					kp.seen = time.Now()
					kp.nping = 0
					kp.drop = 0
				} else {
					peers[pktpid] = &known{peer: pktpeer}
					fmt.Println("<-pkts added", pktpid)
				}
				m := pkt.msg
				switch m.Op {
				case dave.Op_PEER:
					for _, p := range m.Peers {
						pid := peerId(p)
						_, ok := peers[pid]
						if !ok {
							peers[pid] = &known{peer: pktpeer}
							fmt.Println("<-pkts added gossip", pid)
						}
					}
				case dave.Op_GETPEER:
					wraddr(conn, marshal(&dave.Msg{Op: dave.Op_PEER, Peers: rndPeers(peers, []*dave.Peer{pktpeer}, NPEER)}), pkt.ip)
				case dave.Op_SETDAT:
					check := CheckWork(m)
					if check >= work {
						data[hex.EncodeToString(m.Work)] = &Dat{m.Prev, m.Val, m.Tag, m.Nonce}
					} else {
						panic(fmt.Sprintf("work invalid: %d", check))
					}
					if check >= WORK_MIN_FANOUT && len(m.Peers) < DISTANCE {
						for _, rp := range rndPeers(peers, m.Peers, FANOUT_SETDAT) {
							wraddr(conn, marshal(m), parsePeer(rp))
						}
					}
				case dave.Op_GETDAT:
					d, ok := data[hex.EncodeToString(m.Work)]
					if ok {
						for _, mp := range m.Peers {
							wraddr(conn, marshal(&dave.Msg{Op: dave.Op_DAT, Prev: d.Prev, Val: d.Val,
								Tag: d.Tag, Nonce: d.Nonce, Work: m.Work}), parsePeer(mp))
						}
					} else if len(m.Peers) < DISTANCE {
						for _, rp := range rndPeers(peers, m.Peers, FANOUT_GETDAT) {
							wraddr(conn, marshal(m), parsePeer(rp))
						}
					}
				case dave.Op_DAT:
					if CheckWork(m) >= work {
						data[hex.EncodeToString(m.Work)] = &Dat{m.Prev, m.Val, m.Tag, m.Nonce}
					} else {
						panic(fmt.Sprintf("work invalid: %d", CheckWork(m)))
					}
				}
				recv <- m
			case <-time.After(PERIOD):
				ping(conn, rndPeer(peers))
				for pid, p := range peers {
					if !p.bootstrap && p.nping > TOLERANCE {
						p.drop += 1
						p.nping = 0
						if p.drop > DROP*TOLERANCE {
							delete(peers, pid)
							fmt.Println("dropped", pid)
						}
					}
				}
			}
		}
	}()
	return recv
}

func peerId(p *dave.Peer) string {
	return hex.EncodeToString(p.Ip) + ":" + strconv.Itoa(int(p.Port))
}

func lstn(conn *net.UDPConn) <-chan packet {
	pkts := make(chan packet, 1)
	go func() {
		msgPool := sync.Pool{
			New: func() interface{} {
				return &dave.Msg{}
			},
		}
		defer conn.Close()
		for {
			buf := make([]byte, LEN_PACKET)
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
				rp := peerFrom(raddr)
				if len(msg.Peers) == 0 {
					msg.Peers = []*dave.Peer{rp}
				} else {
					msg.Peers = append(msg.Peers, rp)
				}
			}
			pkts <- packet{msg, raddr}
			msgPool.Put(msg)
		}
	}()
	return pkts
}

func ping(conn *net.UDPConn, k *known) {
	if k != nil && time.Since(k.seen) > PERIOD {
		k.nping += 1
		wraddr(conn, marshal(&dave.Msg{Op: dave.Op_GETPEER}), parsePeer(k.peer))
	}
}

func rndPeers(knownPeers map[string]*known, exclude []*dave.Peer, limit int) []*dave.Peer {
	excludeMap := make(map[string]struct{}, len(exclude))
	for _, pexcl := range exclude {
		excludeMap[peerId(pexcl)] = struct{}{}
	}
	candidates := make([]*dave.Peer, 0, len(knownPeers))
	for _, k := range knownPeers {
		if !k.bootstrap && k.drop == 0 && k.nping <= TOLERANCE {
			if _, ok := excludeMap[peerId(k.peer)]; !ok {
				candidates = append(candidates, k.peer)
			}
		}
	}
	if len(candidates) <= limit {
		return candidates
	}
	ans := make([]*dave.Peer, limit)
	for i := 0; i < limit; i++ {
		r := i + mrand.Intn(len(candidates)-i)
		ans[i] = candidates[r]
		candidates[r] = candidates[i]
	}
	return ans
}

func rndPeer(peers map[string]*known) *known {
	var r, j int
	if len(peers) > 1 {
		r = mrand.Intn(len(peers) - 1)
	}
	for _, k := range peers {
		if r == j {
			return k
		}
		j++
	}
	return nil
}

func wraddr(conn *net.UDPConn, payload []byte, addr netip.AddrPort) error {
	_, err := conn.WriteToUDPAddrPort(payload, addr)
	return err
}

func parsePeer(peer *dave.Peer) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(peer.Ip)), uint16(peer.Port))
}

func peerFrom(raddr netip.AddrPort) *dave.Peer {
	ip := raddr.Addr().As16()
	return &dave.Peer{Ip: ip[:], Port: uint32(raddr.Port())}
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
