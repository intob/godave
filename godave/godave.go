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
	PERIOD        = 100 * time.Millisecond
	LEN_PACKET    = 1500
	LEN_VAL       = 1200
	NPEER         = 2
	TOLERANCE     = 2
	DROP          = 12
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

type known struct {
	peer      *dave.Peer
	added     time.Time
	seen      time.Time
	ping      int
	bootstrap bool
	drop      int
	msg       int
}

type packet struct {
	msg *dave.Msg
	ip  netip.AddrPort
}

func NewDave(laddr *net.UDPAddr, bootstrap []netip.AddrPort) (*Dave, error) {
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	fmt.Printf("listening %s\n", conn.LocalAddr())
	peers := make(map[string]*known)
	for _, ap := range bootstrap {
		p := peerFrom(ap)
		peers[peerId(p)] = &known{peer: p, added: time.Now(), bootstrap: true}
	}
	send := make(chan *dave.Msg)
	recv := make(chan *dave.Msg, 1)
	go d(conn, peers, lstn(conn), send, recv)
	for _, ap := range bootstrap {
		wraddr(conn, marshal(&dave.Msg{Op: dave.Op_GETPEER}), ap)
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

func d(c *net.UDPConn, ks map[string]*known, pch <-chan packet, send <-chan *dave.Msg, recv chan<- *dave.Msg) {
	data := make(map[string]Dat)
	for {
		select {
		case msend := <-send: // SEND PACKET
			if msend != nil {
				switch msend.Op {
				case dave.Op_SETDAT:
					for _, rp := range rndPeers(ks, nil, FANOUT_SETDAT, func(k *known) bool { return k.drop == 0 }) {
						wraddr(c, marshal(msend), parsePeer(rp))
						fmt.Println("SENT TO", peerId(rp))
					}
				case dave.Op_GETDAT:
					for _, rp := range rndPeers(ks, nil, FANOUT_GETDAT, func(k *known) bool { return k.drop == 0 }) {
						wraddr(c, marshal(msend), parsePeer(rp))
						fmt.Println("SENT TO", peerId(rp))
					}
				}
			}
		case pkt := <-pch: // HANDLE INCOMING PACKET
			recv <- pkt.msg
			pktpeer := peerFrom(pkt.ip)
			pktpid := peerId(pktpeer)
			k, ok := ks[pktpid]
			if ok {
				k.seen = time.Now()
				k.ping = 0
				k.drop = max(k.drop-1, 0)
				k.msg++
			} else {
				ks[pktpid] = &known{peer: pktpeer, added: time.Now()}
				fmt.Println("<-pkts added", pktpid)
			}
			m := pkt.msg
			switch m.Op {
			case dave.Op_PEER: // STORE PEERS
				for _, p := range m.Peers {
					pid := peerId(p)
					_, ok := ks[pid]
					if !ok {
						ks[pid] = &known{peer: pktpeer}
						fmt.Println("<-pkts added gossip", pid)
					}
				}
			case dave.Op_GETPEER: // GIVE PEERS
				rps := rndPeers(ks, []*dave.Peer{pktpeer}, NPEER, func(k *known) bool { return k.drop == 0 && time.Since(k.added) > PERIOD*DROP*TOLERANCE && k.msg > 8 })
				wraddr(c, marshal(&dave.Msg{Op: dave.Op_PEER, Peers: rps}), pkt.ip)
			case dave.Op_SETDAT:
				check := CheckWork(m)
				if check < MINWORK {
					fmt.Printf("dropped SETDAT: require %d, has %d\n", MINWORK, check)
					continue
				}
				data[hex.EncodeToString(m.Work)] = Dat{m.Prev, m.Val, m.Tag, m.Nonce}
				if len(m.Peers) < DISTANCE {
					for _, fp := range rndPeers(ks, m.Peers, FANOUT_SETDAT, func(k *known) bool { return k.drop == 0 }) {
						wraddr(c, marshal(m), parsePeer(fp))
					}
				}
			case dave.Op_GETDAT: // RETURN DAT OR FORWARD
				if nzero(m.Work) < MINWORK {
					fmt.Printf("dropped GETDAT: require %d, has %d\n", MINWORK, nzero(m.Work))
					continue
				}
				d, ok := data[hex.EncodeToString(m.Work)]
				if ok {
					for _, mp := range m.Peers {
						wraddr(c, marshal(&dave.Msg{Op: dave.Op_DAT, Prev: d.Prev, Val: d.Val,
							Tag: d.Tag, Nonce: d.Nonce, Work: m.Work}), parsePeer(mp))
					}
				} else if len(m.Peers) < DISTANCE {
					for _, fp := range rndPeers(ks, m.Peers, FANOUT_GETDAT, func(k *known) bool { return k.drop == 0 }) {
						wraddr(c, marshal(m), parsePeer(fp))
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
		case <-time.After(time.Second):
			fmt.Println("PING")
			for kid, k := range ks {
				if k.ping > TOLERANCE {
					k.drop++
					k.ping = 0
				}
				if k.drop > DROP {
					delete(ks, kid)
					fmt.Println("dropped", kid)
				}
			}
			r := rndKnown(ks)
			if r != nil {
				ping(c, r)
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
	wraddr(conn, marshal(&dave.Msg{Op: dave.Op_GETPEER}), parsePeer(k.peer))
	k.ping++
}

func rndPeers(knownPeers map[string]*known, exclude []*dave.Peer, limit int, match func(*known) bool) []*dave.Peer {
	excludeMap := make(map[string]struct{}, len(exclude))
	for _, pexcl := range exclude {
		excludeMap[peerId(pexcl)] = struct{}{}
	}
	candidates := make([]*dave.Peer, 0, len(knownPeers))
	for _, k := range knownPeers {
		if match(k) {
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
	}
	return ans
}

func rndKnown(peers map[string]*known) *known {
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

func parsePeer(peer *dave.Peer) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16([16]byte(peer.Ip)), uint16(peer.Port))
}

func peerFrom(addrport netip.AddrPort) *dave.Peer {
	ip := addrport.Addr().As16()
	return &dave.Peer{Ip: ip[:], Port: uint32(addrport.Port())}
}

func peerId(p *dave.Peer) string {
	return hex.EncodeToString(p.Ip) + ":" + strconv.Itoa(int(p.Port))
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
