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
	"time"

	"github.com/intob/dave/godave/dave"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	PERIOD                 = 127713920 * time.Nanosecond // Heartbeat
	PACKET_SIZE            = 1500                        // Size of buffer
	VAL_SIZE               = 1280                        // Maximum size of
	NPEER                  = 3                           // Number of peers to give
	TOLERANCE              = 2                           // Threshold of peer.nping to increment peer.drop
	DROP                   = 4                           // Tolerance multiplier
	DISTANCE               = 7                           // Number of forwards per packet
	FANOUT_GETDAT          = 2                           // Number of peers to forward GETDATs
	FANOUT_SETDAT          = 2                           // Number of peers to forward SETDATs
	WORK_MIN_FANOUT        = 2                           // Looks good for now
	DEFAULT_WORK_MIN_STORE = 3                           // Looks good for now
)

type Dave struct {
	Send chan<- *dave.Msg
	Recv <-chan *dave.Msg
}

type Dat struct {
	Prev  []byte
	Val   []byte
	Tag   []byte
	Time  []byte
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

func NewDave(port int, bootstrap []netip.AddrPort) (*Dave, error) {
	laddr, err := net.ResolveUDPAddr("udp6", fmt.Sprintf("[::1]:%d", port))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp6", laddr)
	if err != nil {
		return nil, err
	}
	fmt.Printf("listening %s\n", conn.LocalAddr())
	peers := make(map[netip.AddrPort]*peer)
	for _, ip := range bootstrap {
		peers[ip] = &peer{time.Time{}, 0, true, 0}
	}
	send := make(chan *dave.Msg, 1)
	return &Dave{send, d(conn, peers, lstn(conn), send)}, nil
}

func Work(msg *dave.Msg, work int) (<-chan *dave.Msg, error) {
	if len(marshal(msg)) >= PACKET_SIZE {
		return nil, fmt.Errorf("msg exceeds packet size of %dB", PACKET_SIZE)
	}
	if CheckWork(msg) < -1 {
		return nil, fmt.Errorf("msg is invalid")
	}
	result := make(chan *dave.Msg)
	go func() {
		zeros := make([]byte, work)
		msg.Nonce = make([]byte, 32)
		msg.Time = timeToBytes(time.Now())
		h := sha256.New()
		h.Write(msg.Prev)
		h.Write(msg.Val)
		h.Write(msg.Tag)
		h.Write(msg.Time)
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
	if len(msg.Nonce) != 0 && len(msg.Nonce) != 32 {
		return -2
	}
	if len(msg.Prev) != 0 && len(msg.Prev) != 32 {
		return -3
	}
	if len(msg.Time) != 0 && len(msg.Time) != 8 {
		return -4
	}
	if bytesToTime(msg.Time).After(time.Now()) {
		return -5
	}
	h := sha256.New()
	h.Write(msg.Prev)
	h.Write(msg.Val)
	h.Write(msg.Tag)
	h.Write(msg.Time)
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
	pkts <-chan packet, send <-chan *dave.Msg) <-chan *dave.Msg {
	recv := make(chan *dave.Msg, 1)
	go func() {
		data := make(map[string]*Dat)
		for {
			select {
			case msend := <-send:
				switch msend.Op {
				case dave.Op_SETDAT:
					for _, rad := range rndAddr(peers, nil, FANOUT_SETDAT) {
						wraddr(conn, marshal(msend), parseAddr(rad))
					}
				case dave.Op_GETDAT:
					for _, rad := range rndAddr(peers, nil, FANOUT_GETDAT) {
						wraddr(conn, marshal(msend), parseAddr(rad))
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
					wraddr(conn, marshal(&dave.Msg{
						Op:    dave.Op_PEER,
						Peers: rndAddr(peers, []string{pkt.ip.String()}, NPEER),
					}), pkt.ip)
				case dave.Op_SETDAT:
					if CheckWork(m) >= DEFAULT_WORK_MIN_STORE {
						data[hex.EncodeToString(m.Work)] = &Dat{m.Prev, m.Val, m.Tag, m.Time, m.Nonce}
					}
					if CheckWork(m) >= WORK_MIN_FANOUT && len(m.Peers) < DISTANCE {
						for _, rad := range rndAddr(peers, m.Peers, FANOUT_SETDAT) {
							wraddr(conn, marshal(m), parseAddr(rad))
						}
					}
				case dave.Op_GETDAT:
					d, ok := data[hex.EncodeToString(m.Work)]
					if ok {
						for _, addr := range m.Peers {
							wraddr(conn, marshal(&dave.Msg{Op: dave.Op_DAT, Prev: d.Prev, Val: d.Val,
								Tag: d.Tag, Time: d.Time, Nonce: d.Nonce, Work: m.Work}), parseAddr(addr))
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
			buf := make([]byte, PACKET_SIZE)
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
	if q != nil && time.Since(q.seen) > TOLERANCE*PERIOD*DROP {
		q.nping += 1
		wraddr(conn, marshal(&dave.Msg{
			Op: dave.Op_GETPEER,
		}), qip)
	}
}

func rndAddr(peers map[netip.AddrPort]*peer, exclude []string, limit int) []string {
	candidates := make([]string, 0)
	for ip, p := range peers {
		if !in(ip.String(), exclude) && p.drop <= 1 && p.nping <= 1 {
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

func timeToBytes(t time.Time) []byte {
	milli := t.UnixNano() / 1000000
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, uint64(milli))
	return bytes
}

func bytesToTime(b []byte) time.Time {
	if len(b) != 8 {
		return time.Time{}
	}
	milli := int64(binary.BigEndian.Uint64(b))
	return time.Unix(0, milli*1000000)
}
