package godave

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/intob/dave/godave/davepb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	PACKET_SIZE   = 2048
	FANOUT_GETDAT = 2
	FANOUT_SETDAT = 2
	FWD_DIST      = 7
	NADDR         = 3
	PING_PERIOD   = 127713920 * time.Nanosecond
	TOLERANCE     = 8
	WORK_MIN      = 3
	BOOTSTRAP_MSG = 8
)

type Dave struct {
	send  chan<- *davepb.Msg
	msgch <-chan *davepb.Msg
}

type Dat struct {
	Val   []byte
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
	msg *davepb.Msg
	ip  netip.AddrPort
}

func (d *Dave) Send(msg *davepb.Msg) error {
	switch msg.Op {
	case davepb.Op_SETDAT:
	case davepb.Op_GETDAT:
		d.send <- msg
	default:
		return fmt.Errorf("sending %v is not supported", msg.Op)
	}
	return nil
}

func (d *Dave) Msgch() <-chan *davepb.Msg {
	return d.msgch
}

func NewDave(port int, bootstrap []netip.AddrPort) (*Dave, error) {
	laddr, err := net.ResolveUDPAddr("udp6", fmt.Sprintf("[::1]:%d", port))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp6", laddr)
	if err != nil {
		laddr, err = net.ResolveUDPAddr("udp6", ":0")
		if err != nil {
			return nil, err
		}
		conn, err = net.ListenUDP("udp6", laddr)
		if err != nil {
			return nil, err
		}
	}
	fmt.Printf("listening %s\n", conn.LocalAddr())
	packetRelay := listen(conn)
	peers := make(map[netip.AddrPort]*peer)
	for _, ip := range bootstrap {
		peers[ip] = &peer{time.Time{}, 0, true, 0}
	}
	send := make(chan *davepb.Msg, 1)
	return &Dave{send, dave(conn, peers, packetRelay, send)}, nil
}

func Work(msg *davepb.Msg, work int) (<-chan *davepb.Msg, error) {
	if len(marshal(msg)) >= PACKET_SIZE {
		return nil, fmt.Errorf("msg exceeds packet size of %dB", PACKET_SIZE)
	}
	result := make(chan *davepb.Msg)
	go func() {
		zeros := make([]byte, work)
		msg.Time = timeToBytes(time.Now())
		msg.Nonce = make([]byte, 32)
		valSum := sha256.Sum256(msg.Val)
		h := sha256.New()
		for {
			crand.Read(msg.Nonce)
			h.Reset()
			h.Write(valSum[:])
			h.Write(msg.Time)
			h.Write(msg.Nonce)
			msg.Key = h.Sum(nil)
			if bytes.HasPrefix(msg.Key, zeros) {
				result <- msg
				return
			}
		}
	}()
	return result, nil
}

func CheckWork(msg *davepb.Msg) int {
	valSum := sha256.Sum256(msg.Val)
	h := sha256.New()
	h.Write(valSum[:])
	h.Write(msg.Time)
	h.Write(msg.Nonce)
	if !bytes.Equal(h.Sum(nil), msg.Key) {
		return -1
	}
	if bytesToTime(msg.Time).After(time.Now()) {
		return -2
	}
	return getPrefixLen(msg.Key)
}

func dave(conn *net.UDPConn, peers map[netip.AddrPort]*peer, pktsch <-chan packet, sendch <-chan *davepb.Msg) <-chan *davepb.Msg {
	msgch := make(chan *davepb.Msg, 1)
	go func() {
		for {
			select {
			case pkt := <-pktsch:
				p, ok := peers[pkt.ip]
				if ok {
					p.seen = time.Now()
					p.nping = 0
					p.drop = 0
				} else {
					peers[pkt.ip] = &peer{}
				}
				for _, maddrstr := range pkt.msg.Addrs {
					maddr := parseAddr(maddrstr)
					_, ok := peers[maddr]
					if !ok {
						peers[maddr] = &peer{}
					}
				}
				switch pkt.msg.Op {
				case davepb.Op_GETADDR:
					writeAddr(conn, marshal(&davepb.Msg{
						Op:    davepb.Op_ADDR,
						Addrs: randomAddrs(peers, []string{pkt.ip.String()}, NADDR),
					}), pkt.ip)
				case davepb.Op_SETDAT:
					if len(pkt.msg.Addrs) < FWD_DIST && CheckWork(pkt.msg) >= WORK_MIN {
						for _, rad := range randomAddrs(peers, pkt.msg.Addrs, FANOUT_SETDAT) {
							writeAddr(conn, marshal(pkt.msg), parseAddr(rad))
						}
					}
				case davepb.Op_GETDAT:
					if len(pkt.msg.Addrs) < FWD_DIST {
						for _, rad := range randomAddrs(peers, pkt.msg.Addrs, FANOUT_GETDAT) {
							writeAddr(conn, marshal(pkt.msg), parseAddr(rad))
						}
					}
				case davepb.Op_DAT:
					work := CheckWork(pkt.msg)
					fmt.Printf("work: %d of %d\n", work, WORK_MIN)
				}
				msgch <- &davepb.Msg{
					Op:    pkt.msg.Op,
					Addrs: pkt.msg.Addrs,
					Val:   pkt.msg.Val,
					Time:  pkt.msg.Time,
					Nonce: pkt.msg.Nonce,
					Key:   pkt.msg.Key,
				}
			case msend := <-sendch:
				payload := marshal(msend)
				switch msend.Op {
				case davepb.Op_SETDAT:
					for _, rad := range randomAddrs(peers, nil, FANOUT_SETDAT) {
						writeAddr(conn, payload, parseAddr(rad))
					}
				case davepb.Op_GETDAT:
					for _, rad := range randomAddrs(peers, nil, FANOUT_GETDAT) {
						writeAddr(conn, payload, parseAddr(rad))
					}
				}
			case <-time.After(PING_PERIOD):
				q, qip := random(peers)
				ping(conn, q, qip)
				for ip, p := range peers {
					if !p.bootstrap && p.nping > TOLERANCE {
						p.drop += 1
						if p.drop > TOLERANCE*2 {
							delete(peers, ip)
						}
					}
				}
			}
		}
	}()
	return msgch
}

func ping(conn *net.UDPConn, q *peer, qip netip.AddrPort) {
	if q != nil {
		q.nping += 1
		writeAddr(conn, marshal(&davepb.Msg{
			Op: davepb.Op_GETADDR,
		}), qip)
	}
}

func randomAddrs(peers map[netip.AddrPort]*peer, exclude []string, limit int) []string {
	n := len(peers) - len(exclude)
	if n <= 0 {
		return []string{}
	}
	if n > limit {
		n = limit
	}
	mygs := make(map[netip.AddrPort]string)
	next := make([]string, 0)
	for len(next) < n {
		r := mrand.Intn(len(peers) - 1)
		j := 0
		for ip, p := range peers {
			_, already := mygs[ip]
			ipstr := ip.String()
			if j == r && !already && !in(ipstr, exclude) && p.nping <= 1 {
				mygs[ip] = ipstr
				next = append(next, ipstr)
				break
			}
			j++
		}
	}
	return next
}

func random(peers map[netip.AddrPort]*peer) (*peer, netip.AddrPort) {
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

func listen(conn *net.UDPConn) <-chan packet {
	msgch := make(chan packet, 1)
	go func() {
		defer conn.Close()
		for {
			buf := make([]byte, PACKET_SIZE)
			n, raddr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				panic(err)
			}
			msg := &davepb.Msg{}
			err = proto.Unmarshal(buf[:n], msg)
			if err != nil {
				panic(err)
			}
			if msg.Op != davepb.Op_ADDR {
				if len(msg.Addrs) == 0 {
					msg.Addrs = []string{raddr.String()}
				} else {
					msg.Addrs = append(msg.Addrs, raddr.String())
				}
			}
			msgch <- packet{msg, raddr}
		}
	}()
	return msgch
}

func writeAddr(conn *net.UDPConn, payload []byte, addr netip.AddrPort) {
	_, err := conn.WriteToUDPAddrPort(payload, addr)
	if err != nil {
		panic(err)
	}
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

func getPrefixLen(key []byte) int {
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

func bytesToTime(bytes []byte) time.Time {
	milli := int64(binary.BigEndian.Uint64(bytes))
	return time.Unix(0, milli*1000000)
}
