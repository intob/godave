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
	TOLERANCE     = 2
	WORK_MIN      = 3
	BOOTSTRAP_MSG = 8
)

type Dave struct {
	Send chan<- *davepb.Msg
	Recv <-chan *davepb.Msg
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
			msg.Work = h.Sum(nil)
			if bytes.HasPrefix(msg.Work, zeros) {
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
	if !bytes.Equal(h.Sum(nil), msg.Work) {
		return -1
	}
	if bytesToTime(msg.Time).After(time.Now()) {
		return -2
	}
	return getPrefixLen(msg.Work)
}

func dave(conn *net.UDPConn, peers map[netip.AddrPort]*peer,
	pkts <-chan packet, send <-chan *davepb.Msg) <-chan *davepb.Msg {
	recv := make(chan *davepb.Msg, 1)
	go func() {
		data := make(map[string]*Dat)
		for {
			select {
			case msend := <-send:
				switch msend.Op {
				case davepb.Op_SETDAT:
					for _, rad := range randomAddrs(peers, nil, FANOUT_SETDAT) {
						writeAddr(conn, marshal(msend), parseAddr(rad))
					}
				case davepb.Op_GETDAT:
					for _, rad := range randomAddrs(peers, nil, FANOUT_GETDAT) {
						writeAddr(conn, marshal(msend), parseAddr(rad))
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
				case davepb.Op_ADDR:
					for _, maddrstr := range m.Addrs {
						maddr := parseAddr(maddrstr)
						_, ok := peers[maddr]
						if !ok {
							peers[maddr] = &peer{}
						}
					}
				case davepb.Op_GETADDR:
					writeAddr(conn, marshal(&davepb.Msg{
						Op:    davepb.Op_ADDR,
						Addrs: randomAddrs(peers, []string{pkt.ip.String()}, NADDR),
					}), pkt.ip)
				case davepb.Op_SETDAT:
					if CheckWork(m) >= WORK_MIN {
						data[hex.EncodeToString(m.Work)] = &Dat{m.Val, m.Time, m.Nonce}
						if len(m.Addrs) < FWD_DIST {
							for _, rad := range randomAddrs(peers, m.Addrs, FANOUT_SETDAT) {
								writeAddr(conn, marshal(m), parseAddr(rad))
							}
						}
					}
				case davepb.Op_GETDAT:
					d, ok := data[hex.EncodeToString(m.Work)]
					if ok {
						for _, addr := range m.Addrs {
							writeAddr(conn, marshal(&davepb.Msg{
								Op:    davepb.Op_DAT,
								Val:   d.Val,
								Time:  d.Time,
								Nonce: d.Nonce,
								Work:  m.Work,
							}), parseAddr(addr))
						}
					} else if len(m.Addrs) < FWD_DIST {
						for _, rad := range randomAddrs(peers, m.Addrs, FANOUT_GETDAT) {
							writeAddr(conn, marshal(m), parseAddr(rad))
						}
					}
				case davepb.Op_DAT:
					fmt.Printf("work: %d of %d\n", CheckWork(m), WORK_MIN)
				}
				recv <- m
			case <-time.After(PING_PERIOD):
				q, qip := random(peers)
				ping(conn, q, qip)
				for ip, p := range peers {
					if !p.bootstrap && p.nping > TOLERANCE {
						p.drop += 1
						p.nping = 0
						if p.drop > 3*TOLERANCE {
							delete(peers, ip)
						}
					}
				}
			}
		}
	}()
	return recv
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
		c := candidates[r]
		_, already := mygs[c]
		if !already {
			ans = append(ans, c)
		}
	}
	return ans
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
	pkts := make(chan packet, 1)
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
			pkts <- packet{msg, raddr}
		}
	}()
	return pkts
}

func writeAddr(conn *net.UDPConn, payload []byte, addr netip.AddrPort) error {
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
