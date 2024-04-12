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
	PACKET_SIZE    = 2048
	PORT_DEFAULT   = 1618
	FANOUT_GETDAT  = 2
	FANOUT_SETDAT  = 2
	FWD_DIST       = 6
	NADDR          = 3
	PING_PERIOD    = time.Second
	DROP_THRESHOLD = 8
	WORK_MIN       = 3
	BOOTSTRAP_MSG  = 8
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
	ip    netip.AddrPort
	seen  time.Time
	nping int
}

type packet struct {
	msg *davepb.Msg
	ip  netip.AddrPort
}

func (d *Dave) Send(msg *davepb.Msg) {
	d.send <- msg
}

func (d *Dave) Msg() <-chan *davepb.Msg {
	return d.msgch
}

func NewDave(port int, bootstrap []netip.AddrPort) *Dave {
	laddrstr := fmt.Sprintf(":%d", port)
	laddr, err := net.ResolveUDPAddr("udp", laddrstr)
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		laddr, err = net.ResolveUDPAddr("udp", ":0")
		if err != nil {
			panic(err)
		}
		conn, err = net.ListenUDP("udp", laddr)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("%s\n", conn.LocalAddr())
	packetRelay := listen(conn)
	send := make(chan *davepb.Msg, 1)
	payload := marshal(&davepb.Msg{Op: davepb.Op_GETADDR})
	for _, b := range bootstrap {
		writeAddr(conn, payload, b)
	}
	return &Dave{send, dave(conn, packetRelay, send)}
}

func Work(msg *davepb.Msg, difficulty int) (<-chan *davepb.Msg, error) {
	payload := marshal(msg)
	if len(payload) >= PACKET_SIZE {
		return nil, fmt.Errorf("msg exceeds packet size of %dB", PACKET_SIZE)
	}
	result := make(chan *davepb.Msg)
	go func() {
		zeros := make([]byte, difficulty)
		t := time.Now()
		msg.Time = timeToBytes(t)
		msg.Nonce = make([]byte, 32)
		valSum := sha256.Sum256(msg.Val)
		for {
			crand.Read(msg.Nonce)
			h := sha256.New()
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
	pl := getPrefixLen(msg.Key)
	if pl == 0 {
		return 0
	}
	valSum := sha256.Sum256(msg.Val)
	h := sha256.New()
	h.Write(valSum[:])
	h.Write(msg.Time)
	h.Write(msg.Nonce)
	sum := h.Sum(nil)
	if !bytes.Equal(sum, msg.Key) {
		return -1
	}
	t := bytesToTime(msg.Time)
	if t.After(time.Now()) {
		return -2
	}
	return pl
}

func dave(conn *net.UDPConn, pktsch <-chan packet, sendch <-chan *davepb.Msg) <-chan *davepb.Msg {
	msgch := make(chan *davepb.Msg, 1)
	go func() {
		peers := make(map[string]*peer)
		for {
			select {
			case pkt := <-pktsch:
				ipstr := pkt.ip.String()
				p, ok := peers[ipstr]
				if !ok {
					peers[ipstr] = &peer{parseAddr(ipstr), time.Now(), 0}
					p = peers[ipstr]
				}
				p.seen = time.Now()
				p.nping = 0
				for _, maddrstr := range pkt.msg.Addrs {
					maddr := parseAddr(maddrstr)
					_, ok := peers[maddrstr]
					if !ok {
						peers[maddrstr] = &peer{
							ip: maddr,
						}
					}
				}
				switch pkt.msg.Op {
				case davepb.Op_GETADDR:
					payload := marshal(&davepb.Msg{
						Op:    davepb.Op_ADDR,
						Addrs: randomAddrs(peers, pkt.msg.Addrs, NADDR),
					})
					writeAddr(conn, payload, pkt.ip)
				case davepb.Op_SETDAT:
					if len(pkt.msg.Addrs) < FWD_DIST && CheckWork(pkt.msg) >= WORK_MIN {
						payload := marshal(pkt.msg)
						for _, rad := range randomAddrs(peers, nil, FANOUT_SETDAT) {
							writeAddr(conn, payload, parseAddr(rad))
						}
					}
				case davepb.Op_GETDAT:
					if len(pkt.msg.Addrs) < FWD_DIST {
						payload := marshal(pkt.msg)
						for _, rad := range randomAddrs(peers, nil, FANOUT_GETDAT) {
							writeAddr(conn, payload, parseAddr(rad))
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
					payload := marshal(msend)
					for _, rad := range randomAddrs(peers, nil, FANOUT_GETDAT) {
						writeAddr(conn, payload, parseAddr(rad))
					}
				default:
					panic(fmt.Sprintf("unsupported op %v", msend.Op))
				}
			case <-time.After(PING_PERIOD):
				peer := quiet(peers)
				if peer != nil {
					payload := marshal(&davepb.Msg{
						Op: davepb.Op_GETADDR,
					})
					writeAddr(conn, payload, peer.ip)
					peer.nping += 1
				}
				for key, p := range peers {
					if p.nping > DROP_THRESHOLD {
						delete(peers, key)
						fmt.Println("dropped", key)
					}
				}
			}
		}
	}()
	return msgch
}

func randomAddrs(peers map[string]*peer, exclude []string, limit int) []string {
	n := len(peers) - len(exclude)
	if n <= 0 {
		return []string{}
	}
	if n > limit {
		n = limit
	}
	mygs := make(map[string]string, 0)
	next := make([]string, 0)
	for len(mygs) < n {
		r := mrand.Intn(len(peers) - 1)
		j := 0
		for key, p := range peers {
			if j == r && p.nping < DROP_THRESHOLD/2 {
				if !in(key, exclude) {
					mygs[key] = key
					next = append(next, key)
				}
			}
			j++
		}
	}
	return next
}

func quiet(peers map[string]*peer) *peer {
	var quiet *peer
	for _, r := range peers {
		if quiet == nil {
			quiet = r
		} else if r.seen.Before(quiet.seen) {
			quiet = r
		}
	}
	return quiet
}

func listen(conn *net.UDPConn) <-chan packet {
	msgch := make(chan packet, 10)
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
			if len(msg.Addrs) == 0 {
				msg.Addrs = []string{raddr.String()}
			} else {
				msg.Addrs = append(msg.Addrs, raddr.String())
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
