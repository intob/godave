package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/inneslabs/dave/pkt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	PING_PERIOD      = 100 * time.Millisecond
	DROP_THRESHOLD   = 8
	FORWARD_DISTANCE = 4
)

type app struct {
	lstnPort uint32
	conn     *net.UDPConn
	peers    map[string]*peer
	data     map[string]*dat
}

type peer struct {
	ip    netip.AddrPort
	seen  time.Time
	nping atomic.Uint32
}

type dat struct {
	chunk *pkt.Chunk
	nonce []byte
}

func main() {
	lstnPortFlag := flag.Int("p", 2034, "listen port")
	bootstapFlag := flag.String("b", "", "bootstrap peer")
	flag.Parse()
	laddrstr := fmt.Sprintf(":%d", *lstnPortFlag)
	laddr, err := net.ResolveUDPAddr("udp", laddrstr)
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		panic(err)
	}
	fmt.Printf("listening on %s :: ", conn.LocalAddr().String())
	a := &app{
		lstnPort: uint32(*lstnPortFlag),
		conn:     conn,
		peers:    make(map[string]*peer, 1),
		data:     make(map[string]*dat),
	}
	msgs := a.listen()
	go a.pingPeers()
	go a.dropPeers()
	if *bootstapFlag != "" {
		payload := marshal(&pkt.Msg{Op: pkt.Op_GETADDR})
		a.writeAddr(payload, parseAddr(*bootstapFlag))
	}
	var n int
	fmt.Print("bootstrap")
	for range msgs {
		n++
		fmt.Printf(".")
		if n >= 3 {
			fmt.Print("\n")
			break
		}
	}
	if flag.NArg() > 0 {
		action := flag.Arg(0)
		switch strings.ToUpper(action) {
		case pkt.Op_SETDAT.String():
			if flag.NArg() < 2 {
				fmt.Println("SETDAT failed: correct usage is setdat <value>")
				return
			}
			val := flag.Arg(1)
			m := &pkt.Msg{
				Op: pkt.Op_SETDAT,
				Chunk: &pkt.Chunk{
					Val: []byte(val),
				},
			}
			mch := work(m, 2)
			m = <-mch
			fmt.Printf("%x\n", m.Key)
			// SETDAT fanout is 2, but send only to one node before fanout
			a.gossip(1, m, nil)
		case pkt.Op_GETDAT.String():
			if flag.NArg() < 2 {
				fmt.Println("GETDAT failed: correct usage is getdat <key>")
				return
			}
			keyHex := flag.Arg(1)
			d, ok := a.data[keyHex]
			if ok {
				fmt.Printf("%s: %s\n", keyHex, string(d.chunk.Val))
				return
			}
			key, err := hex.DecodeString(keyHex)
			if err != nil {
				panic(err)
			}
			a.gossip(1, &pkt.Msg{
				Op:  pkt.Op_GETDAT,
				Key: key,
			}, nil)
		}
	}
	for m := range msgs {
		switch m.Op {
		case pkt.Op_DAT:
			fmt.Printf("DAT :: %s\n", string(m.Chunk.Val))
		case pkt.Op_SETDAT:
			fmt.Printf("SETDAT :: %x\n", m.Key)
		}
	}
}

func (a *app) listen() <-chan *pkt.Msg {
	msgch := make(chan *pkt.Msg, 1)
	go func() {
		defer a.conn.Close()
		for {
			buf := make([]byte, 2048)
			n, raddr, err := a.conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				panic(err)
			}
			msg := &pkt.Msg{}
			err = proto.Unmarshal(buf[:n], msg)
			if err != nil {
				panic(err)
			}
			if len(msg.Addrs) == 0 {
				msg.Addrs = make([]string, 1)
				msg.Addrs[0] = raddr.String()
			}
			r, ok := a.peers[raddr.String()]
			if ok {
				r.seen = time.Now()
			} else {
				r = &peer{
					ip:   raddr,
					seen: time.Now(),
				}
				a.peers[raddr.String()] = r
			}
			err = a.handleMsg(msg, r)
			if err != nil {
				fmt.Println(err)
			} else {
				select {
				case msgch <- msg:
				default:
				}
			}
		}
	}()
	return msgch
}

func (a *app) handleMsg(msg *pkt.Msg, r *peer) error {
	switch msg.Op {
	case pkt.Op_GETADDR:
		a.giveAddr(r.ip)
	case pkt.Op_ADDR:
		if r.nping.Load() > 0 {
			r.nping.Store(0)
		}
		for _, addrstr := range msg.Addrs {
			pap := parseAddr(addrstr)
			_, ok := a.peers[addrstr]
			if !ok {
				a.peers[addrstr] = &peer{
					ip: pap,
				}
			}
		}
	case pkt.Op_DAT: // don't forward, just store
		if checkWork(msg) >= 2 { // difficulty required? hmm
			a.set(msg)
		} else {
			return fmt.Errorf("work is invalid: key: %x", msg.Key)
		}
	case pkt.Op_SETDAT:
		if checkWork(msg) >= 2 {
			a.set(msg)
			a.forward(2, msg, r.ip) // forward SET, fanout=2
		} else {
			return fmt.Errorf("work is invalid: key: %x", msg.Key)
		}
	case pkt.Op_GETDAT:
		dat, ok := a.data[hex.EncodeToString(msg.Key)]
		if !ok {
			a.forward(1, msg, r.ip) // forward GET, fanout=1
		} else {
			payload := marshal(&pkt.Msg{
				Op:    pkt.Op_DAT,
				Chunk: dat.chunk,
				Nonce: dat.nonce,
				Key:   msg.Key,
			})
			for _, j := range msg.Addrs {
				a.writeAddr(payload, parseAddr(j))
			}
		}
	}
	return nil
}

func (a *app) dropPeers() {
	last := time.Now()
	for {
		if time.Since(last) < PING_PERIOD {
			time.Sleep(PING_PERIOD - time.Since(last))
		}
		last = time.Now()
		for adstr, ad := range a.peers {
			if ad.nping.Load() > DROP_THRESHOLD {
				delete(a.peers, adstr)
			}
		}
	}
}

func (a *app) pingPeers() {
	last := time.Now()
	for {
		addr := a.peerToPing()
		if addr != nil {
			payload := marshal(&pkt.Msg{
				Op: pkt.Op_GETADDR,
			})
			a.writeAddr(payload, addr.ip)
			addr.nping.Add(1)
		}
		if time.Since(last) < PING_PERIOD {
			time.Sleep(PING_PERIOD - time.Since(last))
		}
		last = time.Now()
	}
}

func (a *app) peerToPing() *peer {
	var quiet *peer
	for _, r := range a.peers {
		if quiet == nil {
			quiet = r
		} else if r.seen.Before(quiet.seen) {
			quiet = r
		}
	}
	return quiet
}

// send 2 random addresses, excluding raddr
func (a *app) giveAddr(raddr netip.AddrPort) {
	if len(a.peers) == 0 {
		return
	}
	addrs := a.list(len(a.peers)-1, func(p *peer) bool {
		return p.ip.Compare(raddr) != 0 && p.nping.Load() == 0
	})
	ans := make([]netip.AddrPort, 0)
	for len(ans) < 2 && len(ans) < len(addrs)-1 { // -1 for raddr
		r := addrs[rand.Intn(len(addrs))]
		if !in(r, ans) && r.Compare(raddr) != 0 {
			ans = append(ans, r)
		}
	}
	ansstr := make([]string, len(ans))
	for i, ad := range ans {
		ansstr[i] = ad.String()
	}
	payload := marshal(&pkt.Msg{
		Op:    pkt.Op_ADDR,
		Addrs: ansstr,
	})
	a.writeAddr(payload, raddr)
}

func (a *app) set(msg *pkt.Msg) {
	a.data[hex.EncodeToString(msg.Key)] = &dat{
		chunk: msg.Chunk,
		nonce: msg.Nonce,
	}
}

func (a *app) forward(fanout int, msg *pkt.Msg, raddrPort netip.AddrPort) {
	if len(msg.Addrs) >= FORWARD_DISTANCE {
		return
	}
	route := make([]netip.AddrPort, 0, len(msg.Addrs)+1)
	for _, addr := range msg.Addrs {
		route = append(route, parseAddr(addr))
	}
	route = append(route, raddrPort)
	a.gossip(fanout, &pkt.Msg{
		Addrs: append(msg.Addrs, raddrPort.String()),
		Op:    msg.Op,
		Chunk: msg.Chunk,
		Key:   msg.Key,
	}, route)
}

func (a *app) gossip(fanout int, msg *pkt.Msg, route []netip.AddrPort) {
	payload := marshal(msg)
	cap := len(a.peers) - len(route)
	if cap < 0 {
		cap = 0
	}
	next := a.list(cap, func(p *peer) bool {
		return !in(p.ip, route)
	})
	var sent int
	sentTo := make(map[string]struct{}, 0)
	for sent < fanout && len(sentTo) < len(next) {
		addr := next[rand.Intn(len(next))]
		_, alreadySentTo := sentTo[addr.String()]
		if alreadySentTo {
			continue
		}
		sentTo[addr.String()] = struct{}{}
		a.writeAddr(payload, addr)
		sent++
	}
}

func (a *app) writeAddr(payload []byte, addr netip.AddrPort) {
	_, err := a.conn.WriteToUDPAddrPort(payload, addr)
	if err != nil {
		panic(err)
	}
}

func (a *app) list(cap int, add func(p *peer) bool) []netip.AddrPort {
	addrs := make([]netip.AddrPort, 0, cap)
	for _, p := range a.peers {
		if add(p) {
			addrs = append(addrs, p.ip)
		}
	}
	return addrs
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

func in(m netip.AddrPort, n []netip.AddrPort) bool {
	for _, nn := range n {
		if nn.Compare(m) == 0 {
			return true
		}
	}
	return false
}

// work computes a key of the given difficulty
func work(msg *pkt.Msg, difficulty int) <-chan *pkt.Msg {
	result := make(chan *pkt.Msg)
	go func() {
		prefix := make([]byte, difficulty)
		nonce := make([]byte, 32)
		var (
			t  time.Time
			cb []byte
		)
		for {
			if cb == nil || time.Since(t) > time.Second {
				msg.Chunk.T = time.Now().UnixMilli()
				cb = marshal(msg.Chunk)
			}
			_, err := crand.Read(nonce)
			if err != nil {
				panic(err)
			}
			h := sha256.New()
			h.Write(cb)
			h.Write(nonce)
			sum := h.Sum(nil)
			if bytes.HasPrefix(sum, prefix) {
				msg.Nonce = nonce
				msg.Key = sum
				result <- msg
				return
			}
		}
	}()
	return result
}

func checkWork(msg *pkt.Msg) int {
	pl := getPrefixLen(msg.Key)
	if pl == 0 {
		return 0
	}
	cb, err := proto.Marshal(msg.Chunk)
	if err != nil {
		panic(err)
	}
	h := sha256.New()
	h.Write(cb)
	h.Write(msg.Nonce)
	sum := h.Sum(nil)
	if !bytes.Equal(sum, msg.Key) {
		return -1
	}
	return pl
}

func getPrefixLen(key []byte) int {
	for i, j := range key {
		if j != 0 {
			return i
		}
	}
	return len(key)
}
