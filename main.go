package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"

	"github.com/inneslabs/dave/pkt"
	"google.golang.org/protobuf/proto"
)

var bootstrapAddrs = []string{
	"127.0.0.1:1231",
	"127.0.0.1:1232",
	"127.0.0.1:1233",
	"127.0.0.1:1234",
}

type app struct {
	data       map[string][]byte
	conn       *net.UDPConn
	nodes      []netip.AddrPort
	listenPort uint32
}

func main() {
	listenPortFlag := flag.Int("p", 2034, "listen port")
	listenFlag := flag.Bool("l", false, "listen")
	flag.Parse()
	laddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", *listenPortFlag))
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		panic(err)
	}
	a := &app{
		data:       make(map[string][]byte),
		conn:       conn,
		nodes:      make([]netip.AddrPort, 0, len(bootstrapAddrs)),
		listenPort: uint32(*listenPortFlag),
	}
	go a.listen()
	for _, b := range bootstrapAddrs {
		ap, err := netip.ParseAddrPort(b)
		if err != nil {
			panic(err)
		}
		a.nodes = append(a.nodes, ap)
	}
	if flag.NArg() > 0 {
		fmt.Println(flag.Args())
		action := flag.Arg(0)
		switch strings.ToUpper(action) {
		case "SET":
			if flag.NArg() < 3 {
				fmt.Println("SET failed: correct usage is set <key> <value>")
				return
			}
			key := flag.Arg(1)
			val := flag.Arg(2)
			// SET fanout is 2, but send only to one node before fanout
			a.gossip(1, &pkt.Msg{
				Op:  pkt.Op_SET,
				Key: key,
				Val: []byte(val),
			}, nil)
		case "GET":
			if flag.NArg() < 2 {
				fmt.Println("GET failed: correct usage is read <key>")
				return
			}
			key := flag.Arg(1)
			d, ok := a.data[key]
			if ok {
				fmt.Printf("%s: %s\n", key, string(d))
				return
			}
			fmt.Println("no local copy")
			a.gossip(1, &pkt.Msg{ // GET fanout is 1
				Op:  pkt.Op_GET,
				Key: key,
			}, nil)
		}
	}
	if *listenFlag {
		<-make(chan struct{})
	}
}

func (a *app) listen() {
	fmt.Printf("listening on %s\n", a.conn.LocalAddr().String())
	defer a.conn.Close()
	for {
		buf := make([]byte, 2048)
		n, raddrPort, err := a.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			panic(err)
		}
		msg := &pkt.Msg{}
		err = proto.Unmarshal(buf[:n], msg)
		if err != nil {
			panic(err)
		}
		if len(msg.Route) == 0 {
			msg.Route = make([]string, 1)
			msg.Route[0] = raddrPort.String()
		}
		switch msg.Op {
		case pkt.Op_SET:
			a.forward(2, msg, raddrPort)
			a.data[msg.Key] = msg.Val
		case pkt.Op_GET:
			d, ok := a.data[msg.Key]
			if !ok {
				fmt.Println("not found, forwarding to 1")
				a.forward(1, msg, raddrPort)
			} else {
				fmt.Printf("found %q: %s\n", msg.Key, string(d))
				payload, err := proto.Marshal(&pkt.Msg{
					Op:  pkt.Op_VAL,
					Key: msg.Key,
					Val: d,
				})
				if err != nil {
					panic(err)
				}
				// we know that all addrs in route do not yet have the key
				// send to each addr in route, starting with the first
				for _, j := range msg.Route {
					addr, err := netip.ParseAddrPort(j)
					if err != nil {
						panic(err)
					}
					_, err = a.conn.WriteToUDPAddrPort(payload, addr)
					if err != nil {
						panic(err)
					}
				}

			}
		case pkt.Op_VAL:
			a.data[msg.Key] = msg.Val
			log(msg, "got val, stored")
		}
	}
}

func (a *app) forward(fanout int, msg *pkt.Msg, raddrPort netip.AddrPort) {
	if len(msg.Route) >= 3 { // limit to 3 hops
		fmt.Printf("msg already has 3 hops, don't forward\n")
		return
	}
	route := make([]netip.AddrPort, 0, len(msg.Route)+1)
	for _, a := range msg.Route {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			panic(err)
		}
		route = append(route, ap)
	}
	route = append(route, raddrPort)
	a.gossip(fanout, &pkt.Msg{
		Route: append(msg.Route, raddrPort.String()),
		Op:    msg.Op,
		Val:   msg.Val,
		Key:   msg.Key,
	}, route)
}

func (a *app) gossip(fanout int, msg *pkt.Msg, route []netip.AddrPort) {
	log(msg, "gossip")
	payload, err := proto.Marshal(msg)
	if err != nil {
		panic(err)
	}
	next := exclude(a.nodes, route)
	sent := 0
	tried := make(map[string]struct{}, 0)
	for sent < fanout && len(tried) < len(next) {
		addr := next[rand.Intn(len(next))]
		_, alreadyTried := tried[addr.String()]
		if alreadyTried {
			continue
		}
		tried[addr.String()] = struct{}{}
		_, err := a.conn.WriteToUDPAddrPort(payload, addr)
		if err != nil {
			panic(err)
		}
		sent++
	}
}

func exclude(from, not []netip.AddrPort) []netip.AddrPort {
	if len(from) == 0 {
		return nil
	}
	if len(not) == 0 {
		return from
	}
	out := make([]netip.AddrPort, 0, len(from)-len(not))
	for _, m := range from {
		if !in(m, not) {
			out = append(out, m)
		}
	}
	return out
}

func in(m netip.AddrPort, n []netip.AddrPort) bool {
	for _, nn := range n {
		if nn.Compare(m) == 0 {
			return true
		}
	}
	return false
}

func log(msg *pkt.Msg, txt string) {
	src := "nil"
	if len(msg.Route) > 0 {
		src = msg.Route[0]
	}
	fmt.Printf("%s :: %s :: %s :: %s // %s \n", src, msg.Op, msg.Key, msg.Val, txt)
}
