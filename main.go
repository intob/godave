package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"

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
	defer conn.Close()
	a := &app{
		data:       make(map[string][]byte),
		conn:       conn,
		nodes:      make([]netip.AddrPort, 0, len(bootstrapAddrs)),
		listenPort: uint32(*listenPortFlag),
	}
	go func() {
		a.listen()
	}()
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
		case "SET": // gossip the data
			if flag.NArg() < 3 {
				fmt.Println("SET failed: correct usage is set <key> <value>")
				return
			}
			key := flag.Arg(1)
			value := flag.Arg(2)
			// SET fanout is 2, but send only to one node before fanout
			a.gossip(1, &pkt.Msg{
				Op:    pkt.Op_SET,
				Key:   key,
				Value: []byte(value),
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
			fmt.Println("no local copy, gossip Op_GET")
			// GET fanout is 1
			a.gossip(1, &pkt.Msg{
				Op:  pkt.Op_GET,
				Key: key,
			}, nil)
		}
	}
	if *listenFlag {
		var wg sync.WaitGroup
		wg.Add(1)
		wg.Wait()
	}
}

func (a *app) listen() {
	fmt.Printf("listening on %s\n", a.conn.LocalAddr().String())
	for {
		buf := make([]byte, 2048)
		n, raddrPort, err := a.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			panic(err)
		}
		//fmt.Println(raddr, string(buf[:n]))
		p := &pkt.Msg{}
		err = proto.Unmarshal(buf[:n], p)
		if err != nil {
			panic(err)
		}
		if len(p.Route) == 0 {
			p.Route = make([]string, 1)
			p.Route[0] = raddrPort.String()
		}
		fmt.Printf("%s :: %s :: %s :: %s\n", p.Op, p.Key, string(p.Value), p.Route[0])
		switch p.Op {
		case pkt.Op_SET:
			a.forward(2, p, raddrPort)
			// store
			a.data[p.Key] = p.Value
		case pkt.Op_GET:
			// try to read
			d, ok := a.data[p.Key]
			if !ok {
				fmt.Println("not found, forwarding to 1")
				a.forward(1, p, raddrPort)
			} else {
				fmt.Printf("found %q: %s\n", p.Key, string(d))
				// reply with val
				payload, err := proto.Marshal(&pkt.Msg{
					Op:    pkt.Op_VAL,
					Key:   p.Key,
					Value: d,
				})
				if err != nil {
					panic(err)
				}
				src, err := netip.ParseAddrPort(p.Route[0])
				if err != nil {
					panic(err)
				}
				_, err = a.conn.WriteToUDPAddrPort(payload, src)
				if err != nil {
					panic(err)
				}
			}
		case pkt.Op_VAL:
			// got value!
			fmt.Printf("%s: %s\n", p.Key, string(p.Value))
		}
	}
}

func (a *app) forward(fanout int, p *pkt.Msg, raddrPort netip.AddrPort) {
	if len(p.Route) >= 3 { // limit to 3 hops
		//fmt.Printf("msg already has 3 hops, don't forward")
		return
	}
	route := make([]netip.AddrPort, 0, len(p.Route)+1)
	for _, a := range p.Route {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			panic(err)
		}
		route = append(route, ap)
	}
	route = append(route, raddrPort)
	a.gossip(fanout, &pkt.Msg{
		Route: append(p.Route, raddrPort.String()),
		Op:    p.Op,
		Value: p.Value,
		Key:   p.Key,
	}, route)
}

func (a *app) gossip(fanout int, msg *pkt.Msg, route []netip.AddrPort) {
	payload, err := proto.Marshal(msg)
	if err != nil {
		panic(err)
	}
	next := exclude(a.nodes, route)
	sent := 0
	tried := make(map[string]struct{}, 0)
	for sent < fanout && len(tried) < len(a.nodes) { // fanout = 2
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

func exclude(nodes, exclude []netip.AddrPort) []netip.AddrPort {
	if len(nodes) == 0 {
		return nil
	}
	if len(exclude) == 0 {
		return nodes
	}
	result := make([]netip.AddrPort, 0, len(nodes))
	for _, n := range nodes {
		if !in(n, exclude) {
			result = append(result, n)
		}
	}
	return result
}

func in(n netip.AddrPort, haystack []netip.AddrPort) bool {
	for _, x := range haystack {
		if x.Compare(n) == 0 {
			return true
		}
	}
	return false
}
