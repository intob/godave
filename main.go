package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

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
	data     map[string]*pkt.Kv
	conn     *net.UDPConn
	addrs    []netip.AddrPort
	lstnPort uint32
}

func main() {
	lstnPortFlag := flag.Int("p", 2034, "listen port")
	lstnFlag := flag.Bool("l", false, "listen")
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
	a := &app{
		data:     make(map[string]*pkt.Kv),
		conn:     conn,
		addrs:    make([]netip.AddrPort, 0, len(bootstrapAddrs)),
		lstnPort: uint32(*lstnPortFlag),
	}
	for _, bastr := range bootstrapAddrs {
		bap, err := netip.ParseAddrPort(bastr)
		if err != nil {
			panic(err)
		}
		a.addrs = append(a.addrs, bap)
	}
	go a.listen()
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
				Op: pkt.Op_SET,
				Kv: &pkt.Kv{
					Key: key,
					Val: []byte(val),
					T:   time.Now().UnixMilli(),
				},
			}, nil)
		case "GET":
			if flag.NArg() < 2 {
				fmt.Println("GET failed: correct usage is read <key>")
				return
			}
			key := flag.Arg(1)
			d, ok := a.data[key]
			if ok {
				fmt.Printf("%s: %s\n", key, string(d.Val))
				return
			}
			fmt.Println("no local copy")
			// protocol does not fanout GET (fanout=1)
			a.gossip(1, &pkt.Msg{
				Op: pkt.Op_GET,
				Kv: &pkt.Kv{
					Key: key,
				},
			}, nil)
		}
	}
	if *lstnFlag {
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
		log(msg)
		switch msg.Op {
		case pkt.Op_VAL:
			a.set(msg.Kv)
		case pkt.Op_SET:
			a.set(msg.Kv)
			// forward with fanout=2
			a.forward(2, msg, raddrPort)
		case pkt.Op_GET:
			kv, ok := a.data[msg.Kv.Key]
			if !ok {
				fmt.Println("not found, forwarding to 1")
				a.forward(1, msg, raddrPort)
			} else {
				fmt.Printf("found %q: %s\n", kv.Key, string(kv.Val))
				payload, err := proto.Marshal(&pkt.Msg{
					Op: pkt.Op_VAL,
					Kv: kv,
				})
				if err != nil {
					panic(err)
				}
				// no addr in route has kv yet, send it
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
		}
	}
}

func (a *app) set(m *pkt.Kv) {
	s, ok := a.data[m.Key]
	if !ok || m.T > s.T {
		fmt.Printf("set %s: %s\n", m.Key, string(m.Val))
		a.data[m.Key] = &pkt.Kv{
			Key: m.Key,
			Val: m.Val,
			T:   m.T,
		}
	}
}

func (a *app) forward(fanout int, msg *pkt.Msg, raddrPort netip.AddrPort) {
	if len(msg.Route) >= 3 { // limit to 3 hops
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
		Kv:    msg.Kv,
	}, route)
}

func (a *app) gossip(fanout int, msg *pkt.Msg, route []netip.AddrPort) {
	payload, err := proto.Marshal(msg)
	if err != nil {
		panic(err)
	}
	next := exclude(a.addrs, route)
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
		fmt.Println("sent to", addr.String())
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

func log(msg *pkt.Msg) {
	src := "nil"
	if len(msg.Route) > 0 {
		src = msg.Route[0]
	}
	if msg.Kv != nil {
		fmt.Printf("%s :: %s :: %s :: %s\n", src, msg.Op, msg.Kv.Key, msg.Kv.Val)
	} else {
		fmt.Printf("%s :: %s\n", src, msg.Op)
	}
}
