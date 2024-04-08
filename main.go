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

type app struct {
	data     map[string]*pkt.Kv
	conn     *net.UDPConn
	addrs    map[string]*addr
	lstnPort uint32
}

type addr struct {
	ip   netip.AddrPort
	seen time.Time
}

func main() {
	lstnPortFlag := flag.Int("p", 2034, "listen port")
	lstnFlag := flag.Bool("l", false, "listen")
	bootstapFlag := flag.String("b", "", "bootstrap addr")
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
		addrs:    make(map[string]*addr, 1),
		lstnPort: uint32(*lstnPortFlag),
	}
	if *bootstapFlag != "" {
		bap, err := netip.ParseAddrPort(*bootstapFlag)
		if err != nil {
			panic(err)
		}
		a.addrs[*bootstapFlag] = &addr{
			ip: bap,
		}
	}
	go a.listen()
	go a.pingAddrs()
	if flag.NArg() > 0 {
		fmt.Println(flag.Args())
		action := flag.Arg(0)
		switch strings.ToUpper(action) {
		case "GETADDR":
			a.gossip(1, &pkt.Msg{
				Op: pkt.Op_GETADDR,
			}, nil)
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
		r, ok := a.addrs[raddr.String()]
		if ok {
			r.seen = time.Now()
		}
		log(msg)
		switch msg.Op {
		case pkt.Op_GETADDR:
			a.giveAddr(raddr)
		case pkt.Op_ADDR:
			for _, addrstr := range msg.Addrs {
				pap, err := netip.ParseAddrPort(addrstr)
				if err != nil {
					panic(err)
				}
				_, ok := a.addrs[addrstr]
				if !ok {
					fmt.Println("added", addrstr)
					a.addrs[addrstr] = &addr{
						ip: pap,
					}
				}
			}
		case pkt.Op_VAL:
			a.set(msg.Kv)
		case pkt.Op_SET:
			a.set(msg.Kv)
			a.forward(2, msg, raddr) // forward SET, fanout=2
		case pkt.Op_GET:
			kv, ok := a.data[msg.Kv.Key]
			if !ok {
				a.forward(1, msg, raddr) // forward GET, fanout=1
			} else {
				fmt.Printf("found %q: %s\n", kv.Key, string(kv.Val))
				payload, err := proto.Marshal(&pkt.Msg{
					Op: pkt.Op_VAL,
					Kv: kv,
				})
				if err != nil {
					panic(err)
				}
				// no addr in addrs has kv yet, send to each
				for _, j := range msg.Addrs {
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

func (a *app) pingAddrs() {
	last := time.Now()
	for {
		if time.Since(last) < 10*time.Second {
			time.Sleep(10*time.Second - time.Since(last))
		}
		last = time.Now()
		addr := a.addrToPing()
		if addr != nil {
			payload, err := proto.Marshal(&pkt.Msg{
				Op: pkt.Op_GETADDR,
			})
			if err != nil {
				panic(err)
			}
			_, err = a.conn.WriteToUDPAddrPort(payload, addr.ip)
			if err != nil {
				panic(err)
			}
			fmt.Println("pinged", addr.ip.String())
		}
	}
}

func (a *app) addrToPing() *addr {
	var quiet *addr
	for _, r := range a.addrs {
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
	if len(a.addrs) == 0 {
		return
	}
	addrs := a.list(len(a.addrs)-1, func(ad *addr) bool {
		return ad.ip.Compare(raddr) != 0
	})
	n := 2
	if len(addrs) < 2 {
		n = len(addrs)
	}
	ans := make([]string, 0, n)
	if len(addrs) > 1 {
		r := addrs[rand.Intn(len(addrs))]
		ans = append(ans, r.String())
		addrs = exclude(addrs, []netip.AddrPort{r})
	}
	if len(addrs) > 0 {
		r := addrs[rand.Intn(len(addrs))]
		ans = append(ans, r.String())
	}
	payload, err := proto.Marshal(&pkt.Msg{
		Op:    pkt.Op_ADDR,
		Addrs: ans,
	})
	if err != nil {
		panic(err)
	}
	_, err = a.conn.WriteToUDPAddrPort(payload, raddr)
	if err != nil {
		panic(err)
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
	if len(msg.Addrs) >= 3 {
		return
	}
	route := make([]netip.AddrPort, 0, len(msg.Addrs)+1)
	for _, a := range msg.Addrs {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			panic(err)
		}
		route = append(route, ap)
	}
	route = append(route, raddrPort)
	a.gossip(fanout, &pkt.Msg{
		Addrs: append(msg.Addrs, raddrPort.String()),
		Op:    msg.Op,
		Kv:    msg.Kv,
	}, route)
}

func (a *app) gossip(fanout int, msg *pkt.Msg, route []netip.AddrPort) {
	payload, err := proto.Marshal(msg)
	if err != nil {
		panic(err)
	}
	cap := len(a.addrs) - len(route)
	if cap < 0 {
		cap = 0
	}
	next := a.list(cap, func(ad *addr) bool {
		return !in(ad.ip, route)
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
		_, err := a.conn.WriteToUDPAddrPort(payload, addr)
		if err != nil {
			panic(err)
		}
		sent++
	}
}

func (a *app) list(cap int, add func(ad *addr) bool) []netip.AddrPort {
	addrs := make([]netip.AddrPort, 0, cap)
	for _, addr := range a.addrs {
		if add(addr) {
			addrs = append(addrs, addr.ip)
		}
	}
	return addrs
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
	if len(msg.Addrs) > 0 {
		src = msg.Addrs[0]
	}
	if msg.Kv != nil {
		fmt.Printf("%s :: %s :: %s :: %s\n", src, msg.Op, msg.Kv.Key, msg.Kv.Val)
	} else {
		fmt.Printf("%s :: %s\n", src, msg.Op)
	}
}
