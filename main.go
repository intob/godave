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

var bootstrapAddr = []string{
	"127.0.0.1:1231",
	"127.0.0.1:1232",
	"127.0.0.1:1233",
	"127.0.0.1:1234",
}

func main() {
	portFlag := flag.Int("p", 2034, "listen port")
	listenFlag := flag.Bool("l", false, "listen")
	flag.Parse()
	l, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", *portFlag))
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", l)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	bootstrap := make([]netip.AddrPort, 0, len(bootstrapAddr))
	for _, b := range bootstrapAddr {
		ap, err := netip.ParseAddrPort(b)
		if err != nil {
			panic(err)
		}
		bootstrap = append(bootstrap, ap)
	}
	if flag.NArg() > 0 {
		fmt.Println(flag.Args())
		action := flag.Arg(0)
		switch strings.ToUpper(action) {
		case "WRITE": // gossip the data
			if flag.NArg() < 3 {
				fmt.Println("write failed: correct usage is write <key> <value>")
				return
			}
			key := flag.Arg(1)
			value := flag.Arg(2)
			payload, err := proto.Marshal(&pkt.Msg{
				Op:    pkt.Op_WRITE,
				Key:   key,
				Value: []byte(value),
			})
			if err != nil {
				panic(err)
			}
			// TODO: all known addrs
			gossip(conn, bootstrap, payload)
		}
	}
	if *listenFlag {
		go func() {
			listen(conn, bootstrap)
		}()
		var wg sync.WaitGroup
		wg.Add(1)
		wg.Wait()
	}
}

func listen(conn *net.UDPConn, addrs []netip.AddrPort) {
	fmt.Printf("listening on %s\n", conn.LocalAddr().String())
	for {
		buf := make([]byte, 2048)
		n, raddr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			panic(err)
		}
		//fmt.Println(raddr, string(buf[:n]))
		p := &pkt.Msg{}
		err = proto.Unmarshal(buf[:n], p)
		if err != nil {
			panic(err)
		}
		if len(p.Via) >= 3 {
			//fmt.Printf("msg already has 3 hops, don't forward")
			continue
		}
		fmt.Println(p.Op, p.Key, string(p.Value))
		raddrBytes, err := raddr.MarshalBinary()
		if err != nil {
			panic(err)
		}
		hops := make([][]byte, 0, len(p.Via)+1)
		hops = append(hops, p.Via...)
		hops = append(hops, raddrBytes)
		/*for n, h := range hops {
			fmt.Printf("hop %d: %s\n", n, string(h))
		}*/
		forward, err := proto.Marshal(&pkt.Msg{
			Op:    p.Op,
			Value: p.Value,
			Key:   p.Key,
			Via:   hops,
		})
		if err != nil {
			panic(err)
		}
		hopsAddrs := make([]netip.AddrPort, len(hops))
		for i, hop := range hops {
			addr := &netip.AddrPort{}
			err := addr.UnmarshalBinary(hop)
			if err != nil {
				panic(err)
			}
			hopsAddrs[i] = *addr
		}
		gossip(conn, exclude(addrs, hopsAddrs), forward)
	}
}

func gossip(conn *net.UDPConn, addrs []netip.AddrPort, payload []byte) {
	sent := 0
	tried := make(map[string]struct{}, 0)
	for sent < 2 && len(tried) < len(addrs) { // fanout = 2
		addr := addrs[rand.Intn(len(addrs))]
		_, alreadyTried := tried[addr.String()]
		if alreadyTried {
			continue
		}
		tried[addr.String()] = struct{}{}
		_, err := conn.WriteToUDPAddrPort(payload, addr)
		if err != nil {
			panic(err)
		}
		sent++
	}
}

func exclude(addrs, exclude []netip.AddrPort) []netip.AddrPort {
	if len(addrs) == 0 {
		return []netip.AddrPort{}
	}
	if len(exclude) == 0 {
		return addrs
	}
	result := make([]netip.AddrPort, 0, len(addrs))
	for _, addr := range addrs {
		if !in(addr, exclude) {
			result = append(result, addr)
		}
	}
	return result
}

func in(needle netip.AddrPort, haystack []netip.AddrPort) bool {
	for _, x := range haystack {
		if x.Compare(needle) == 0 {
			return true
		}
	}
	return false
}
