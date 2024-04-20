package main

import (
	"bufio"
	crand "crypto/rand"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/intob/dave/godave/dave"
	"github.com/intob/jfmt"
	"google.golang.org/protobuf/proto"
)

func main() {
	lap := flag.String("l", "[::]:0", "<LAP> listen address:port")
	bapref := flag.String("b", "", "<BAP> bootstrap address:port")
	bfile := flag.String("bf", "", "<BFILE> bootstrap file of address:port\\n")
	rref := flag.Duration("r", 250*time.Microsecond, "rate")
	flag.Parse()
	bootstrap := make([]netip.AddrPort, 0)
	bap := *bapref
	r := *rref
	if bap != "" {
		if strings.HasPrefix(bap, ":") {
			bap = "[::1]" + bap
		}
		addr, err := netip.ParseAddrPort(bap)
		if err != nil {
			panic(err)
		}
		bootstrap = append(bootstrap, addr)
	}
	if *bfile != "" {
		bh, err := readHosts(*bfile)
		if err != nil {
			panic(err)
		}
		bootstrap = append(bootstrap, bh...)
	}
	udpaddr, err := net.ResolveUDPAddr("udp", *lap)
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", udpaddr)
	if err != nil {
		panic(err)
	}
	var action string
	if flag.NArg() > 0 {
		action = flag.Arg(0)
	}
	switch strings.ToUpper(action) {
	case "FIRE":
		t := time.Now()
		tlp := time.Now()
		var i uint32
		for {
			for _, b := range bootstrap {
				r := make([]byte, 32)
				_, err := crand.Read(r)
				if err != nil {
					panic(err)
				}
				m, err := proto.Marshal(&dave.M{Op: dave.Op_DAT, Work: r})
				if err != nil {
					panic(err)
				}
				_, err = conn.WriteToUDPAddrPort(m, b)
				if err != nil {
					panic(err)
				}
			}
			time.Sleep(r - time.Since(tlp))
			tlp = time.Now()
			i++
			if i%10 == 0 {
				dt := time.Since(t)
				fmt.Printf("\rsent %s packets in %s (%.2f/s)\033[0K", jfmt.FmtCount32(i), jfmt.FmtDuration(dt), float64(i)/dt.Seconds())
			}
		}
	default:
		fmt.Printf("command unrecognised %q\n", flag.Arg(0))
		os.Exit(1)
	}
}

func readHosts(fname string) ([]netip.AddrPort, error) {
	ans := make([]netip.AddrPort, 0)
	f, err := os.Open(fname)
	if err != nil {
		return ans, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		l := s.Text()
		if l != "" && !strings.HasPrefix(l, "#") {
			l = strings.ReplaceAll(l, "\t", " ")
			fields := strings.Split(l, " ")
			if len(fields) == 0 {
				continue
			}
			ap, err := netip.ParseAddrPort(fields[0])
			if err == nil {
				ans = append(ans, ap)
			} else {
				fmt.Println(err)
			}
		}
	}
	return ans, nil
}
