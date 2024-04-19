package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/dave"
	"github.com/intob/jfmt"
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
			exit(1, "failed to parse -p=%q: %v", bap, err)
		}
		bootstrap = append(bootstrap, addr)
	}
	if *bfile != "" {
		bh, err := readHosts(*bfile)
		if err != nil {
			exit(1, "failed to read file %s: %v", *bfile, err)
		}
		bootstrap = append(bootstrap, bh...)
	}
	udpaddr, err := net.ResolveUDPAddr("udp", *lap)
	if err != nil {
		exit(1, "failed to resolve UDP address: %v", err)
	}
	d, err := godave.NewDave(udpaddr, bootstrap)
	if err != nil {
		exit(1, "failed to make dave: %v", err)
	}
	var action string
	if flag.NArg() > 0 {
		action = flag.Arg(0)
	}
	switch strings.ToUpper(action) {
	case "FIRE":
		var i uint32
		t := time.Now()
		tlp := time.Now()
		for {
			select {
			case <-d.Recv:
				fmt.Println("stat", d.Stat())
			case d.Send <- &dave.M{Op: dave.Op_DAT, Val: []byte("test")}:
				time.Sleep(r - time.Since(tlp))
				tlp = time.Now()
				i++
				if i%100 == 0 {
					dt := time.Since(t)
					r := jfmt.FmtCount32(uint32(float64(i) / dt.Seconds()))
					fmt.Printf("\rsent %s packets in %s (%s/s)\033[0K", jfmt.FmtCount32(i), jfmt.FmtDuration(dt), r)
				}
			}
		}
	default:
		fmt.Printf("command unrecognised %q\n", flag.Arg(0))
		for range d.Recv {
		}
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

func exit(code int, msg string, args ...any) {
	fmt.Printf(msg, args...)
	os.Exit(code)
}
