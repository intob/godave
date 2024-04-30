package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/intob/dave/dapi"
	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/dave"
	"github.com/intob/jfmt"
)

func main() {
	bootstraps := []netip.AddrPort{
		netip.MustParseAddrPort("54.195.136.26:1618"),
		netip.MustParseAddrPort("3.255.246.69:1618"),
		netip.MustParseAddrPort("3.250.242.160:1618"),
	}
	g := flag.Bool("g", false, "genesis, don't bootstrap")
	lap := flag.String("l", "[::]:0", "listen address:port")
	bap := flag.String("b", "", "bootstrap address:port")
	difficulty := flag.Int("d", 3, "number of leading zeros")
	dcap := flag.Uint("dc", 500000, "dat map capacity")
	fcap := flag.Uint("fc", 1000000, "cuckoo filter capacity")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()
	if *g {
		bootstraps = []netip.AddrPort{}
	}
	if *bap != "" {
		if strings.HasPrefix(*bap, ":") {
			*bap = "[::1]" + *bap
		}
		addr, err := netip.ParseAddrPort(*bap)
		if err != nil {
			exit(1, "failed to parse -p=%q: %v", *bap, err)
		}
		bootstraps = append(bootstraps, addr)
	}
	laddr, err := net.ResolveUDPAddr("udp", *lap)
	if err != nil {
		exit(1, "failed to resolve UDP address: %v", err)
	}
	lch := make(chan string, 4)
	d, err := godave.NewDave(&godave.Cfg{
		Listen:     laddr,
		Bootstraps: bootstraps,
		DatCap:     *dcap,
		FilterCap:  *fcap,
		Log:        lch})
	if err != nil {
		exit(1, "failed to make dave: %v", err)
	}
	go func(lch <-chan string) {
		var dlf *os.File
		if *verbose {
			dlf = os.Stdout
		} else {
			dlf, err = os.Open(os.DevNull)
			if err != nil {
				panic(err)
			}
		}
		defer dlf.Close()
		dlw := bufio.NewWriter(dlf)
		for l := range lch {
			dlw.Write([]byte(l))
		}
	}(lch)
	var action string
	if flag.NArg() > 0 {
		action = flag.Arg(0)
	}
	switch strings.ToLower(action) {
	case "set":
		if flag.NArg() < 2 {
			exit(1, "missing argument: set <VAL>")
		}
		set(d, []byte(flag.Arg(1)), *difficulty)
		return
	case "setfile":
		if flag.NArg() < 2 {
			exit(1, "missing argument: setfile <FILENAME>")
		}
		data, err := os.ReadFile(flag.Arg(1))
		if err != nil {
			exit(2, "error reading file: %v", err)
		}
		set(d, data, *difficulty)
		return
	case "get":
		if flag.NArg() < 2 {
			exit(1, "correct usage is get <WORK>")
		}
		work, err := hex.DecodeString(flag.Arg(1))
		if err != nil {
			exit(1, "invalid input <WORK>: %v", err)
		}
		dat, err := dapi.GetDat(d, work)
		if err != nil {
			exit(1, "failed: %v", err)
		}
		fmt.Println(string(dat.V))
		return
	}
	dapi.WaitForFirstDat(d, os.Stdout)
	if *verbose {
		for range d.Recv { // dave logs enough
		}
	} else {
		var i uint64
		var p uint32
		ts := time.Now()
		tick := time.NewTicker(time.Second)
		for {
			select {
			case <-d.Recv:
				i++
				p++
			case <-tick.C:
				fmt.Printf("\rhandled %s packets in %s (%d/s)\033[0K", jfmt.FmtCount64(i), jfmt.FmtDuration(time.Since(ts)), p)
				p = 0
			}
		}
	}
}

func set(d *godave.Dave, val []byte, difficulty int) {
	done := make(chan struct{})
	go func() {
		ti := time.NewTicker(time.Second)
		t := time.Now()
		for {
			select {
			case <-done:
				fmt.Print("\n")
				return
			case <-ti.C:
				fmt.Printf("\rworking for %s\033[0K", jfmt.FmtDuration(time.Since(t)))
			}
		}
	}()
	m := &dave.M{Op: dave.Op_SET, Val: val, Time: godave.Ttb(time.Now())}
	type sol struct{ work, nonce []byte }
	solch := make(chan sol)
	ncpu := max(runtime.NumCPU()-2, 1)
	fmt.Printf("running on %d cores\n", ncpu)
	for n := 0; n < ncpu; n++ {
		go func() {
			w, n := godave.Work(m.Val, m.Time, difficulty)
			solch <- sol{w, n}
		}()
	}
	s := <-solch
	m.Work = s.work
	m.Nonce = s.nonce
	done <- struct{}{}
	err := dapi.SendM(d, m)
	if err != nil {
		fmt.Printf("failed to set dat: %v\n", err)
	}
	printMsg(os.Stdout, m)
	fmt.Printf("\n%x\n", m.Work)
	if err != nil {
		exit(1, err.Error())
	}
}

func printMsg(w io.Writer, m *dave.M) bool {
	if m.Op == dave.Op_GETPEER || m.Op == dave.Op_PEER {
		return false
	}
	if m.Op == dave.Op_DAT {
		fmt.Fprintf(w, "%s %v %s\n", m.Op, godave.Weight(m.Work, godave.Btt(m.Time)), m.Val)
	} else {
		fmt.Fprintf(w, "%s %s\n", m.Op, m.Val)
	}
	return true
}

func exit(code int, msg string, args ...any) {
	fmt.Printf(msg+"\n", args...)
	os.Exit(code)
}
