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
	lap := flag.String("l", "[::]:0", "<LAP> listen address:port")
	bapref := flag.String("b", "", "<BAP> bootstrap address:port")
	bfile := flag.String("bf", "", "<BFILE> bootstrap file of address:port\\n")
	difficulty := flag.Int("d", 3, "<DIFFICULTY> number of leading zeros")
	dcap := flag.Uint("dc", 500000, "<DCAP> dat map capacity")
	fcap := flag.Uint("fc", 1000000, "<FCAP> cuckoo filter capacity")
	tag := flag.String("t", "", "<TAG> arbitrary")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()
	bootstraps := make([]netip.AddrPort, 0)
	bap := *bapref
	if bap != "" {
		if strings.HasPrefix(bap, ":") {
			bap = "[::1]" + bap
		}
		addr, err := netip.ParseAddrPort(bap)
		if err != nil {
			exit(1, "failed to parse -p=%q: %v", bap, err)
		}
		bootstraps = append(bootstraps, addr)
	}
	if *bfile != "" {
		bh, err := readHosts(*bfile)
		if err != nil {
			exit(1, "failed to read file %q: %v", *bfile, err)
		}
		bootstraps = append(bootstraps, bh...)
	}
	laddr, err := net.ResolveUDPAddr("udp", *lap)
	if err != nil {
		exit(1, "failed to resolve UDP address: %v", err)
	}
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
	d, err := godave.NewDave(&godave.Cfg{
		Listen:     laddr,
		Bootstraps: bootstraps,
		DatCap:     *dcap,
		FilterCap:  *fcap,
		Log:        dlw})
	if err != nil {
		exit(1, "failed to make dave: %v", err)
	}
	lw := bufio.NewWriter(os.Stdout)
	var action string
	if flag.NArg() > 0 {
		action = flag.Arg(0)
	}
	switch strings.ToLower(action) {
	case "set":
		if flag.NArg() < 2 {
			exit(1, "missing argument: set <VAL>")
		}
		done := make(chan struct{})
		go func() {
			tim := time.NewTicker(time.Second)
			t := time.Now()
			for {
				select {
				case <-done:
					fmt.Print("\n")
					return
				case <-tim.C:
					fmt.Printf("\rworking for %s\033[0K", jfmt.FmtDuration(time.Since(t)))
				}
			}
		}()
		m := &dave.M{Op: dave.Op_SET, Val: []byte(flag.Arg(1)), Tag: []byte(*tag)}
		type sol struct{ work, nonce []byte }
		solch := make(chan sol)
		ncpu := max(runtime.NumCPU()-2, 1)
		fmt.Printf("running on %d cores\n", ncpu)
		for n := 0; n < ncpu; n++ {
			go func() {
				w, n := godave.Work(m.Val, m.Tag, *difficulty)
				solch <- sol{w, n}
			}()
		}
		s := <-solch
		m.Work = s.work
		m.Nonce = s.nonce
		done <- struct{}{}
		err := dapi.SendM(d, m, time.Second)
		if err != nil {
			fmt.Printf("failed to set dat: %v\n", err)
		}
		printMsg(os.Stdout, m)
		fmt.Printf("\n%x\n", m.Work)
		if err != nil {
			exit(1, err.Error())
		}
		return
	case "get":
		if flag.NArg() < 2 {
			exit(1, "correct usage is get <WORK>")
		}
		work, err := hex.DecodeString(flag.Arg(1))
		if err != nil {
			exit(1, "invalid input <WORK>: %v", err)
		}
		dat, err := dapi.GetDat(d, work, time.Second, 3)
		if err != nil {
			exit(1, "failed: %v", err)
		}
		fmt.Println(string(dat.Val))
		return
	}
	dapi.WaitForFirstDat(d, lw)
	for m := range d.Recv {
		if printMsg(lw, m) {
			lw.Flush()
		}
	}
}

func printMsg(w io.Writer, m *dave.M) bool {
	if m.Op == dave.Op_GETPEER || m.Op == dave.Op_PEER {
		return false
	}
	fmt.Fprintf(w, "%s #%s %s\n", m.Op, m.Tag, m.Val)
	return true
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
