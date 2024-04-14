package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/davepb"
)

func main() {
	flagport := flag.Int("p", 0, "listen port")
	flagpeer := flag.String("b", "", "bootstrap peer")
	hosts := flag.String("h", "", "hosts file")
	flag.Parse()
	bootstrap := make([]netip.AddrPort, 0)
	peerstr := *flagpeer
	if peerstr != "" {
		if strings.HasPrefix(peerstr, ":") {
			peerstr = "[::1]" + peerstr
		}
		addr, err := netip.ParseAddrPort(peerstr)
		if err != nil {
			panic(err)
		}
		bootstrap = append(bootstrap, addr)
	}
	if *hosts != "" {
		bh, err := readHosts(*hosts)
		if err != nil {
			panic(err)
		}
		bootstrap = append(bootstrap, bh...)
	}
	d, err := godave.NewDave(*flagport, bootstrap)
	if err != nil {
		panic(err)
	}
	var n int
	fmt.Printf("%v\nbootstrap", bootstrap)
	for range d.Msgch() {
		n++
		fmt.Printf(".\033[0K")
		if n >= godave.BOOTSTRAP_MSG {
			fmt.Print("\n\033[0K")
			break
		}
	}
	if flag.NArg() > 0 {
		action := flag.Arg(0)
		switch strings.ToUpper(action) {
		case davepb.Op_SETDAT.String():
			if flag.NArg() < 2 {
				fmt.Println("SETDAT failed: correct usage is setdat <value>")
				return
			}
			val := flag.Arg(1)
			m := &davepb.Msg{
				Val: []byte(val),
			}
			fmt.Println("setdat working...")
			mworkch, err := godave.Work(m, godave.WORK_MIN)
			if err != nil {
				panic(err)
			}
			mworked := <-mworkch
			fmt.Printf("setdat sending... %x\n", mworked.Key)
			d.Send(mworked)
		case davepb.Op_GETDAT.String():
			if flag.NArg() < 2 {
				fmt.Println("GETDAT failed: correct usage is getdat <key>")
				return
			}
		default:
			panic("command not recognized")
		}
	}
	for m := range d.Msgch() {
		switch m.Op {
		case davepb.Op_SETDAT:
			fmt.Printf("SETDAT :: %x\n", m.Key)
		case davepb.Op_GETDAT:
			fmt.Printf("GETDAT :: %x\n", m.Key)
		case davepb.Op_DAT:
			fmt.Printf("DAT :: %x :: %s\n", m.Key, string(m.Val))
		case davepb.Op_ADDR:
			fmt.Printf("%v :: %+v\n", m.Op, m.Addrs)
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
