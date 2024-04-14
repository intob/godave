package main

import (
	"bufio"
	"encoding/hex"
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
	flaghosts := flag.String("h", "", "hosts file")
	flagprev := flag.String("prev", "", "prev work")
	flagtag := flag.String("tag", "", "tag")
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
	if *flaghosts != "" {
		bh, err := readHosts(*flaghosts)
		if err != nil {
			panic(err)
		}
		bootstrap = append(bootstrap, bh...)
	}
	d, err := godave.NewDave(*flagport, bootstrap)
	if err != nil {
		panic(err)
	}
	go func() {
		var n int
		fmt.Printf("%v\nbootstrap\n", bootstrap)
		for range d.Recv {
			n++
			fmt.Printf(".\033[0K")
			if n >= godave.BOOTSTRAP_MSG {
				fmt.Print("\n\033[0K")
				break
			}
		}
	}()
	go func() {
		if flag.NArg() > 0 {
			action := flag.Arg(0)
			switch strings.ToUpper(action) {
			case davepb.Op_SETDAT.String():
				if flag.NArg() < 2 {
					fmt.Println("SETDAT failed: correct usage is setdat <value>")
					os.Exit(1)
				}
				fmt.Println("setdat working...")
				var prev []byte
				if *flagprev != "" {
					prev, err = hex.DecodeString(*flagprev)
					if err != nil {
						fmt.Println("SETDAT failed: failed to decode prev hex")
						os.Exit(1)
					}
				}
				work, err := godave.Work(&davepb.Msg{
					Prev: prev,
					Val:  []byte(flag.Arg(1)),
					Tag:  []byte(*flagtag),
				}, godave.WORK_MIN)
				if err != nil {
					panic(err)
				}
				msg := <-work
				d.Send <- msg
				fmt.Printf("SETDAT done :: %s\n%x\n", msg.Tag, msg.Work)
				return
			case davepb.Op_GETDAT.String():
				if flag.NArg() < 2 {
					fmt.Println("GETDAT failed: correct usage is getdat <work>")
					os.Exit(1)
				}
				work, err := hex.DecodeString(flag.Arg(1))
				if err != nil {
					fmt.Println("GETDAT failed: failed to decode work hex")
					os.Exit(1)
				}
				d.Send <- &davepb.Msg{
					Op:   davepb.Op_GETDAT,
					Work: work,
				}
			default:
				panic("command not recognized")
			}
		}
	}()
	for m := range d.Recv {
		switch m.Op {
		case davepb.Op_ADDR:
			fmt.Printf("ADDR :: %v\n", m.Addrs)
		case davepb.Op_SETDAT:
			fmt.Printf("SETDAT :: %s :: %x\n", m.Tag, m.Work)
		case davepb.Op_GETDAT:
			fmt.Printf("GETDAT :: %x\n", m.Work)
		case davepb.Op_DAT:
			fmt.Printf("DAT :: %s :: %x :: %s\n", m.Tag, m.Work, string(m.Val))
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
