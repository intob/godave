package main

import (
	"flag"
	"fmt"
	"net/netip"
	"strings"

	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/davepb"
)

func main() {
	portFlag := flag.Int("p", godave.PORT_DEFAULT, "listen port")
	peerFlag := flag.String("b", "", "bootstrap peer")
	flag.Parse()
	bootstrap := make([]netip.AddrPort, 0)
	peerstr := *peerFlag
	if peerstr != "" {
		if strings.HasPrefix(peerstr, ":") {
			peerstr = "127.0.0.1" + peerstr
		}
		addr, err := netip.ParseAddrPort(peerstr)
		if err != nil {
			panic(err)
		}
		bootstrap = append(bootstrap, addr)
	}
	d := godave.NewDave(*portFlag, bootstrap)
	var n int
	fmt.Printf("bootstrap")
	for range d.Msg() {
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
	for m := range d.Msg() {
		switch m.Op {
		case davepb.Op_DAT:
			fmt.Printf("DAT :: %s\n", string(m.Val))
		case davepb.Op_SETDAT:
			fmt.Printf("SETDAT :: %x\n", m.Key)
		case davepb.Op_GETDAT:
			fmt.Printf("GETDAT :: %x\n", m.Key)
		default:
			fmt.Printf("%v :: %+v\n", m.Op, m.Addrs)
		}
	}
}

/*
func readHosts(fname string) ([]string, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hosts := make([]string, 0)
	s := bufio.NewScanner(f)
	for s.Scan() {
		l := s.Text()
		if l != "" && !strings.HasPrefix(l, "#") {
			l = strings.ReplaceAll(l, "\t", " ")
			fields := strings.Split(l, " ")
			if len(fields) == 0 {
				continue
			}
			addr := fmt.Sprintf("%s:%d", fields[0], PORT_DEFAULT)
			hosts = append(hosts, addr)
		}
	}
	return hosts, nil
}
*/
