package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/dave"
)

const (
	BOOTSTRAP_MSG  = 8
	TIMEOUT_GETDAT = time.Second
)

func main() {
	network := flag.String("network", "udp", "<udp|udp6|udp4>")
	lap := flag.String("l", "[::]:0", "<LAP> listen address:port")
	bapref := flag.String("b", "", "<BAP> bootstrap address:port")
	bfile := flag.String("bf", "", "<BFILE> bootstrap file of address:port\\n")
	work := flag.Int("w", 3, "<WORK> minimum work to store DAT")
	prevhex := flag.String("p", "", "<PREV> prev work")
	tag := flag.String("t", "", "<TAG> arbitrary data")
	flag.Parse()

	bootstrap := make([]netip.AddrPort, 0)
	bap := *bapref
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

	udpaddr, err := net.ResolveUDPAddr(*network, *lap)
	if err != nil {
		exit(1, "failed to resolve UDP address: %v", err)
	}
	d, err := godave.NewDave(*work, udpaddr, bootstrap)
	if err != nil {
		exit(1, "failed to make dave: %v", err)
	}

	var n int
	fmt.Printf("%v\nbootstrap\n", bootstrap)
	for range d.Recv {
		n++
		fmt.Printf(".\033[0K")
		if n >= BOOTSTRAP_MSG {
			fmt.Print("\n\033[0K")
			break
		}
	}

	var action string
	if flag.NArg() > 0 {
		action = flag.Arg(0)
	}
	switch strings.ToUpper(action) {
	case "GETFILE":
		if flag.NArg() < 2 {
			exit(1, "failed: correct usage is getfile <HEAD> /output/to/file")
		}
		dats := getFile(d, *work, flag.Arg(1))
		result := make([]byte, 0)
		var f *os.File
		if flag.NArg() > 2 {
			f, err = os.Create(flag.Arg(2))
			if err != nil {
				fmt.Println("failed: create", flag.Arg(2), err)
			}
			defer f.Close()
		}
		for d := range dats {
			result = append(d, result...)
		}
		if f != nil {
			f.Write(result)
		} else {
			fmt.Println(string(result))
		}

	case "SETFILE":
		if flag.NArg() < 2 {
			exit(1, "missing argument: setfile /path/to/file")
		}
		setFile(d, *work, flag.Arg(1), *tag)

	case "SETDAT":
		if flag.NArg() < 2 {
			exit(1, "missing argument: setdat <VAL>")
		}
		fmt.Println("setdat working...")
		var prev []byte
		if *prevhex != "" {
			prev, err = hex.DecodeString(*prevhex)
			if err != nil {
				exit(1, "failed to decode -p <PREV>")
			}
		}
		work, err := godave.Work(&dave.Msg{
			Op:   dave.Op_SETDAT,
			Prev: prev,
			Val:  []byte(flag.Arg(1)),
			Tag:  []byte(*tag),
		}, *work)
		if err != nil {
			panic(err)
		}
		msg := <-work
	send:
		for {
			select {
			case d.Send <- msg:
				break send
			case <-d.Recv:
			}
		}
		fmt.Print("-> ")
		printMsg(msg)
		time.Sleep(500 * time.Millisecond)

	case "GETDAT":
		if flag.NArg() < 2 {
			exit(1, "failed: correct usage is getdat <WORK>")
		}
		getDat(d, flag.Arg(1))

	default:
		for m := range d.Recv {
			printMsg(m)
		}
	}
}

func getDat(d *godave.Dave, workhex string) {
	work, err := hex.DecodeString(workhex)
	if err != nil {
		exit(1, "failed: failed to decode hex")
	}
	done := make(chan struct{})
	go func() {
		t := time.After(TIMEOUT_GETDAT)
		for {
			select {
			case d.Send <- &dave.Msg{
				Op:   dave.Op_GETDAT,
				Work: work,
			}:
				for {
					select {
					case m := <-d.Recv:
						if m.Op == dave.Op_DAT && bytes.Equal(m.Work, work) {
							printMsg(m)
							done <- struct{}{}
							return
						}
					case <-t:
						done <- struct{}{}
						return
					}
				}
			case <-d.Recv:
			}
		}
	}()
	<-done
}

func setFile(d *godave.Dave, work int, fname, tag string) {
	f, err := os.Open(fname)
	if err != nil {
		exit(1, "failed: open %s: %s", fname, err)
	}
	defer f.Close()
	var head []byte
	var i int
	for {
		buf := make([]byte, godave.VAL_SIZE)
		n, err := f.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
		}
		wch, err := godave.Work(&dave.Msg{
			Op:   dave.Op_SETDAT,
			Prev: head,
			Val:  buf[:n],
			Tag:  []byte(tag),
		}, work)
		if err != nil {
			panic(err)
		}
		msg := <-wch
	send:
		for {
			select {
			case d.Send <- msg:
				break send
			case <-d.Recv:
			}
		}
		head = msg.Work
		i++
		fmt.Printf("DAT %d SENT -> %x\n", i, head)
		fmt.Println(string(msg.Val))
	}
	fmt.Printf("HEAD %x\n", head)
}

func getFile(d *godave.Dave, work int, headstr string) <-chan []byte {
	out := make(chan []byte)
	go func() {
		head, err := hex.DecodeString(headstr)
		if err != nil {
			fmt.Println("failed: failed to decode hex")
		}
	sendhead:
		for {
			select {
			case d.Send <- &dave.Msg{
				Op:   dave.Op_GETDAT,
				Work: head,
			}:
				break sendhead
			case <-d.Recv:
			}
		}

		var i int
		for m := range d.Recv {
			if m.Op == dave.Op_DAT && bytes.Equal(m.Work, head) {
				check := godave.CheckWork(m)
				if check < work {
					exit(1, "invalid work: %v, require: %v", check, work)
				}
				out <- m.Val
				head = m.Prev
				i++
				fmt.Printf("GOT DAT %d PREV::%x\n", i, head)
				if head == nil {
					close(out)
					return
				}
			send:
				for {
					select {
					case d.Send <- &dave.Msg{
						Op:   dave.Op_GETDAT,
						Work: head,
					}:
						break send
					case <-d.Recv:
					}
				}

			}
		}
	}()
	return out
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

func printMsg(m *dave.Msg) {
	if m.Op == dave.Op_GETPEER {
		return
	}
	fmt.Printf("%s ", m.Op)
	switch m.Op {
	case dave.Op_PEER:
		fmt.Printf("%v\n", m.Peers)
	case dave.Op_GETDAT:
		fmt.Printf("WORK::%x\n", m.Work)
	case dave.Op_SETDAT:
		fmt.Printf("TAG::%s PREV::%x WORK::%x\n", m.Tag, m.Prev, m.Work)
	case dave.Op_DAT:
		fmt.Printf("TAG::%s PREV::%x WORK::%x VAL::%s\n", m.Tag, m.Prev, m.Work, string(m.Val))
	}
}

func exit(code int, msg string, args ...any) {
	fmt.Printf(msg, args...)
	os.Exit(code)
}
