package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/dave"
)

const BOOTSTRAP_MSG = 8

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
		dats := getFile(d, flag.Arg(1))
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
			exit(1, "failed: correct usage is setfile /path/to/file")
		}
		setFile(d, flag.Arg(1), *flagtag)

	case "SETDAT":
		if flag.NArg() < 2 {
			exit(1, "failed: correct usage is setdat <VAL>")
		}
		fmt.Println("setdat working...")
		var prev []byte
		if *flagprev != "" {
			prev, err = hex.DecodeString(*flagprev)
			if err != nil {
				exit(1, "failed: failed to decode hex")
			}
		}
		work, err := godave.Work(&dave.Msg{
			Op:   dave.Op_SETDAT,
			Prev: prev,
			Val:  []byte(flag.Arg(1)),
			Tag:  []byte(*flagtag),
		}, godave.WORK_MIN)
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
		t := time.After(time.Second)
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
	}()
	d.Send <- &dave.Msg{
		Op:   dave.Op_GETDAT,
		Work: work,
	}
	<-done
}

func setFile(d *godave.Dave, fname, tag string) {
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
		work, err := godave.Work(&dave.Msg{
			Op:   dave.Op_SETDAT,
			Prev: head,
			Val:  buf[:n],
			Tag:  []byte(tag),
		}, godave.WORK_MIN)
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
		head = msg.Work
		i++
		fmt.Printf("DAT %d SENT -> %x\n", i, head)
		fmt.Println(string(msg.Val))
	}
	fmt.Printf("HEAD %x\n", head)
}

func getFile(d *godave.Dave, headstr string) <-chan []byte {
	out := make(chan []byte)
	go func() {
		head, err := hex.DecodeString(headstr)
		if err != nil {
			fmt.Println("failed: failed to decode hex")
		}
		d.Send <- &dave.Msg{
			Op:   dave.Op_GETDAT,
			Work: head,
		}
		var i int
		for m := range d.Recv {
			if m.Op == dave.Op_DAT && bytes.Equal(m.Work, head) {
				if godave.CheckWork(m) < godave.WORK_MIN {
					exit(1, "invalid work")
				}
				out <- m.Val
				head = m.Prev
				i++
				fmt.Printf("GOT DAT %d HEAD::%x\n", i, head)
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
