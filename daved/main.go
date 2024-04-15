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
	case "GETIMG":
		if flag.NArg() < 2 {
			exit(1, "failed: correct usage is getimg <HEAD> /path/to/file")
		}
		/*f, err := os.Create(flag.Arg(1))
		if err != nil {
			fmt.Println("failed: create", flag.Arg(1), err)
		}*/
		chunks := make([][]byte, 0)
		head, err := hex.DecodeString(flag.Arg(1))
		if err != nil {
			fmt.Println("failed: failed to decode hex")
		}
		var i int
		d.Send <- &dave.Msg{
			Op:   dave.Op_GETDAT,
			Work: head,
		}
		for m := range d.Recv {
			if m.Op == dave.Op_DAT && bytes.Equal(m.Work, head) {
				chunks = append(chunks, m.Val)
				head = m.Prev
				i++
				fmt.Printf("chunk %d: work::%x, prev::%x\n", i, m.Work, m.Prev)
				if head != nil {
					fmt.Println("sending...")
					d.Send <- &dave.Msg{
						Op:   dave.Op_GETDAT,
						Work: head,
					}
					fmt.Println("sent!")
				} else {
					break
				}

			}
		}
		fmt.Printf("got %d chunks: %v\n", len(chunks), chunks)

	case "SETIMG":
		if flag.NArg() < 2 {
			exit(1, "failed: correct usage is setimg /path/to/file")
		}
		f, err := os.Open(flag.Arg(1))
		if err != nil {
			exit(1, "failed: open %s: %s", flag.Arg(1), err)
		}
		defer f.Close()
		go func() {
			for m := range d.Recv {
				printMsg(m)
			}
		}()
		prev := make([]byte, 0, 32)
		var i int
		for {
			buf := make([]byte, 1280)
			n, err := f.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
			}
			work, err := godave.Work(&dave.Msg{
				Op:   dave.Op_SETDAT,
				Prev: prev,
				Val:  buf[:n],
				Tag:  []byte(*flagtag),
			}, godave.WORK_MIN)
			if err != nil {
				panic(err)
			}
			msg := <-work
			d.Send <- msg
			prev = msg.Work
			i++
			fmt.Printf("CHUNK %d SENT -> %x\n", i, msg.Work)
		}
		fmt.Println("done")
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)
	case dave.Op_SETDAT.String():
		go func() {
			for m := range d.Recv {
				printMsg(m)
			}
		}()
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
		d.Send <- msg
		fmt.Print("-> ")
		printMsg(msg)
		time.Sleep(500 * time.Millisecond)
	case dave.Op_GETDAT.String():
		if flag.NArg() < 2 {
			exit(1, "failed: correct usage is getdat <WORK>")
		}
		work, err := hex.DecodeString(flag.Arg(1))
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
	default:
		for m := range d.Recv {
			printMsg(m)
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
