package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
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
	BOOTSTRAP_MSG  = 3
	TIMEOUT_GETDAT = time.Second
)

func main() {
	network := flag.String("network", "udp", "<udp|udp6|udp4>")
	lap := flag.String("l", "[::]:0", "<LAP> listen address:port")
	bapref := flag.String("b", "", "<BAP> bootstrap address:port")
	bfile := flag.String("bf", "", "<BFILE> bootstrap file of address:port\\n")
	work := flag.Int("w", 3, "<WORK> ammount of work to do")
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
	d, err := godave.NewDave(udpaddr, bootstrap)
	if err != nil {
		exit(1, "failed to make dave: %v", err)
	}

	var n int
	for range d.Recv {
		n++
		if n >= BOOTSTRAP_MSG {
			break
		}
	}

	var action string
	if flag.NArg() > 0 {
		action = flag.Arg(0)
	}
	switch strings.ToUpper(action) {
	case "TESTFILE":
		if flag.NArg() < 2 {
			exit(1, "failed: correct usage is getfile <HEAD>")
		}
		testFile(d, flag.Arg(1))

	case "GETFILE":
		if flag.NArg() < 2 {
			exit(1, "failed: correct usage is getfile <HEAD> /output/to/file")
		}
		getFile(d, flag.Arg(1), flag.Arg(2))

	case "SETFILE":
		if flag.NArg() < 2 {
			exit(1, "missing argument: setfile /path/to/file")
		}
		setFile(d, *work, flag.Arg(1), *tag)

	case "SETDAT":
		if flag.NArg() < 2 {
			exit(1, "missing argument: setdat <VAL>")
		}
		setDat(d, *work, *prevhex, *tag)

	case "GETDAT":
		if flag.NArg() < 2 {
			exit(1, "failed: correct usage is getdat <WORK>")
		}
		getDat(d, flag.Arg(1), TIMEOUT_GETDAT)

	default:
		for m := range d.Recv {
			printMsg(m)
		}
	}
}

func setDat(d *godave.Dave, work int, prevhex, tag string) {
	var prev []byte
	if prevhex != "" {
		var err error
		prev, err = hex.DecodeString(prevhex)
		if err != nil {
			exit(1, "failed to decode -p <PREV>")
		}
	}
	wch, err := godave.Work(&dave.Msg{Op: dave.Op_SETDAT, Prev: prev, Val: []byte(flag.Arg(1)), Tag: []byte(tag)}, work)
	if err != nil {
		panic(err)
	}
	msg := <-wch
	err = send(d, msg, 10*time.Second)
	if err != nil {
		exit(1, "failed to set dat: %v", err)
	}
	fmt.Print("-> ")
	printMsg(msg)
	time.Sleep(500 * time.Millisecond)
}

func getDat(d *godave.Dave, workhex string, timeout time.Duration) {
	work, err := hex.DecodeString(workhex)
	if err != nil {
		exit(1, "failed: failed to decode hex")
	}
	t := time.After(timeout)
	send(d, &dave.Msg{Op: dave.Op_GETDAT, Work: work}, timeout)
	for {
		select {
		case m := <-d.Recv:
			if m.Op == dave.Op_DAT && bytes.Equal(m.Work, work) {
				printMsg(m)
				return
			}
		case <-t:
			return
		}
	}
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
		buf := make([]byte, godave.LEN_VAL)
		n, err := f.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
		}
		wch, err := godave.Work(&dave.Msg{Op: dave.Op_SETDAT, Prev: head, Val: buf[:n], Tag: []byte(tag)}, work)
		if err != nil {
			panic(err)
		}
		msg := <-wch
		send(d, msg, 5*time.Second)
		send(d, nil, time.Second)
		head = msg.Work
		i++
		fmt.Printf("DAT %d SENT -> %x\n", i, head)
		fmt.Println(string(msg.Val))
	}
	fmt.Printf("HEAD %x\n%s/%x\n", head, "http://localhost:8080", head)
}

func testFile(d *godave.Dave, headhex string) {
	dats := getFileDats(d, headhex, TIMEOUT_GETDAT)
	for range dats {
	}
}

func getFile(d *godave.Dave, headhex, fname string) {
	dats := getFileDats(d, headhex, TIMEOUT_GETDAT)
	result := make([]byte, 0)
	var f *os.File
	if fname != "" {
		f, err := os.Create(fname)
		if err != nil {
			fmt.Println("failed: create", fname, err)
		}
		defer f.Close()
	}
	for d := range dats {
		result = append(d, result...)
	}
	if fname != "" {
		_, err := f.Write(result)
		if err != nil {
			exit(1, "failed to write file: %v", err)
		}
	} else {
		fmt.Println(string(result))
	}
}

func getFileDats(d *godave.Dave, headstr string, timeout time.Duration) <-chan []byte {
	out := make(chan []byte)
	go func() {
		head, err := hex.DecodeString(headstr)
		if err != nil {
			fmt.Println("failed to decode hex")
		}
		send(d, &dave.Msg{Op: dave.Op_GETDAT, Work: head}, timeout)
		var i int
		for m := range d.Recv {
			if m.Op != dave.Op_DAT || !bytes.Equal(m.Work, head) {
				continue
			}
			check := godave.CheckWork(m)
			if check < godave.MINWORK {
				fmt.Printf("invalid work: require %d, has %d, trying again...\n", godave.MINWORK, check)
				send(d, &dave.Msg{Op: dave.Op_GETDAT, Work: head}, timeout)
				continue
			}
			out <- m.Val
			i++
			fmt.Printf("GOT DAT %d PREV: %x\n", i, m.Prev)
			if m.Prev == nil {
				close(out)
				return
			}
			head = m.Prev
			send(d, &dave.Msg{Op: dave.Op_GETDAT, Work: head}, timeout)
		}
	}()
	return out
}

func send(d *godave.Dave, msg *dave.Msg, timeout time.Duration) error {
	t := time.After(timeout)
	for {
		select {
		case <-d.Recv:
		case d.Send <- msg:
			return nil
		case <-t:
			return errors.New("timeout")
		}
	}
}

func printMsg(m *dave.Msg) {
	if m.Op == dave.Op_GETPEER || m.Op == dave.Op_PEER {
		return
	}
	fmt.Printf("%s ", m.Op)
	switch m.Op {
	case dave.Op_GETDAT:
		fmt.Printf("%x\n", m.Work)
	case dave.Op_SETDAT:
		fmt.Printf("PREV: %x\nWORK: %x\nTAG: %s\n", m.Prev, m.Work, m.Tag)
	case dave.Op_DAT:
		fmt.Printf("PREV: %x\nWORK: %x\nVAL: %s\nTAG: %s\n", m.Prev, m.Work, string(m.Val), m.Tag)
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
