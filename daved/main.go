package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/dave"
)

const (
	BOOTSTRAP_MSG = 3
)

func main() {
	network := flag.String("network", "udp", "<udp|udp6|udp4>")
	lap := flag.String("l", "[::]:0", "<LAP> listen address:port")
	bapref := flag.String("b", "", "<BAP> bootstrap address:port")
	bfile := flag.String("bf", "", "<BFILE> bootstrap file of address:port\\n")
	work := flag.Int("w", 3, "<WORK> ammount of work to do")
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
	case "SETDAT":
		if flag.NArg() < 2 {
			exit(1, "missing argument: setdat <VAL>")
		}
		setDat(d, *work, *tag)
	case "GETDAT":
		if flag.NArg() < 2 {
			exit(1, "failed: correct usage is getdat <WORK>")
		}
		getDat(d, flag.Arg(1), time.Second)
	default:
		for {
			select {
			case m := <-d.Recv:
				printMsg(m)
			case <-time.After(10 * time.Second):
				fmt.Printf("Stat: %+v\n", d.Stat())
			}
		}
	}
}

func setDat(d *godave.Dave, work int, tag string) {
	wch, err := godave.Work(&dave.M{Op: dave.Op_SETDAT, Val: []byte(flag.Arg(1)), Tag: []byte(tag)}, work)
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
	send(d, &dave.M{Op: dave.Op_GETDAT, Work: work}, timeout)
	var tries int
	for {
		select {
		case m := <-d.Recv:
			if m.Op == dave.Op_DAT && bytes.Equal(m.Work, work) {
				printMsg(m)
				return
			}
		case <-t:
			tries++
			if tries > 3 {
				return
			}
			send(d, &dave.M{Op: dave.Op_GETDAT, Work: work}, timeout)
			t = time.After(timeout)
		}
	}
}

func send(d *godave.Dave, msg *dave.M, timeout time.Duration) error {
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

func printMsg(m *dave.M) {
	if m.Op == dave.Op_GETPEER || m.Op == dave.Op_PEER {
		return
	}
	fmt.Printf("%s ", m.Op)
	switch m.Op {
	case dave.Op_GETDAT:
		fmt.Printf("%x\n", m.Work)
	case dave.Op_SETDAT:
		fmt.Printf("WORK: %x\nTAG: %s\n", m.Work, m.Tag)
	case dave.Op_DAT:
		fmt.Printf("WORK: %x\nVAL: %s\nTAG: %s\n", m.Work, string(m.Val), m.Tag)
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
