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

func main() {
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
			exit(1, "failed to read file %q: %v", *bfile, err)
		}
		bootstrap = append(bootstrap, bh...)
	}
	udpaddr, err := net.ResolveUDPAddr("udp", *lap)
	if err != nil {
		exit(1, "failed to resolve UDP address: %v", err)
	}
	d, err := godave.NewDave(udpaddr, bootstrap)
	if err != nil {
		exit(1, "failed to make dave: %v", err)
	}
	var action string
	if flag.NArg() > 0 {
		action = flag.Arg(0)
	}
	switch strings.ToLower(action) {
	case "set":
		if flag.NArg() < 2 {
			exit(1, "missing argument: set <VAL>")
		}
		go setDat(d, *work, *tag)
	case "get":
		if flag.NArg() < 2 {
			exit(1, "correct usage is get <WORK>")
		}
		work, err := hex.DecodeString(flag.Arg(1))
		if err != nil {
			exit(1, "invalid input <WORK>: %v", err)
		}
		dat, err := GetDat(d, work, time.Second)
		if err != nil {
			exit(1, "failed: %v", err)
		}
		fmt.Println(string(dat.Val))
	}
	t := time.After(10 * time.Second)
	for {
		select {
		case <-t:
			fmt.Printf("stat: %+v\n", d.Stat())
			t = time.After(10 * time.Second)
		case m := <-d.Recv:
			printMsg(m)
		}
	}
}

func setDat(d *godave.Dave, work int, tag string) {
	wch, err := godave.Work(&dave.M{Op: dave.Op_SET, Val: []byte(flag.Arg(1)), Tag: []byte(tag)}, work)
	if err != nil {
		panic(err)
	}
	msg := <-wch
	err = send(d, msg, time.Second)
	if err != nil {
		exit(1, "failed to set dat: %v", err)
	}
	printMsg(msg)
}

func GetDat(d *godave.Dave, work []byte, timeout time.Duration) (*godave.Dat, error) {
	send(d, &dave.M{Op: dave.Op_GET, Work: work}, timeout)
	var tries int
	t := time.After(time.Second)
	for {
		select {
		case m := <-d.Recv:
			if m.Op == dave.Op_DAT && bytes.Equal(m.Work, work) {
				check := godave.CheckMsg(m)
				dat := &godave.Dat{Val: m.Val, Tag: m.Tag, Nonce: m.Nonce}
				if check < godave.MINWORK {
					return dat, errors.New("invalid work")
				}
				return dat, nil
			}
		case <-t:
			tries++
			if tries > 3 {
				return nil, errors.New("not found")
			}
			send(d, &dave.M{Op: dave.Op_GET, Work: work}, timeout)
			t = time.After(time.Second)
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
	case dave.Op_GET:
		fmt.Printf("%x\n", m.Work)
	case dave.Op_SET:
		fmt.Printf("TAG: %s :: WORK: %x\n", m.Tag, m.Work)
	case dave.Op_DAT:
		fmt.Printf("TAG: %s :: WORK: %x\nVAL: %s\n", m.Tag, m.Work, string(m.Val))
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
