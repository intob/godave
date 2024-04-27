package dapi

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/intob/dave/dapi/can"
	"github.com/intob/dave/godave"
	"google.golang.org/protobuf/proto"
)

/*
func TestRead(t *testing.T) {
	buf := &bytes.Buffer{}
	f, _ := os.Open("../README")
	defer f.Close()
	buf.ReadFrom(f)
	ch := Read(buf, 1200)
	for b := range ch {
		fmt.Println("______")
		fmt.Println("CHUNK:", len(b))
		fmt.Print(string(b))
		fmt.Println("")
		fmt.Println("______")
		if len(b) > 1200 {
			t.FailNow()
		}
	}
}

func TestPrepChunks(t *testing.T) {
	buf := &bytes.Buffer{}
	f, _ := os.Open("../README")
	defer f.Close()
	buf.ReadFrom(f)
	ch := Read(buf, 1200)
	mch := PrepChunks(ch, 2)
	to := time.After(time.Minute)
	for {
		select {
		case wm, ok := <-mch:
			if ok {
				fmt.Println(godave.Check(wm.Val, wm.Time, wm.Nonce, wm.Work))
			} else {
				return
			}
		case <-to:
			t.Fatalf("timeout")
		}
	}
}
*/

func makeDave() *godave.Dave {
	laddr, err := net.ResolveUDPAddr("udp", "[::]:0")
	if err != nil {
		panic(err)
	}
	ap, err := netip.ParseAddrPort("54.195.136.26:1618")
	if err != nil {
		panic(err)
	}
	log := make(chan string, 1)
	go func() {
		for range log {
		}
	}()
	d, err := godave.NewDave(&godave.Cfg{Listen: laddr, Bootstraps: []netip.AddrPort{ap}, DatCap: 500000, FilterCap: 1000000, Log: log})
	if err != nil {
		panic(err)
	}
	return d
}

func TestMakeCans(t *testing.T) {
	d := makeDave()
	f, _ := os.Open("../README")
	defer f.Close()
	ch := Read(f, 1200)
	chunkchan := PrepChunks(ch, 2)
	datchan := SendDats(d, chunkchan)
	canchan := MakeCans(d, 2, datchan)
	to := time.After(time.Minute)
	for {
		select {
		case canmsg, ok := <-canchan:
			if ok {
				pl()
				fmt.Printf("CANMSG: %x\n", canmsg.Work)
				pl()
				testCan(d, canmsg.Work)
			} else {
				return
			}
		case <-to:
			t.Fatalf("timeout")
		}
	}
}

func testCan(d *godave.Dave, canHash []byte) {
	dat, err := GetDat(d, canHash)
	if err != nil {
		panic(err)
	}
	c := &can.Can{}
	err = proto.Unmarshal(dat.Val, c)
	if err != nil {
		panic(err)
	}
	for _, dat := range c.Dats {
		d, err := GetDat(d, dat)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%f %x\n", godave.Weight(d.Work, d.Ti), d.Work)
	}
	pl()
	for _, dat := range c.Dats {
		d, err := GetDat(d, dat)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", d.Val)
	}
}

func pl() {
	fmt.Print("--------------------------------------------------------------------------§\n")
}
