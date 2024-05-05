package godave

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/intob/godave/dave"
)

func TestMass(t *testing.T) {
	testMassDifficulty(2)
	testMassDifficulty(3)
}

func testMassDifficulty(dif int) {
	work, _ := Work([]byte("test"), Ttb(time.Now()), dif)
	ws := Mass(work, time.Now().Add(-time.Second))
	wm := Mass(work, time.Now().Add(-time.Minute))
	wh := Mass(work, time.Now().Add(-time.Hour))
	wd := Mass(work, time.Now().Add(-24*time.Hour))
	zero := Mass(work, time.Time{})
	fmt.Printf("second: %v\nminute: %v\nhour: %v\nday: %v\nzero: %v\n", ws, wm, wh, wd, zero)
}

func makeDave() *Dave {
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
	d, err := NewDave(&Cfg{Listen: laddr, Bootstraps: []netip.AddrPort{ap}, DatCap: 500000, FilterCap: 1000000, Log: log})
	if err != nil {
		panic(err)
	}
	return d
}

func TestPacket(t *testing.T) {
	const n = 100
	//d := makeDave()
	var max int
	for i := 0; i < n; i++ {
		m := &dave.M{
			Op: dave.Op_DAT,
			//Pds: collectPds(d),
			V: make([]byte, 1180), // THIS WILL HIT MTU WITH MAX DISTANCE
			T: Ttb(time.Now()),
		}
		m.W, m.S = Work(m.V, m.T, 0)
		l := len(marshal(m))
		if l > max {
			max = l
		}
	}
	fmt.Printf("largest packet of %d: %d, MTU: %d", n, max, MTU)
}
