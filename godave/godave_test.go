package godave

import (
	mrand "math/rand"
	"net/netip"
	"testing"

	"github.com/intob/dave/godave/dave"
)

func TestCheckWorkEmpty(t *testing.T) {
	expect := -1
	c := CheckWork(&dave.Msg{})
	if c != expect {
		t.Fatalf("Expected %v, CheckWork returned %v", expect, c)
	}
	c = CheckWork(&dave.Msg{
		Op:  dave.Op_SETDAT,
		Val: []byte("test"),
	})
	if c != expect {
		t.Fatalf("Expected %v, CheckWork returned %v", expect, c)
	}
}

func TestWork(t *testing.T) {
	work := 2
	m := &dave.Msg{
		Op:  dave.Op_SETDAT,
		Val: []byte("test"),
	}
	w, err := Work(m, work)
	if err != nil {
		t.Fatal(err)
	}
	c := CheckWork(<-w)
	if c != work {
		t.Fatalf("Expected %v, CheckWork returned %v", work, c)
	}
}

func TestBuggyRndAddr(t *testing.T) {
	peers := make(map[netip.AddrPort]*peer)
	for i := 0; i < 100000; i++ {
		peers[test_randomAddrPort()] = &peer{}
	}
	exclude := make([]string, 0)
	var i int
	for ap := range peers {
		exclude = append(exclude, ap.String())
		if i > 100000 {
			break
		}
		i++
	}
	// test exclusion
	rndAddrs := rndAddr(peers, exclude, 100000)
	for _, r := range rndAddrs {
		if in(r, exclude) {
			t.Fatalf("addr %q is excluded, but included in output:\n%+v\nExcluding:\n%+v\n", r, rndAddrs, exclude)
		}
	}
	// ensure addrs are not duplicated
	m := make(map[string]struct{})
	for _, ap := range rndAddrs {
		_, ok := m[ap]
		if ok {
			t.Fatalf("duplicate found: %v", rndAddrs)
		}
		m[ap] = struct{}{}
	}
}

func test_randomAddrPort() netip.AddrPort {
	ip := netip.AddrFrom4([4]byte{byte(mrand.Intn(256)), byte(mrand.Intn(256)), byte(mrand.Intn(256)), byte(mrand.Intn(256))})
	return netip.AddrPortFrom(netip.Addr(ip), uint16(mrand.Intn(65535-1024)+1024))
}
