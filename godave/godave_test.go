package godave

import (
	"math/rand"
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
	for i := 0; i < 10000; i++ {
		peers[test_randomAddrPort()] = &peer{}
	}
	exclude := make([]string, 0)
	var i int
	for ap := range peers {
		exclude = append(exclude, ap.String())
		if i > 10000 {
			break
		}
		i++
	}
	// test exclusion
	rndAddrs := buggy_rndAddr(peers, exclude, 10000)
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

// buggy as shit
func buggy_rndAddr(peers map[netip.AddrPort]*peer, exclude []string, limit int) []string {
	candidates := make([]string, 0, len(peers)-len(exclude))
	for ip, p := range peers {
		// don't overload bootstrap peers
		if !p.bootstrap && p.drop <= 1 && p.nping <= 1 && !in(ip.String(), exclude) {
			candidates = append(candidates, ip.String())
		}
	}
	if len(candidates) == 0 {
		return []string{}
	}
	if len(candidates) == 1 {
		return []string{candidates[0]}
	}
	mygs := make(map[string]struct{})
	ans := make([]string, 0)
	for len(ans) < len(candidates) && len(ans) < limit {
		r := mrand.Intn(len(candidates) - 1)
		_, already := mygs[candidates[r]]
		if !already {
			ans = append(ans, candidates[r])
		}
	}
	return ans
}

func test_randomAddrPort() netip.AddrPort {
	ip := netip.AddrFrom4([4]byte{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))})
	return netip.AddrPortFrom(netip.Addr(ip), uint16(mrand.Intn(65535-1024)+1024))
}
