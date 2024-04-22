package godave

import (
	"fmt"
	"testing"
	"time"

	"github.com/intob/dave/godave/dave"
)

func TestWeight(t *testing.T) {
	testWeightDifficulty(2)
	testWeightDifficulty(3)
	testWeightDifficulty(4)
}

func testWeightDifficulty(dif int) {
	m := &dave.M{Val: []byte("test")}
	wch, _ := Work(m, dif)
	mw := <-wch
	d := &Dat{mw.Val, mw.Tag, mw.Nonce, mw.Work, time.Time{}}
	ws := weight(wt(d, time.Now().Add(-time.Second)))
	wm := weight(wt(d, time.Now().Add(-time.Minute)))
	wh := weight(wt(d, time.Now().Add(-time.Hour)))
	wd := weight(wt(d, time.Now().Add(-24*time.Hour)))
	zero := weight(wt(d, time.Time{}))
	fmt.Printf("second: %v\nminute: %v\nhour: %v\nday: %v\nzero: %v\n", ws, wm, wh, wd, zero)
}

func wt(d *Dat, t time.Time) *Dat {
	d.added = t
	return d
}
