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
}

func testWeightDifficulty(dif int) {
	m := &dave.M{Val: []byte("test")}
	wch, _ := Work(m, dif)
	mw := <-wch
	ws := weight(mw.Work, time.Now().Add(-time.Second))
	wm := weight(mw.Work, time.Now().Add(-time.Minute))
	wh := weight(mw.Work, time.Now().Add(-time.Hour))
	wd := weight(mw.Work, time.Now().Add(-24*time.Hour))
	zero := weight(mw.Work, time.Time{})
	fmt.Printf("second: %v\nminute: %v\nhour: %v\nday: %v\nzero: %v\n", ws, wm, wh, wd, zero)
}
