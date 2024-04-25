package godave

import (
	"fmt"
	"testing"
	"time"
)

func TestWeight(t *testing.T) {
	testWeightDifficulty(2)
	testWeightDifficulty(3)
}

func testWeightDifficulty(dif int) {
	work, _ := Work([]byte("test"), Ttb(time.Now()), dif)
	ws := Weight(work, time.Now().Add(-time.Second))
	wm := Weight(work, time.Now().Add(-time.Minute))
	wh := Weight(work, time.Now().Add(-time.Hour))
	wd := Weight(work, time.Now().Add(-24*time.Hour))
	zero := Weight(work, time.Time{})
	fmt.Printf("second: %v\nminute: %v\nhour: %v\nday: %v\nzero: %v\n", ws, wm, wh, wd, zero)
}
