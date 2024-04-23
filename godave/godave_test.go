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
	work, _ := Work([]byte("test"), nil, dif)
	ws := weight(work, time.Now().Add(-time.Second))
	wm := weight(work, time.Now().Add(-time.Minute))
	wh := weight(work, time.Now().Add(-time.Hour))
	wd := weight(work, time.Now().Add(-24*time.Hour))
	zero := weight(work, time.Time{})
	fmt.Printf("second: %v\nminute: %v\nhour: %v\nday: %v\nzero: %v\n", ws, wm, wh, wd, zero)
}
