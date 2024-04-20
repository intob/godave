package godave

import (
	"testing"

	"github.com/intob/dave/godave/dave"
)

func TestCheckMsgEmpty(t *testing.T) {
	expect := -1
	c := CheckMsg(&dave.M{})
	if c != expect {
		t.Fatalf("Expected %v, CheckWork returned %v", expect, c)
	}
	c = CheckMsg(&dave.M{Op: dave.Op_SET, Val: []byte("test")})
	if c != expect {
		t.Fatalf("Expected %v, CheckWork returned %v", expect, c)
	}
}

func TestWork(t *testing.T) {
	work := 2
	m := &dave.M{Op: dave.Op_SET, Val: []byte("test")}
	w, err := Work(m, work)
	if err != nil {
		t.Fatal(err)
	}
	c := CheckMsg(<-w)
	if c != work {
		t.Fatalf("Expected %v, CheckWork returned %v", work, c)
	}
}
