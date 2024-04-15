package godave

import (
	"testing"

	"github.com/intob/dave/godave/davepb"
)

func TestCheckWorkEmpty(t *testing.T) {
	expect := -1
	c := CheckWork(&davepb.Msg{})
	if c != expect {
		t.Fatalf("Expected %v, CheckWork returned %v", expect, c)
	}
	c = CheckWork(&davepb.Msg{
		Op:  davepb.Op_SETDAT,
		Val: []byte("test"),
	})
	if c != expect {
		t.Fatalf("Expected %v, CheckWork returned %v", expect, c)
	}
}

func TestWork(t *testing.T) {
	work := 2
	m := &davepb.Msg{
		Op:  davepb.Op_SETDAT,
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
