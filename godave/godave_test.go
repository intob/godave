// Copyright 2024 Joey Innes
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package godave

import (
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
