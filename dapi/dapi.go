package dapi

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/dave"
)

func WaitForBootstrap(d *godave.Dave, w *bufio.Writer) {
	fph := fnv.New64a()
	for bm := range d.Recv {
		if bm.Op == dave.Op_DAT {
			break
		}
		if bm.Op == dave.Op_PEER && len(bm.Pds) > 0 {
			fmt.Fprintf(w, "%s %x, ", bm.Op, godave.Pdfp(fph, bm.Pds[0]))
			w.Flush()
		}
	}
	fmt.Fprint(w, "\n")
	w.Flush()
}

func GetDat(d *godave.Dave, work []byte, timeout time.Duration) (*godave.Dat, error) {
	err := SendM(d, &dave.M{Op: dave.Op_GET, Work: work}, timeout)
	if err != nil {
		return nil, err
	}
	var tries int
	for {
		select {
		case m := <-d.Recv:
			if m.Op == dave.Op_DAT && bytes.Equal(m.Work, work) {
				check := godave.Check(m.Val, m.Tag, m.Nonce, m.Work)
				if check < godave.MINWORK {
					return nil, fmt.Errorf("invalid work: %d", check)
				}
				return &godave.Dat{Val: m.Val, Tag: m.Tag, Nonce: m.Nonce, Work: m.Work}, nil
			}
		case <-time.After(timeout):
			tries++
			if tries > 2 {
				return nil, fmt.Errorf("not found after %d tries", tries)
			}
			err = SendM(d, &dave.M{Op: dave.Op_GET, Work: work}, timeout)
			if err != nil {
				return nil, err
			}
		}
	}
}

func SendM(d *godave.Dave, m *dave.M, timeout time.Duration) error {
	for {
		select {
		case d.Send <- m:
			return nil
		case <-d.Recv:
		case <-time.After(timeout):
			return errors.New("timeout")
		}
	}
}
