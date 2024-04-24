package dapi

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"time"

	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/dave"
)

// WaitForFirstDat logs the peer collection process, until we receive a DAT,
// expected after godave.SHARE_DELAY.
func WaitForFirstDat(d *godave.Dave, w io.Writer) {
	fph := fnv.New64a()
	var pc uint32
	for bm := range d.Recv {
		if bm.Op == dave.Op_DAT {
			break
		}
		if len(bm.Pds) > 0 {
			pc += uint32(len(bm.Pds))
			fmt.Fprintf(w, "\rpeer descriptors collected: %d, latest from: %x", pc, godave.Pdfp(fph, bm.Pds[0]))
		}

	}
	fmt.Fprint(w, "\n")
}

// GetDat is a helper to get with timeout & retry.
func GetDat(d *godave.Dave, work []byte, timeout time.Duration, retry uint) (*godave.Dat, error) {
	err := SendM(d, &dave.M{Op: dave.Op_GET, Work: work}, timeout)
	if err != nil {
		return nil, err
	}
	var tries uint
	for {
		select {
		case m := <-d.Recv:
			if m.Op == dave.Op_DAT && bytes.Equal(m.Work, work) {
				check := godave.Check(m.Val, m.Nonce, m.Work)
				if check < godave.MINWORK {
					return nil, fmt.Errorf("invalid work: %d", check)
				}
				return &godave.Dat{Val: m.Val, Nonce: m.Nonce, Work: m.Work}, nil
			}
		case <-time.After(timeout):
			tries++
			if tries > retry {
				return nil, fmt.Errorf("not found after %d tries", tries)
			}
			err = SendM(d, &dave.M{Op: dave.Op_GET, Work: work}, timeout)
			if err != nil {
				return nil, err
			}
		}
	}
}

// SendM sends message on dave's send chan with timeout.
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
