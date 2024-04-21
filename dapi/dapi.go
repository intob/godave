package dapi

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/dave"
)

func GetDat(d *godave.Dave, work []byte, timeout time.Duration) (*godave.Dat, error) {
	SendM(d, &dave.M{Op: dave.Op_GET, Work: work}, timeout)
	var tries int
	for {
		select {
		case m := <-d.Recv:
			if m.Op == dave.Op_DAT && bytes.Equal(m.Work, work) {
				check := godave.CheckMsg(m)
				dat := &godave.Dat{Val: m.Val, Tag: m.Tag, Nonce: m.Nonce}
				if check < godave.MINWORK {
					return dat, fmt.Errorf("invalid work: %d", check)
				}
				return dat, nil
			}
		case <-time.After(time.Second):
			tries++
			if tries > 3 {
				return nil, errors.New("not found")
			}
			SendM(d, &dave.M{Op: dave.Op_GET, Work: work}, timeout)
		}
	}
}

func SendM(d *godave.Dave, m *dave.M, timeout time.Duration) error {
	select {
	case d.Send <- m:
		return nil
	case <-time.After(timeout):
		return errors.New("timeout")
	}
}
