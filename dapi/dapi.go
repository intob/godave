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
	err := SendM(d, &dave.M{Op: dave.Op_GET, Work: work}, timeout)
	if err != nil {
		fmt.Println("first send timeout")
		return nil, err
	}
	var tries int
	for {
		select {
		case m := <-d.Recv:
			if (m.Op == dave.Op_DAT || m.Op == dave.Op_RAND) && bytes.Equal(m.Work, work) {
				check := godave.CheckMsg(m)
				dat := &godave.Dat{Val: m.Val, Tag: m.Tag, Nonce: m.Nonce, Work: m.Work}
				if check < godave.MINWORK {
					return dat, fmt.Errorf("invalid work: %d", check)
				}
				return dat, nil
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
