package dapi

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	mrand "math/rand"
	"runtime"
	"time"

	"github.com/intob/dave/dapi/can"
	"github.com/intob/dave/godave"
	"github.com/intob/dave/godave/dave"
	"github.com/intob/jfmt"
	"google.golang.org/protobuf/proto"
)

const NDAT = 38
const SIZE = 1234

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

func GetDat(d *godave.Dave, work []byte) (*godave.Dat, error) {
	err := SendShaGet(d, work)
	if err != nil {
		return nil, err
	}
	var tries uint
	tick := time.NewTicker(300 * time.Millisecond)
	for {
		select {
		case m := <-d.Recv:
			if m.Op == dave.Op_DAT && bytes.Equal(m.Work, work) {
				check := godave.Check(m.Val, m.Time, m.Nonce, m.Work)
				if check < godave.MINWORK {
					return nil, fmt.Errorf("invalid work: %d", check)
				}
				return &godave.Dat{V: m.Val, N: m.Nonce, W: m.Work, Ti: godave.Btt(m.Time)}, nil
			}
		case <-tick.C:
			tries++
			if tries > 2 {
				return nil, fmt.Errorf("not found after %d tries", tries)
			}
			err := SendShaGet(d, work)
			if err != nil {
				return nil, err
			}
		}
	}
}

// Sends a randomised DAT message to a random peer. The work is invalid, but the hash correct.
func SendShaGet(d *godave.Dave, work []byte) error {
	rv := make([]byte, mrand.Intn(1200))
	crand.Read(rv)
	nonce := make([]byte, 32)
	crand.Read(nonce)
	mt := time.Now().Add(-time.Duration(mrand.Int63n(4*60*1000)+120*1000) * time.Millisecond)
	return SendM(d, &dave.M{Op: dave.Op_DAT, Work: work, Val: rv, Time: godave.Ttb(mt)})
}

// SendM sends message on dave's send chan with timeout.
func SendM(d *godave.Dave, m *dave.M) error {
	to := time.After(300 * time.Millisecond)
	for {
		select {
		case d.Send <- m:
			return nil
		case <-d.Recv:
		case <-to:
			return errors.New("timeout")
		}
	}
}

func Walk(d *godave.Dave, work []byte) ([]*can.Can, []*godave.Dat, error) {
	dat, err := GetDat(d, work)
	if err != nil {
		return nil, nil, err
	}
	c := &can.Can{}
	err = proto.Unmarshal(dat.V, c)
	if err != nil {
		return nil, []*godave.Dat{dat}, err
	}
	wc := make([]*can.Can, 0)
	wd := make([]*godave.Dat, 0)
	for _, cd := range c.GetDats() {
		cdc, cdd, _ := Walk(d, cd)
		if len(cdc) > 0 {
			wc = append(wc, cdc...)
		}
		if len(cdd) > 0 {
			wd = append(wd, cdd...)
		}
	}
	return wc, wd, nil
}

func Read(r io.Reader, size int) <-chan []byte {
	ch := make(chan []byte, 1)
	go func() {
		for {
			buf := make([]byte, size)
			n, err := r.Read(buf)
			ch <- buf[:n]
			if err == io.EOF {
				break
			}
		}
		close(ch)
	}()
	return ch
}

func PrepChunks(chunks <-chan []byte, difficulty int) <-chan *dave.M {
	out := make(chan *dave.M, 1)
	go func() {
		for c := range chunks {
			done := make(chan struct{})
			go func() {
				tim := time.NewTicker(time.Second)
				t := time.Now()
				for {
					select {
					case <-done:
						fmt.Print("\n")
						return
					case <-tim.C:
						fmt.Printf("\rworking for %s\033[0K", jfmt.FmtDuration(time.Since(t)))
					}
				}
			}()
			m := &dave.M{Op: dave.Op_DAT, Val: c, Time: godave.Ttb(time.Now())}
			type sol struct{ work, nonce []byte }
			solch := make(chan sol)
			ncpu := max(runtime.NumCPU()-2, 1)
			for n := 0; n < ncpu; n++ {
				go func(c, t []byte, d int) {
					w, n := godave.Work(c, t, d)
					solch <- sol{w, n}
				}(c, m.Time, difficulty)
			}
			s := <-solch
			m.Work = s.work
			m.Nonce = s.nonce
			done <- struct{}{}
			out <- m
		}
		close(out)
	}()
	return out
}

func SendDats(d *godave.Dave, mch <-chan *dave.M) <-chan *dave.M {
	out := make(chan *dave.M, 1)
	go func() {
		for m := range mch {
			err := SendM(d, m)
			if err != nil {
				panic(err)
			}
			_, err = GetDat(d, m.Work)
			if err != nil {
				panic(err)
			}
			fmt.Printf("sent %x\n", m.Work)
			out <- m
		}
		close(out)
	}()
	return out
}

func MakeCans(d *godave.Dave, difficulty int, mch <-chan *dave.M) <-chan *dave.M {
	out := make(chan *dave.M, 1)
	go func() {
		c := &can.Can{Dats: make([][]byte, 0, NDAT)}
		for {
			m, ok := <-mch
			if ok {
				c.Dats = append(c.Dats, m.Work)
			}
			if len(c.Dats) > 0 && (!ok || len(c.Dats) >= NDAT) {
				cb, err := proto.Marshal(c)
				if err != nil {
					panic(err)
				}
				if len(cb) > SIZE {
					panic("err: can is too big")
				}
				cm := &dave.M{Op: dave.Op_DAT, Val: cb, Time: godave.Ttb(time.Now())}
				cm.Work, cm.Nonce = godave.Work(cb, cm.Time, difficulty)
				check := godave.Check(cm.Val, cm.Time, cm.Nonce, cm.Work)
				if check < godave.MINWORK {
					panic(fmt.Sprintf("make cans: invalid work: %d", check))
				}
				err = SendM(d, cm)
				if err != nil {
					panic(err)
				}
				out <- cm
				c.Dats = make([][]byte, 0, NDAT)
			}
			if !ok {
				break
			}
		}
		close(out)
	}()
	return out
}
