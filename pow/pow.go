package pow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"time"
	"unsafe"

	"github.com/intob/godave/dave"
	"lukechampine.com/blake3"
)

var zeroTable = [256]uint8{ // Lookup table for the number of leading zero bits in a byte
	8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

// DoWork computes a proof-of-work, either on a single core or on all cores,
// depending on the difficulty level. For lower difficulty levels (< 12),
// the single-core implementation performs best.
func DoWork(key, val, tim []byte, d uint8) (work []byte, salt []byte) {
	if d >= 12 {
		return doWorkAllCores(key, val, tim, d)
	} else {
		return doWorkSingleCore(key, val, tim, d)
	}
}

// doWork computes a proof-of-work on a single core.
// For low difficulty settings (< 12), this outperforms the multi-core implementation.
func doWorkSingleCore(key, val, tim []byte, d uint8) (work, salt []byte) {
	salt = make([]byte, 8)
	h := blake3.New(32, nil)
	h.Write(key)
	h.Write(val)
	h.Write(tim)
	load := h.Sum(nil)
	counter := uint64(0)
	for {
		*(*uint64)(unsafe.Pointer(&salt[0])) = counter
		h.Reset()
		h.Write(salt)
		h.Write(load)
		work = h.Sum(nil)
		if Nzerobit(work) >= d {
			return work, salt
		}
		counter++
	}
}

// doWorkAllCores computes a proof-of-work using all cores.
// For higher difficulty settings (>= 12), this outperforms the single-core implementation.
func doWorkAllCores(key, val, tim []byte, d uint8) (work, salt []byte) {
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	type Result struct{ work, salt []byte }
	resultChan := make(chan Result)
	quit := make(chan struct{})
	h := blake3.New(32, nil)
	h.Write(key)
	h.Write(val)
	h.Write(tim)
	load := h.Sum(nil)
	for i := 0; i < numCPU; i++ {
		go func(offset uint64) {
			salt := make([]byte, 8)
			h := blake3.New(32, nil)
			counter := offset
			for {
				select {
				case <-quit:
					return
				default:
					*(*uint64)(unsafe.Pointer(&salt[0])) = counter
					h.Reset()
					h.Write(salt)
					h.Write(load)
					work := h.Sum(nil)
					if Nzerobit(work) >= d {
						select {
						case resultChan <- Result{work: work, salt: salt}:
						case <-quit:
						}
						return
					}
					counter += uint64(numCPU)
				}
			}
		}(uint64(i))
	}
	result := <-resultChan
	close(quit)
	return result.work, result.salt
}

func Nzerobit(key []byte) uint8 {
	var count uint8
	for _, b := range key {
		count += zeroTable[b]
		if b != 0 {
			return count
		}
	}
	return count
}

func Ttb(t time.Time) []byte {
	milli := t.UnixNano() / 1000000
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(milli))
	return bytes
}

func Btt(b []byte) time.Time {
	return time.Unix(0, int64(binary.LittleEndian.Uint64(b))*1000000)
}

func Check(h *blake3.Hasher, m *dave.M) error {
	if len(m.Time) != 8 || Btt(m.Time).After(time.Now()) {
		return errors.New("time is invalid")
	}
	h.Reset()
	h.Write(m.DatKey)
	h.Write(m.Val)
	h.Write(m.Time)
	load := h.Sum(nil)
	h.Reset()
	h.Write(m.Salt)
	h.Write(load)
	if !bytes.Equal(h.Sum(nil), m.Work) {
		return errors.New("hash is invalid")
	}
	return nil
}
