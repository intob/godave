package pow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"runtime"
	"time"

	"github.com/intob/godave/types"
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
// depending on the difficulty level. For lower difficulty levels (< 10),
// the single-core implementation performs best.
func DoWork(key string, val []byte, tim time.Time, d uint8) (work types.Hash, salt types.Salt) {
	if d >= 10 {
		return doWorkAllCores(key, val, tim, d)
	} else {
		return doWorkSingleCore(key, val, tim, d)
	}
}

// doWork computes a proof-of-work on a single core.
// For low difficulty settings (< 12), this outperforms the multi-core implementation.
func doWorkSingleCore(key string, val []byte, tim time.Time, d uint8) (types.Hash, types.Salt) {
	h := blake3.New(32, nil)
	h.Write([]byte(key))
	h.Write(val)
	h.Write(types.Ttb(tim))
	load := h.Sum(nil)
	saltSlice := make([]byte, 16)
	var n1, n2 uint64
	for {
		binary.LittleEndian.PutUint64(saltSlice[8:], n2)
		h.Reset()
		h.Write(saltSlice)
		h.Write(load)
		hash := h.Sum(nil)
		if nzerobitSlice(hash) >= d {
			return types.Hash(hash), types.Salt(saltSlice)
		}
		if n2 == math.MaxUint64 {
			n1++
			binary.LittleEndian.PutUint64(saltSlice[:8], n1)
			n2 = 0
		} else {
			n2++
		}
	}
}

type result struct {
	work types.Hash
	salt types.Salt
}

// doWorkAllCores computes a proof-of-work using all cores.
// For higher difficulty settings (>= 12), this outperforms the single-core implementation.
func doWorkAllCores(key string, val []byte, tim time.Time, d uint8) (types.Hash, types.Salt) {
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)
	resultChan := make(chan result)
	quit := make(chan struct{})
	h := blake3.New(32, nil)
	h.Write([]byte(key))
	h.Write(val)
	h.Write(types.Ttb(tim))
	load := h.Sum(nil)
	for i := 0; i < numCPU; i++ {
		go func(offset uint64) {
			h := blake3.New(32, nil)
			saltSlice := make([]byte, 16)
			n1 := uint64(0)
			n2 := offset
			for {
				select {
				case <-quit:
					return
				default:
					binary.LittleEndian.PutUint64(saltSlice[8:], n2)
					h.Reset()
					h.Write(saltSlice)
					h.Write(load)
					hash := h.Sum(nil)
					if nzerobitSlice(hash) >= d {
						select {
						case resultChan <- result{
							work: types.Hash(hash),
							salt: types.Salt(saltSlice)}:
						case <-quit:
						}
						return
					}
					if n2 == math.MaxUint64 {
						n1++
						binary.LittleEndian.PutUint64(saltSlice[:8], n1)
						n2 = offset
					} else {
						n2 += uint64(numCPU)
					}
				}
			}
		}(uint64(i))
	}
	result := <-resultChan
	close(quit)
	return result.work, result.salt
}

func Nzerobit(work types.Hash) uint8 {
	var count uint8
	for _, b := range work {
		count += zeroTable[b]
		if b != 0 {
			return count
		}
	}
	return count
}

func nzerobitSlice(work []byte) uint8 {
	var count uint8
	for _, b := range work {
		count += zeroTable[b]
		if b != 0 {
			return count
		}
	}
	return count
}

func Check(h *blake3.Hasher, dat *types.Dat) error {
	if dat.Time.After(time.Now()) {
		return errors.New("time is invalid")
	}
	h.Reset()
	h.Write([]byte(dat.Key))
	h.Write(dat.Val)
	h.Write(types.Ttb(dat.Time))
	load := h.Sum(nil)
	h.Reset()
	h.Write(dat.Salt[:])
	h.Write(load)
	if !bytes.Equal(h.Sum(nil), dat.Work[:]) {
		return errors.New("hash is invalid")
	}
	return nil
}
