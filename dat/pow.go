package dat

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"runtime"

	"lukechampine.com/blake3"
)

type Work [32]byte
type Salt [16]byte

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
func DoWork(sig Signature, d uint8) (work Work, salt Salt) {
	if d >= 12 {
		return doWorkAllCores(sig, d)
	} else {
		return doWorkSingleCore(sig, d)
	}
}

// doWork computes a proof-of-work on a single core.
// For low difficulty settings (< 12), this outperforms the multi-core implementation.
func doWorkSingleCore(sig Signature, d uint8) (Work, Salt) {
	h := blake3.New(32, nil)
	h.Write(sig[:])
	sigHash := h.Sum(nil)
	saltSlice := make([]byte, 16)
	var n1, n2 uint64
	for {
		binary.LittleEndian.PutUint64(saltSlice[8:], n2)
		h.Reset()
		h.Write(saltSlice)
		h.Write(sigHash)
		work := h.Sum(nil)
		if nzerobitSlice(work) >= d {
			return Work(work), Salt(saltSlice)
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
	work Work
	salt Salt
}

// doWorkAllCores computes a proof-of-work using all cores.
// For higher difficulty settings (>= 12), this outperforms the single-core implementation.
func doWorkAllCores(sig Signature, d uint8) (Work, Salt) {
	h := blake3.New(32, nil)
	h.Write(sig[:])
	sigHash := h.Sum(nil)
	numCPU := runtime.NumCPU()
	resultChan := make(chan result)
	quit := make(chan struct{})
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
					h.Write(sigHash)
					work := h.Sum(nil)
					if nzerobitSlice(work) >= d {
						select {
						case resultChan <- result{
							work: Work(work),
							salt: Salt(saltSlice)}:
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

func Nzerobit(work Work) uint8 {
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

func CheckWork(h *blake3.Hasher, sig Signature, salt Salt, work Work) error {
	h.Write(sig[:])
	sigHash := h.Sum(nil)
	h.Reset()
	h.Write(salt[:])
	h.Write(sigHash)
	if !bytes.Equal(h.Sum(nil), work[:]) {
		return errors.New("hash is invalid")
	}
	return nil
}
