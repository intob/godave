package perf

import (
	"math/rand"
	"testing"
)

const N = 1000000 // input size for benchmarks

// naive bit counting
func naiveZeroBitsCount(x []byte) int {
	count := 0
	for _, b := range x {
		for i := 0; i < 8; i++ {
			if b&(1<<i) == 0 {
				count++
			}
		}
	}
	return count
}

// optimized bit counting
func zeroBitsCount(x []byte) int {
	count := 0
	for _, b := range x {
		for i := 0; i < 8; i++ {
			if (b>>i)&1 == 0 {
				count++
			} else {
				return count
			}
		}
	}
	return count
}

// naive leading zeros
func naiveLeadingZeros(x []byte) int {
	for i, b := range x {
		if b != 0 {
			return i*8 + ntz8(b)
		}
	}
	return len(x) * 8
}

// number of trailing zeros in a byte
func ntz8(x byte) int {
	n := 1
	if x&0x0f == 0 {
		n += 4
		x >>= 4
	}
	if x&0x03 == 0 {
		n += 2
		x >>= 2
	}
	return n - int(x&1)
}

// optimized leading zeros using byte-wise lookup table
var debruijn = [...]byte{
	0, 1, 56, 2, 57, 49, 28, 3, 61, 58, 42, 50, 38, 29, 17, 4,
	62, 47, 59, 36, 45, 43, 51, 22, 53, 39, 33, 30, 24, 18, 12, 5,
	63, 55, 48, 27, 60, 41, 37, 16, 46, 35, 44, 21, 52, 32, 23, 11,
	54, 26, 40, 15, 34, 20, 31, 10, 25, 14, 19, 9, 13, 8, 7, 6,
}

func leadingZeros(x []byte) int {
	for i, b := range x {
		if b != 0 {
			return i*8 + int(debruijn[b&-b*0x03f>>6])
		}
	}
	return len(x) * 8
}

// benchmark functions
func BenchmarkNaiveZeroBitsCount(b *testing.B) {
	data := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		rand.Read(data)
		naiveZeroBitsCount(data)
	}
}

func BenchmarkZeroBitsCount(b *testing.B) {
	data := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		rand.Read(data)
		zeroBitsCount(data)
	}
}

func BenchmarkNaiveLeadingZeros(b *testing.B) {
	data := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		rand.Read(data)
		naiveLeadingZeros(data)
	}
}

func BenchmarkLeadingZeros(b *testing.B) {
	data := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		rand.Read(data)
		leadingZeros(data)
	}
}
