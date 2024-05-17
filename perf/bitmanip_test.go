package perf

import (
	"crypto/rand"
	"testing"
)

const N = 1000000 // input size for benchmarks

func nzerobitsNaive(x []byte) int {
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

// optimized leading zeros using byte-wise lookup table
var debruijn = [...]byte{
	0, 1, 56, 2, 57, 49, 28, 3, 61, 58, 42, 50, 38, 29, 17, 4,
	62, 47, 59, 36, 45, 43, 51, 22, 53, 39, 33, 30, 24, 18, 12, 5,
	63, 55, 48, 27, 60, 41, 37, 16, 46, 35, 44, 21, 52, 32, 23, 11,
	54, 26, 40, 15, 34, 20, 31, 10, 25, 14, 19, 9, 13, 8, 7, 6,
}

func nzerobitdebruijn(x []byte) int {
	for i, b := range x {
		if b != 0 {
			return i*8 + int(debruijn[b&-b*0x03f>>6])
		}
	}
	return len(x) * 8
}

var lut = [256]int{
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

func nzerobitsLUT(key []byte) int {
	count := 0
	for _, b := range key {
		count += lut[b]
		if b != 0 {
			return count
		}
	}
	return count
}

func BenchmarkNaive(b *testing.B) {
	data := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		rand.Read(data)
		nzerobitsNaive(data)
	}
}

func BenchmarkLUT(b *testing.B) {
	data := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		rand.Read(data)
		nzerobitsLUT(data)
	}
}

func BenchmarkDeBruijn(b *testing.B) {
	data := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		rand.Read(data)
		nzerobitdebruijn(data)
	}
}
