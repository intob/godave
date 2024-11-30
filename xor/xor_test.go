package xor

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/bits"
	"sync"
	"testing"
	"unsafe"
)

const (
	hexA = "cd04bcd026c8ee86760ae342f978d4aee311df27eafdd5262f463bc3a42862cd"
	hexB = "b77c90a112a6c8f1be099272a686f6572b288ec7b9efc73248d3e58d1df40bc8"
)

func testData() [2][]byte {
	aa, _ := hex.DecodeString(hexA)
	bb, _ := hex.DecodeString(hexB)
	return [2][]byte{aa, bb}
}

func xor256PureGo(dst, a, b []byte) {
	for i := 0; i < 32; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func xor256Uint8Slow(a, b []byte) (uint8, error) {
	if len(a) != 32 || len(b) != 32 {
		return 0, errors.New("inputs must be of equal length")
	}
	var distance uint8
	for i := 0; i < 32; i++ {
		distance += uint8(bits.OnesCount8(a[i] ^ b[i]))
	}
	return distance, nil
}

// This version is a little over x4 faster than the naive version.
func xor256Uint8RolledUp(a, b []byte) (uint8, error) {
	if len(a) != 32 || len(b) != 32 {
		return 0, errors.New("inputs must be of equal length")
	}
	// Process 8 bytes at a time using uint64
	var total uint64
	for i := 0; i < len(a); i += 8 {
		x := *(*uint64)(unsafe.Pointer(&a[i]))
		y := *(*uint64)(unsafe.Pointer(&b[i]))
		total += uint64(bits.OnesCount64(x ^ y))
	}

	return uint8(total), nil
}

func BenchmarkPureGo(b *testing.B) {
	data := testData()
	dst := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xor256PureGo(dst, data[0], data[1])
	}
}

func BenchmarkAsm(b *testing.B) {
	data := testData()
	dst := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xor256Into(dst, data[0], data[1])
	}
}

func BenchmarkXorUint8Slow(b *testing.B) {
	data := testData()
	for i := 0; i < b.N; i++ {
		xor256Uint8Slow(data[0], data[1])
	}
}

func BenchmarkXorUint8RolledUp(b *testing.B) {
	data := testData()
	for i := 0; i < b.N; i++ {
		xor256Uint8RolledUp(data[0], data[1])
	}
}

func BenchmarkXorUint8(b *testing.B) {
	data := testData()
	for i := 0; i < b.N; i++ {
		Xor256Uint8(data[0], data[1])
	}
}

func TestXor256Into(t *testing.T) {
	data := testData()
	dst := make([]byte, 32)
	expected := make([]byte, 32)
	xor256PureGo(expected, data[0], data[1])
	xor256Into(dst, data[0], data[1])
	if !bytes.Equal(expected, dst) {
		t.FailNow()
	}
}

func TestXor256IntoConcurrently(t *testing.T) {
	const numGoroutines = 1000
	const iterations = 1000
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			a := make([]byte, 32)
			b := make([]byte, 32)
			dst := make([]byte, 32)
			expected := make([]byte, 32)
			for j := 0; j < iterations; j++ {
				rand.Read(a)
				rand.Read(b)
				for k := 0; k < 32; k++ {
					expected[k] = a[k] ^ b[k]
				}
				xor256Into(dst, a, b)
				if !bytes.Equal(dst, expected) {
					t.Errorf("XorInto produced incorrect result: got %x, want %x", dst, expected)
				}
				if len(dst) != 32 {
					t.Errorf("XorInto produced wrong length output: got %d, want 32", len(dst))
				}
			}
		}()
	}
	wg.Wait()
}

func TestXor256Uint8(t *testing.T) {
	data := testData()
	result, _ := Xor256Uint8(data[0], data[1])
	if result != 123 {
		t.Errorf("expected 123, got %d", result)
	}
}
