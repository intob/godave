package xor

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
)

func xorPureGo(dst, a, b []byte) {
	for i := 0; i < 32; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func BenchmarkPureGo(b *testing.B) {
	buf1 := make([]byte, 32)
	buf2 := make([]byte, len(buf1))
	dst := make([]byte, len(buf1))
	rand.Read(buf1)
	rand.Read(buf2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xorPureGo(dst, buf1, buf2)
	}
}

func BenchmarkAsm(b *testing.B) {
	buf1 := make([]byte, 32)
	buf2 := make([]byte, len(buf1))
	dst := make([]byte, len(buf1))
	rand.Read(buf1)
	rand.Read(buf2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xorInto(dst, buf1, buf2)
	}
}

func TestXorIntoOne(t *testing.T) {
	buf1 := make([]byte, 32)
	buf2 := make([]byte, len(buf1))
	dst := make([]byte, len(buf1))
	for i := 0; i < len(buf1); i++ {
		buf2[i] = 255
	}
	xorInto(dst, buf1, buf2)
	if !bytes.Equal(buf2, dst) {
		t.FailNow()
	}
}

func TestXorIntoTwo(t *testing.T) {
	buf1 := make([]byte, 32)
	buf2 := make([]byte, len(buf1))
	dst := make([]byte, len(buf1))
	for i := 0; i < 16; i++ {
		buf2[i] = 255
	}
	xorInto(dst, buf1, buf2)
	if !bytes.Equal(bytes.Repeat([]byte{0xFF}, 16), dst[:16]) {
		t.FailNow()
	}
	if !bytes.Equal(bytes.Repeat([]byte{0x00}, 16), dst[16:]) {
		t.FailNow()
	}
}

func TestXorInto(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
	}{
		{
			name: "32 byte zero keys",
			a:    make([]byte, 32),
			b:    make([]byte, 32),
		},
		{
			name: "32 byte different keys",
			a:    bytes.Repeat([]byte{0xFF}, 32),
			b:    bytes.Repeat([]byte{0xAA}, 32),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := make([]byte, 32)
			xorInto(dst, tt.a, tt.b)

			// Verify length
			if len(dst) != 32 {
				t.Errorf("XorInto produced wrong length output: got %d, want 32", len(dst))
			}

			// Verify XOR operation
			for i := 0; i < 32; i++ {
				expected := tt.a[i] ^ tt.b[i]
				if dst[i] != expected {
					t.Errorf("XorInto at position %d: got %x, want %x", i, dst[i], expected)
				}
			}
		})
	}
}

func TestXorIntoConcurrently(t *testing.T) {
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

				xorInto(dst, a, b)

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
