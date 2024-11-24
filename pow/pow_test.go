package pow

import (
	"encoding/hex"
	"testing"
	"time"
)

const hashStr = "000001db4044b9c5bf5247b463fe0f5e181e424d151d9f03fb9f3720d4795f18"

// The original rolled up version is faster.

func BenchmarkNzerobit(b *testing.B) {
	hash, err := hex.DecodeString(hashStr)
	if err != nil {
		panic(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Nzerobit(hash)
	}
}

func BenchmarkNzerobitUnrolled(b *testing.B) {
	hash, err := hex.DecodeString(hashStr)
	if err != nil {
		panic(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nzerobitUnrolled(hash)
	}
}

func TestNzerobit(t *testing.T) {
	hash, err := hex.DecodeString(hashStr)
	if err != nil {
		panic(err)
	}
	if Nzerobit(hash) != nzerobitUnrolled(hash) {
		t.FailNow()
	}
}

func nzerobitUnrolled(key []byte) uint8 {
	var count uint8
	n := len(key)
	i := 0

	// Process 4 bytes at a time
	for ; i < n-3; i += 4 {
		if b := key[i]; b != 0 {
			return count + zeroTable[b]
		}
		count += zeroTable[key[i]]

		if b := key[i+1]; b != 0 {
			return count + zeroTable[b]
		}
		count += zeroTable[key[i+1]]

		if b := key[i+2]; b != 0 {
			return count + zeroTable[b]
		}
		count += zeroTable[key[i+2]]

		if b := key[i+3]; b != 0 {
			return count + zeroTable[b]
		}
		count += zeroTable[key[i+3]]
	}

	// Handle remaining bytes
	for ; i < n; i++ {
		if b := key[i]; b != 0 {
			return count + zeroTable[b]
		}
		count += zeroTable[key[i]]
	}

	return count
}

func BenchmarkWork(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		doWorkSingleCore([]byte("test"), []byte("val"), Ttb(time.Now()), 12)
	}
}

func BenchmarkWork2(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		doWorkAllCores([]byte("test"), []byte("val"), Ttb(time.Now()), 12)
	}
}
