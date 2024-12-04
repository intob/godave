package dat

import (
	"testing"
)

func BenchmarkWork(b *testing.B) {
	sig := Signature{}
	for i := 0; i < b.N; i++ {
		doWorkSingleCore(sig, 12)
	}
}

func BenchmarkWorkAllCores(b *testing.B) {
	sig := Signature{}
	for i := 0; i < b.N; i++ {
		doWorkAllCores(sig, 12)
	}
}
