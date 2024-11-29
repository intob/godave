package pow

import (
	"testing"
	"time"
)

func BenchmarkWork(b *testing.B) {
	for i := 0; i < b.N; i++ {
		doWorkSingleCore("test", []byte("val"), time.Time{}, 10)
	}
}

func BenchmarkWorkAllCores(b *testing.B) {
	for i := 0; i < b.N; i++ {
		doWorkAllCores("test", []byte("val"), time.Time{}, 10)
	}
}
