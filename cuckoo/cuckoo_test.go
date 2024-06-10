package cuckoo

import (
	"math/rand"
	"testing"
)

func TestInsertLookup(t *testing.T) {
	f := NewFilter(1000)
	hash := rand.Uint64()
	if f.Lookup(hash) {
		t.Errorf("empty filter should not contain %x", hash)
	}
	f.Insert(hash)
	if !f.Lookup(hash) {
		t.Errorf("filter should contain %x", hash)
	}
}

func TestInsertResetLookup(t *testing.T) {
	f := NewFilter(1000)
	hash := rand.Uint64()
	f.Insert(hash)
	f.Reset()
	if f.Lookup(hash) {
		t.Errorf("filter should contain %x", hash)
	}
}

func TestFalsePositives(t *testing.T) {
	f := NewFilter(10000)
	numItems := 1000
	for i := 0; i < numItems; i++ {
		f.Insert(rand.Uint64())
	}
	numTests := 100000
	falsePositives := 0
	for i := 0; i < numTests; i++ {
		if f.Lookup(rand.Uint64()) {
			falsePositives++
		}
	}
	fpRate := float64(falsePositives) / float64(numTests)
	if fpRate > 0.01 {
		t.Errorf("false positive rate too high: %f", fpRate)
	}
}

const benchmarkItemCount = 1000000

func BenchmarkCuckooFilterInsert(b *testing.B) {
	cf := NewFilter(uint32(benchmarkItemCount))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cf.Insert(uint64(rand.Intn(benchmarkItemCount)))
	}
}

func BenchmarkCuckooFilterLookup(b *testing.B) {
	cf := NewFilter(uint32(benchmarkItemCount))
	for i := 0; i < benchmarkItemCount; i++ {
		cf.Insert(uint64(i))
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cf.Lookup(uint64(rand.Intn(benchmarkItemCount)))
	}
}

func BenchmarkCuckooFilterInsertLookup(b *testing.B) {
	cf := NewFilter(uint32(benchmarkItemCount))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		item := uint64(rand.Intn(benchmarkItemCount))
		if i%2 == 0 {
			cf.Insert(item)
		} else {
			cf.Lookup(item)
		}
	}
}

func BenchmarkCuckooFilterFalsePositiveRate(b *testing.B) {
	cf := NewFilter(uint32(benchmarkItemCount))
	for i := 0; i < benchmarkItemCount; i++ {
		cf.Insert(uint64(i))
	}
	b.ResetTimer()

	falsePositives := 0
	for i := 0; i < b.N; i++ {
		if cf.Lookup(uint64(benchmarkItemCount + i)) {
			falsePositives++
		}
	}

	falsePositiveRate := float64(falsePositives) / float64(b.N)
	b.ReportMetric(falsePositiveRate, "false-positive-rate")
}

func BenchmarkLoadFactor(b *testing.B) {
	f := NewFilter(1000000)
	numItems := 1000000
	for i := 0; i < numItems; i++ {
		f.Insert(rand.Uint64())
	}
	b.ResetTimer()
	f.LoadFactor()
}
