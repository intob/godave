package godave

import (
	"encoding/hex"
	"reflect"
	"testing"
	"time"
)

func makeTime(minutes int) time.Time {
	return time.Date(2024, 1, 1, 0, minutes, 0, 0, time.UTC)
}

func TestPruneDats(t *testing.T) {
	tests := []struct {
		name  string
		input []map[uint64]Dat
		cap   int
		want  []map[uint64]Dat
	}{
		{
			name: "Empty input",
			input: []map[uint64]Dat{
				make(map[uint64]Dat),
			},
			cap: 2,
			want: []map[uint64]Dat{
				make(map[uint64]Dat),
			},
		},
		{
			name: "Single shard under capacity",
			input: []map[uint64]Dat{
				{
					1: Dat{Time: makeTime(1)},
					2: Dat{Time: makeTime(2)},
				},
			},
			cap: 3,
			want: []map[uint64]Dat{
				{
					1: Dat{Time: makeTime(1)},
					2: Dat{Time: makeTime(2)},
				},
			},
		},
		{
			name: "Single shard over capacity",
			input: []map[uint64]Dat{
				{
					1: Dat{Time: makeTime(1)},
					2: Dat{Time: makeTime(2)},
					3: Dat{Time: makeTime(3)},
					4: Dat{Time: makeTime(4)},
				},
			},
			cap: 2,
			want: []map[uint64]Dat{
				{
					3: Dat{Time: makeTime(3)},
					4: Dat{Time: makeTime(4)},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create full-sized input and want slices
			fullInput := make([]map[uint64]Dat, 256)
			fullWant := make([]map[uint64]Dat, 256)

			// Copy the test data into the first position
			if len(tt.input) > 0 {
				fullInput[0] = tt.input[0]
			}
			if len(tt.want) > 0 {
				fullWant[0] = tt.want[0]
			}

			// Initialize remaining positions with empty maps
			for i := 1; i < 256; i++ {
				fullInput[i] = make(map[uint64]Dat)
				fullWant[i] = make(map[uint64]Dat)
			}

			_, got := pruneDats(fullInput, tt.cap)

			if !reflect.DeepEqual(got, fullWant) {
				t.Errorf("pruneDats() = %v, want %v", got, fullWant)
			}

			// Verify capacity constraints
			for _, shard := range got {
				if len(shard) > tt.cap {
					t.Errorf("shard size %d exceeds capacity %d", len(shard), tt.cap)
				}
			}

			// Verify we kept the newest timestamps
			for shardID, shard := range got {
				if len(fullInput[shardID]) > tt.cap {
					var oldest time.Time
					for _, dat := range shard {
						if oldest.IsZero() || dat.Time.Before(oldest) {
							oldest = dat.Time
						}
					}

					// Check that we didn't miss any newer timestamps
					for _, dat := range fullInput[shardID] {
						if dat.Time.After(oldest) && !containsTimestamp(shard, dat.Time) {
							t.Errorf("missing newer timestamp %v in pruned data", dat.Time)
						}
					}
				}
			}
		})
	}
}

// Helper function to check if a timestamp exists in a shard
func containsTimestamp(shard map[uint64]Dat, timestamp time.Time) bool {
	for _, dat := range shard {
		if dat.Time.Equal(timestamp) {
			return true
		}
	}
	return false
}

/*
func BenchmarkPruneDatsOld(b *testing.B) {
	dats := make([]map[uint64]Dat, MAXWORK-MINWORK)
	for shardid := range dats {
		dats[shardid] = make(map[uint64]Dat)
		for i := 0; i < 1_000_000; i++ {
			timestamp := time.Now().Add(time.Duration(mrand.Intn(1000000)) * time.Second)
			dats[shardid][uint64(i)] = Dat{Ti: timestamp}
		}
	}
	cap := 100_000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pruneDatsOld(dats, cap)
	}
}

func pruneDatsOld(dats []map[uint64]Dat, cap int) []map[uint64]Dat {
	newdats := make([]map[uint64]Dat, MAXWORK-MINWORK)
	for shardid, shard := range dats {
		dh := &datheap{}
		heap.Init(dh)
		for datid, dat := range shard {
			if dh.Len() < cap {
				heap.Push(dh, &pair{datid, dat})
			} else if Mass(dat.W, dat.Ti) > Mass(dh.Peek().dat.W, dh.Peek().dat.Ti) {
				heap.Pop(dh)
				heap.Push(dh, &pair{datid, dat})
			}
		}
		newdats[shardid] = make(map[uint64]Dat, dh.Len())
		for dh.Len() > 0 {
			pair := heap.Pop(dh).(*pair)
			newdats[shardid][pair.id] = pair.dat
		}
	}
	return newdats
}
*/

/*
func BenchmarkPruneDatsSlightlyOptimised(b *testing.B) {
	dats := make([]map[uint64]Dat, MAXWORK-MINWORK)
	for shardid := range dats {
		dats[shardid] = make(map[uint64]Dat)
		for i := 0; i < (1+shardid)*20_000; i++ { // roughly 1.12M in largest shard
			timestamp := time.Now().Add(time.Duration(mrand.Intn(1000000)) * time.Second)
			dats[shardid][uint64(i)] = Dat{Ti: timestamp}
		}
	}
	cap := 100_000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pruneDatsSlightlyOptimised(dats, cap)
	}
}

func pruneDatsSlightlyOptimised(dats []map[uint64]Dat, cap int) (uint32, []map[uint64]Dat) {
	newdats := make([]map[uint64]Dat, MAXWORK-MINWORK)
	var ndat uint32
	for shardid, shard := range dats {
		dh := &datheap{}
		heap.Init(dh)
		for datid, dat := range shard {
			if dh.Len() < cap {
				heap.Push(dh, &pair{datid, dat})
			} else if dat.Ti.After(dh.Peek().dat.Ti) {
				heap.Pop(dh)
				heap.Push(dh, &pair{datid, dat})
			}
		}
		newdats[shardid] = make(map[uint64]Dat, dh.Len())
		for dh.Len() > 0 {
			pair := heap.Pop(dh).(*pair)
			newdats[shardid][pair.id] = pair.dat
			ndat++
		}
	}
	return ndat, newdats
}

func BenchmarkPruneDats(b *testing.B) {
	dats := make([]map[uint64]Dat, MAXWORK-MINWORK)
	for shardid := range dats {
		dats[shardid] = make(map[uint64]Dat)
		for i := 0; i < (1+shardid)*20_000; i++ { // roughly 1.12M in largest shard
			timestamp := time.Now().Add(time.Duration(mrand.Intn(1000000)) * time.Second)
			dats[shardid][uint64(i)] = Dat{Ti: timestamp}
		}
	}
	cap := 100_000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pruneDats(dats, cap)
	}

*/

// BenchmarkPruneDatsSlightlyOptimised-12    	       1	1992280667 ns/op	1732469520 B/op	 5489174 allocs/op
// BenchmarkPruneDats-12                     	       3	 388144792 ns/op	1732345648 B/op	 5489071 allocs/op
// Slightly optimised version is twice as fast as original.
// Concurrent version is 5.4 times faster than slightly optimised version.

const hashStr = "000001db4044b9c5bf5247b463fe0f5e181e424d151d9f03fb9f3720d4795f18"

// The original rolled up version is faster.
func BenchmarkNzerobit(b *testing.B) {
	hash, err := hex.DecodeString(hashStr)
	if err != nil {
		panic(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nzerobit(hash)
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
	if nzerobit(hash) != nzerobitUnrolled(hash) {
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
