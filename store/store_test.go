package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/intob/godave/logger"
	"github.com/intob/godave/types"
)

const (
	NUM_PUT     = 1000
	NUM_ROUTINE = 250
)

func TestConcurrentPut(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(&StoreCfg{
		ShardCap:   100000,
		PruneEvery: 200 * time.Millisecond,
		Logger:     logger.NewLoggerToDevNull(),
		PublicKey:  pubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	wg := sync.WaitGroup{}
	for i := 0; i < NUM_ROUTINE; i++ {
		wg.Add(1)
		go func(routine int) {
			defer wg.Done()
			for j := 0; j < NUM_PUT; j++ {
				store.Put(&types.Dat{
					Key:    fmt.Sprintf("routine_%d_test_%d", routine, j),
					Val:    []byte("test"),
					Time:   time.Now(),
					PubKey: pubKey,
				})
			}
		}(i)
	}
	wg.Wait()

	fmt.Println(store.count.Load())

	// Wait for prune
	time.Sleep(time.Second)

	count := store.count.Load()

	if count != NUM_PUT*NUM_ROUTINE {
		t.Errorf("expected %d, got %d", NUM_PUT*NUM_ROUTINE, count)
	}

	dat, ok := store.Get(pubKey, fmt.Sprintf("routine_%d_test_%d", NUM_ROUTINE-1, NUM_PUT-1))
	if !ok {
		t.FailNow()
	}
	if !bytes.Equal(dat.Val, []byte("test")) {
		t.FailNow()
	}
}

func TestList(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(&StoreCfg{
		ShardCap:   100000,
		PruneEvery: 5 * time.Second,
		Logger:     logger.NewLoggerToDevNull(),
		PublicKey:  pubKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	wg := sync.WaitGroup{}
	for i := 0; i < NUM_ROUTINE; i++ {
		wg.Add(1)
		go func(routine int) {
			defer wg.Done()
			for j := 0; j < NUM_PUT; j++ {
				store.Put(&types.Dat{
					Key:    fmt.Sprintf("routine_%d_test_%d", routine, j),
					Val:    []byte("test"),
					Time:   time.Now(),
					PubKey: pubKey,
				})
			}
		}(i)
	}
	wg.Wait()
	dats := store.List(pubKey, fmt.Sprintf("routine_%d", NUM_ROUTINE-1))
	if len(dats) != NUM_PUT {
		t.FailNow()
	}
}

func TestStorePrune(t *testing.T) {
	storePubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const shardCap = 10
	logger, err := logger.NewLogger(&logger.LoggerCfg{
		Level:  logger.DEBUG,
		Output: logger.DevNull(),
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(&StoreCfg{
		ShardCap:   shardCap,
		PruneEvery: 200 * time.Millisecond,
		Logger:     logger,
		PublicKey:  storePubKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create dats with zero distance (same as store public key)
	zeroDats := make([]types.Dat, 5)
	for i := range zeroDats {
		zeroDats[i] = types.Dat{
			Key:    fmt.Sprintf("zero_%d", i),
			Val:    []byte("zero_value"),
			Time:   time.Now(),
			PubKey: storePubKey,
		}
		err = store.Put(&zeroDats[i])
		if err != nil {
			t.Fatalf("failed to put zero dat: %s", err)
		}
	}

	// Create random dats concurrently
	const numRoutines = 8
	const datsPerRoutine = 1000
	wg := sync.WaitGroup{}
	for i := 0; i < numRoutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < datsPerRoutine; j++ {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Error(err)
					return
				}
				err = store.Put(&types.Dat{
					Key:    fmt.Sprintf("routine_%d_random_%d", i, j),
					Val:    []byte("random_value"),
					Time:   time.Now(),
					PubKey: pub,
				})
				if err != nil {
					panic("failed to put dat")
				}
			}
		}(i)
	}
	wg.Wait()

	// Wait for pruning to occur
	time.Sleep(300 * time.Millisecond)

	// Verify all zero-distance dats are retained
	for _, dat := range zeroDats {
		_, exists := store.Get(dat.PubKey, dat.Key)
		if !exists {
			t.Errorf("zero-distance dat with key %s was pruned", dat.Key)
		}
	}

	// Verify each shard stays within capacity
	for _, shard := range store.shards {
		shard.mu.Lock()
		count := len(shard.table)
		if count > shardCap {
			t.Errorf("shard exceeded capacity: got %d items, want <= %d", count, shardCap)
		}
		shard.mu.Unlock()
	}
}
