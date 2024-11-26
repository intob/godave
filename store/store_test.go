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
)

const (
	NUM_PUT     = 1000
	NUM_ROUTINE = 250
)

func TestConcurrentPut(t *testing.T) {
	store, err := New(&StoreCfg{
		ShardCap:   100000,
		PruneEvery: 200 * time.Millisecond,
		Logger:     logger.NewLogger(&logger.LoggerCfg{}),
	})
	if err != nil {
		t.Error(err)
	}
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	wg := sync.WaitGroup{}
	for i := 0; i < NUM_ROUTINE; i++ {
		wg.Add(1)
		go func(routine int) {
			defer wg.Done()
			for j := 0; j < NUM_PUT; j++ {
				store.Put(&Dat{
					Key:    []byte(fmt.Sprintf("routine_%d_test_%d", routine, j)),
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

	dat, ok := store.Get(pubKey, []byte(fmt.Sprintf("routine_%d_test_%d", NUM_ROUTINE-1, NUM_PUT-1)))
	if !ok {
		t.FailNow()
	}
	if !bytes.Equal(dat.Val, []byte("test")) {
		t.FailNow()
	}
}

func TestList(t *testing.T) {
	store, err := New(&StoreCfg{
		ShardCap:   100000,
		PruneEvery: 5 * time.Second,
		Logger:     logger.NewLogger(&logger.LoggerCfg{}),
	})
	if err != nil {
		t.Error(err)
	}
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	wg := sync.WaitGroup{}
	for i := 0; i < NUM_ROUTINE; i++ {
		wg.Add(1)
		go func(routine int) {
			defer wg.Done()
			for j := 0; j < NUM_PUT; j++ {
				store.Put(&Dat{
					Key:    []byte(fmt.Sprintf("routine_%d_test_%d", routine, j)),
					Val:    []byte("test"),
					Time:   time.Now(),
					PubKey: pubKey,
				})
			}
		}(i)
	}
	wg.Wait()
	dats := store.List(pubKey, []byte(fmt.Sprintf("routine_%d", NUM_ROUTINE-1)))
	if len(dats) != NUM_PUT {
		t.FailNow()
	}
}
