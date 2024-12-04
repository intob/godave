package store

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/intob/godave/dat"
	"github.com/intob/godave/network"
	"github.com/intob/godave/peer"
)

const (
	NUM_PUT     = 100000
	NUM_ROUTINE = 250
	CAPACITY    = 1000000000
)

func TestStoreWriteAndRead(t *testing.T) {
	store := NewStore(&StoreCfg{
		MyID:     1,
		Capacity: 1024 * 1024, // 1MB
		Kill:     make(chan struct{}),
		Done:     make(chan struct{}),
	})
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	testData := &Entry{
		Dat: dat.Dat{
			PubKey: pub,
			Key:    "test-key",
			Val:    []byte("test-value"),
			Time:   time.Now(),
		},
	}
	err = store.Write(testData)
	if err != nil {
		t.Errorf("failed to write data: %v", err)
	}
	result, err := store.Read(pub, "test-key")
	if err != nil {
		t.Errorf("failed to read data: %v", err)
	}
	if string(result.Dat.Val) != string(testData.Dat.Val) {
		t.Errorf("got %s, want %s", string(result.Dat.Val), string(testData.Dat.Val))
	}
}

func TestStorePriorityReplacement(t *testing.T) {
	myPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	myID := peer.IDFromPublicKey(myPubKey)
	// Setup store with small capacity
	store := NewStore(&StoreCfg{
		MyID:     myID,
		Capacity: 400,
		Kill:     make(chan struct{}),
		Done:     make(chan struct{}),
	})
	dataKey := "test-key"
	// Generate first key
	pubA, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubAShardID, _ := keys(pubA, dataKey)
	// Brute-force second pub key that lands in the same shard
	var pubB ed25519.PublicKey
	for {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}
		shardID, _ := keys(pub, dataKey)
		if pubAShardID == shardID {
			pubB = pub
			break
		}
	}
	var farPub, closePub ed25519.PublicKey
	if myID^peer.IDFromPublicKey(pubA) < myID^peer.IDFromPublicKey(pubB) {
		closePub = pubA
		farPub = pubB
	} else {
		closePub = pubB
		farPub = pubA
	}
	// Create data from a "far" peer
	farData := &Entry{Dat: dat.Dat{
		PubKey: farPub,
		Key:    dataKey,
		Val:    []byte("far-peer-data"),
		Time:   time.Now().Add(-time.Hour),
	}}
	// Write far peer data
	err = store.Write(farData)
	if err != nil {
		t.Errorf("failed to write far peer data: %v", err)
	}
	// Verify far peer data was written
	result, err := store.Read(farPub, dataKey)
	if err != nil {
		t.Errorf("failed to read far peer data: %v", err)
	}
	if string(result.Dat.Val) != "far-peer-data" {
		t.Errorf("got %s, want far-peer-data", string(result.Dat.Val))
	}
	// Create data from a "closer" peer with same key
	closeData := &Entry{Dat: dat.Dat{
		PubKey: closePub,
		Key:    dataKey,
		Val:    []byte("close-peer-data"),
		Time:   time.Now(),
	}}
	// Write close peer data
	err = store.Write(closeData)
	if err != nil {
		t.Errorf("failed to write close peer data: %v", err)
	}
	// Verify close peer data replaced far peer data
	result, err = store.Read(closePub, dataKey)
	if err != nil {
		t.Errorf("failed to read close peer data: %v", err)
	}
	if string(result.Dat.Val) != "close-peer-data" {
		t.Errorf("got %s, want close-peer-data", string(result.Dat.Val))
	}
	// Verify far peer data was removed
	_, err = store.Read(farPub, dataKey)
	if err == nil {
		t.Error("far peer data should have been removed")
	}
}

func TestConcurrentPut(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	store := NewStore(&StoreCfg{
		MyID:     peer.IDFromPublicKey(pubKey),
		Done:     make(chan<- struct{}),
		Capacity: CAPACITY,
	})
	wg := sync.WaitGroup{}
	for i := 0; i < NUM_ROUTINE; i++ {
		wg.Add(1)
		go func(routine int) {
			defer wg.Done()
			for j := 0; j < NUM_PUT; j++ {
				store.Write(&Entry{Dat: dat.Dat{
					Key:    fmt.Sprintf("routine_%d_test_%d", routine, j),
					Val:    []byte("test"),
					Time:   time.Now(),
					PubKey: pubKey,
				}})
			}
		}(i)
	}
	wg.Wait()
	fmt.Println(store.usedSpace.Load())
	entry, err := store.Read(pubKey, fmt.Sprintf("routine_%d_test_%d", NUM_ROUTINE-1, NUM_PUT-1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entry.Dat.Val, []byte("test")) {
		t.Fatalf("expected value %s, got %s", "test", string(entry.Dat.Val))
	}
}

func TestListWithReplicaID(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	id := peer.IDFromPublicKey(pubKey)
	store := NewStore(&StoreCfg{
		MyID:     id,
		Done:     make(chan<- struct{}),
		Capacity: CAPACITY,
	})
	wg := sync.WaitGroup{}
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func(routine int) {
			defer wg.Done()
			for j := 0; j < NUM_PUT; j++ {
				store.Write(&Entry{Dat: dat.Dat{
					Key:    fmt.Sprintf("routine_%d_test_%d", routine, j),
					Val:    []byte("test"),
					Time:   time.Now(),
					PubKey: pubKey,
				}, Replicas: [network.FANOUT]uint64{0, 1, id}})
			}
		}(i)
	}
	wg.Wait()
	entries := store.ListWithReplicaID(id)
	if len(entries) != NUM_PUT*runtime.NumCPU() {
		t.Fatalf("expected %d dats, got %d", NUM_PUT*runtime.NumCPU(), len(entries))
	}
}

/*
func TestList(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	store := NewStore(&StoreCfg{
		MyID:     peer.IDFromPublicKey(pubKey),
		Done:     make(chan<- struct{}),
		Capacity: CAPACITY,
	})
	wg := sync.WaitGroup{}
	for i := 0; i < NUM_ROUTINE; i++ {
		wg.Add(1)
		go func(routine int) {
			defer wg.Done()
			for j := 0; j < NUM_PUT; j++ {
				store.Write(&dat.Dat{
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
		t.Fatalf("expected %d dats, got %d", NUM_PUT, len(dats))
	}
}
*/

func TestStorePrune(t *testing.T) {
	storePubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(&StoreCfg{
		MyID:     peer.IDFromPublicKey(storePubKey),
		Done:     make(chan<- struct{}),
		Capacity: CAPACITY,
	})
	// Create entries with zero distance (same as store public key)
	zeroEntries := make([]*Entry, 5)
	for i := range zeroEntries {
		zeroEntries[i] = &Entry{Dat: dat.Dat{
			Key:    fmt.Sprintf("zero_%d", i),
			Val:    []byte("zero_value"),
			Time:   time.Now(),
			PubKey: storePubKey,
		}}
		err = store.Write(zeroEntries[i])
		if err != nil {
			t.Fatalf("failed to put zero entry: %s", err)
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
				pub, _, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Error(err)
					return
				}
				err = store.Write(&Entry{Dat: dat.Dat{
					Key:    fmt.Sprintf("routine_%d_random_%d", i, j),
					Val:    []byte("random_value"),
					Time:   time.Now(),
					PubKey: pub,
				}})
				if err != nil {
					panic("failed to put dat")
				}
			}
		}(i)
	}
	wg.Wait()
	// Verify all zero-distance entries are retained
	for _, e := range zeroEntries {
		_, err := store.Read(e.Dat.PubKey, e.Dat.Key)
		if err != nil {
			t.Errorf("zero-distance entry with key %s was pruned", e.Dat.Key)
		}
	}
}

func initListByPublicKeyTestStore(a, b ed25519.PublicKey) *Store {
	store := NewStore(&StoreCfg{
		MyID:     peer.IDFromPublicKey(a),
		Done:     make(chan<- struct{}),
		Capacity: CAPACITY,
	})
	wg := sync.WaitGroup{}
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func(routine int) {
			defer wg.Done()
			for j := 0; j < NUM_PUT; j++ {
				store.Write(&Entry{Dat: dat.Dat{
					Key:    fmt.Sprintf("a_routine_%d_test_%d", routine, j),
					Val:    []byte("test"),
					Time:   time.Now(),
					PubKey: a,
				}})
				store.Write(&Entry{Dat: dat.Dat{
					Key:    fmt.Sprintf("b_routine_%d_test_%d", routine, j),
					Val:    []byte("test"),
					Time:   time.Now(),
					PubKey: b,
				}})
			}
		}(i)
	}
	wg.Wait()
	return store
}

func BenchmarkListWithReplicaID(b *testing.B) {
	pubKeyA, _, _ := ed25519.GenerateKey(nil)
	pubKeyB, _, _ := ed25519.GenerateKey(nil)
	store := initListByPublicKeyTestStore(pubKeyA, pubKeyB)
	idA := peer.IDFromPublicKey(pubKeyA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.ListWithReplicaID(idA)
	}
}
