package store

import (
	"bufio"
	"bytes"
	"container/heap"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/cespare/xxhash/v2"
	"github.com/intob/godave/logger"
	"github.com/intob/godave/network"
	"github.com/intob/godave/peer"
	"lukechampine.com/blake3"
)

type Store struct {
	myID           uint64
	shards         [256]*shard
	backupFilename string
	backup         chan *Entry
	kill           <-chan struct{}
	done           chan<- struct{}
	capacity       int64
	usedSpace      atomic.Int64
	logger         logger.Logger
}

type StoreCfg struct {
	MyID           uint64
	Capacity       int64
	BackupFilename string
	Kill           <-chan struct{}
	Done           chan<- struct{}
	Logger         logger.Logger
}

type shard struct {
	mu   sync.RWMutex
	data map[uint64]Entry
	heap *priorityHeap
}

func NewStore(cfg *StoreCfg) *Store {
	s := &Store{
		myID:           cfg.MyID,
		capacity:       cfg.Capacity,
		usedSpace:      atomic.Int64{},
		backupFilename: cfg.BackupFilename,
		logger:         cfg.Logger,
		kill:           cfg.Kill,
		done:           cfg.Done,
	}
	for i := range s.shards {
		s.shards[i] = &shard{
			data: make(map[uint64]Entry),
			heap: newPriorityHeap(),
		}
	}
	if s.backupFilename != "" {
		s.backup = make(chan *Entry, 1000)
		go s.writeBackup()
	} else {
		close(s.done)
		s.log(logger.ERROR, "backup disabled")
	}
	return s
}

func (s *Store) ReadBackup() error {
	if s.backupFilename == "" {
		return fmt.Errorf("backup filename is unset")
	}
	err := s.readBackup()
	if err != nil {
		return fmt.Errorf("error reading backup: %s", err)
	}
	s.log(logger.ERROR, "read %d from %s", s.usedSpace.Load(), s.backupFilename)
	return s.writeFreshBackup()
}

func (s *Store) Capacity() int64 {
	return s.capacity
}

func (s *Store) Used() int64 {
	return s.usedSpace.Load()
}

func (s *Store) Write(e *Entry) error {
	return s.write(e, true)
}

func (s *Store) write(e *Entry, backup bool) error {
	if e == nil {
		return errors.New("nil dat provided")
	}
	shardIndex, key := keys(e.Dat.PubKey, e.Dat.Key)
	shard := s.shards[shardIndex]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	newEntry := &heapEntry{
		key:      key,
		distance: peer.IDFromPublicKey(e.Dat.PubKey) ^ s.myID,
		expires:  e.Dat.Time.Add(network.TTL),
	}
	// Check if updating an existing entry
	existing, exists := shard.data[key]
	if exists {
		if !existing.Dat.PubKey.Equal(e.Dat.PubKey) {
			return errors.New("public keys don't match")
		}
		if existing.Dat.Time.After(e.Dat.Time) {
			return errors.New("existing data is newer")
		}
		if existing.Dat.Time == e.Dat.Time && bytes.Equal(existing.Dat.Val, e.Dat.Val) &&
			existing.Replicas == e.Replicas {
			return errors.New("existing data matches new data")
		}
	}
	// If at capacity and no existing entry, try to make space
	newEntrySize := calculateEntrySize(e)
	if !exists && s.usedSpace.Load()+newEntrySize > s.capacity {
		if shard.heap.Len() > 0 {
			lowest := shard.heap.Peek()
			if lowest.priority() < newEntry.priority() {
				removed := heap.Pop(shard.heap).(*heapEntry)
				removedDat := shard.data[removed.key]
				delete(shard.data, removed.key)
				s.usedSpace.Add(-calculateEntrySize(&removedDat))
			} else {
				return errors.New("insufficient priority")
			}
		} else {
			return errors.New("storage full")
		}
	}
	// Add/update map & heap
	if exists {
		shard.heap.Remove(key)
		oldSize := calculateEntrySize(&existing)
		s.usedSpace.Add(newEntrySize - oldSize)
	} else {
		s.usedSpace.Add(calculateEntrySize(e))
	}
	shard.data[key] = *e
	heap.Push(shard.heap, newEntry)
	if backup && s.backupFilename != "" {
		s.backup <- e
	}
	return nil
}

func (s *Store) Read(publicKey ed25519.PublicKey, datKey string) (Entry, error) {
	shardIndex, key := keys(publicKey, datKey)
	shard := s.shards[shardIndex]
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	if data, exists := shard.data[key]; exists {
		return data, nil
	}
	return Entry{}, errors.New("not found")
}

func (s *Store) ListAll() <-chan Entry {
	resultChan := make(chan Entry, 100)
	jobs := make(chan int, len(s.shards))
	go func() {
		for shardIndex := range jobs {
			shard := s.shards[shardIndex]
			shard.mu.RLock()
			for _, e := range shard.data {
				resultChan <- e
			}
			shard.mu.RUnlock()
		}
		close(resultChan)
	}()
	go func() {
		for j := 0; j < len(s.shards); j++ {
			jobs <- j
		}
		close(jobs)
	}()
	return resultChan
}

func (s *Store) ListWithReplicaID(id uint64) <-chan Entry {
	buffer := make(chan []Entry, 1)
	out := make(chan Entry, 1)
	jobs := make(chan int)
	go func() {
		for shardIndex := range jobs {
			shard := s.shards[shardIndex]
			result := make([]Entry, 0, 100)
			shard.mu.RLock()
			for _, e := range shard.data {
				for _, r := range e.Replicas {
					if r == id {
						result = append(result, e)
						break
					}
				}
			}
			shard.mu.RUnlock()
			buffer <- result
		}
		close(buffer)
	}()
	go func() {
		for j := 0; j < len(s.shards); j++ {
			jobs <- j
		}
		close(jobs)
	}()
	go func() {
		for buf := range buffer {
			for _, r := range buf {
				out <- r
			}
		}
		close(out)
	}()
	return out
}

/*
func (s *Store) List(pubKey ed25519.PublicKey, datKeyPrefix string) []dat.Dat {
	resultChan := make(chan dat.Dat, 1)
	jobs := make(chan int, len(s.shards))
	wg := sync.WaitGroup{}
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for shardIndex := range jobs {
				shard := s.shards[shardIndex]
				shard.mu.RLock()
				for _, dat := range shard.data {
					if !bytes.Equal(dat.PubKey, pubKey) {
						continue
					}
					if !strings.HasPrefix(dat.Key, datKeyPrefix) {
						continue
					}
					resultChan <- dat
				}
				shard.mu.RUnlock()
			}
		}()
	}
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	for j := 0; j < len(s.shards); j++ {
		jobs <- j
	}
	close(jobs)
	results := make([]dat.Dat, 0, 100)
	for result := range resultChan {
		results = append(results, result)
	}
	return results
}
*/

func (s *Store) readBackup() error {
	f, err := os.Open(s.backupFilename)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("err reading file info: %w", err)
	}
	size := info.Size()
	var pos int64
	lb := make([]byte, 2)
	h := blake3.New(32, nil)
	for pos < size {
		n, err := f.Read(lb)
		pos += int64(n)
		if err != nil {
			return fmt.Errorf("err reading length prefix: %w", err)
		}
		buf := make([]byte, binary.LittleEndian.Uint16(lb)) // TODO: make once & reslice
		n, err = f.Read(buf)
		pos += int64(n)
		if err != nil {
			return fmt.Errorf("err reading length-prefixed msg: %w", err)
		}
		entry := &Entry{}
		err = entry.Unmarshal(buf)
		if err != nil {
			return fmt.Errorf("err unmarshalling dat: %w", err)
		}
		h.Reset()
		err = entry.Dat.Verify(h)
		if err != nil {
			return fmt.Errorf("err verifying dat: %w", err)
		}
		s.write(entry, false)
	}
	return nil
}

// Recreate backup after pruning
// TODO: Process shards concurrently
func (s *Store) writeFreshBackup() error {
	f, err := os.Create(s.backupFilename)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := bufio.NewWriter(f)
	for _, shard := range s.shards {
		shard.mu.Lock()
		for _, e := range shard.data {
			bin := make([]byte, network.MAX_MSG_LEN)
			n, err := e.Marshal(bin)
			if err != nil {
				return err
			}
			lenb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenb, uint16(len(bin)))
			buf.Write(lenb)
			buf.Write(bin[:n])
		}
		shard.mu.Unlock()
	}
	return buf.Flush()
}

func (s *Store) writeBackup() {
	f, err := os.OpenFile(s.backupFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		s.log(logger.ERROR, "failed to open file: %s", err)
		return
	}
	writer := bufio.NewWriter(f)
	for {
		select {
		case <-s.kill:
			flushErr := writer.Flush()
			closeErr := f.Close()
			s.log(logger.ERROR, "backup buffer flushed, file closed, errors if any: %v %v", flushErr, closeErr)
			close(s.done)
			return
		case d := <-s.backup:
			buf := make([]byte, network.MAX_MSG_LEN)
			n, err := d.Marshal(buf)
			if err != nil {
				s.log(logger.ERROR, "backup failed to marshal: %s", err)
				continue
			}
			lenb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenb, uint16(n))
			writer.Write(lenb)
			writer.Write(buf[:n])
		}
	}
}

func (s *Store) log(level logger.LogLevel, msg string, args ...any) {
	if s.logger != nil {
		s.logger.Log(level, msg, args...)
	}
}

func keys(publicKey ed25519.PublicKey, datKey string) (uint8, uint64) {
	h := xxhash.New()
	h.Write(publicKey)
	h.WriteString(datKey)
	sum64 := h.Sum64()
	return uint8(sum64 >> 56), sum64
}

func calculateEntrySize(e *Entry) int64 {
	return int64(len(e.Dat.Val) + len(e.Dat.Key) + 224)
}
