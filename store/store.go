package store

import (
	"bufio"
	"bytes"
	"container/heap"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/intob/godave/dave"
	"github.com/intob/godave/logger"
	"github.com/intob/godave/pow"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

type Store struct {
	shards         []map[uint64]Dat
	shardCap       int
	count          atomic.Uint32
	mu             sync.RWMutex
	logger         *logger.Logger
	backupFilename string
	backup         chan *Dat
	kill           <-chan struct{}
	done           chan<- struct{}
}

type StoreCfg struct {
	ShardCap       int
	PruneEvery     time.Duration
	BackupFilename string
	Logger         *logger.Logger
	Kill           <-chan struct{}
	Done           chan<- struct{}
}

type Dat struct {
	Key    []byte
	Val    []byte
	Time   time.Time
	Salt   []byte
	Work   []byte
	Sig    []byte
	PubKey ed25519.PublicKey
}

type pair struct {
	id  uint64
	dat Dat
}

type datheap []*pair

func (h datheap) Len() int { return len(h) }
func (h datheap) Less(i, j int) bool {
	return Mass(h[i].dat.Work, h[i].dat.Time) < Mass(h[j].dat.Work, h[j].dat.Time)
}
func (h datheap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *datheap) Push(x interface{}) { *h = append(*h, x.(*pair)) }
func (h *datheap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
func (h *datheap) Peek() *pair { return (*h)[0] }

func New(cfg *StoreCfg) (*Store, error) {
	shards := make([]map[uint64]Dat, 256)
	for i := range shards {
		shards[i] = make(map[uint64]Dat)
	}
	s := &Store{
		shards:         shards,
		shardCap:       cfg.ShardCap,
		count:          atomic.Uint32{},
		backupFilename: cfg.BackupFilename,
		logger:         cfg.Logger,
		kill:           cfg.Kill,
		done:           cfg.Done,
	}
	go func() {
		tick := time.NewTicker(cfg.PruneEvery)
		for range tick.C {
			s.prune()
		}
	}()
	if s.backupFilename == "" {
		s.done <- struct{}{}
		s.logger.Error("backup disabled")
		return s, nil
	}
	err := s.readBackup()
	if err != nil {
		s.logger.Error("error reading backup: %s", err)
	}
	s.prune()
	s.logger.Error("read %d dats from backup", s.count.Load())
	err = s.writeFreshBackup()
	if err != nil {
		return nil, err
	}
	go s.writeBackup()
	return s, nil
}

func (s *Store) Count() uint32 {
	return s.count.Load()
}

func (s *Store) Put(dat *Dat) (bool, error) {
	shard, key := Keys(dat.PubKey, dat.Key)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.shards[shard][key]
	if !exists {
		s.shards[shard][key] = *dat
		s.count.Add(1)
		if s.backupFilename != "" {
			s.backup <- dat
		}
		return true, nil
	}
	if !current.PubKey.Equal(dat.PubKey) {
		return false, errors.New("public keys don't match")
	}
	if current.Time.After(dat.Time) {
		return false, errors.New("current data is newer")
	}
	if current.Time == dat.Time && bytes.Equal(current.Val, dat.Val) {
		return false, errors.New("duplicate data")
	}
	s.shards[shard][key] = *dat
	if s.backupFilename != "" {
		s.backup <- dat
	}
	return false, nil
}

func (s *Store) Get(pubKey ed25519.PublicKey, datKey []byte) (*Dat, bool) {
	shard, key := Keys(pubKey, datKey)
	s.mu.RLock()
	defer s.mu.RUnlock()
	dat, ok := s.shards[shard][key]
	if !ok {
		return nil, false
	}
	return &dat, true
}

func Keys(pubKey ed25519.PublicKey, datKey []byte) (uint8, uint64) {
	h := xxhash.New()
	h.Write(pubKey)
	h.Write(datKey)
	sum64 := h.Sum64()
	return uint8(sum64 >> 56), sum64
}

func (s *Store) readBackup() error {
	f, err := os.Open(s.backupFilename)
	if err != nil {
		return fmt.Errorf("err opening file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("err reading file info: %w", err)
	}
	size := info.Size()
	var pos int64
	lb := make([]byte, 2)
	hasher := blake3.New(32, nil)
	for pos < size {
		n, err := f.Read(lb)
		pos += int64(n)
		if err != nil {
			return fmt.Errorf("err reading length prefix: %w", err)
		}
		datbuf := make([]byte, binary.LittleEndian.Uint16(lb))
		n, err = f.Read(datbuf)
		pos += int64(n)
		if err != nil {
			return fmt.Errorf("err reading length-prefixed msg: %w", err)
		}
		m := &dave.M{}
		err = proto.Unmarshal(datbuf, m)
		if err != nil {
			return fmt.Errorf("err unmarshalling proto msg: %w", err)
		}
		err = pow.Check(hasher, m)
		if err != nil {
			continue
		}
		s.Put(&Dat{Key: m.DatKey, Val: m.Val, Time: pow.Btt(m.Time), Salt: m.Salt, Work: m.Work, Sig: m.Sig, PubKey: m.PubKey})
	}
	return nil
}

// Recreate backup after pruning
func (s *Store) writeFreshBackup() error {
	f, err := os.Create(s.backupFilename)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := bufio.NewWriter(f)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, shard := range s.shards {
		for _, d := range shard {
			bin, err := proto.Marshal(&dave.M{Op: dave.Op_PUT, DatKey: d.Key, Val: d.Val, Time: pow.Ttb(d.Time), Salt: d.Salt, Work: d.Work, PubKey: d.PubKey, Sig: d.Sig})
			if err != nil {
				return err
			}
			lenb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenb, uint16(len(bin)))
			buf.Write(lenb)
			buf.Write(bin)
		}
	}
	return buf.Flush()
}

func (s *Store) prune() {
	start := time.Now()
	var count uint32
	newShards := make([]map[uint64]Dat, len(s.shards))
	var wg sync.WaitGroup
	var mu sync.Mutex
	jobs := make(chan int, len(s.shards))
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for shardid := range jobs {
				dh := &datheap{}
				heap.Init(dh)
				for datid, dat := range s.shards[shardid] {
					if dh.Len() < s.shardCap {
						heap.Push(dh, &pair{datid, dat})
					} else if Mass(dat.Work, dat.Time) > Mass(dh.Peek().dat.Work, dh.Peek().dat.Time) {
						heap.Pop(dh)
						heap.Push(dh, &pair{datid, dat})
					}
				}
				shard := make(map[uint64]Dat, dh.Len())
				var localCount uint32
				for dh.Len() > 0 {
					pair := heap.Pop(dh).(*pair)
					shard[pair.id] = pair.dat
					localCount++
				}
				newShards[shardid] = shard
				mu.Lock()
				count += localCount
				mu.Unlock()
			}
		}()
	}
	for shardid := range s.shards {
		jobs <- shardid
	}
	close(jobs)
	wg.Wait()
	s.count.Store(count)
	s.logger.Error("pruned %d dats in %s", s.count.Load(), time.Since(start))
}

func Mass(work []byte, t time.Time) float64 {
	return float64(pow.Nzerobit(work)) * (1 / float64(time.Since(t).Milliseconds()))
}

func (s *Store) writeBackup() error {
	f, err := os.OpenFile(s.backupFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %s", err)
	}
	buf := bufio.NewWriter(f)
	for {
		select {
		case <-s.kill:
			flushErr := buf.Flush()
			closeErr := f.Close()
			s.done <- struct{}{}
			s.logger.Debug("backup buffer flushed, file closed, errors if any: %v %v", flushErr, closeErr)
			return nil
		case d := <-s.backup:
			b, err := proto.Marshal(&dave.M{Op: dave.Op_PUT, DatKey: d.Key, Val: d.Val, Time: pow.Ttb(d.Time), Salt: d.Salt, Work: d.Work, Sig: d.Sig, PubKey: d.PubKey})
			if err != nil {
				s.logger.Error("backup failed to marshal: %s", err)
				continue
			}
			lenb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenb, uint16(len(b)))
			buf.Write(lenb)
			buf.Write(b)
		}
	}
}

func (s *Store) Rand(shard uint8) *Dat {
	if len(s.shards[shard]) == 0 {
		return nil
	}
	datPos := mrand.Intn(len(s.shards[shard]))
	var cDatPos int
	for _, dat := range s.shards[shard] {
		if cDatPos != datPos {
			cDatPos++
			continue
		}
		return &dat
	}
	return nil
}
