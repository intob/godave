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
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/intob/godave/dave"
	"github.com/intob/godave/logger"
	"github.com/intob/godave/pow"
	"github.com/intob/godave/xor"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"
)

type Store struct {
	shards         [256]*shard
	shardCap       int
	count          atomic.Uint32
	logger         *logger.Logger
	backupFilename string
	backup         chan *Dat
	kill           <-chan struct{}
	done           chan<- struct{}
	currentShard   uint8
	publicKey      ed25519.PublicKey
}

type StoreCfg struct {
	ShardCap       int
	PruneEvery     time.Duration
	BackupFilename string
	PublicKey      ed25519.PublicKey
	Logger         *logger.Logger
	Kill           <-chan struct{}
	Done           chan<- struct{}
}

type shard struct {
	mu    sync.Mutex
	table map[uint64]Dat
	pos   uint32
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
	id       uint64
	dat      Dat
	distance []byte
}

type datheap []*pair

func (h datheap) Len() int { return len(h) }
func (h datheap) Less(i, j int) bool { // This is a min heap, less means further away.
	return bytes.Compare(h[i].distance, h[j].distance) > 0
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
	if cfg.ShardCap <= 0 {
		return nil, errors.New("inavlid shard cap provided, must be greater than 0")
	}
	if cfg.PublicKey == nil {
		return nil, errors.New("no public key provided")
	}
	s := &Store{
		shardCap:       cfg.ShardCap,
		count:          atomic.Uint32{},
		backupFilename: cfg.BackupFilename,
		publicKey:      cfg.PublicKey,
		logger:         cfg.Logger,
		kill:           cfg.Kill,
		done:           cfg.Done,
	}
	if s.backupFilename != "" {
		s.backup = make(chan *Dat, 1000)
	}
	for i := range s.shards {
		s.shards[i] = &shard{
			table: make(map[uint64]Dat),
		}
	}
	go func() {
		tick := time.NewTicker(cfg.PruneEvery)
		for range tick.C {
			s.prune()
		}
	}()
	if s.backupFilename == "" {
		select {
		case s.done <- struct{}{}:
		default:
		}
		s.logger.Error("backup disabled")
		return s, nil
	}
	err := s.readBackup()
	if err != nil {
		s.logger.Error("error reading backup: %s", err)
	}
	s.prune() // TODO: prune frequently while reading backup
	s.logger.Error("read %d from %s", s.count.Load(), s.backupFilename)
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

func (s *Store) Put(dat *Dat) error {
	if dat == nil {
		return errors.New("nil dat provided")
	}
	shardIndex, key := Keys(dat.PubKey, dat.Key)
	shard := s.shards[shardIndex]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	current, exists := shard.table[key]
	if !exists {
		shard.table[key] = *dat
		s.count.Add(1)
		if s.backupFilename != "" {
			s.backup <- dat
		}
		return nil
	}
	if !current.PubKey.Equal(dat.PubKey) {
		return errors.New("public keys don't match")
	}
	if current.Time.After(dat.Time) {
		return errors.New("current data is newer")
	}
	if current.Time == dat.Time && bytes.Equal(current.Val, dat.Val) {
		return errors.New("duplicate data")
	}
	shard.table[key] = *dat
	if s.backupFilename != "" {
		s.backup <- dat
	}
	return nil
}

func (s *Store) Get(pubKey ed25519.PublicKey, datKey []byte) (Dat, bool) {
	shardIndex, key := Keys(pubKey, datKey)
	shard := s.shards[shardIndex]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	dat, ok := shard.table[key]
	return dat, ok
}

func (s *Store) List(pubKey ed25519.PublicKey, datKeyPrefix []byte) []Dat {
	resultChan := make(chan Dat, 1)
	jobs := make(chan int, len(s.shards))
	wg := sync.WaitGroup{}
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for shardIndex := range jobs {
				shard := s.shards[shardIndex]
				shard.mu.Lock()
				for _, dat := range shard.table {
					if !bytes.Equal(dat.PubKey, pubKey) {
						continue
					}
					if !bytes.HasPrefix(dat.Key, datKeyPrefix) {
						continue
					}
					resultChan <- dat
				}
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
	results := make([]Dat, 0, 100)
	for result := range resultChan {
		results = append(results, result)
	}
	return results
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
		s.putFromBackup(&Dat{
			Key:    m.DatKey,
			Val:    m.Val,
			Time:   pow.Btt(m.Time),
			Salt:   m.Salt,
			Work:   m.Work,
			Sig:    m.Sig,
			PubKey: m.PubKey,
		})
	}
	return nil
}

// Similar to Put but does not send to backup buffer
func (s *Store) putFromBackup(dat *Dat) {
	shardIndex, key := Keys(dat.PubKey, dat.Key)
	shard := s.shards[shardIndex]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	current, exists := shard.table[key]
	if !exists {
		shard.table[key] = *dat
		s.count.Add(1)
		return
	}
	if !current.PubKey.Equal(dat.PubKey) {
		return
	}
	if current.Time.After(dat.Time) {
		return
	}
	if current.Time == dat.Time && bytes.Equal(current.Val, dat.Val) {
		return
	}
	shard.table[key] = *dat
}

// Recreate backup after pruning
func (s *Store) writeFreshBackup() error {
	f, err := os.Create(s.backupFilename)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := bufio.NewWriter(f)
	for _, shard := range s.shards {
		shard.mu.Lock()
		for _, d := range shard.table {
			bin, err := proto.Marshal(&dave.M{Op: dave.Op_PUT, DatKey: d.Key, Val: d.Val, Time: pow.Ttb(d.Time), Salt: d.Salt, Work: d.Work, PubKey: d.PubKey, Sig: d.Sig})
			if err != nil {
				return err
			}
			lenb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenb, uint16(len(bin)))
			buf.Write(lenb)
			buf.Write(bin)
		}
		shard.mu.Unlock()
	}
	return buf.Flush()
}

func (s *Store) prune() {
	start := time.Now()
	var count uint32
	var countMu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan int, len(s.shards))
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dist := make([]byte, ed25519.PublicKeySize) // Pre-allocate once per goroutine
			for shardIndex := range jobs {
				dh := &datheap{}
				heap.Init(dh)
				currentShard := s.shards[shardIndex]
				currentShard.mu.Lock()
				for datKey, dat := range currentShard.table {
					xor.Xor256Into(dist, s.publicKey, dat.PubKey)
					if dh.Len() < s.shardCap {
						heap.Push(dh, &pair{datKey, dat, dist})
					} else {
						peek := dh.Peek()
						cmp := bytes.Compare(dist, peek.distance)
						if cmp < 0 || (cmp == 0 && dat.Time.After(peek.dat.Time)) {
							// current is closer or
							// if distance is equal, current is newer
							/*
								if s.logger.Level() == logger.DEBUG {
									replacedDist, _ := xor.XorFloat(peek.dat.PubKey, s.publicKey)
									newDist, _ := xor.XorFloat(dat.PubKey, s.publicKey)
									s.logger.Debug("kicked %s (dist %f), for %s (dist %f)", peek.dat.Key, replacedDist, dat.Key, newDist)
								}
							*/
							heap.Pop(dh)
							heap.Push(dh, &pair{datKey, dat, dist})
						}
					}
				}
				newTable := make(map[uint64]Dat, dh.Len())
				var localCount uint32
				for dh.Len() > 0 {
					pair := heap.Pop(dh).(*pair)
					newTable[pair.id] = pair.dat
					localCount++
				}
				currentShard.table = newTable
				currentShard.mu.Unlock()
				countMu.Lock()
				count += localCount
				countMu.Unlock()
			}
		}()
	}
	for shardid := range s.shards {
		jobs <- shardid
	}
	close(jobs)
	wg.Wait()
	s.count.Store(count)
	s.logger.Error("pruned %d in %s", count, time.Since(start))
	if s.logger.Level() == logger.DEBUG {
		var smallest, largest int
		for _, shard := range s.shards {
			l := len(shard.table)
			if l < smallest || smallest == 0 {
				smallest = l
			} else if l > largest || largest == 0 {
				largest = l
			}
		}
		mean := int(count) / len(s.shards)
		s.logger.Debug("shard sizes: mean=%d min=%d max=%d", mean, smallest, largest)
	}
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

func (s *Store) Next() (Dat, bool) {
	s.currentShard++ // overflows to 0
	shard := s.shards[s.currentShard]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if len(shard.table) == 0 {
		return Dat{}, false
	}
	shard.pos++
	if shard.pos >= uint32(len(shard.table)) {
		shard.pos = 0
	}
	var currentPos uint32
	for _, dat := range shard.table {
		if currentPos != shard.pos {
			currentPos++
			continue
		}
		return dat, true
	}
	return Dat{}, false
}
