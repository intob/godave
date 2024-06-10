package cuckoo

import (
	"encoding/binary"

	"github.com/cespare/xxhash"
)

const bucketSize = 4

type Filter struct {
	buckets                          []bucket
	numBuckets, count, cap, maxKicks uint32
}

type bucket [bucketSize]uint8

func NewFilter(cap, maxKicks uint32) *Filter {
	numBuckets := nextPowerOfTwo(cap / bucketSize)
	return &Filter{
		buckets:    make([]bucket, numBuckets),
		numBuckets: numBuckets,
		cap:        cap,
		maxKicks:   maxKicks,
	}
}

func (f *Filter) Reset() {
	f.buckets = make([]bucket, f.numBuckets)
	f.count = 0
}

func (f *Filter) LoadFactor() float32 {
	return float32(f.count) / float32(f.cap)
}

func (f *Filter) Count() uint32 {
	return f.count
}

func (f *Filter) Insert(hash uint64) bool {
	if f.Lookup(hash) {
		return true
	}
	i1, i2, fp := f.indexes(hash)
	if f.insert(fp, i1) || f.insert(fp, i2) {
		f.count++
		return true
	}
	i := i1
	for n := uint32(0); n < f.maxKicks; n++ {
		f.buckets[i][0], fp = fp, f.buckets[i][0]
		i ^= uint32(hash64(uint64(fp))) % uint32(len(f.buckets))
		if f.insert(fp, i) {
			f.count++
			return true
		}
	}
	return false
}

func (f *Filter) Lookup(hash uint64) bool {
	i1, i2, fp := f.indexes(hash)
	return f.lookup(fp, i1) || f.lookup(fp, i2)
}

func (f *Filter) insert(fp uint8, i uint32) bool {
	b := &f.buckets[i]
	for n := range b {
		if b[n] == 0 {
			b[n] = fp
			return true
		}
	}
	return false
}

func (f *Filter) lookup(fp uint8, i uint32) bool {
	b := f.buckets[i]
	for n := range b {
		if b[n] == fp {
			return true
		}
	}
	return false
}

func (f *Filter) indexes(hash uint64) (i1, i2 uint32, fp uint8) {
	hash1, hash2 := hash64(hash), hash64(hash+1)
	i1 = uint32(hash1 % uint64(len(f.buckets)))
	i2 = uint32(hash2 % uint64(len(f.buckets)))
	fp = uint8(hash1 >> 56)
	return
}

func hash64(data uint64) uint64 {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, data)
	return xxhash.Sum64(b)
}

func nextPowerOfTwo(n uint32) uint32 {
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}
