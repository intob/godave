package store

import (
	"container/heap"
	"time"
)

type heapEntry struct {
	key, distance uint64
	expires       time.Time
}

// Priority calculation combines TTL and XOR distance
func (e *heapEntry) priority() float64 {
	timeLeft := time.Until(e.expires).Seconds()
	if timeLeft <= 0 {
		return 0 // Expired items get lowest priority
	}
	// Normalize distance (assuming uint64 max as denominator)
	normDistance := float64(e.distance) / float64(^uint64(0))
	// Inverse distance, closer = higher priority
	priority := (1 - normDistance) * timeLeft
	return priority
}

type priorityHeap struct {
	entries []*heapEntry
	lookup  map[uint64]int // Track positions by key
}

func newPriorityHeap() *priorityHeap {
	return &priorityHeap{
		entries: make([]*heapEntry, 0),
		lookup:  make(map[uint64]int),
	}
}

func (h *priorityHeap) Update(key uint64) {
	if pos, exists := h.lookup[key]; exists {
		heap.Fix(h, pos)
	}
}

func (h *priorityHeap) Remove(key uint64) *heapEntry {
	if pos, exists := h.lookup[key]; exists {
		entry := heap.Remove(h, pos).(*heapEntry)
		return entry
	}
	return nil
}

func (h *priorityHeap) Contains(key uint64) bool {
	_, exists := h.lookup[key]
	return exists
}

func (h priorityHeap) Len() int {
	return len(h.entries)
}

func (h priorityHeap) Less(i, j int) bool {
	return h.entries[i].priority() < h.entries[j].priority()
}

func (h priorityHeap) Swap(i, j int) {
	h.entries[i], h.entries[j] = h.entries[j], h.entries[i]
	h.lookup[h.entries[i].key] = i
	h.lookup[h.entries[j].key] = j
}

func (h *priorityHeap) Push(x interface{}) {
	e := x.(*heapEntry)
	h.lookup[e.key] = len(h.entries)
	h.entries = append(h.entries, e)
}

func (h *priorityHeap) Pop() interface{} {
	old := h.entries
	n := len(old)
	x := old[n-1]
	h.entries = old[0 : n-1]
	delete(h.lookup, x.key)
	if n > 1 { // Update position for the last element that was moved
		h.lookup[old[n-2].key] = n - 2
	}
	return x
}

func (h *priorityHeap) Peek() *heapEntry {
	if len(h.entries) == 0 {
		return nil
	}
	return h.entries[0]
}
