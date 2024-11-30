package ringbuffer

import "sync"

type RingBuffer[T any] struct {
	mu     sync.RWMutex
	buffer []T
	size   int
	read   int
	write  int
	count  int
}

func NewRingBuffer[T any](size int) *RingBuffer[T] {
	if size < 1 {
		size = 1
	}
	return &RingBuffer[T]{
		buffer: make([]T, size),
		size:   size,
		read:   0,
		write:  0,
		count:  0,
	}
}

func (rb *RingBuffer[T]) Write(data T) bool {
	rb.mu.Lock()
	if rb.count == rb.size {
		// Buffer is full, overwrite oldest data
		rb.read = (rb.read + 1) % rb.size
		rb.count--
	}
	rb.buffer[rb.write] = data
	rb.write = (rb.write + 1) % rb.size
	rb.count++
	rb.mu.Unlock()
	return true
}

func (rb *RingBuffer[T]) Read() (T, bool) {
	rb.mu.RLock()
	var zero T
	if rb.count == 0 {
		rb.mu.RUnlock()
		return zero, false
	}
	data := rb.buffer[rb.read]
	rb.read = (rb.read + 1) % rb.size
	rb.count--
	rb.mu.RUnlock()
	return data, true
}

func (rb *RingBuffer[T]) IsEmpty() bool {
	rb.mu.RLock()
	defer rb.mu.Unlock()
	return rb.count == 0
}

func (rb *RingBuffer[T]) IsFull() bool {
	rb.mu.RLock()
	defer rb.mu.Unlock()
	return rb.count == rb.size
}

func (rb *RingBuffer[T]) Length() int {
	rb.mu.RLock()
	defer rb.mu.Unlock()
	return rb.count
}

func (rb *RingBuffer[T]) Capacity() int {
	rb.mu.RLock()
	defer rb.mu.Unlock()
	return rb.size
}
