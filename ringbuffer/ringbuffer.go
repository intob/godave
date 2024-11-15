package ringbuffer

type RingBuffer[T any] struct {
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
	if rb.count == rb.size {
		// Buffer is full, overwrite oldest data
		rb.read = (rb.read + 1) % rb.size
	} else {
		rb.count++
	}

	rb.buffer[rb.write] = data
	rb.write = (rb.write + 1) % rb.size
	return true
}

func (rb *RingBuffer[T]) Read() (T, bool) {
	var zero T
	if rb.count == 0 {
		return zero, false
	}

	data := rb.buffer[rb.read]
	rb.read = (rb.read + 1) % rb.size

	if rb.read == rb.write {
		rb.read = 0
	}

	return data, true
}

func (rb *RingBuffer[T]) IsEmpty() bool {
	return rb.count == 0
}

func (rb *RingBuffer[T]) IsFull() bool {
	return rb.count == rb.size
}

func (rb *RingBuffer[T]) Length() int {
	return rb.count
}

func (rb *RingBuffer[T]) Capacity() int {
	return rb.size
}
