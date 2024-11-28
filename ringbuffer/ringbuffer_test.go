package ringbuffer

import (
	"testing"
)

func TestNewRingBuffer(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		wantSize int
	}{
		{"zero size", 0, 1},
		{"negative size", -1, 1},
		{"valid size", 5, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rb := NewRingBuffer[int](tt.size)
			if rb.Capacity() != tt.wantSize {
				t.Errorf("NewRingBuffer(%d) got size = %d, want %d", tt.size, rb.Capacity(), tt.wantSize)
			}
		})
	}
}

func TestRingBufferBasicOperations(t *testing.T) {
	rb := NewRingBuffer[int](3)

	// Test initial state
	if !rb.IsEmpty() {
		t.Error("New buffer should be empty")
	}
	if rb.IsFull() {
		t.Error("New buffer should not be full")
	}

	// Test writing
	rb.Write(1)
	if rb.Length() != 1 {
		t.Errorf("Buffer length = %d, want 1", rb.Length())
	}

	// Test reading
	val, ok := rb.Read()
	if !ok || val != 1 {
		t.Errorf("Read() = %d, %v, want 1, true", val, ok)
	}
	if !rb.IsEmpty() {
		t.Error("Buffer should be empty after reading")
	}
}

func TestRingBufferOverflow(t *testing.T) {
	rb := NewRingBuffer[int](2)

	rb.Write(1)
	rb.Write(2)
	rb.Write(3) // Should overwrite 1

	val, ok := rb.Read()
	if !ok || val != 2 {
		t.Errorf("Read() = %d, %v, want 2, true", val, ok)
	}

	val, ok = rb.Read()
	if !ok || val != 3 {
		t.Errorf("Read() = %d, %v, want 3, true", val, ok)
	}
}

func TestRingBufferEmptyRead(t *testing.T) {
	rb := NewRingBuffer[int](2)

	val, ok := rb.Read()
	if ok {
		t.Errorf("Read() from empty buffer returned ok=true and val=%d", val)
	}
}

func TestRingBufferFullCycle(t *testing.T) {
	rb := NewRingBuffer[int](3)

	// Fill buffer
	rb.Write(1)
	rb.Write(2)
	rb.Write(3)

	if !rb.IsFull() {
		t.Error("Buffer should be full")
	}

	// Read all items
	for i := 1; i <= 3; i++ {
		val, ok := rb.Read()
		if !ok || val != i {
			t.Errorf("Read() = %d, %v, want %d, true", val, ok, i)
		}
	}

	if !rb.IsEmpty() {
		t.Error("Buffer should be empty after reading all items")
	}
}

func TestRingBufferGenericType(t *testing.T) {
	rb := NewRingBuffer[string](2)

	rb.Write("hello")
	rb.Write("world")

	val, ok := rb.Read()
	if !ok || val != "hello" {
		t.Errorf("Read() = %s, %v, want hello, true", val, ok)
	}

	val, ok = rb.Read()
	if !ok || val != "world" {
		t.Errorf("Read() = %s, %v, want world, true", val, ok)
	}
}
