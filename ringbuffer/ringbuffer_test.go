package ringbuffer

import (
	"testing"
)

func TestRingBufferBasicOperations(t *testing.T) {
	rb := NewRingBuffer[int](3)

	// Test initial state
	if !rb.IsEmpty() {
		t.Error("New buffer should be empty")
	}

	if rb.IsFull() {
		t.Error("New buffer should not be full")
	}

	if rb.Length() != 0 {
		t.Errorf("Expected length 0, got %d", rb.Length())
	}

	if rb.Capacity() != 3 {
		t.Errorf("Expected capacity 3, got %d", rb.Capacity())
	}
}

func TestRingBufferWriteAndRead(t *testing.T) {
	rb := NewRingBuffer[int](3)

	// Test writing
	rb.Write(1)
	rb.Write(2)

	if rb.Length() != 2 {
		t.Errorf("Expected length 2, got %d", rb.Length())
	}

	// Test reading
	if val, ok := rb.Read(); !ok || val != 1 {
		t.Errorf("Expected 1, got %d", val)
	}

	if rb.Length() != 2 {
		t.Errorf("Expected length 2, got %d", rb.Length())
	}
}

func TestRingBufferOverflow(t *testing.T) {
	rb := NewRingBuffer[int](3)

	// Fill the buffer
	rb.Write(1)
	rb.Write(2)
	rb.Write(3)

	if !rb.IsFull() {
		t.Error("Buffer should be full")
	}

	// Write one more element (should overwrite the first)
	rb.Write(4)

	// Read and verify the elements
	expected := []int{2, 3, 4}
	for i, exp := range expected {
		if val, ok := rb.Read(); !ok || val != exp {
			t.Errorf("Element %d: expected %d, got %d", i, exp, val)
		}
	}
}

func TestRingBufferEmptyRead(t *testing.T) {
	rb := NewRingBuffer[int](3)

	// Try to read from empty buffer
	if val, ok := rb.Read(); ok {
		t.Errorf("Read from empty buffer should fail, got %d", val)
	}
}

func TestRingBufferWraparound(t *testing.T) {
	rb := NewRingBuffer[int](3)

	rb.Write(1)
	rb.Write(2)
	rb.Write(3)

	// Write new elements
	rb.Write(4)
	rb.Write(5)

	// Verify the elements
	expected := []int{3, 4, 5}
	for i, exp := range expected {
		if val, ok := rb.Read(); !ok || val != exp {
			t.Errorf("Element %d: expected %d, got %d", i, exp, val)
		}
	}
}

func TestRingBufferWithStrings(t *testing.T) {
	rb := NewRingBuffer[string](2)

	rb.Write("hello")
	rb.Write("world")

	if val, ok := rb.Read(); !ok || val != "hello" {
		t.Errorf("Expected 'hello', got '%s'", val)
	}

	if val, ok := rb.Read(); !ok || val != "world" {
		t.Errorf("Expected 'world', got '%s'", val)
	}
}

func TestRingBufferFullCycle(t *testing.T) {
	rb := NewRingBuffer[int](3)

	// Fill buffer
	for i := 1; i <= 3; i++ {
		rb.Write(i)
	}

	// Empty buffer
	for i := 1; i <= 3; i++ {
		if val, ok := rb.Read(); !ok || val != i {
			t.Errorf("Expected %d, got %d", i, val)
		}
	}
}
func TestRingBufferZeroSize(t *testing.T) {
	// When creating a buffer with size 0, it should create a buffer with size 1
	rb := NewRingBuffer[int](0)

	if rb.Capacity() != 1 {
		t.Errorf("Expected capacity 1 for zero-sized buffer, got %d", rb.Capacity())
	}

	// Write should succeed for one element
	rb.Write(1)

	if rb.Length() != 1 {
		t.Errorf("Expected length 1, got %d", rb.Length())
	}

	// Read should return the written value
	if val, ok := rb.Read(); !ok || val != 1 {
		t.Errorf("Expected to read 1, got %d", val)
	}
}

func TestRingBufferNegativeSize(t *testing.T) {
	rb := NewRingBuffer[int](-5)

	if rb.Capacity() != 1 {
		t.Errorf("Expected capacity 1 for negative-sized buffer, got %d", rb.Capacity())
	}

	rb.Write(42)
	if val, ok := rb.Read(); !ok || val != 42 {
		t.Errorf("Expected to read 42, got %d", val)
	}
}
