package xor

import (
	"errors"
	"math/bits"
	"unsafe"
)

// XorInto xor's 32-byte slices, putting the result into dst
// Length checks are omitted, be careful.
func Xor256Into(dst, a, b []byte) {
	xor256Into(dst, a, b)
}

// This version is around x4.45 faster than the naive implementation.
// It's remarkably close to the Arm assembly version. Yay 64-bit registers!
func Xor256Uint8(a, b []byte) (uint8, error) {
	if len(a) != 32 || len(b) != 32 {
		return 0, errors.New("inputs must be equal length")
	}
	x1 := *(*uint64)(unsafe.Pointer(&a[0]))
	y1 := *(*uint64)(unsafe.Pointer(&b[0]))
	x2 := *(*uint64)(unsafe.Pointer(&a[8]))
	y2 := *(*uint64)(unsafe.Pointer(&b[8]))
	x3 := *(*uint64)(unsafe.Pointer(&a[16]))
	y3 := *(*uint64)(unsafe.Pointer(&b[16]))
	x4 := *(*uint64)(unsafe.Pointer(&a[24]))
	y4 := *(*uint64)(unsafe.Pointer(&b[24]))

	total := uint64(bits.OnesCount64(x1^y1)) +
		uint64(bits.OnesCount64(x2^y2)) +
		uint64(bits.OnesCount64(x3^y3)) +
		uint64(bits.OnesCount64(x4^y4))

	return uint8(total), nil
}

func Xor256Uint64(a, b []byte) (uint64, error) {
	if len(a) != 32 || len(b) != 32 {
		return 0, errors.New("inputs must be equal length")
	}
	x1 := *(*uint64)(unsafe.Pointer(&a[0]))
	y1 := *(*uint64)(unsafe.Pointer(&b[0]))
	x2 := *(*uint64)(unsafe.Pointer(&a[8]))
	y2 := *(*uint64)(unsafe.Pointer(&b[8]))
	x3 := *(*uint64)(unsafe.Pointer(&a[16]))
	y3 := *(*uint64)(unsafe.Pointer(&b[16]))
	x4 := *(*uint64)(unsafe.Pointer(&a[24]))
	y4 := *(*uint64)(unsafe.Pointer(&b[24]))
	return x1 ^ y1 | x2 ^ y2 | x3 ^ y3 | x4 ^ y4, nil
}
