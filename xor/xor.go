package xor

import (
	"errors"
)

// Maximum possible distance between two 32-byte keys
const maxDistance = 32 * 255

// XorInto xor's 32-byte slices, putting the result into dst
// Length checks are omitted, be careful.
func Xor256Into(dst, a, b []byte) {
	xorInto(dst, a, b)
}

// Human-readable normalised distance
func XorFloat(a, b []byte) (float64, error) {
	if len(a) != 32 || len(b) != 32 {
		return 0, errors.New("inputs must be of equal length")
	}
	var distance int
	for i := 0; i < 32; i++ {
		distance += int(a[i] ^ b[i])
	}
	return float64(distance) / float64(maxDistance), nil
}
