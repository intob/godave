package xor

import (
	"crypto/ed25519"
	"errors"
)

// XorInto xor's 32-byte slices, putting the result into dst
// Length checks are omitted, be careful.
func Xor256Into(dst, a, b []byte) {
	xorInto(dst, a, b)
}

// Human-readable normalised distance
func XorFloat(a, b []byte) (float64, error) {
	if len(a) != ed25519.PublicKeySize || len(b) != ed25519.PublicKeySize {
		return 0, errors.New("inputs must be of equal length")
	}
	var distance int
	for i := 0; i < ed25519.PublicKeySize; i++ {
		distance += int(a[i] ^ b[i])
	}
	// Maximum possible distance is PublicKeySize * 255
	maxDistance := ed25519.PublicKeySize * 255
	return float64(distance) / float64(maxDistance), nil
}
