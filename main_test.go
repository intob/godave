package godave

import (
	"crypto/ed25519"
	"testing"

	"github.com/intob/godave/xor"
)

func TestXORDistanceFloat(t *testing.T) {
	t.Run("Equal Keys", func(t *testing.T) {
		key1 := make([]byte, ed25519.PublicKeySize)
		key2 := make([]byte, ed25519.PublicKeySize)
		distance, _ := xor.XorFloat(key1, key2)
		if distance != 0.0 {
			t.Errorf("Expected distance 0.0 for identical keys, got %f", distance)
		}
	})

	t.Run("Maximum Distance", func(t *testing.T) {
		key1 := make([]byte, ed25519.PublicKeySize)
		key2 := make([]byte, ed25519.PublicKeySize)
		for i := range key2 {
			key2[i] = 255
		}
		distance, _ := xor.XorFloat(key1, key2)
		if distance != 1.0 {
			t.Errorf("Expected distance 1.0 for maximum difference, got %f", distance)
		}
	})

	t.Run("Partial Distance", func(t *testing.T) {
		key1 := make([]byte, ed25519.PublicKeySize)
		key2 := make([]byte, ed25519.PublicKeySize)
		// Set half of the bytes to 255
		for i := 0; i < ed25519.PublicKeySize/2; i++ {
			key2[i] = 255
		}
		distance, _ := xor.XorFloat(key1, key2)
		expectedDistance := 0.5
		if distance != expectedDistance {
			t.Errorf("Expected distance %f for half difference, got %f", expectedDistance, distance)
		}
	})
}
