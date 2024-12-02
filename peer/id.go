package peer

import (
	"crypto/ed25519"
	"encoding/binary"
)

// Returns the first 8 bytes of the public key
func IDFromPublicKey(publicKey ed25519.PublicKey) uint64 {
	return binary.LittleEndian.Uint64(publicKey[:8])
}
