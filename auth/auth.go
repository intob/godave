package auth

import (
	"crypto/ed25519"
	"errors"
)

type Salt [16]byte
type Signature [64]byte

type AuthChallenge [8]byte
type AuthSolution struct {
	Challenge AuthChallenge
	// Salting the challenge prevents a "chosen-text" attack
	Salt      Salt
	PublicKey ed25519.PublicKey
	Signature Signature
}

func (sol AuthSolution) Marshal(buf []byte) (int, error) {
	n := copy(buf, sol.Challenge[:])     // 8
	n += copy(buf[n:], sol.Salt[:])      // 16
	n += copy(buf[n:], sol.PublicKey)    // 32
	n += copy(buf[n:], sol.Signature[:]) // 64
	if n != 8+16+32+64 {
		return 0, errors.New("copy failed")
	}
	return n, nil
}

func (sol *AuthSolution) Unmarshal(buf []byte) error {
	if len(buf) != 8+16+32+64 {
		return errors.New("invalid buffer length")
	}
	n := copy(sol.Challenge[:], buf)
	n += copy(sol.Salt[:], buf[n:])
	sol.PublicKey = make([]byte, 32)
	n += copy(sol.PublicKey, buf[n:])
	copy(sol.Signature[:], buf[n:])
	return nil
}
