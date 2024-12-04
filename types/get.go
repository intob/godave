package types

import (
	"crypto/ed25519"
	"errors"
)

type Get struct {
	PublicKey ed25519.PublicKey
	DatKey    string
}

func (g Get) Marshal(buf []byte) (int, error) {
	if len(buf) < 32+1+len(g.DatKey) {
		return 0, errors.New("buffer too small")
	}
	copy(buf, g.PublicKey)
	buf[32] = byte(len(g.DatKey))
	copy(buf[33:], g.DatKey)
	return 32 + 1 + len(g.DatKey), nil
}

func (g *Get) Unmarshal(buf []byte) error {
	if len(buf) < 32+1 {
		return errors.New("buffer too small")
	}
	g.PublicKey = make([]byte, 32)
	copy(g.PublicKey, buf[:32])
	keyLen := int(buf[32])
	if len(buf) < 32+1+keyLen {
		return errors.New("buffer too small for dat key")
	}
	g.DatKey = string(buf[33 : 33+keyLen])
	return nil
}
