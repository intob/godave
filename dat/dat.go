package dat

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/intob/godave/network"
	"lukechampine.com/blake3"
)

const (
	DAT_IN_MEMORY_SIZE = 200
	DAT_HEADER_SIZE    = 8 + 16 + 32 + 64 + 32 + 1 + 2
	maxKVLen           = network.MAX_MSG_LEN - DAT_HEADER_SIZE
)

type Signature [64]byte

type Dat struct {
	Time   time.Time
	Salt   Salt
	Work   Work
	Sig    Signature
	PubKey ed25519.PublicKey
	Key    string
	Val    []byte
}

func (dat Dat) Marshal(buf []byte) (int, error) {
	lenKey := len(dat.Key)
	lenVal := len(dat.Val)
	// Validate lengths
	if lenKey > 255 {
		return 0, errors.New("key must be no longer than 255 bytes")
	}
	totalNeeded := DAT_HEADER_SIZE + lenKey + lenVal
	if len(buf) < totalNeeded {
		return 0, errors.New("buffer too small")
	}

	if lenKey+lenVal > maxKVLen {
		return 0, fmt.Errorf("length of key+val must be no greater than %d bytes", maxKVLen)
	}
	// Copy fixed-length fields
	n := copy(buf[0:], Ttb(dat.Time)) // 8
	n += copy(buf[n:], dat.Salt[:])   // 16
	n += copy(buf[n:], dat.Work[:])   // 32
	n += copy(buf[n:], dat.Sig[:])    // 64
	n += copy(buf[n:], dat.PubKey)    // 32
	// Marshal len-prefixed key
	buf[n] = byte(lenKey)
	n++
	n += copy(buf[n:], dat.Key)
	// Marshal len-prefixed value
	binary.LittleEndian.PutUint16(buf[n:], uint16(lenVal))
	n += 2
	n += copy(buf[n:], dat.Val)
	return n, nil
}

func (dat *Dat) Unmarshal(buf []byte) error {
	// Minimum size check for fixed fields
	if len(buf) < DAT_HEADER_SIZE {
		return errors.New("buffer too small for fixed fields")
	}

	// Read fixed-size fields
	dat.Time = Btt(buf[:8])
	n := 8
	n += copy(dat.Salt[:], buf[n:])
	n += copy(dat.Work[:], buf[n:])
	n += copy(dat.Sig[:], buf[n:])
	dat.PubKey = make([]byte, 32)
	n += copy(dat.PubKey, buf[n:])

	// Read key length and validate
	keyLen := int(buf[n])
	n++
	if len(buf) < n+keyLen+2 { // +2 for val length
		return errors.New("buffer too small for key")
	}

	// Read key
	dat.Key = string(buf[n : n+keyLen])
	n += keyLen

	// Read value length
	if len(buf) < n+2 {
		return errors.New("buffer too small for value length")
	}
	valLen := int(binary.LittleEndian.Uint16(buf[n:]))
	n += 2

	// Validate total message length
	if len(buf) < n+valLen {
		return errors.New("buffer too small for value")
	}
	if keyLen+valLen > maxKVLen {
		return errors.New("total length exceeds maximum")
	}

	// Read value
	dat.Val = make([]byte, valLen)
	copy(dat.Val, buf[n:])

	return nil
}

func (d *Dat) Sign(privKey ed25519.PrivateKey) {
	h := blake3.New(32, nil)
	h.Write([]byte(d.Key))
	h.Write(d.Val)
	h.Write(Ttb(d.Time))
	sum := h.Sum(nil)
	d.Sig = Signature(ed25519.Sign(privKey, sum))
}

// Verify verifies the time, proof-of-work, and signature.
func (d *Dat) Verify(h *blake3.Hasher) error {
	if d.Time.After(time.Now()) {
		return errors.New("time is invalid")
	}
	if len(d.PubKey) != ed25519.PublicKeySize {
		return errors.New("pub key must be 32 bytes")
	}
	if Nzerobit(d.Work) < network.MIN_WORK {
		return errors.New("work is insufficient")
	}
	err := CheckWork(h, d.Sig, d.Salt, d.Work)
	if err != nil {
		return fmt.Errorf("work invalid: %w", err)
	}
	h.Reset()
	h.Write([]byte(d.Key))
	h.Write(d.Val)
	h.Write(Ttb(d.Time))
	sum := h.Sum(nil)
	if !ed25519.Verify(d.PubKey, sum, d.Sig[:]) {
		return errors.New("signature invalid")
	}
	return nil
}

func Ttb(t time.Time) []byte {
	milli := t.UnixNano() / 1000000
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, uint64(milli))
	return bytes
}

func Btt(b []byte) time.Time {
	return time.Unix(0, int64(binary.LittleEndian.Uint64(b))*1000000)
}
