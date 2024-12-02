package types

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	DatInMemorySize = 200
	DatHeaderSize   = 8 + 16 + 32 + 64 + 32 + 1 + 2
	DatMaxKVLen     = MaxMsgLen - DatHeaderSize
)

type Dat struct {
	Time   time.Time
	Salt   Salt
	Work   Hash
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
	totalNeeded := DatHeaderSize + lenKey + lenVal
	if len(buf) < totalNeeded {
		return 0, errors.New("buffer too small")
	}

	if lenKey+lenVal > DatMaxKVLen {
		return 0, fmt.Errorf("length of key+val must be no greater than %d bytes", DatMaxKVLen)
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
	if len(buf) < DatHeaderSize {
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
	if keyLen+valLen > DatMaxKVLen {
		return errors.New("total length exceeds maximum")
	}

	// Read value
	dat.Val = make([]byte, valLen)
	copy(dat.Val, buf[n:])

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
