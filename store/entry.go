package store

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/intob/godave/dat"
	"github.com/intob/godave/network"
)

type Entry struct {
	Dat      dat.Dat
	Replicas [network.FANOUT]uint64
}

func (e *Entry) Unmarshal(buf []byte) error {
	if len(buf) < network.FANOUT*8+2 {
		return errors.New("buffer too small")
	}
	// Read replicas
	for i := 0; i < network.FANOUT; i++ {
		e.Replicas[i] = binary.LittleEndian.Uint64(buf[i*8:])
	}
	// Read len prefix
	lp := int(binary.LittleEndian.Uint16(buf[network.FANOUT*8:]))
	if lp == 0 {
		return errors.New("len prefix is zero")
	}
	e.Dat = dat.Dat{}
	return e.Dat.Unmarshal(buf[network.FANOUT*8+2:])
}

func (e Entry) Marshal(buf []byte) (int, error) {
	if len(buf) < network.FANOUT*8+2 {
		return 0, errors.New("buffer too small")
	}
	// Write replicas
	for i := 0; i < network.FANOUT; i++ {
		binary.LittleEndian.PutUint64(buf[i*8:], e.Replicas[i])
	}
	// Marshal dat
	n, err := e.Dat.Marshal(buf[network.FANOUT*8+2:])
	if err != nil {
		return 0, fmt.Errorf("failed to marshal dat: %w", err)
	}
	// Write len prefix
	binary.LittleEndian.PutUint16(buf[network.FANOUT*8:], uint16(n))
	return network.FANOUT*8 + 2 + n, nil
}
