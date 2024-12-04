package types

import (
	"encoding/binary"
	"errors"
)

type Status struct {
	UsedSpace int64
	Capacity  int64
}

func (s Status) Marshal(buf []byte) (int, error) {
	if len(buf) < 16 {
		return 0, errors.New("buffer too small")
	}
	binary.LittleEndian.PutUint64(buf[:8], uint64(s.UsedSpace))
	binary.LittleEndian.PutUint64(buf[8:], uint64(s.Capacity))
	return 16, nil
}

func (s *Status) Unmarshal(buf []byte) error {
	if len(buf) < 16 {
		return errors.New("buffer too small")
	}
	s.UsedSpace = int64(binary.LittleEndian.Uint64(buf[:8]))
	s.Capacity = int64(binary.LittleEndian.Uint64(buf[8:16]))
	return nil
}
