package types

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	Op_PING     = Op(0)
	Op_PONG     = Op(1)
	Op_PUT      = Op(2)
	maxOpCode   = 2
	lenAddrPort = 18 // 16B Addr 2B port
)

type Op byte
type Challenge [8]byte
type Hash [32]byte
type Salt [16]byte
type Signature [64]byte

type Solution struct {
	Challenge Challenge
	// Salting the challenge prevents a "chosen-text" attack
	Salt      Salt
	PublicKey ed25519.PublicKey
	Signature Signature
}

func (sol Solution) Marshal(buf []byte) (int, error) {
	n := copy(buf, sol.Challenge[:])     // 8
	n += copy(buf[n:], sol.Salt[:])      // 16
	n += copy(buf[n:], sol.PublicKey)    // 32
	n += copy(buf[n:], sol.Signature[:]) // 64
	if n != 8+16+32+64 {
		return 0, errors.New("copy failed")
	}
	return n, nil
}

func (sol *Solution) Unmarshal(buf []byte) error {
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

type Msg struct {
	Op        Op
	AddrPorts []netip.AddrPort
	Challenge Challenge
	Solution  *Solution
	Dat       *Dat
}

func (msg *Msg) Unmarshal(buf []byte) error {
	if buf[0] > maxOpCode {
		return errors.New("invalid op code")
	}
	msg.Op = Op(buf[0])
	switch msg.Op {
	case Op_PING:
		if len(buf) < 1+8 {
			return errors.New("buffer too small for op code and challenge")
		}
		msg.Challenge = Challenge(buf[1:9])
	case Op_PONG:
		lenAddrs := uint8(buf[1])
		if lenAddrs > 0 {
			var err error
			msg.AddrPorts, err = parseAddrs(buf[2 : 2+lenAddrs])
			if err != nil {
				return fmt.Errorf("failed to parse addrports: %s", err)
			}
		}
		msg.Solution = &Solution{}
		err := msg.Solution.Unmarshal(buf[2+lenAddrs:])
		if err != nil {
			return fmt.Errorf("failed to unmarshal solution: %s", err)
		}
	case Op_PUT:
		if len(buf) < 1+2 {
			return errors.New("buffer too small for op code and len prefix")
		}
		lenDat := binary.LittleEndian.Uint16(buf[1:3])
		if lenDat == 0 {
			return errors.New("dat len prefix is zero")
		}
		if int(lenDat) > len(buf)-3 {
			return errors.New("dat len prefix value is too large")
		}
		msg.Dat = &Dat{}
		msg.Dat.Unmarshal(buf[3:])
	}
	return nil
}

func (msg *Msg) Marshal(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, errors.New("buffer too small")
	}
	buf[0] = byte(msg.Op)
	n := 1

	switch msg.Op {
	case Op_PING:
		if len(buf) < 1+8 {
			return 0, errors.New("buffer too small")
		}
		n += copy(buf[1:], msg.Challenge[:])
		return n, nil
	case Op_PONG:
		// Write length of addresses
		addrBufLen := len(msg.AddrPorts) * lenAddrPort
		buf[1] = uint8(addrBufLen)

		// Marshal addresses
		offset := 2
		for _, addr := range msg.AddrPorts {
			ip := addr.Addr().As16()
			copy(buf[offset:offset+16], ip[:])
			binary.LittleEndian.PutUint16(buf[offset+16:offset+18], addr.Port())
			offset += lenAddrPort
		}

		// Marshal solution
		if msg.Solution == nil {
			return 0, errors.New("solution is required for PONG")
		}
		solLen, err := msg.Solution.Marshal(buf[offset:])
		if err != nil {
			return 0, fmt.Errorf("failed to marshal solution: %s", err)
		}
		return 1 + 1 + addrBufLen + solLen, nil
	case Op_PUT:
		if msg.Dat == nil {
			return 0, errors.New("dat is required for PUT")
		}
		datLen, err := msg.Dat.Marshal(buf[3:])
		if err != nil {
			return 0, fmt.Errorf("failed to marshal dat: %s", err)
		}
		binary.LittleEndian.PutUint16(buf[1:3], uint16(datLen))
		return 1 + 2 + datLen, nil
	}
	return 0, errors.New("unknown op code")
}

func parseAddrs(buf []byte) ([]netip.AddrPort, error) {
	l := len(buf)
	if l%lenAddrPort != 0 {
		return nil, fmt.Errorf("address buffer length is invalid: %d", l)
	}
	addrs := make([]netip.AddrPort, 0, l/18)
	for i := 0; i < l; i += lenAddrPort {
		ip := netip.AddrFrom16([16]byte(buf[i : i+16]))
		port := binary.LittleEndian.Uint16(buf[i+16 : i+18])
		addrs = append(addrs, netip.AddrPortFrom(ip, port))
	}
	return addrs, nil
}
