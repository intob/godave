package types

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	// Max packet size, 1500 MTU is typical, prevents packet fragmentation
	MaxMsgLen            = 1424
	OP_PING              = Op(0)
	OP_PONG              = Op(1)
	OP_PUT               = Op(2)
	OP_GET               = Op(3)
	OP_GETMYADDRPORT     = Op(4)
	OP_GETMYADDRPORT_ACK = Op(5)
	lenAddrPort          = 18
)

type Op byte
type AuthChallenge [8]byte
type Hash [32]byte
type Salt [16]byte
type Signature [64]byte

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

type Msg struct {
	Op            Op
	AddrPorts     []netip.AddrPort
	AuthChallenge AuthChallenge
	AuthSolution  *AuthSolution
	Dat           *Dat
}

func (msg *Msg) Unmarshal(buf []byte) error {
	msg.Op = Op(buf[0])
	switch msg.Op {
	case OP_PING:
		if len(buf) < 1+8 {
			return errors.New("buffer too small for op code and challenge")
		}
		msg.AuthChallenge = AuthChallenge(buf[1:9])
	case OP_PONG:
		lenAddrs := uint8(buf[1])
		if lenAddrs > 0 {
			var err error
			msg.AddrPorts, err = parseAddrs(buf[2 : 2+lenAddrs])
			if err != nil {
				return fmt.Errorf("failed to parse addrports: %s", err)
			}
		}
		msg.AuthSolution = &AuthSolution{}
		err := msg.AuthSolution.Unmarshal(buf[2+lenAddrs:])
		if err != nil {
			return fmt.Errorf("failed to unmarshal solution: %s", err)
		}
	case OP_PUT:
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
	case OP_GETMYADDRPORT_ACK:
		addrPort, err := parseAddr(buf[1:])
		if err != nil {
			return fmt.Errorf("failed to parse addrport: %w", err)
		}
		msg.AddrPorts = []netip.AddrPort{addrPort}
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
	case OP_PING:
		if len(buf) < 1+8 {
			return 0, errors.New("buffer too small")
		}
		n += copy(buf[1:], msg.AuthChallenge[:])
		return n, nil
	case OP_PONG:
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
		if msg.AuthSolution == nil {
			return 0, errors.New("solution is required for PONG")
		}
		solLen, err := msg.AuthSolution.Marshal(buf[offset:])
		if err != nil {
			return 0, fmt.Errorf("failed to marshal solution: %s", err)
		}
		return 1 + 1 + addrBufLen + solLen, nil
	case OP_PUT:
		if msg.Dat == nil {
			return 0, errors.New("dat is required for PUT")
		}
		datLen, err := msg.Dat.Marshal(buf[3:])
		if err != nil {
			return 0, fmt.Errorf("failed to marshal dat: %s", err)
		}
		binary.LittleEndian.PutUint16(buf[1:3], uint16(datLen))
		return 1 + 2 + datLen, nil
	case OP_GETMYADDRPORT:
		return n, nil
	case OP_GETMYADDRPORT_ACK:
		if len(msg.AddrPorts) != 1 {
			return 0, errors.New("expected one addrport")
		}
		ip := msg.AddrPorts[0].Addr().As16()
		n += copy(buf[n:n+16], ip[:])
		binary.LittleEndian.PutUint16(buf[n:n+2], msg.AddrPorts[0].Port())
		n += 2
		return n, nil
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

func parseAddr(buf []byte) (netip.AddrPort, error) {
	if len(buf) < 18 {
		return netip.AddrPort{}, errors.New("buffer is too small")
	}
	ip := netip.AddrFrom16([16]byte(buf[:16]))
	port := binary.LittleEndian.Uint16(buf[16:18])
	return netip.AddrPortFrom(ip, port), nil
}
