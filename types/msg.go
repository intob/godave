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
	OP_GET_ACK           = Op(4)
	OP_GETMYADDRPORT     = Op(5)
	OP_GETMYADDRPORT_ACK = Op(6)
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

type Msg struct {
	Op            Op
	AddrPorts     []netip.AddrPort
	AuthChallenge AuthChallenge
	AuthSolution  *AuthSolution
	Dat           *Dat
	Get           *Get
	Status        *Status
}

func (msg *Msg) Unmarshal(buf []byte) error {
	msg.Op = Op(buf[0])
	switch msg.Op {
	case OP_PING:
		if len(buf) < 1+8+16 {
			return errors.New("buffer too small")
		}
		msg.AuthChallenge = AuthChallenge(buf[1:9])
		msg.Status = &Status{}
		return msg.Status.Unmarshal(buf[9:])
	case OP_PONG:
		lenAddrs := uint8(buf[1])
		if lenAddrs > 0 {
			var err error
			msg.AddrPorts, err = parseAddrs(buf[2 : 2+lenAddrs])
			if err != nil {
				return fmt.Errorf("failed to parse addrports: %w", err)
			}
		}
		msg.AuthSolution = &AuthSolution{}
		return msg.AuthSolution.Unmarshal(buf[2+lenAddrs:])
	case OP_PUT:
		return msg.unmarshalDat(buf[1:])
	case OP_GET:
		msg.Get = &Get{}
		return msg.Get.Unmarshal(buf[1:])
	case OP_GET_ACK:
		return msg.unmarshalDat(buf[1:])
	case OP_GETMYADDRPORT_ACK:
		addrPort, err := parseAddr(buf[1:])
		if err != nil {
			return fmt.Errorf("failed to parse addrport: %w", err)
		}
		msg.AddrPorts = []netip.AddrPort{addrPort}
	}
	return nil
}

func (msg *Msg) unmarshalDat(buf []byte) error {
	if len(buf) < 2 {
		return errors.New("buffer too small for op code and len prefix")
	}
	lenDat := binary.LittleEndian.Uint16(buf[:2])
	if lenDat == 0 {
		return errors.New("dat len prefix is zero")
	}
	if int(lenDat) > len(buf)-2 {
		return errors.New("dat len prefix value is too large")
	}
	msg.Dat = &Dat{}
	err := msg.Dat.Unmarshal(buf[2:])
	return err
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
		if msg.Status == nil {
			return 0, errors.New("status is nil")
		}
		statLen, err := msg.Status.Marshal(buf[n:])
		return n + statLen, err
	case OP_PONG:
		addrBufLen := len(msg.AddrPorts) * lenAddrPort
		buf[1] = uint8(addrBufLen)
		offset := 2
		for _, addr := range msg.AddrPorts {
			ip := addr.Addr().As16()
			copy(buf[offset:offset+16], ip[:])
			binary.LittleEndian.PutUint16(buf[offset+16:offset+18], addr.Port())
			offset += lenAddrPort
		}
		if msg.AuthSolution == nil {
			return 0, errors.New("solution is required for PONG")
		}
		solLen, err := msg.AuthSolution.Marshal(buf[offset:])
		if err != nil {
			return 0, fmt.Errorf("failed to marshal solution: %s", err)
		}
		return 1 + 1 + addrBufLen + solLen, nil
	case OP_PUT:
		datLen, err := msg.marshalDat(buf[1:])
		return 1 + datLen, err
	case OP_GET:
		if msg.Get == nil {
			return 0, errors.New("msg.Get is nil")
		}
		getLen, err := msg.Get.Marshal(buf[1:])
		if err != nil {
			return 0, fmt.Errorf("failed to marshal get: %w", err)
		}
		return 1 + getLen, nil
	case OP_GET_ACK:
		datLen, err := msg.marshalDat(buf[1:])
		return 1 + datLen, err
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

func (msg *Msg) marshalDat(buf []byte) (int, error) {
	if msg.Dat == nil {
		return 0, errors.New("dat is nil")
	}
	datLen, err := msg.Dat.Marshal(buf[2:])
	if err != nil {
		return 0, fmt.Errorf("failed to marshal dat: %w", err)
	}
	binary.LittleEndian.PutUint16(buf[:2], uint16(datLen))
	return 2 + datLen, nil
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
