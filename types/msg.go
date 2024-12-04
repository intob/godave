package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/intob/godave/auth"
	"github.com/intob/godave/dat"
)

const (
	OP_PING              = Op(0)
	OP_PONG              = Op(1)
	OP_PUT               = Op(2)
	OP_PUT_ACK           = Op(3)
	OP_GET               = Op(4)
	OP_GET_ACK           = Op(5)
	OP_GETMYADDRPORT     = Op(6)
	OP_GETMYADDRPORT_ACK = Op(7)
	lenAddrPort          = 18
)

type Op byte

type Msg struct {
	Op            Op
	AddrPorts     []netip.AddrPort
	AuthChallenge auth.AuthChallenge
	AuthSolution  *auth.AuthSolution
	Dat           *dat.Dat
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
		msg.AuthChallenge = auth.AuthChallenge(buf[1:9])
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
		msg.AuthSolution = &auth.AuthSolution{}
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
	msg.Dat = &dat.Dat{}
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
