package types

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestParseAddrs(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []netip.AddrPort
		wantErr bool
	}{
		{
			name:    "Empty buffer",
			input:   []byte{},
			want:    []netip.AddrPort{},
			wantErr: false,
		},
		{
			name:    "Invalid buffer length",
			input:   make([]byte, 17),
			want:    nil,
			wantErr: true,
		},
		{
			name: "Single IPv6 address with port",
			input: []byte{
				0x20, 0x01, 0x0d, 0xb8, // 2001:0db8
				0x00, 0x00, 0x00, 0x00, // 0000:0000
				0x00, 0x00, 0x00, 0x00, // 0000:0000
				0x00, 0x00, 0x00, 0x01, // 0000:0001
				0x23, 0x28, // Port 10275 (0x2823 in little-endian)
			},
			want: []netip.AddrPort{
				netip.AddrPortFrom(
					netip.MustParseAddr("2001:db8::1"),
					10275,
				),
			},
			wantErr: false,
		},
		{
			name: "Multiple IPv6 addresses with ports",
			input: []byte{
				// First address: 2001:db8::1 port 10275
				0x20, 0x01, 0x0d, 0xb8,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,
				0x23, 0x28,

				// Second address: 2001:db8::2 port 8080
				0x20, 0x01, 0x0d, 0xb8,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x02,
				0x90, 0x1f, // Port 8080 (0x1f90 in little-endian)
			},
			want: []netip.AddrPort{
				netip.AddrPortFrom(
					netip.MustParseAddr("2001:db8::1"),
					10275,
				),
				netip.AddrPortFrom(
					netip.MustParseAddr("2001:db8::2"),
					8080,
				),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAddrs(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAddrs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAddrs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPongMessageMarshalUnmarshal(t *testing.T) {
	// Setup test data
	pubKey, _, _ := ed25519.GenerateKey(nil)
	solution := &AuthSolution{
		Challenge: AuthChallenge{1, 2, 3, 4, 5, 6, 7, 8},
		Salt:      Salt{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		PublicKey: pubKey,
		Signature: Signature{},
	}

	addr1 := netip.MustParseAddrPort("[2001:db8::1]:8080")
	addr2 := netip.MustParseAddrPort("[2001:db8::2]:9090")

	msg := &Msg{
		Op:           OP_PONG,
		AddrPorts:    []netip.AddrPort{addr1, addr2},
		AuthSolution: solution,
	}

	// Test marshaling
	buf := make([]byte, 1000)
	n, err := msg.Marshal(buf)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Test unmarshaling
	newMsg := &Msg{}
	err = newMsg.Unmarshal(buf[:n])
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify fields
	if newMsg.Op != OP_PONG {
		t.Errorf("Op mismatch: got %v, want %v", newMsg.Op, OP_PONG)
	}

	if len(newMsg.AddrPorts) != len(msg.AddrPorts) {
		t.Errorf("AddrPorts length mismatch: got %v, want %v", len(newMsg.AddrPorts), len(msg.AddrPorts))
	}

	for i, addr := range msg.AddrPorts {
		if addr.String() != newMsg.AddrPorts[i].String() {
			t.Errorf("AddrPort %d mismatch: got %v, want %v", i, newMsg.AddrPorts[i], addr)
		}
	}

	if !bytes.Equal(newMsg.AuthSolution.Challenge[:], solution.Challenge[:]) {
		t.Error("Challenge mismatch")
	}

	if !bytes.Equal(newMsg.AuthSolution.Salt[:], solution.Salt[:]) {
		t.Error("Salt mismatch")
	}

	if !bytes.Equal(newMsg.AuthSolution.PublicKey, solution.PublicKey) {
		t.Error("PublicKey mismatch")
	}
}

func TestParseAddrs2(t *testing.T) {
	// Create test addresses
	addrs := []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::1]:8080"),
		netip.MustParseAddrPort("[2001:db8::2]:9090"),
	}

	// Create buffer and marshal addresses
	buf := make([]byte, 2*lenAddrPort)
	offset := 0
	for _, addr := range addrs {
		ip := addr.Addr().As16()
		copy(buf[offset:offset+16], ip[:])
		binary.LittleEndian.PutUint16(buf[offset+16:offset+18], addr.Port())
		offset += lenAddrPort
	}

	// Parse addresses back
	parsed, err := parseAddrs(buf)
	if err != nil {
		t.Fatalf("parseAddrs failed: %v", err)
	}

	if len(parsed) != len(addrs) {
		t.Errorf("Expected %d addresses, got %d", len(addrs), len(parsed))
	}

	for i, addr := range addrs {
		if addr.String() != parsed[i].String() {
			t.Errorf("Address %d mismatch: got %v, want %v", i, parsed[i], addr)
		}
	}
}

func TestPongMessageEdgeCases(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(nil)
	solution := &AuthSolution{
		Challenge: AuthChallenge{1, 2, 3, 4, 5, 6, 7, 8},
		Salt:      Salt{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		PublicKey: pubKey,
		Signature: Signature{},
	}

	tests := []struct {
		name    string
		msg     *Msg
		wantErr bool
	}{
		{
			name: "empty addrports",
			msg: &Msg{
				Op:           OP_PONG,
				AddrPorts:    []netip.AddrPort{},
				AuthSolution: solution,
			},
			wantErr: false,
		},
		{
			name: "nil solution",
			msg: &Msg{
				Op:           OP_PONG,
				AddrPorts:    []netip.AddrPort{},
				AuthSolution: nil,
			},
			wantErr: true,
		},
		{
			name: "multiple addresses",
			msg: &Msg{
				Op: OP_PONG,
				AddrPorts: []netip.AddrPort{
					netip.MustParseAddrPort("[2001:db8::1]:8080"),
					netip.MustParseAddrPort("[2001:db8::2]:9090"),
					netip.MustParseAddrPort("[2001:db8::3]:7070"),
				},
				AuthSolution: solution,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 1000)
			_, err := tt.msg.Marshal(buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMarshalGetMyAddrPortAck(t *testing.T) {
	addr := netip.MustParseAddrPort("[2001:db8::1]:8080")
	msg := &Msg{Op: OP_GETMYADDRPORT_ACK, AddrPorts: []netip.AddrPort{addr}}
	buf := make([]byte, 19)
	n, err := msg.Marshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 19 {
		t.Fatalf("len is %d, expected %d", n, 19)
	}
}
func TestUnmarshalGetMyAddrPortAck(t *testing.T) {
	addr := netip.MustParseAddrPort("[2001:db8::1]:8080")
	msg := &Msg{Op: OP_GETMYADDRPORT_ACK, AddrPorts: []netip.AddrPort{addr}}
	buf := make([]byte, 19)
	_, err := msg.Marshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg2 := &Msg{}
	msg2.Unmarshal(buf)
	if len(msg2.AddrPorts) != 1 {
		t.Fatalf("exepected one addrport, got %d", len(msg2.AddrPorts))
	}
	if msg2.AddrPorts[0] != addr {
		t.Fatalf("expected %s, got %s", addr, msg2.AddrPorts[0])
	}
}

/*
BenchmarkProto-12        				2904609	       412.0 ns/op	     600 B/op	       9 allocs/op
BenchmarkMsgMarshalUnmarshal-12    	 	9422624	       109.4 ns/op	     256 B/op	       4 allocs/op
*/
func BenchmarkMsgMarshalUnmarshal(b *testing.B) {
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	msg := &Msg{
		Op: OP_PUT,
		Dat: &Dat{
			Key:    "test",
			Val:    []byte("test_val"),
			Time:   time.Now(),
			PubKey: pubKey,
		},
	}
	rand.Read(msg.Dat.Salt[:])
	rand.Read(msg.Dat.Work[:])
	rand.Read(msg.Dat.Sig[:])
	buf := make([]byte, MaxMsgLen)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, _ := msg.Marshal(buf)
		m := &Msg{}
		m.Unmarshal(buf[:n])
	}
}

func BenchmarkMsgMarshal(b *testing.B) {
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	msg := &Msg{
		Op: OP_PUT,
		Dat: &Dat{
			Key:    "test",
			Val:    []byte("test_val"),
			Time:   time.Now(),
			PubKey: pubKey,
		},
	}
	rand.Read(msg.Dat.Salt[:])
	rand.Read(msg.Dat.Work[:])
	rand.Read(msg.Dat.Sig[:])
	buf := make([]byte, MaxMsgLen)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg.Marshal(buf)
	}
}

func BenchmarkMsgUnmarshal(b *testing.B) {
	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	msg := &Msg{
		Op: OP_PUT,
		Dat: &Dat{
			Key:    "test",
			Val:    []byte("test_val"),
			Time:   time.Now(),
			PubKey: pubKey,
		},
	}
	rand.Read(msg.Dat.Salt[:])
	rand.Read(msg.Dat.Work[:])
	rand.Read(msg.Dat.Sig[:])
	buf := make([]byte, MaxMsgLen)
	n, _ := msg.Marshal(buf)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := &Msg{}
		m.Unmarshal(buf[:n])
	}
}
