package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/intob/dave/pkt"
)

const TEST_DIFFICULTY = 4

func workV1(msg *pkt.Msg, difficulty int) {
	prefix := make([]byte, difficulty)
	t := time.Now()
	msg.Time = timeToBytes(t)
	msg.Nonce = make([]byte, 32)
	for {
		if time.Since(t) > time.Second {
			t = time.Now()
			msg.Time = timeToBytes(t)
		}
		crand.Read(msg.Nonce)
		h := sha256.New()
		h.Write(msg.Val)
		h.Write(msg.Time)
		h.Write(msg.Nonce)
		msg.Key = h.Sum(nil)
		if bytes.HasPrefix(msg.Key, prefix) {
			return
		}
	}
}

func workV2(msg *pkt.Msg, difficulty int) {
	t := time.Now()
	msg.Time = timeToBytes(t)
	msg.Nonce = make([]byte, 32)
	for {
		if time.Since(t) > time.Second {
			t = time.Now()
			msg.Time = timeToBytes(t)
		}
		crand.Read(msg.Nonce)
		h := sha256.New()
		h.Write(msg.Val)
		h.Write(msg.Time)
		h.Write(msg.Nonce)
		msg.Key = h.Sum(nil)
		if leadingZerosV1(msg.Key) >= difficulty {
			return
		}
	}
}

func workV3(msg *pkt.Msg, difficulty int) {
	t := time.Now()
	msg.Time = timeToBytes(t)
	msg.Nonce = make([]byte, 32)
	for {
		if time.Since(t) > time.Second {
			t = time.Now()
			msg.Time = timeToBytes(t)
		}
		crand.Read(msg.Nonce)
		h := sha256.New()
		h.Write(msg.Val)
		h.Write(msg.Time)
		h.Write(msg.Nonce)
		msg.Key = h.Sum(nil)
		if leadingZerosV2(msg.Key) >= difficulty {
			return
		}
	}
}

// same speed as V2
func leadingZerosV1(b []byte) int {
	for i, j := range b {
		if j != 0 {
			return i
		}
	}
	return len(b)
}

// same speed as V1's range
func leadingZerosV2(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			return i
		}
	}
	return len(b)
}

func TestLeadingZerosV1(t *testing.T) {
	fiveOfEight := leadingZerosV1([]byte{0, 0, 0, 0, 0, 1, 2, 3})
	oneOfOne := leadingZerosV1([]byte{0})
	zeroOfOne := leadingZerosV1([]byte{1})
	none := leadingZerosV1([]byte{})
	if fiveOfEight != 5 || none != 0 || oneOfOne != 1 || zeroOfOne != 0 {
		t.FailNow()
	}
}

func TestLeadingZerosV2(t *testing.T) {
	fiveOfEight := leadingZerosV2([]byte{0, 0, 0, 0, 0, 1, 2, 3})
	oneOfOne := leadingZerosV2([]byte{0})
	zeroOfOne := leadingZerosV2([]byte{1})
	none := leadingZerosV2([]byte{})
	if fiveOfEight != 5 || none != 0 || oneOfOne != 1 || zeroOfOne != 0 {
		t.FailNow()
	}
}

func BenchmarkWorkV1(b *testing.B) {
	msg := &pkt.Msg{
		Op:  pkt.Op_SETDAT,
		Val: []byte("my_test"),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		workV1(msg, TEST_DIFFICULTY)
	}
	fmt.Printf("%x :: %x :: %v\n", msg.Key, msg.Nonce, msg.Time)
}

func BenchmarkWorkV2(b *testing.B) {
	msg := &pkt.Msg{
		Op:  pkt.Op_SETDAT,
		Val: []byte("my_test"),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		workV2(msg, TEST_DIFFICULTY)
	}
	fmt.Printf("%x :: %x :: %v\n", msg.Key, msg.Nonce, msg.Time)
}

func BenchmarkWorkV3(b *testing.B) {
	msg := &pkt.Msg{
		Op:  pkt.Op_SETDAT,
		Val: []byte("my_test"),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		workV3(msg, 4)
	}
	fmt.Printf("%x :: %x :: %v\n", msg.Key, msg.Nonce, msg.Time)
}

func BenchmarkBytesHasPrefix(b *testing.B) {
	x := make([]byte, 32)
	y := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !bytes.HasPrefix(x, y) {
			b.FailNow()
		}
	}
}

func BenchmarkLeadingZerosV1(b *testing.B) {
	x := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if leadingZerosV1(x) != 32 {
			b.FailNow()
		}
	}
	fmt.Println("done")
}

func BenchmarkLeadingZerosV2(b *testing.B) {
	x := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if leadingZerosV2(x) != 32 {
			b.FailNow()
		}
	}
	fmt.Println("done")
}
