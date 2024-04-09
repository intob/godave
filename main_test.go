package main

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/inneslabs/dave/pkt"
)

func TestWorkDifficulty2(t *testing.T) {
	// Test case 2: Check if the function returns a key with 3 leading zeros
	msg := &pkt.Msg{
		Val: []byte("hello"),
	}
	const difficulty = 2
	prefix := make([]byte, difficulty)
	resultChan := work(msg, difficulty)
	select {
	case result := <-resultChan:
		// Check if the key has 3 leading zeros
		if !bytes.HasPrefix(result.Key, prefix) {
			t.Errorf("Expected key to have 2 leading zeros, but got: %x", result.Key)
		}
	case <-time.After(10 * time.Second):
		t.Error("Timed out waiting for result")
	}
}

func TestCheckWorkValidPrefix2(t *testing.T) {
	difficulty := 2
	wantPrefix := 2
	msg := &pkt.Msg{
		Val: []byte("hello"),
	}
	resultCh := work(msg, difficulty)
	validMsg := <-resultCh
	h := sha256.New()
	h.Write(validMsg.Val)
	h.Write(validMsg.Nonce)
	validMsg.Key = h.Sum(nil)
	gotPrefix := checkWork(validMsg)
	if gotPrefix != wantPrefix {
		t.Errorf("checkWork() = %d, want %d", gotPrefix, wantPrefix)
	}
}

func TestCheckWorkValidPrefix0(t *testing.T) {
	difficulty := 0
	wantPrefix := 0
	msg := &pkt.Msg{
		Val: []byte("hello"),
	}
	resultCh := work(msg, difficulty)
	validMsg := <-resultCh
	h := sha256.New()
	h.Write(validMsg.Val)
	h.Write(validMsg.Nonce)
	validMsg.Key = h.Sum(nil)
	gotPrefix := checkWork(validMsg)
	if gotPrefix != wantPrefix {
		t.Errorf("checkWork() = %d, want %d", gotPrefix, wantPrefix)
	}
}

func TestCheckWorkInvalid(t *testing.T) {
	difficulty := 2
	wantPrefix := -1
	msg := &pkt.Msg{
		Val: []byte("hello"),
	}
	resultCh := work(msg, difficulty)
	validMsg := <-resultCh
	// Modify the key to make it invalid
	validMsg.Key[31] ^= 1
	h := sha256.New()
	h.Write(validMsg.Val)
	h.Write(validMsg.Nonce)
	gotPrefix := checkWork(validMsg)
	if gotPrefix != wantPrefix {
		t.Errorf("checkWork() = %d, want %d", gotPrefix, wantPrefix)
	}
}
