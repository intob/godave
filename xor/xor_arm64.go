//go:build arm64 && !appengine && gc && !purego
// +build arm64,!appengine,gc,!purego

package xor

//go:noescape
func xorInto(dst, a, b []byte)
