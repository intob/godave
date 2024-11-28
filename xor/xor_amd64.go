//go:build amd64 && !appengine && gc && !purego
// +build amd64,!appengine,gc,!purego

package xor

//go:noescape
func xorInto(dst, a, b []byte)
