//go:build (!arm64 && !amd64) || appengine || !gc || purego
// +build !arm64,!amd64 appengine !gc purego

package xor

func xor256Into(dst, a, b []byte) {
	for i := 0; i < 32; i++ {
		dst[i] = a[i] ^ b[i]
	}
}
