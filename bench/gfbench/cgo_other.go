//go:build !arm64 || !cgo

package main

// 非 arm64/无 cgo 的兜底（纯 Go，仅供编译通过；性能无意义）

func gfMulGo(a, b byte) byte {
	var acc byte
	for b != 0 {
		if b&1 != 0 {
			acc ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1D
		}
		b >>= 1
	}
	return acc
}

func buildNibbleTable(coef byte) []byte {
	tab := make([]byte, 32)
	for lo := 0; lo < 16; lo++ {
		tab[lo] = gfMulGo(byte(lo), coef)
	}
	hiMul := gfMulGo(16, coef)
	for hi := 0; hi < 16; hi++ {
		tab[16+hi] = gfMulGo(byte(hi), hiMul)
	}
	return tab
}

func mulAddC(dst, src, tab []byte, coef byte) {
	for i := range src {
		dst[i] ^= gfMulGo(src[i], coef)
	}
}

func xorC(dst, src []byte) {
	for i := range src {
		dst[i] ^= src[i]
	}
}

const backendName = "go-fallback(无 NEON)"
