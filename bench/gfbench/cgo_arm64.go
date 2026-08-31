//go:build arm64 && cgo

package main

/*
#cgo CFLAGS: -O3 -march=armv8.2-a+crypto
#include "gf256_neon.h"
*/
import "C"

import "unsafe"

// buildNibbleTable 生成常系数 c 的 32B 奇偶表。
func buildNibbleTable(coef byte) []byte {
	tab := make([]byte, 32)
	C.gf256_build_nibble(C.uint8_t(coef), (*C.uint8_t)(unsafe.Pointer(&tab[0])))
	return tab
}

// mulAddC dst ^= gf_mul(src, coef)（NEON vtbl 内核）
func mulAddC(dst, src, tab []byte, coef byte) {
	C.gf256_muladd((*C.uint8_t)(unsafe.Pointer(&dst[0])),
		(*C.uint8_t)(unsafe.Pointer(&src[0])),
		(*C.uint8_t)(unsafe.Pointer(&tab[0])),
		C.uint8_t(coef), C.size_t(len(dst)))
}

// xorC dst ^= src（NEON）
func xorC(dst, src []byte) {
	C.gf256_xor((*C.uint8_t)(unsafe.Pointer(&dst[0])),
		(*C.uint8_t)(unsafe.Pointer(&src[0])), C.size_t(len(dst)))
}

// backendName 报告当前内核后端
const backendName = "cgo-neon-vtbl(-O3 -march=armv8.2-a+crypto)"
