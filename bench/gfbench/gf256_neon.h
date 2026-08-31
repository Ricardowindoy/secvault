#ifndef GF256_NEON_H
#define GF256_NEON_H

#include <stdint.h>
#include <stddef.h>

/*
 * GF(256) 常系数乘加内核（NEON vtbl 方案，poly=0x11D）。
 * 原理：字节 x = lo + hi<<4；x·c = lo·c ^ hi·(16·c)，
 * 两个 16 项表（共 32B，常驻 NEON 寄存器）+ 2 次 vqtbl2 即完成 16 字节乘加。
 */

// 构建 32B 奇偶表：tab[0..15]=gf_mul(lo,c)，tab[16+hi]=gf_mul(hi, gf_mul(16,c))
void gf256_build_nibble(uint8_t coef, uint8_t *tab /*32B*/);

// dst ^= table[src]（coef 常系数乘加累加），n 需为 16 的倍数
void gf256_muladd(uint8_t *dst, const uint8_t *src, const uint8_t *tab, uint8_t coef, size_t n);

// dst ^= src（纯异或，parity 累加/coef==1 快路径）
void gf256_xor(uint8_t *dst, const uint8_t *src, size_t n);

#endif
