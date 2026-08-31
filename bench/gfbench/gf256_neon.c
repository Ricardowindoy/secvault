#include "gf256_neon.h"
#include <arm_neon.h>

static uint8_t gf_mul_byte(uint8_t a, uint8_t b) {
    uint8_t acc = 0;
    while (b) {
        if (b & 1) acc ^= a;
        uint8_t hi = (uint8_t)(a & 0x80);
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1D; /* x^8 mod 0x11D */
        b >>= 1;
    }
    return acc;
}

void gf256_build_nibble(uint8_t coef, uint8_t *tab) {
    for (int lo = 0; lo < 16; lo++) tab[lo] = gf_mul_byte((uint8_t)lo, coef);
    uint8_t hi_mul = gf_mul_byte(16, coef); /* x^4 乘 c */
    for (int hi = 0; hi < 16; hi++) tab[16 + hi] = gf_mul_byte((uint8_t)hi, hi_mul);
}

void gf256_muladd(uint8_t *dst, const uint8_t *src, const uint8_t *tab, uint8_t coef, size_t n) {
    uint8x16x2_t t;
    t.val[0] = vld1q_u8(tab);       /* lo 表 */
    t.val[1] = vld1q_u8(tab + 16);  /* hi 表 */
    uint8x16_t mask0f = vdupq_n_u8(0x0F);
    uint8x16_t sixteen = vdupq_n_u8(16);
    size_t i = 0;
    for (; i + 16 <= n; i += 16) {
        uint8x16_t s = vld1q_u8(src + i);
        uint8x16_t d = vld1q_u8(dst + i);
        uint8x16_t lo = vandq_u8(s, mask0f);
        uint8x16_t hi = vaddq_u8(vshrq_n_u8(s, 4), sixteen);
        uint8x16_t p = veorq_u8(vqtbl2q_u8(t, lo), vqtbl2q_u8(t, hi));
        vst1q_u8(dst + i, veorq_u8(d, p));
    }
    for (; i < n; i++) {
        /* n 非 16 倍数的兜底（基准中不会走到） */
        dst[i] ^= gf_mul_byte(src[i], coef);
    }
}

void gf256_xor(uint8_t *dst, const uint8_t *src, size_t n) {
    size_t i = 0;
    for (; i + 64 <= n; i += 64) {
        vst1q_u8(dst + i,      veorq_u8(vld1q_u8(dst + i),      vld1q_u8(src + i)));
        vst1q_u8(dst + i + 16, veorq_u8(vld1q_u8(dst + i + 16), vld1q_u8(src + i + 16)));
        vst1q_u8(dst + i + 32, veorq_u8(vld1q_u8(dst + i + 32), vld1q_u8(src + i + 32)));
        vst1q_u8(dst + i + 48, veorq_u8(vld1q_u8(dst + i + 48), vld1q_u8(src + i + 48)));
    }
    for (; i < n; i++) dst[i] ^= src[i];
}
