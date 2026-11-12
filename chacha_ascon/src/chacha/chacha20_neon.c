/* ChaCha20, four blocks at a time in ARMv7 NEON (Cortex-A7), word-sliced:
 * v[i] holds state word i of four consecutive blocks, one per 32-bit lane --
 * the same layout as the AVX2 x8 code, at a quarter of the width.
 *
 * Rotations: by 16 is VREV32.16 (one op); by 8 is a byte shuffle, VTBL on each
 * 64-bit half (on the A7 a Q-register op takes two cycles anyway, so two D-reg
 * VTBLs cost the same as one Q op); by 12 and 7 are VSHL + VSRI (shift left,
 * then shift-right-and-insert), two ops. 16 state vectors fill all 16 Q
 * registers, so the compiler spills; its choice, measured below rather than
 * assumed.
 *
 * Output: add the input state, 4x4 transposes (VTRN.32 + VSWP of halves via
 * vcombine), XOR 64 bytes per block with unaligned VLD1/VST1. Tail (< 256
 * bytes) through the scalar lazy-rotation code with the counter advanced. */
#include <arm_neon.h>
#include <string.h>
#include "chacha20.h"

void chacha20_xor_lazy(uint8_t *, const uint8_t *, size_t, const uint8_t[32], const uint8_t[12], uint32_t);

static inline uint32x4_t rotl16(uint32x4_t x) { return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x))); }
static inline uint32x4_t rotl12(uint32x4_t x) { return vsriq_n_u32(vshlq_n_u32(x, 12), x, 20); }
static inline uint32x4_t rotl7(uint32x4_t x) { return vsriq_n_u32(vshlq_n_u32(x, 7), x, 25); }
static inline uint32x4_t rotl8(uint32x4_t x, uint8x8_t tbl)
{
    uint8x16_t b = vreinterpretq_u8_u32(x);
    return vreinterpretq_u32_u8(vcombine_u8(vtbl1_u8(vget_low_u8(b), tbl), vtbl1_u8(vget_high_u8(b), tbl)));
}

#define QR(a, b, c, d)                                          \
    a = vaddq_u32(a, b); d = veorq_u32(d, a); d = rotl16(d);    \
    c = vaddq_u32(c, d); b = veorq_u32(b, c); b = rotl12(b);    \
    a = vaddq_u32(a, b); d = veorq_u32(d, a); d = rotl8(d, r8); \
    c = vaddq_u32(c, d); b = veorq_u32(b, c); b = rotl7(b)

/* 4x4 transpose of 32-bit lanes: afterwards r[j] holds lane j of x0..x3 */
static inline void transpose4(uint32x4_t *x0, uint32x4_t *x1, uint32x4_t *x2, uint32x4_t *x3)
{
    uint32x4x2_t a = vtrnq_u32(*x0, *x1), b = vtrnq_u32(*x2, *x3);
    *x0 = vcombine_u32(vget_low_u32(a.val[0]), vget_low_u32(b.val[0]));
    *x1 = vcombine_u32(vget_low_u32(a.val[1]), vget_low_u32(b.val[1]));
    *x2 = vcombine_u32(vget_high_u32(a.val[0]), vget_high_u32(b.val[0]));
    *x3 = vcombine_u32(vget_high_u32(a.val[1]), vget_high_u32(b.val[1]));
}

static inline uint32_t ld32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

static inline void xor_out(uint8_t *out, const uint8_t *in, uint32x4_t k)
{
    vst1q_u8(out, veorq_u8(vld1q_u8(in), vreinterpretq_u8_u32(k)));
}

void chacha20_xor_neon_x4(uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t key[32], const uint8_t nonce[12], uint32_t counter)
{
    static const uint8_t r8b[8] = {3, 0, 1, 2, 7, 4, 5, 6};
    const uint8x8_t r8 = vld1_u8(r8b);
    uint32_t sk[8], sn[3];
    for (int i = 0; i < 8; i++) sk[i] = ld32(key + 4 * i);
    for (int i = 0; i < 3; i++) sn[i] = ld32(nonce + 4 * i);
    const uint32x4_t lane = {0, 1, 2, 3};
    while (len >= 256) {
        uint32x4_t x0 = vdupq_n_u32(0x61707865), x1 = vdupq_n_u32(0x3320646e);
        uint32x4_t x2 = vdupq_n_u32(0x79622d32), x3 = vdupq_n_u32(0x6b206574);
        uint32x4_t x4 = vdupq_n_u32(sk[0]), x5 = vdupq_n_u32(sk[1]), x6 = vdupq_n_u32(sk[2]), x7 = vdupq_n_u32(sk[3]);
        uint32x4_t x8 = vdupq_n_u32(sk[4]), x9 = vdupq_n_u32(sk[5]), x10 = vdupq_n_u32(sk[6]), x11 = vdupq_n_u32(sk[7]);
        uint32x4_t ctr = vaddq_u32(vdupq_n_u32(counter), lane);
        uint32x4_t x12 = ctr, x13 = vdupq_n_u32(sn[0]), x14 = vdupq_n_u32(sn[1]), x15 = vdupq_n_u32(sn[2]);
        for (int r = 0; r < 10; r++) {
            QR(x0, x4, x8, x12); QR(x1, x5, x9, x13); QR(x2, x6, x10, x14); QR(x3, x7, x11, x15);
            QR(x0, x5, x10, x15); QR(x1, x6, x11, x12); QR(x2, x7, x8, x13); QR(x3, x4, x9, x14);
        }
        x0 = vaddq_u32(x0, vdupq_n_u32(0x61707865)); x1 = vaddq_u32(x1, vdupq_n_u32(0x3320646e));
        x2 = vaddq_u32(x2, vdupq_n_u32(0x79622d32)); x3 = vaddq_u32(x3, vdupq_n_u32(0x6b206574));
        x4 = vaddq_u32(x4, vdupq_n_u32(sk[0])); x5 = vaddq_u32(x5, vdupq_n_u32(sk[1]));
        x6 = vaddq_u32(x6, vdupq_n_u32(sk[2])); x7 = vaddq_u32(x7, vdupq_n_u32(sk[3]));
        x8 = vaddq_u32(x8, vdupq_n_u32(sk[4])); x9 = vaddq_u32(x9, vdupq_n_u32(sk[5]));
        x10 = vaddq_u32(x10, vdupq_n_u32(sk[6])); x11 = vaddq_u32(x11, vdupq_n_u32(sk[7]));
        x12 = vaddq_u32(x12, ctr); x13 = vaddq_u32(x13, vdupq_n_u32(sn[0]));
        x14 = vaddq_u32(x14, vdupq_n_u32(sn[1])); x15 = vaddq_u32(x15, vdupq_n_u32(sn[2]));
        transpose4(&x0, &x1, &x2, &x3);
        transpose4(&x4, &x5, &x6, &x7);
        transpose4(&x8, &x9, &x10, &x11);
        transpose4(&x12, &x13, &x14, &x15);
        /* block j = words (x0..x3)[j] rows: after transposing, x0 = block 0 words 0-3,
         * x4 = block 0 words 4-7, x8 = block 0 words 8-11, x12 = block 0 words 12-15 */
        xor_out(out + 0, in + 0, x0);    xor_out(out + 16, in + 16, x4);
        xor_out(out + 32, in + 32, x8);  xor_out(out + 48, in + 48, x12);
        xor_out(out + 64, in + 64, x1);  xor_out(out + 80, in + 80, x5);
        xor_out(out + 96, in + 96, x9);  xor_out(out + 112, in + 112, x13);
        xor_out(out + 128, in + 128, x2); xor_out(out + 144, in + 144, x6);
        xor_out(out + 160, in + 160, x10); xor_out(out + 176, in + 176, x14);
        xor_out(out + 192, in + 192, x3); xor_out(out + 208, in + 208, x7);
        xor_out(out + 224, in + 224, x11); xor_out(out + 240, in + 240, x15);
        counter += 4;
        in += 256; out += 256; len -= 256;
    }
    if (len)
        chacha20_xor_lazy(out, in, len, key, nonce, counter);
}
