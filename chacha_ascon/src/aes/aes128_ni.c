/* AES-128-CTR and AES-256-CTR with the x86 AES instructions (NR = 10 / 14 rounds;
 * one always-inline body per kernel, instantiated for both).
 *
 *   aesni-x8      AES-NI (128-bit xmm): 8 independent counter blocks in flight.
 *                 Golden/Raptor Cove issue two AESENC per cycle at 3-4 cycles
 *                 latency, so >= 8 blocks keep both AES units busy.
 *   vaes-x{8,12,16}  VAES on 256-bit ymm (two blocks per register; no AVX-512 on
 *                 this CPU): 4/6/8 ymm = 8/12/16 blocks in flight.
 *
 * Counter blocks: the counter block nonce || BE32(ctr) is kept byte-reversed in a
 * register, where the 32-bit counter is the low little-endian lane, so block i is
 * one PADDD of a constant and one PSHUFB back to byte order; the 32-bit add wraps
 * mod 2^32 without carrying into the nonce, as the contract requires. Round keys:
 * the FIPS-197 byte schedule from aes128/256_key_expand (AES-NI uses the same byte
 * order), loaded once per call; the context is that 176- or 240-byte schedule.
 * Tail: remaining whole blocks one (xmm) or two (ymm) at a time, then the final
 * partial block through a 16-byte stack buffer. */
#include <immintrin.h>
#include <string.h>
#include "blockctr.h"

#define AI static inline __attribute__((always_inline))

void aes128_setup_ni(void *ctx, const uint8_t *key) { aes128_key_expand(ctx, key); }
void aes256_setup_ni(void *ctx, const uint8_t *key) { aes256_key_expand(ctx, key); }

/* One block (xmm), byte-order counter block `cb`. */
AI __m128i enc1(__m128i cb, const __m128i k[15], const int NR)
{
    __m128i x = _mm_xor_si128(cb, k[0]);
    for (int r = 1; r < NR; r++) x = _mm_aesenc_si128(x, k[r]);
    return _mm_aesenclast_si128(x, k[NR]);
}

/* Shared tail: whole blocks then the partial one, starting at reversed counter `rc`. */
AI void tail_xmm(uint8_t *out, const uint8_t *in, size_t len, __m128i rc, const __m128i k[15], const int NR)
{
    const __m128i rev = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    const __m128i one = _mm_setr_epi32(1, 0, 0, 0);
    for (; len >= 16; len -= 16, in += 16, out += 16, rc = _mm_add_epi32(rc, one)) {
        __m128i ks = enc1(_mm_shuffle_epi8(rc, rev), k, NR);
        _mm_storeu_si128((__m128i *)out, _mm_xor_si128(ks, _mm_loadu_si128((const __m128i *)in)));
    }
    if (len) {
        uint8_t ks[16];
        _mm_storeu_si128((__m128i *)ks, enc1(_mm_shuffle_epi8(rc, rev), k, NR));
        for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(in[i] ^ ks[i]);
    }
}

AI __m128i rev_counter(const uint8_t nonce[12], uint32_t ctr)
{
    const __m128i rev = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    uint8_t blk[16];
    bc_counter_block(blk, nonce, ctr);
    return _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)blk), rev);
}

AI void aesni_x8(const void *ctx, uint8_t *out, const uint8_t *in, size_t len,
                 const uint8_t nonce[12], uint32_t ctr, const int NR)
{
    const __m128i rev = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    __m128i k[15];
    for (int r = 0; r <= NR; r++) k[r] = _mm_load_si128((const __m128i *)ctx + r);
    __m128i rc = rev_counter(nonce, ctr);
    __m128i inc[8];
    for (int i = 0; i < 8; i++) inc[i] = _mm_setr_epi32(i, 0, 0, 0);
    const __m128i eight = _mm_setr_epi32(8, 0, 0, 0);
    for (; len >= 128; len -= 128, in += 128, out += 128) {
        __m128i x[8];
#pragma GCC unroll 8
        for (int i = 0; i < 8; i++) x[i] = _mm_xor_si128(_mm_shuffle_epi8(_mm_add_epi32(rc, inc[i]), rev), k[0]);
        rc = _mm_add_epi32(rc, eight);
#pragma GCC unroll 13
        for (int r = 1; r < NR; r++)
#pragma GCC unroll 8
            for (int i = 0; i < 8; i++) x[i] = _mm_aesenc_si128(x[i], k[r]);
#pragma GCC unroll 8
        for (int i = 0; i < 8; i++) {
            x[i] = _mm_aesenclast_si128(x[i], k[NR]);
            _mm_storeu_si128((__m128i *)out + i, _mm_xor_si128(x[i], _mm_loadu_si128((const __m128i *)in + i)));
        }
    }
    tail_xmm(out, in, len, rc, k, NR);
}
void aes128_ctr_aesni_x8(const void *ctx, uint8_t *out, const uint8_t *in, size_t len,
                         const uint8_t nonce[12], uint32_t ctr) { aesni_x8(ctx, out, in, len, nonce, ctr, 10); }
void aes256_ctr_aesni_x8(const void *ctx, uint8_t *out, const uint8_t *in, size_t len,
                         const uint8_t nonce[12], uint32_t ctr) { aesni_x8(ctx, out, in, len, nonce, ctr, 14); }

/* VAES, NY ymm registers = 2*NY blocks per iteration. */
AI void vaes_ctr(const void *ctx, uint8_t *out, const uint8_t *in, size_t len,
                 const uint8_t nonce[12], uint32_t ctr, const int NY, const int NR)
{
    const __m256i rev = _mm256_broadcastsi128_si256(
        _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0));
    __m128i k[15];
    __m256i K[15];
    for (int r = 0; r <= NR; r++) {
        k[r] = _mm_load_si128((const __m128i *)ctx + r);
        K[r] = _mm256_broadcastsi128_si256(k[r]);
    }
    __m128i rc = rev_counter(nonce, ctr);
    /* RC: blocks (j, j+1) of the current pair; lanes hold counters +0 and +1 */
    __m256i RC = _mm256_add_epi32(_mm256_broadcastsi128_si256(rc), _mm256_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0));
    const __m256i two = _mm256_setr_epi32(2, 0, 0, 0, 2, 0, 0, 0);
    const __m256i step = _mm256_setr_epi32(2 * NY, 0, 0, 0, 2 * NY, 0, 0, 0);
    const size_t chunk = 32 * (size_t)NY;
    for (; len >= chunk; len -= chunk, in += chunk, out += chunk) {
        __m256i x[8], c = RC;
#pragma GCC unroll 8
        for (int i = 0; i < NY; i++) {
            x[i] = _mm256_xor_si256(_mm256_shuffle_epi8(c, rev), K[0]);
            c = _mm256_add_epi32(c, two);
        }
        RC = _mm256_add_epi32(RC, step);
#pragma GCC unroll 13
        for (int r = 1; r < NR; r++)
#pragma GCC unroll 8
            for (int i = 0; i < NY; i++) x[i] = _mm256_aesenc_epi128(x[i], K[r]);
#pragma GCC unroll 8
        for (int i = 0; i < NY; i++) {
            x[i] = _mm256_aesenclast_epi128(x[i], K[NR]);
            _mm256_storeu_si256((__m256i *)out + i, _mm256_xor_si256(x[i], _mm256_loadu_si256((const __m256i *)in + i)));
        }
    }
    for (; len >= 32; len -= 32, in += 32, out += 32) {
        __m256i x = _mm256_xor_si256(_mm256_shuffle_epi8(RC, rev), K[0]);
        RC = _mm256_add_epi32(RC, two);
        for (int r = 1; r < NR; r++) x = _mm256_aesenc_epi128(x, K[r]);
        x = _mm256_aesenclast_epi128(x, K[NR]);
        _mm256_storeu_si256((__m256i *)out, _mm256_xor_si256(x, _mm256_loadu_si256((const __m256i *)in)));
    }
    tail_xmm(out, in, len, _mm256_castsi256_si128(RC), k, NR);
}

#define VAES_ENTRY(name, NY, NR)                                                                 \
    void name(const void *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t nonce[12], \
              uint32_t ctr) { vaes_ctr(ctx, out, in, len, nonce, ctr, NY, NR); }
VAES_ENTRY(aes128_ctr_vaes_x8, 4, 10)
VAES_ENTRY(aes128_ctr_vaes_x12, 6, 10)
VAES_ENTRY(aes128_ctr_vaes_x16, 8, 10)
VAES_ENTRY(aes256_ctr_vaes_x8, 4, 14)
VAES_ENTRY(aes256_ctr_vaes_x12, 6, 14)
VAES_ENTRY(aes256_ctr_vaes_x16, 8, 14)
