/* ChaCha20, eight blocks at a time in AVX2 ("vertical" or word-sliced layout).
 *
 * v[i] holds state word i of eight consecutive blocks, one block per 32-bit lane,
 * so a quarter-round on v[] is a quarter-round on eight blocks with no shuffling
 * between rounds at all -- the diagonal round only renames registers. That is
 * the layout of Goll & Gueron's "Vectorization on ChaCha stream cipher" (ITNG
 * 2014) and of every fast AVX2 ChaCha since (OpenSSL's 8xAVX2 path, libsodium's
 * dolbeau code, the Linux kernel's chacha-avx2).
 *
 * Per double round and eight blocks: 8 quarter-rounds x (4 add + 4 xor + 4 rotate).
 * Rotations by 16 and 8 are byte permutations, one vpshufb each; 12 and 7 need
 * shift-shift-or. 128 vector ops per quarter-round set, 1280 per 512 bytes over the
 * 20 rounds, which on three vector ports is the ~0.83 core cycles/byte floor this
 * path cannot go below without AVX-512's vprold.
 *
 * The 16 state vectors fill the whole ymm file, so the compiler spills two or
 * three of them per round; v[8..11] (the "c" row) are the ones it picks, and the
 * cost is load/store-port work that overlaps the ALU work. Measured, not assumed:
 * see chacha_ascon/results.
 *
 * Output: the eight blocks are recovered with two 8x8 32-bit transposes (rows
 * 0-7 and rows 8-15), XORed into the input 32 bytes at a time with unaligned
 * loads and stores. The tail (< 512 bytes) goes through chacha20_xor_ref with
 * the counter advanced, so every length is handled. */
#include <immintrin.h>
#include <string.h>
#include "chacha20.h"

#define ROT16(x) _mm256_shuffle_epi8((x), rot16)
#define ROT8(x)  _mm256_shuffle_epi8((x), rot8)
#define ROTL(x, n) _mm256_or_si256(_mm256_slli_epi32((x), (n)), _mm256_srli_epi32((x), 32 - (n)))

#define QR(a, b, c, d)                                                    \
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = ROT16(d); \
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = ROTL(b, 12); \
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = ROT8(d);  \
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = ROTL(b, 7)

/* Two quarter-rounds step-interleaved, so two independent chains are always in
 * flight even where the compiler's spill reloads lengthen one of them. */
#define QR2(a, b, c, d, e, f, g, h)                                              \
    a = _mm256_add_epi32(a, b); e = _mm256_add_epi32(e, f);                     \
    d = _mm256_xor_si256(d, a); h = _mm256_xor_si256(h, e);                     \
    d = ROT16(d); h = ROT16(h);                                                 \
    c = _mm256_add_epi32(c, d); g = _mm256_add_epi32(g, h);                     \
    b = _mm256_xor_si256(b, c); f = _mm256_xor_si256(f, g);                     \
    b = ROTL(b, 12); f = ROTL(f, 12);                                           \
    a = _mm256_add_epi32(a, b); e = _mm256_add_epi32(e, f);                     \
    d = _mm256_xor_si256(d, a); h = _mm256_xor_si256(h, e);                     \
    d = ROT8(d); h = ROT8(h);                                                   \
    c = _mm256_add_epi32(c, d); g = _mm256_add_epi32(g, h);                     \
    b = _mm256_xor_si256(b, c); f = _mm256_xor_si256(f, g);                     \
    b = ROTL(b, 7); f = ROTL(f, 7)

static inline uint32_t ld32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4); /* little-endian host */
    return v;
}

/* 8x8 transpose of 32-bit elements, in place: afterwards x[j] holds what was
 * lane j of x[0..7]. */
static inline void transpose8(__m256i x[8])
{
    __m256i t0 = _mm256_unpacklo_epi32(x[0], x[1]);
    __m256i t1 = _mm256_unpackhi_epi32(x[0], x[1]);
    __m256i t2 = _mm256_unpacklo_epi32(x[2], x[3]);
    __m256i t3 = _mm256_unpackhi_epi32(x[2], x[3]);
    __m256i t4 = _mm256_unpacklo_epi32(x[4], x[5]);
    __m256i t5 = _mm256_unpackhi_epi32(x[4], x[5]);
    __m256i t6 = _mm256_unpacklo_epi32(x[6], x[7]);
    __m256i t7 = _mm256_unpackhi_epi32(x[6], x[7]);
    __m256i u0 = _mm256_unpacklo_epi64(t0, t2);
    __m256i u1 = _mm256_unpackhi_epi64(t0, t2);
    __m256i u2 = _mm256_unpacklo_epi64(t1, t3);
    __m256i u3 = _mm256_unpackhi_epi64(t1, t3);
    __m256i u4 = _mm256_unpacklo_epi64(t4, t6);
    __m256i u5 = _mm256_unpackhi_epi64(t4, t6);
    __m256i u6 = _mm256_unpacklo_epi64(t5, t7);
    __m256i u7 = _mm256_unpackhi_epi64(t5, t7);
    /* u0 = lanes {0,4} words 0-3 / 4-7 interleaved by 128-bit half */
    x[0] = _mm256_permute2x128_si256(u0, u4, 0x20);
    x[4] = _mm256_permute2x128_si256(u0, u4, 0x31);
    x[1] = _mm256_permute2x128_si256(u1, u5, 0x20);
    x[5] = _mm256_permute2x128_si256(u1, u5, 0x31);
    x[2] = _mm256_permute2x128_si256(u2, u6, 0x20);
    x[6] = _mm256_permute2x128_si256(u2, u6, 0x31);
    x[3] = _mm256_permute2x128_si256(u3, u7, 0x20);
    x[7] = _mm256_permute2x128_si256(u3, u7, 0x31);
}

__attribute__((target("avx2")))
void chacha20_xor_avx2_x8(uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t key[32], const uint8_t nonce[12], uint32_t counter)
{
    const __m256i rot16 = _mm256_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
                                           2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
    const __m256i rot8 = _mm256_setr_epi8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14,
                                          3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
    __m256i s[16];
    s[0] = _mm256_set1_epi32(0x61707865);
    s[1] = _mm256_set1_epi32(0x3320646e);
    s[2] = _mm256_set1_epi32(0x79622d32);
    s[3] = _mm256_set1_epi32(0x6b206574);
    for (int i = 0; i < 8; i++)
        s[4 + i] = _mm256_set1_epi32((int)ld32(key + 4 * i));
    for (int i = 0; i < 3; i++)
        s[13 + i] = _mm256_set1_epi32((int)ld32(nonce + 4 * i));
    const __m256i lane = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
    const __m256i eight = _mm256_set1_epi32(8);
    s[12] = _mm256_add_epi32(_mm256_set1_epi32((int)counter), lane);

    while (len >= 512) {
        __m256i x0 = s[0], x1 = s[1], x2 = s[2], x3 = s[3];
        __m256i x4 = s[4], x5 = s[5], x6 = s[6], x7 = s[7];
        __m256i x8 = s[8], x9 = s[9], x10 = s[10], x11 = s[11];
        __m256i x12 = s[12], x13 = s[13], x14 = s[14], x15 = s[15];
        for (int r = 0; r < 10; r++) {
            QR2(x0, x4, x8, x12, x1, x5, x9, x13);
            QR2(x2, x6, x10, x14, x3, x7, x11, x15);
            QR2(x0, x5, x10, x15, x1, x6, x11, x12);
            QR2(x2, x7, x8, x13, x3, x4, x9, x14);
        }
        __m256i a[8] = {
            _mm256_add_epi32(x0, s[0]), _mm256_add_epi32(x1, s[1]),
            _mm256_add_epi32(x2, s[2]), _mm256_add_epi32(x3, s[3]),
            _mm256_add_epi32(x4, s[4]), _mm256_add_epi32(x5, s[5]),
            _mm256_add_epi32(x6, s[6]), _mm256_add_epi32(x7, s[7])};
        __m256i b[8] = {
            _mm256_add_epi32(x8, s[8]), _mm256_add_epi32(x9, s[9]),
            _mm256_add_epi32(x10, s[10]), _mm256_add_epi32(x11, s[11]),
            _mm256_add_epi32(x12, s[12]), _mm256_add_epi32(x13, s[13]),
            _mm256_add_epi32(x14, s[14]), _mm256_add_epi32(x15, s[15])};
        transpose8(a);
        transpose8(b);
        for (int j = 0; j < 8; j++) {
            __m256i p0 = _mm256_loadu_si256((const __m256i *)(in + 64 * j));
            __m256i p1 = _mm256_loadu_si256((const __m256i *)(in + 64 * j + 32));
            _mm256_storeu_si256((__m256i *)(out + 64 * j), _mm256_xor_si256(p0, a[j]));
            _mm256_storeu_si256((__m256i *)(out + 64 * j + 32), _mm256_xor_si256(p1, b[j]));
        }
        s[12] = _mm256_add_epi32(s[12], eight);
        counter += 8;
        in += 512; out += 512; len -= 512;
    }
    if (len)
        chacha20_xor_ref(out, in, len, key, nonce, counter);
}
