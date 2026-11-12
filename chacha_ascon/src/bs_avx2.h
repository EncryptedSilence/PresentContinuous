/* Shared AVX2 helpers of the bitsliced CTR kernels (src/qalqan/qalqan_bs.c,
 * src/aes/aes128_bs.c): byte <-> bit-plane transposition and un-slicing. */
#ifndef CA_BS_AVX2_H
#define CA_BS_AVX2_H
#include <immintrin.h>

#ifndef AI
#define AI static inline __attribute__((always_inline))
#endif
#ifndef XOR
#define XOR(a, b) _mm256_xor_si256((a), (b))
#endif

#define SWAPMOVE(a, b, m, n) do { \
    __m256i t_ = _mm256_and_si256(XOR(_mm256_srli_epi64((a), (n)), (b)), (m)); \
    (b) = XOR((b), t_); \
    (a) = XOR((a), _mm256_slli_epi64(t_, (n))); \
} while (0)

/* 8x8 bit transpose at every byte: out R[b] byte n bit i = in R[i] byte n bit b
 * (an involution) */
AI void bit_transpose(__m256i R[8])
{
    const __m256i m1 = _mm256_set1_epi8(0x55), m2 = _mm256_set1_epi8(0x33), m4 = _mm256_set1_epi8(0x0f);
    SWAPMOVE(R[0], R[1], m1, 1); SWAPMOVE(R[2], R[3], m1, 1);
    SWAPMOVE(R[4], R[5], m1, 1); SWAPMOVE(R[6], R[7], m1, 1);
    SWAPMOVE(R[0], R[2], m2, 2); SWAPMOVE(R[1], R[3], m2, 2);
    SWAPMOVE(R[4], R[6], m2, 2); SWAPMOVE(R[5], R[7], m2, 2);
    SWAPMOVE(R[0], R[4], m4, 4); SWAPMOVE(R[1], R[5], m4, 4);
    SWAPMOVE(R[2], R[6], m4, 4); SWAPMOVE(R[3], R[7], m4, 4);
}

/* 4x4 byte transpose inside each 128-bit lane (an involution) */
AI __m256i bt4(__m256i x)
{
    const __m256i idx = _mm256_setr_epi8(0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
                                         0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15);
    return _mm256_shuffle_epi8(x, idx);
}
/* word-sliced (dword m = block m) -> qword p = byte p of blocks 0..7 */
AI __m256i to_bytecols(__m256i x)
{
    return _mm256_permutevar8x32_epi32(bt4(x), _mm256_setr_epi32(0, 4, 1, 5, 2, 6, 3, 7));
}
AI __m256i from_bytecols(__m256i x)
{
    return bt4(_mm256_permutevar8x32_epi32(x, _mm256_setr_epi32(0, 2, 4, 6, 1, 3, 5, 7)));
}

/* word-sliced W (lane l = word w of block l) -> 4 ymm of 2 consecutive blocks each */
AI void unslice(const __m256i W[4], __m256i o[4])
{
    __m256i t0 = _mm256_unpacklo_epi32(W[0], W[1]), t1 = _mm256_unpackhi_epi32(W[0], W[1]);
    __m256i t2 = _mm256_unpacklo_epi32(W[2], W[3]), t3 = _mm256_unpackhi_epi32(W[2], W[3]);
    __m256i b0 = _mm256_unpacklo_epi64(t0, t2), b1 = _mm256_unpackhi_epi64(t0, t2);
    __m256i b2 = _mm256_unpacklo_epi64(t1, t3), b3 = _mm256_unpackhi_epi64(t1, t3);
    o[0] = _mm256_permute2x128_si256(b0, b1, 0x20);
    o[1] = _mm256_permute2x128_si256(b2, b3, 0x20);
    o[2] = _mm256_permute2x128_si256(b0, b1, 0x31);
    o[3] = _mm256_permute2x128_si256(b2, b3, 0x31);
}

/* 4x4 qword transpose of a[0..3] (an involution) */
AI void qt4(__m256i a[4])
{
    __m256i t0 = _mm256_unpacklo_epi64(a[0], a[1]), t1 = _mm256_unpackhi_epi64(a[0], a[1]);
    __m256i t2 = _mm256_unpacklo_epi64(a[2], a[3]), t3 = _mm256_unpackhi_epi64(a[2], a[3]);
    a[0] = _mm256_permute2x128_si256(t0, t2, 0x20);
    a[1] = _mm256_permute2x128_si256(t1, t3, 0x20);
    a[2] = _mm256_permute2x128_si256(t0, t2, 0x31);
    a[3] = _mm256_permute2x128_si256(t1, t3, 0x31);
}

#endif
