/* Ascon-AEAD128, four independent messages at a time in AVX2.
 *
 * One Ascon message is a duplex: every 16-byte block waits for the previous
 * permutation, so no SIMD layout speeds up a single stream. Four streams fit one
 * __m256i per state word, one 64-bit lane per stream, and the permutation then
 * maps one-to-one onto AVX2: the S-box's `~a & b` is exactly vpandn, and the five
 * x ^ (x >>> a) ^ (x >>> b) of the linear layer are four shifts and four XORs
 * each (AVX2 has no 64-bit rotate; vprorq is AVX-512).
 *
 * Per round and four streams: 1 constant + 3 + 5 vpandn + 5 + 3 XOR (S-box),
 * 5 x 8 (linear layer), 1 NOT = 58 vector ops, 20 of them shifts that run on two
 * of the three vector ports. ~19.3 core cycles per round, ~155 per p^8 per 64
 * bytes, ~2.4 core cycles/byte before the per-block lane gather/scatter -- against
 * ~4 for the best scalar 64-bit code, which is latency- not throughput-bound.
 *
 * All four messages must have the same length and AD length (ascon_multi_fn's
 * contract); leftover jobs (n not a multiple of 4) are run through the scalar
 * single-stream fallback supplied by the registry. */
#include <immintrin.h>
#include <string.h>
#include "ascon_aead.h"

#define IV_AEAD128 0x00001000808c0001ULL

typedef struct { __m256i x0, x1, x2, x3, x4; } st4;

#define ROR2X(x, a, b)                                                           \
    _mm256_xor_si256(                                                            \
        _mm256_xor_si256(x, _mm256_xor_si256(_mm256_srli_epi64(x, a),            \
                                             _mm256_slli_epi64(x, 64 - (a)))),   \
        _mm256_xor_si256(_mm256_srli_epi64(x, b), _mm256_slli_epi64(x, 64 - (b))))

static inline __attribute__((always_inline, target("avx2"))) void round4(st4 *s, uint64_t c)
{
    __m256i x0 = s->x0, x1 = s->x1, x2 = s->x2, x3 = s->x3, x4 = s->x4;
    x2 = _mm256_xor_si256(x2, _mm256_set1_epi64x((long long)c));
    x0 = _mm256_xor_si256(x0, x4);
    x4 = _mm256_xor_si256(x4, x3);
    x2 = _mm256_xor_si256(x2, x1);
    __m256i t0 = _mm256_xor_si256(x0, _mm256_andnot_si256(x1, x2));
    __m256i t2 = _mm256_xor_si256(x2, _mm256_andnot_si256(x3, x4));
    __m256i t4 = _mm256_xor_si256(x4, _mm256_andnot_si256(x0, x1));
    __m256i t1 = _mm256_xor_si256(x1, _mm256_andnot_si256(x2, x3));
    __m256i t3 = _mm256_xor_si256(x3, _mm256_andnot_si256(x4, x0));
    t1 = _mm256_xor_si256(t1, t0);
    t3 = _mm256_xor_si256(t3, t2);
    t0 = _mm256_xor_si256(t0, t4);
    s->x0 = ROR2X(t0, 19, 28);
    s->x1 = ROR2X(t1, 61, 39);
    s->x2 = _mm256_xor_si256(ROR2X(t2, 1, 6), _mm256_set1_epi64x(-1));
    s->x3 = ROR2X(t3, 10, 17);
    s->x4 = ROR2X(t4, 7, 41);
}

/* Round constants for p^12 are 0xf0, 0xe1, ..., 0x4b; p^8 uses the last eight. */
static const uint8_t RC[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
                               0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

static inline __attribute__((always_inline, target("avx2"))) void p12(st4 *s)
{
    for (int i = 0; i < 12; i++) round4(s, RC[i]);
}
static inline __attribute__((always_inline, target("avx2"))) void p8(st4 *s)
{
    for (int i = 4; i < 12; i++) round4(s, RC[i]);
}

/* Gather the 16-byte blocks at offset `off` of four messages into the two rate
 * words: lo = bytes 0..7 of each, hi = bytes 8..15. */
static inline __attribute__((always_inline, target("avx2")))
void gather16(const uint8_t *const p[4], size_t off, __m256i *lo, __m256i *hi)
{
    __m128i a = _mm_loadu_si128((const __m128i *)(p[0] + off));
    __m128i b = _mm_loadu_si128((const __m128i *)(p[1] + off));
    __m128i c = _mm_loadu_si128((const __m128i *)(p[2] + off));
    __m128i d = _mm_loadu_si128((const __m128i *)(p[3] + off));
    *lo = _mm256_set_m128i(_mm_unpacklo_epi64(c, d), _mm_unpacklo_epi64(a, b));
    *hi = _mm256_set_m128i(_mm_unpackhi_epi64(c, d), _mm_unpackhi_epi64(a, b));
}

static inline __attribute__((always_inline, target("avx2")))
void scatter16(uint8_t *const p[4], size_t off, __m256i lo, __m256i hi)
{
    __m128i l0 = _mm256_castsi256_si128(lo), l1 = _mm256_extracti128_si256(lo, 1);
    __m128i h0 = _mm256_castsi256_si128(hi), h1 = _mm256_extracti128_si256(hi, 1);
    _mm_storeu_si128((__m128i *)(p[0] + off), _mm_unpacklo_epi64(l0, h0));
    _mm_storeu_si128((__m128i *)(p[1] + off), _mm_unpackhi_epi64(l0, h0));
    _mm_storeu_si128((__m128i *)(p[2] + off), _mm_unpacklo_epi64(l1, h1));
    _mm_storeu_si128((__m128i *)(p[3] + off), _mm_unpackhi_epi64(l1, h1));
}

/* Load a final partial block (0..15 bytes) of each message, padded with 0x01
 * after the last byte, through a stack copy. */
static inline __attribute__((always_inline, target("avx2")))
void gather_pad(const uint8_t *const p[4], size_t off, size_t n, __m256i *lo, __m256i *hi)
{
    uint8_t buf[4][16];
    const uint8_t *q[4];
    for (int l = 0; l < 4; l++) {
        memset(buf[l], 0, 16);
        if (n) memcpy(buf[l], p[l] + off, n);
        buf[l][n] = 0x01;
        q[l] = buf[l];
    }
    gather16(q, 0, lo, hi);
}

/* K independent four-lane states advanced in lock-step (K = 1 or 2): with K = 2
 * the two dependency chains interleave. Measured on the i9-14900HX: one 4-lane
 * state runs at 3.5 core cycles/byte, two at 2.7 -- a single state is latency-
 * bound, not port-bound. A third (K = 3, 12 lanes) was tried and bought nothing
 * (2.73), the 15 live state vectors then spilling. */
#define FOR_K for (int k = 0; k < K; k++)
static inline __attribute__((always_inline, target("avx2")))
void encK(const ascon_job *j, size_t mlen, size_t adlen, const int K)
{
    const uint8_t *key[2][4], *non[2][4], *m[2][4], *ad[2][4];
    uint8_t *c[2][4];
    st4 s[2];
    __m256i k0[2], k1[2];
    FOR_K for (int l = 0; l < 4; l++) {
        const ascon_job *q = &j[4 * k + l];
        key[k][l] = q->key; non[k][l] = q->nonce; m[k][l] = q->m; ad[k][l] = q->ad; c[k][l] = q->c;
    }
    FOR_K {
        gather16(key[k], 0, &k0[k], &k1[k]);
        s[k].x0 = _mm256_set1_epi64x((long long)IV_AEAD128);
        s[k].x1 = k0[k];
        s[k].x2 = k1[k];
        gather16(non[k], 0, &s[k].x3, &s[k].x4);
    }
    for (int i = 0; i < 12; i++) FOR_K round4(&s[k], RC[i]);
    FOR_K {
        s[k].x3 = _mm256_xor_si256(s[k].x3, k0[k]);
        s[k].x4 = _mm256_xor_si256(s[k].x4, k1[k]);
    }
    if (adlen) {
        size_t off = 0;
        for (; off + 16 <= adlen; off += 16) {
            FOR_K {
                __m256i lo, hi;
                gather16(ad[k], off, &lo, &hi);
                s[k].x0 = _mm256_xor_si256(s[k].x0, lo);
                s[k].x1 = _mm256_xor_si256(s[k].x1, hi);
            }
            for (int i = 4; i < 12; i++) FOR_K round4(&s[k], RC[i]);
        }
        FOR_K {
            __m256i lo, hi;
            gather_pad(ad[k], off, adlen - off, &lo, &hi);
            s[k].x0 = _mm256_xor_si256(s[k].x0, lo);
            s[k].x1 = _mm256_xor_si256(s[k].x1, hi);
        }
        for (int i = 4; i < 12; i++) FOR_K round4(&s[k], RC[i]);
    }
    FOR_K s[k].x4 = _mm256_xor_si256(s[k].x4, _mm256_set1_epi64x((long long)0x8000000000000000ULL));

    size_t off = 0;
    for (; off + 16 <= mlen; off += 16) {
        FOR_K {
            __m256i lo, hi;
            gather16(m[k], off, &lo, &hi);
            s[k].x0 = _mm256_xor_si256(s[k].x0, lo);
            s[k].x1 = _mm256_xor_si256(s[k].x1, hi);
            scatter16(c[k], off, s[k].x0, s[k].x1);
        }
        for (int i = 4; i < 12; i++) FOR_K round4(&s[k], RC[i]);
    }
    {   /* final (possibly empty) block: absorb padded, emit only n bytes */
        size_t n = mlen - off;
        FOR_K {
            __m256i lo, hi;
            gather_pad(m[k], off, n, &lo, &hi);
            s[k].x0 = _mm256_xor_si256(s[k].x0, lo);
            s[k].x1 = _mm256_xor_si256(s[k].x1, hi);
            if (n) {
                uint8_t buf[4][16];
                uint8_t *q[4] = {buf[0], buf[1], buf[2], buf[3]};
                scatter16(q, 0, s[k].x0, s[k].x1);
                for (int l = 0; l < 4; l++) memcpy(c[k][l] + off, buf[l], n);
            }
        }
    }
    FOR_K {
        s[k].x2 = _mm256_xor_si256(s[k].x2, k0[k]);
        s[k].x3 = _mm256_xor_si256(s[k].x3, k1[k]);
    }
    for (int i = 0; i < 12; i++) FOR_K round4(&s[k], RC[i]);
    FOR_K {
        s[k].x3 = _mm256_xor_si256(s[k].x3, k0[k]);
        s[k].x4 = _mm256_xor_si256(s[k].x4, k1[k]);
        uint8_t *t[4] = {c[k][0] + mlen, c[k][1] + mlen, c[k][2] + mlen, c[k][3] + mlen};
        scatter16(t, 0, s[k].x3, s[k].x4);
    }
}

__attribute__((target("avx2"))) static void enc4(const ascon_job *j, size_t mlen, size_t adlen)
{
    encK(j, mlen, adlen, 1);
}
__attribute__((target("avx2"))) static void enc8(const ascon_job *j, size_t mlen, size_t adlen)
{
    encK(j, mlen, adlen, 2);
}

extern int ascon_c_opt64_encrypt(unsigned char *, unsigned long long *, const unsigned char *,
                                 unsigned long long, const unsigned char *, unsigned long long,
                                 const unsigned char *, const unsigned char *, const unsigned char *);

void ascon_multi_avx2_x8(const ascon_job *jobs, size_t n, size_t mlen, size_t adlen)
{
    size_t i = 0;
    for (; i + 8 <= n; i += 8)
        enc8(jobs + i, mlen, adlen);
    for (; i + 4 <= n; i += 4)
        enc4(jobs + i, mlen, adlen);
    if (i < n)
        ascon_multi_by_single(ascon_c_opt64_encrypt, jobs + i, n - i, mlen, adlen);
}

void ascon_multi_avx2_x4(const ascon_job *jobs, size_t n, size_t mlen, size_t adlen)
{
    size_t i = 0;
    for (; i + 4 <= n; i += 4)
        enc4(jobs + i, mlen, adlen);
    if (i < n)
        ascon_multi_by_single(ascon_c_opt64_encrypt, jobs + i, n - i, mlen, adlen);
}
