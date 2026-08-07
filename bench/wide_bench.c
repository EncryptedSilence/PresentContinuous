/* Speed tests for the 128-bit block ciphers: real AES, and AES-lin444.
 *
 * Why this is a separate program. The library in src/ is 64-bit-block throughout --
 * the state is a uint64_t, the tables are indexed for it, the bitsliced kernels have
 * 64 planes. Widening all of that to compare against AES would be a rewrite. These
 * two ciphers are therefore implemented here, standalone, with the *same measurement
 * protocol* as bench/bench_main.c: same trial count, same warm-up, same working-set
 * size in bytes, same TSC-based cycles/byte, median of trials. That is what makes the
 * numbers comparable across the two programs even though the code is not shared.
 *
 * Both ciphers are round-count parameterised, because the comparison this feeds is at
 * equal proven differential margin rather than at each design's native round count.
 *
 * Hardware GF acceleration is deliberately absent: no AES-NI, no GFNI. Two software
 * kernel families are measured for each cipher, because which one wins is not fixed:
 *
 *   - interleaved fused tables (the "T-table" construction), mirroring the non-GFNI
 *     half of QalqanSpeed/docs/2026-05-25-qalqan-encryption-optimization-report.md,
 *     whose AES-256 T-table figure this program reproduces as a cross-check;
 *   - an AVX2 bitslice over 256 blocks, the same shape as src/present_avx2.c.
 *
 * The bitslice kernel is here for fairness, not for completeness. Every 64-bit
 * variant in this repository is benchmarked with both, and for the ones built on the
 * AES S-box the bitslice wins by a wide margin -- so comparing those against a
 * table-only AES would have charged AES for a kernel it does not have to use. The
 * S-box circuit is the same published Boyar-Peralta one src/gen/sbox_circuits.h
 * generates for the 64-bit variants (circuit c2, 132 gates), so the substitution
 * layer is literally identical code on both sides of the comparison.
 *
 * Correctness gates run before any timing and abort on mismatch:
 *   - AES against the FIPS-197 C.1 known-answer vector, at its native 10 rounds.
 *   - AES-lin444 against a scalar reference written from its definition, at every
 *     round count timed.
 *   - Every interleaved and bitsliced kernel against the single-block one, on random
 *     inputs, at every round count timed.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#define HAVE_RDTSC 1
#endif

#define TRIALS 15
#define WARMUP 3
/* 4096 blocks x 16 bytes = 64 KiB, the same working set bench_main.c uses
 * (8192 blocks x 8 bytes). Matching bytes, not blocks, is what keeps the cache
 * behaviour comparable between the two programs. */
#define BLOCKS 4096

/* aes_key_t, lin_key_t, the key schedules, and the scalar/table-fused encrypt
 * kernels (aes_encrypt1, aes_encrypt4, lin_encrypt_ref, lin_encrypt1) -- the
 * portable cipher definitions the Cortex-M4 firmware also includes. Everything
 * that stays below is x86-only: the AVX2 bitslice kernels and this harness. */
#include "wide_ciphers.h"

/* --- timing ------------------------------------------------------------------- */

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t cycles(void)
{
#ifdef HAVE_RDTSC
    return __rdtsc();
#else
    return now_ns();
#endif
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static volatile uint64_t bench_sink;
static FILE *csv;

static uint64_t rng_state = 0x123456789ABCDEFull;
static uint64_t rng_next(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

/* --- AES-lin444: rotation constants for wide_bench.c's own AVX2 bitslice kernel -
 *
 * wide_ciphers.h fixes lin444's rotation constants at 0/8/15 for the portable
 * reference and table kernels (see that header's comment for why). LIN_C is only
 * this file's own knob for the AVX2 bitslice kernel further down (lin_encrypt_bs),
 * kept for the exploratory --c0 CLI flag; it is not part of the cipher definition
 * the firmware includes; passing a non-default --c0 makes that kernel disagree
 * with wide_ciphers.h's reference on purpose.
 */
static int LIN_C[3];

/* lin_encrypt4/8/16 below reuse wide_ciphers.h's Tl table and LIN_ROUND macro
 * (the SSE2 fused-table kernel, x86-only) -- they were not part of Task 4's move
 * list, so they stay here alongside the harness that benchmarks them. */
#define LIN_MULTI(name, N) \
static void name(const lin_key_t *k, const uint8_t *in, uint8_t *out) \
{ \
    __m128i v[N]; \
    for (int j = 0; j < N; j++) v[j] = _mm_loadu_si128((const __m128i *)(in + 16 * j)); \
    for (int r = 0; r < k->nr; r++) { \
        __m128i rkv = _mm_loadu_si128((const __m128i *)(k->rk + 4 * r)); \
        for (int j = 0; j < N; j++) LIN_ROUND(v[j], rkv); \
    } \
    __m128i last = _mm_loadu_si128((const __m128i *)(k->rk + 4 * k->nr)); \
    for (int j = 0; j < N; j++) \
        _mm_storeu_si128((__m128i *)(out + 16 * j), _mm_xor_si128(v[j], last)); \
}

LIN_MULTI(lin_encrypt4, 4)
LIN_MULTI(lin_encrypt8, 8)
LIN_MULTI(lin_encrypt16, 16)

/* --- AVX2 bitslice: 256 blocks at a time ----------------------------------------
 *
 * State bit j of 256 blocks lives in one __m256i, so a 128-bit block cipher is 128
 * registers' worth -- 4 KiB, which does not fit in the register file the way the
 * 64-bit variants' 2 KiB nearly does, so the plane arrays live on the stack and the
 * kernel is L1-bound rather than register-bound. Plane j is bit (j % 8) of state
 * byte (j / 8), matching the byte order of the buffers the table kernels use.
 *
 * Both ciphers share everything except the linear layer: the same transposes, the
 * same 16 S-box circuits per round, the same key-mask form. That is the point -- it
 * makes the measured difference between them the linear layer and nothing else.
 */
#if defined(__AVX2__)

#include <immintrin.h>
#include "gen/sbox_circuits.h"   /* present_circuit8_avx2_c2: the AES S-box, 132 gates */

#define BS_BLOCKS 256
#define XV(a, b) _mm256_xor_si256((a), (b))

/* Getting 256 blocks into and out of bitsliced form. Lifted from src/present_avx2.c,
 * which does the identical job for 64-bit blocks: four groups of 64 blocks go in the
 * four 64-bit lanes, so one bit transpose serves all four groups. A 128-bit block is
 * two 64-bit halves, so it is that same routine run twice. */
static void lane_transpose_4x4(const uint64_t *in, __m256i *a)
{
    for (int kk = 0; kk < 64; kk += 4) {
        __m256i r0 = _mm256_loadu_si256((const __m256i *)(in + 0 * 64 + kk));
        __m256i r1 = _mm256_loadu_si256((const __m256i *)(in + 1 * 64 + kk));
        __m256i r2 = _mm256_loadu_si256((const __m256i *)(in + 2 * 64 + kk));
        __m256i r3 = _mm256_loadu_si256((const __m256i *)(in + 3 * 64 + kk));
        __m256i t0 = _mm256_unpacklo_epi64(r0, r1);
        __m256i t1 = _mm256_unpackhi_epi64(r0, r1);
        __m256i t2 = _mm256_unpacklo_epi64(r2, r3);
        __m256i t3 = _mm256_unpackhi_epi64(r2, r3);
        a[kk + 0] = _mm256_permute2x128_si256(t0, t2, 0x20);
        a[kk + 1] = _mm256_permute2x128_si256(t1, t3, 0x20);
        a[kk + 2] = _mm256_permute2x128_si256(t0, t2, 0x31);
        a[kk + 3] = _mm256_permute2x128_si256(t1, t3, 0x31);
    }
}

static void lane_transpose_4x4_out(const __m256i *a, uint64_t *out)
{
    for (int kk = 0; kk < 64; kk += 4) {
        __m256i r0 = a[kk + 0], r1 = a[kk + 1], r2 = a[kk + 2], r3 = a[kk + 3];
        __m256i t0 = _mm256_unpacklo_epi64(r0, r1);
        __m256i t1 = _mm256_unpackhi_epi64(r0, r1);
        __m256i t2 = _mm256_unpacklo_epi64(r2, r3);
        __m256i t3 = _mm256_unpackhi_epi64(r2, r3);
        _mm256_storeu_si256((__m256i *)(out + 0 * 64 + kk), _mm256_permute2x128_si256(t0, t2, 0x20));
        _mm256_storeu_si256((__m256i *)(out + 1 * 64 + kk), _mm256_permute2x128_si256(t1, t3, 0x20));
        _mm256_storeu_si256((__m256i *)(out + 2 * 64 + kk), _mm256_permute2x128_si256(t0, t2, 0x31));
        _mm256_storeu_si256((__m256i *)(out + 3 * 64 + kk), _mm256_permute2x128_si256(t1, t3, 0x31));
    }
}

#define DSWAP(X, Y, SH, MM)                                                           \
    do {                                                                              \
        __m256i t_ = _mm256_and_si256(                                                \
            _mm256_xor_si256(_mm256_srli_epi64(X, (SH)), Y), MM);                     \
        X = _mm256_xor_si256(X, _mm256_slli_epi64(t_, (SH)));                         \
        Y = _mm256_xor_si256(Y, t_);                                                  \
    } while (0)

#define BT_OCTET(r, S0, M0, S1, M1, S2, M2)                                           \
    do {                                                                              \
        const __m256i m0_ = _mm256_set1_epi64x((long long)(uint64_t)(M0));            \
        const __m256i m1_ = _mm256_set1_epi64x((long long)(uint64_t)(M1));            \
        const __m256i m2_ = _mm256_set1_epi64x((long long)(uint64_t)(M2));            \
        DSWAP(r[0], r[4], S0, m0_); DSWAP(r[1], r[5], S0, m0_);                       \
        DSWAP(r[2], r[6], S0, m0_); DSWAP(r[3], r[7], S0, m0_);                       \
        DSWAP(r[0], r[2], S1, m1_); DSWAP(r[1], r[3], S1, m1_);                       \
        DSWAP(r[4], r[6], S1, m1_); DSWAP(r[5], r[7], S1, m1_);                       \
        DSWAP(r[0], r[1], S2, m2_); DSWAP(r[2], r[3], S2, m2_);                       \
        DSWAP(r[4], r[5], S2, m2_); DSWAP(r[6], r[7], S2, m2_);                       \
    } while (0)

/* A bit-matrix transpose is its own inverse, so this serves both directions. */
static void bit_transpose64x4(__m256i *a)
{
    for (int m = 0; m < 8; m++) {
        __m256i r[8];
        for (int i = 0; i < 8; i++) r[i] = a[m + 8 * i];
        BT_OCTET(r, 32, 0x00000000FFFFFFFFull,
                    16, 0x0000FFFF0000FFFFull,
                     8, 0x00FF00FF00FF00FFull);
        for (int i = 0; i < 8; i++) a[m + 8 * i] = r[i];
    }
    for (int n = 0; n < 8; n++) {
        __m256i r[8];
        for (int i = 0; i < 8; i++) r[i] = a[8 * n + i];
        BT_OCTET(r, 4, 0x0F0F0F0F0F0F0F0Full,
                    2, 0x3333333333333333ull,
                    1, 0x5555555555555555ull);
        for (int i = 0; i < 8; i++) a[8 * n + i] = r[i];
    }
}

/* Deinterleave the low and high 64-bit halves of four consecutive blocks, so each
 * half is a contiguous 256-entry array the transpose above can consume directly. */
static void bs_split(const uint8_t *in, uint64_t *lo, uint64_t *hi)
{
    for (int i = 0; i < BS_BLOCKS; i += 4) {
        __m256i r0 = _mm256_loadu_si256((const __m256i *)(in + 16 * i));
        __m256i r1 = _mm256_loadu_si256((const __m256i *)(in + 16 * i + 32));
        __m256i p0 = _mm256_permute4x64_epi64(r0, 0xD8);   /* lo,lo,hi,hi */
        __m256i p1 = _mm256_permute4x64_epi64(r1, 0xD8);
        _mm256_storeu_si256((__m256i *)(lo + i), _mm256_permute2x128_si256(p0, p1, 0x20));
        _mm256_storeu_si256((__m256i *)(hi + i), _mm256_permute2x128_si256(p0, p1, 0x31));
    }
}

static void bs_merge(const uint64_t *lo, const uint64_t *hi, uint8_t *out)
{
    for (int i = 0; i < BS_BLOCKS; i += 4) {
        __m256i l = _mm256_loadu_si256((const __m256i *)(lo + i));
        __m256i h = _mm256_loadu_si256((const __m256i *)(hi + i));
        __m256i q0 = _mm256_permute2x128_si256(l, h, 0x20);
        __m256i q1 = _mm256_permute2x128_si256(l, h, 0x31);
        _mm256_storeu_si256((__m256i *)(out + 16 * i),
                            _mm256_permute4x64_epi64(q0, 0xD8));
        _mm256_storeu_si256((__m256i *)(out + 16 * i + 32),
                            _mm256_permute4x64_epi64(q1, 0xD8));
    }
}

static void bs_load(const uint8_t *in, __m256i *st)
{
    uint64_t lo[BS_BLOCKS], hi[BS_BLOCKS];
    bs_split(in, lo, hi);
    lane_transpose_4x4(lo, st);      bit_transpose64x4(st);
    lane_transpose_4x4(hi, st + 64); bit_transpose64x4(st + 64);
}

static void bs_store(__m256i *st, uint8_t *out)
{
    uint64_t lo[BS_BLOCKS], hi[BS_BLOCKS];
    bit_transpose64x4(st);      lane_transpose_4x4_out(st, lo);
    bit_transpose64x4(st + 64); lane_transpose_4x4_out(st + 64, hi);
    bs_merge(lo, hi, out);
}

/* Round keys are pre-broadcast to one all-zero or all-ones plane per state bit, so
 * the key layer is 128 XORs with no per-plane scalar work and no key-dependent
 * branch. (MAX_ROUNDS + 1) * 128 planes is 86 KiB at the largest round count; at the
 * round counts this comparison actually reports it is 24 KiB and L1-resident. */
static __m256i bs_km[(MAX_ROUNDS + 1) * 128] __attribute__((aligned(32)));

static void bs_set_key_byte(__m256i *km, int byte, uint8_t v)
{
    const __m256i ones = _mm256_set1_epi64x(-1), zero = _mm256_setzero_si256();
    for (int j = 0; j < 8; j++) km[8 * byte + j] = ((v >> j) & 1) ? ones : zero;
}

/* AES round key word c is column c with row 0 in the most significant byte, and
 * state byte index is row + 4 * col -- the same indexing GETU32 gives the T-table
 * kernel, which is why the two agree bit for bit. */
static void bs_expand_aes_key(const aes_key_t *k, __m256i *km)
{
    for (int r = 0; r <= k->nr; r++)
        for (int c = 0; c < 4; c++) {
            uint32_t w = k->rk[4 * r + c];
            for (int row = 0; row < 4; row++)
                bs_set_key_byte(km + 128 * r, row + 4 * c,
                                (uint8_t)(w >> (8 * (3 - row))));
        }
}

/* lin444 round key word j is little-endian over state bytes 4j..4j+3. */
static void bs_expand_lin_key(const lin_key_t *k, __m256i *km)
{
    for (int r = 0; r <= k->nr; r++)
        for (int j = 0; j < 4; j++) {
            uint32_t w = k->rk[4 * r + j];
            for (int b = 0; b < 4; b++)
                bs_set_key_byte(km + 128 * r, 4 * j + b, (uint8_t)(w >> (8 * b)));
        }
}

static inline void bs_addkey(__m256i *st, const __m256i *km)
{
    for (int j = 0; j < 128; j++) st[j] = XV(st[j], km[j]);
}

static inline void bs_sub_bytes(__m256i *st)
{
    for (int i = 0; i < 16; i++) {
        __m256i *p = st + 8 * i;
        __m256i y0, y1, y2, y3, y4, y5, y6, y7;
        present_circuit8_avx2_c2(&y7, &y6, &y5, &y4, &y3, &y2, &y1, &y0,
                                 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        p[0] = y0; p[1] = y1; p[2] = y2; p[3] = y3;
        p[4] = y4; p[5] = y5; p[6] = y6; p[7] = y7;
    }
}

/* ShiftRows costs nothing: it only decides which plane group MixColumns reads, so it
 * is folded into the index below rather than moving any data. MixColumns uses
 * b_r = a_r ^ s ^ xtime(a_r ^ a_{r+1}) with s = a_0^a_1^a_2^a_3, which is the cheapest
 * standard form -- 132 XORs per column against 16 * 132 = 2112 gates for the S-box
 * layer, so the substitution is what this cipher costs and the linear layer is 20%.
 * The last round has no MixColumns, exactly as AES specifies. */
static void bs_aes_lin(const __m256i *t, __m256i *st, int last)
{
    for (int c = 0; c < 4; c++) {
        const __m256i *a[4];
        for (int r = 0; r < 4; r++) a[r] = t + 8 * (r + 4 * ((c + r) & 3));
        if (last) {
            for (int r = 0; r < 4; r++)
                for (int k = 0; k < 8; k++) st[8 * (r + 4 * c) + k] = a[r][k];
            continue;
        }
        __m256i s[8];
        for (int k = 0; k < 8; k++)
            s[k] = XV(XV(a[0][k], a[1][k]), XV(a[2][k], a[3][k]));
        for (int r = 0; r < 4; r++) {
            const __m256i *p = a[r], *q = a[(r + 1) & 3];
            __m256i u[8], xt[8];
            for (int k = 0; k < 8; k++) u[k] = XV(p[k], q[k]);
            /* xtime: shift up one, and fold the carry into bits 0,1,3,4 (0x1b). */
            xt[0] = u[7];          xt[1] = XV(u[0], u[7]);
            xt[2] = u[1];          xt[3] = XV(u[2], u[7]);
            xt[4] = XV(u[3], u[7]); xt[5] = u[4];
            xt[6] = u[5];          xt[7] = u[6];
            for (int k = 0; k < 8; k++)
                st[8 * (r + 4 * c) + k] = XV(XV(p[k], s[k]), xt[k]);
        }
    }
}

/* lin444 bitsliced. rotl32 by c sends bit p to bit (p + c) mod 32, so bit p of the
 * rotated word is bit (p - c) mod 32 of the original: a pure change of plane index,
 * no data movement. The rotation amounts come from the command line, so the index is
 * a table lookup rather than an immediate -- built once per call, outside the round
 * loop, since it is the same for every round. */
static void bs_lin444(const __m256i *t, __m256i *st, int rot[3][32])
{
#define WP(j, p) t[32 * (j) + (p)]
    for (int p = 0; p < 32; p++) {
        const int p0 = rot[0][p], p1 = rot[1][p], p2 = rot[2][p];
        st[0 * 32 + p] = XV(XV(WP(0, p), WP(1, p0)), XV(WP(2, p1), WP(3, p2)));
    }
    for (int p = 0; p < 32; p++) {
        const int p0 = rot[0][p], p1 = rot[1][p], p2 = rot[2][p];
        st[1 * 32 + p] = XV(XV(WP(1, p), WP(2, p0)), XV(WP(3, p1), st[0 * 32 + p2]));
    }
    for (int p = 0; p < 32; p++) {
        const int p0 = rot[0][p], p1 = rot[1][p], p2 = rot[2][p];
        st[2 * 32 + p] = XV(XV(WP(2, p), WP(3, p0)), XV(st[0 * 32 + p1], st[1 * 32 + p2]));
    }
    for (int p = 0; p < 32; p++) {
        const int p0 = rot[0][p], p1 = rot[1][p], p2 = rot[2][p];
        st[3 * 32 + p] = XV(XV(WP(3, p), st[0 * 32 + p0]), XV(st[1 * 32 + p1], st[2 * 32 + p2]));
    }
#undef WP
}

/* The plane arrays ping-pong between the S-box (in place) and the linear layer
 * (out of place), so no round needs a copy. */
static void aes_encrypt_bs(const aes_key_t *k, const uint8_t *in, uint8_t *out)
{
    __m256i a[128], b[128];
    __m256i *cur = a, *nxt = b;
    bs_load(in, cur);
    bs_addkey(cur, bs_km);
    for (int r = 1; r <= k->nr; r++) {
        bs_sub_bytes(cur);
        bs_aes_lin(cur, nxt, r == k->nr);
        bs_addkey(nxt, bs_km + 128 * r);
        __m256i *sw = cur; cur = nxt; nxt = sw;
    }
    bs_store(cur, out);
}

static void lin_encrypt_bs(const lin_key_t *k, const uint8_t *in, uint8_t *out)
{
    __m256i a[128], b[128];
    __m256i *cur = a, *nxt = b;
    int rot[3][32];
    for (int i = 0; i < 3; i++)
        for (int p = 0; p < 32; p++) rot[i][p] = ((p - LIN_C[i]) % 32 + 32) % 32;
    bs_load(in, cur);
    for (int r = 0; r < k->nr; r++) {
        bs_addkey(cur, bs_km + 128 * r);
        bs_sub_bytes(cur);
        bs_lin444(cur, nxt, rot);
        __m256i *sw = cur; cur = nxt; nxt = sw;
    }
    bs_addkey(cur, bs_km + 128 * k->nr);
    bs_store(cur, out);
}

#endif /* __AVX2__ */

/* --- correctness gates ---------------------------------------------------------- */

static void die(const char *what)
{
    fprintf(stderr, "FAIL: %s\n", what);
    exit(1);
}

static void kat_aes(void)
{
    /* FIPS-197 C.1, AES-128. */
    static const uint8_t pt[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                                   0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    static const uint8_t key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    static const uint8_t want[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                                     0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    aes_key_t k;
    uint8_t got[16];
    aes_key_schedule(&k, key);
    aes_encrypt1(&k, 10, pt, got);
    if (memcmp(got, want, 16) != 0) die("AES does not match the FIPS-197 C.1 vector");

    /* The 4-way kernel must agree with the 1-way one at every round count timed. */
    for (int nr = 4; nr <= 14; nr++) {
        uint8_t buf[64], a[64], b[64];
        for (int i = 0; i < 64; i++) buf[i] = (uint8_t)rng_next();
        for (int j = 0; j < 4; j++) aes_encrypt1(&k, nr, buf + 16 * j, a + 16 * j);
        aes_encrypt4(&k, nr, buf, b);
        if (memcmp(a, b, 64) != 0) die("AES x4 disagrees with AES x1");
    }
    printf("ok   AES: FIPS-197 C.1 vector, and x4 == x1 for 4..14 rounds\n");
}

/* The bitslice kernels transpose, substitute and mix along completely different axes
 * from the table kernels, so agreeing with them on 256 random blocks at every timed
 * round count is a real check of the plane indexing, not a formality. */
#if defined(__AVX2__)
static void kat_bs(void)
{
    static uint8_t buf[BS_BLOCKS * 16], a[BS_BLOCKS * 16], b[BS_BLOCKS * 16];
    uint8_t key[16];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)rng_next();
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)rng_next();

    for (int nr = 4; nr <= 14; nr++) {
        aes_key_t k;
        aes_key_schedule(&k, key);
        k.nr = nr;  /* bs_expand_aes_key / aes_encrypt_bs still read k.nr directly */
        for (int j = 0; j < BS_BLOCKS; j++) aes_encrypt1(&k, nr, buf + 16 * j, a + 16 * j);
        bs_expand_aes_key(&k, bs_km);
        aes_encrypt_bs(&k, buf, b);
        if (memcmp(a, b, sizeof buf) != 0) die("AES bitslice disagrees with AES x1");
    }
    for (int nr = 2; nr <= MAX_ROUNDS; nr++) {
        lin_key_t k;
        k.nr = nr;
        for (int i = 0; i < 4 * (nr + 1); i++) k.rk[i] = (uint32_t)rng_next();
        for (int j = 0; j < BS_BLOCKS; j++) lin_encrypt_ref(&k, nr, buf + 16 * j, a + 16 * j);
        bs_expand_lin_key(&k, bs_km);
        lin_encrypt_bs(&k, buf, b);
        if (memcmp(a, b, sizeof buf) != 0)
            die("AES-lin444 bitslice disagrees with the scalar reference");
    }
    printf("ok   AVX2 bitslice: AES == x1 for 4..14 rounds, AES-lin444 == reference "
           "for 2..%d rounds\n", MAX_ROUNDS);
}
#endif

static void kat_lin(void)
{
    lin_key_t k;
    uint8_t buf[128], a[128], b[128];
    for (int nr = 2; nr <= MAX_ROUNDS; nr++) {
        k.nr = nr;
        for (int i = 0; i < 4 * (nr + 1); i++) k.rk[i] = (uint32_t)rng_next();
        for (int i = 0; i < 128; i++) buf[i] = (uint8_t)rng_next();
        for (int j = 0; j < 8; j++) lin_encrypt_ref(&k, nr, buf + 16 * j, a + 16 * j);
        for (int j = 0; j < 8; j++) lin_encrypt1(&k, nr, buf + 16 * j, b + 16 * j);
        if (memcmp(a, b, 128) != 0) die("AES-lin444 table kernel disagrees with the reference");
        lin_encrypt4(&k, buf, b); lin_encrypt4(&k, buf + 64, b + 64);
        if (memcmp(a, b, 128) != 0) die("AES-lin444 x4 disagrees with the reference");
        lin_encrypt8(&k, buf, b);
        if (memcmp(a, b, 128) != 0) die("AES-lin444 x8 disagrees with the reference");
        uint8_t big[256], ba[256], bb[256];
        for (int i = 0; i < 256; i++) big[i] = (uint8_t)rng_next();
        for (int j = 0; j < 16; j++) lin_encrypt_ref(&k, nr, big + 16 * j, ba + 16 * j);
        lin_encrypt16(&k, big, bb);
        if (memcmp(ba, bb, 256) != 0) die("AES-lin444 x16 disagrees with the reference");
    }
    printf("ok   AES-lin444: x1/x4/x8 == scalar reference for 2..%d rounds\n", MAX_ROUNDS);
}

/* --- benchmark ------------------------------------------------------------------ */

static void report(const char *cipher, int rounds, const char *impl,
                   double *cyc, double *ns)
{
    qsort(cyc, TRIALS, sizeof(double), cmp_double);
    qsort(ns, TRIALS, sizeof(double), cmp_double);
    double cpb = cyc[TRIALS / 2] / 16.0;
    double cmin = cyc[0] / 16.0;
    double mbps = 16.0 / ns[TRIALS / 2] * 1000.0;
    printf("  %-18s r=%-3d %-10s %8.3f %8.3f %10.1f\n", cipher, rounds, impl, cpb, cmin, mbps);
    if (csv)
        fprintf(csv, "%s,%d,%s,%.4f,%.4f,%.2f\n", cipher, rounds, impl, cpb, cmin, mbps);
}

#define BENCH(cipher, rounds, impl, lanes, call) do { \
    double cyc[TRIALS], ns[TRIALS]; \
    const int groups = BLOCKS / (lanes); \
    uint64_t sink = 0; \
    for (int t = -WARMUP; t < TRIALS; t++) { \
        uint64_t c0 = cycles(), n0 = now_ns(); \
        for (int g = 0; g < groups; g++) { call; } \
        uint64_t c1 = cycles(), n1 = now_ns(); \
        sink ^= out[0]; \
        if (t >= 0) { \
            cyc[t] = (double)(c1 - c0) / (double)(groups * (lanes)); \
            ns[t] = (double)(n1 - n0) / (double)(groups * (lanes)); \
        } \
    } \
    bench_sink = sink; \
    report(cipher, rounds, impl, cyc, ns); \
} while (0)

int main(int argc, char **argv)
{
    const char *csv_path = NULL;
    int only_rounds = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv_path = argv[++i];
        else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) only_rounds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--c0") && i + 3 < argc) {
            LIN_C[0] = atoi(argv[i + 1]); LIN_C[1] = atoi(argv[i + 2]); LIN_C[2] = atoi(argv[i + 3]);
            i += 3;
        } else {
            fprintf(stderr, "usage: %s [--csv PATH] [--rounds N] [--c0 a b c]\n", argv[0]);
            return 2;
        }
    }
    if (!LIN_C[0] && !LIN_C[1] && !LIN_C[2]) { LIN_C[0] = 0; LIN_C[1] = 8; LIN_C[2] = 15; }
    if (LIN_C[0] != 0 || LIN_C[1] != 8 || LIN_C[2] != 15)
        fprintf(stderr,
            "note: --c0 %d %d %d only affects the AVX2 bitslice kernel now -- "
            "wide_ciphers.h fixes the table/reference kernels at 0 8 15, so the "
            "AVX2 kernel's KAT will fail against them (or, without AVX2, --c0 has "
            "no effect at all).\n", LIN_C[0], LIN_C[1], LIN_C[2]);

    aes_init_tables();
    lin_init_tables();
    kat_aes();
    kat_lin();
#if defined(__AVX2__)
    kat_bs();
#endif

    if (csv_path) {
        csv = fopen(csv_path, "w");
        if (csv) fprintf(csv, "cipher,rounds,impl,cycles_per_byte,cycles_per_byte_min,mb_per_sec\n");
    }

    static uint8_t buf[BLOCKS * 16], outbuf[BLOCKS * 16];
    for (size_t i = 0; i < sizeof buf; i++) buf[i] = (uint8_t)rng_next();
    uint8_t *out = outbuf;
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)rng_next();

    printf("wide-block speed tests: %d blocks x 16 B = %d KiB, %d trials, median\n",
           BLOCKS, BLOCKS * 16 / 1024, TRIALS);
    printf("  %-18s %-5s %-10s %8s %8s %10s\n", "cipher", "rnds", "impl", "cyc/B", "min", "MB/s");

    /* --rounds replaces the sweep rather than filtering it, so any round count the
     * comparison needs can be asked for -- not only the ones on this list. */
    int sweep[] = {5, 10, 14, 16, 0};
    int one[] = {only_rounds, 0};
    const int *rounds_list = only_rounds ? one : sweep;
    for (int ri = 0; rounds_list[ri]; ri++) {
        int nr = rounds_list[ri];
        if (nr < 2 || nr > MAX_ROUNDS) {
            fprintf(stderr, "rounds must be 2..%d\n", MAX_ROUNDS);
            return 2;
        }
        aes_key_t ak;
        aes_key_schedule(&ak, key);
        ak.nr = nr;  /* bs_expand_aes_key / aes_encrypt_bs still read ak.nr directly */
        BENCH("aes", nr, "table", 1,
              aes_encrypt1(&ak, nr, buf + (size_t)g * 16, out + (size_t)g * 16));
        BENCH("aes", nr, "table-x4", 4,
              aes_encrypt4(&ak, nr, buf + (size_t)g * 64, out + (size_t)g * 64));
        BENCH("aes", nr, "table-x8", 8,
              { aes_encrypt4(&ak, nr, buf + (size_t)g * 128, out + (size_t)g * 128); \
                aes_encrypt4(&ak, nr, buf + (size_t)g * 128 + 64, out + (size_t)g * 128 + 64); });
#if defined(__AVX2__)
        bs_expand_aes_key(&ak, bs_km);
        BENCH("aes", nr, "avx2-bs", BS_BLOCKS,
              aes_encrypt_bs(&ak, buf + (size_t)g * BS_BLOCKS * 16,
                                  out + (size_t)g * BS_BLOCKS * 16));
#endif

        lin_key_t lk;
        lk.nr = nr;
        for (int i = 0; i < 4 * (nr + 1); i++) lk.rk[i] = (uint32_t)rng_next();
        BENCH("aes-lin444", nr, "table", 1,
              lin_encrypt1(&lk, nr, buf + (size_t)g * 16, out + (size_t)g * 16));
        BENCH("aes-lin444", nr, "table-x4", 4,
              lin_encrypt4(&lk, buf + (size_t)g * 64, out + (size_t)g * 64));
        BENCH("aes-lin444", nr, "table-x8", 8,
              lin_encrypt8(&lk, buf + (size_t)g * 128, out + (size_t)g * 128));
        BENCH("aes-lin444", nr, "table-x16", 16,
              lin_encrypt16(&lk, buf + (size_t)g * 256, out + (size_t)g * 256));
#if defined(__AVX2__)
        bs_expand_lin_key(&lk, bs_km);
        BENCH("aes-lin444", nr, "avx2-bs", BS_BLOCKS,
              lin_encrypt_bs(&lk, buf + (size_t)g * BS_BLOCKS * 16,
                                  out + (size_t)g * BS_BLOCKS * 16));
#endif
    }

    if (csv) fclose(csv);
    return 0;
}
