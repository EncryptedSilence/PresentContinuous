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
#define MAX_ROUNDS 20

static const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

static uint8_t xtime8(uint8_t a) { return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b)); }

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

/* --- AES: classic T-table, round count parameterised --------------------------- */

static uint32_t Te0[256], Te1[256], Te2[256], Te3[256];

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void aes_init_tables(void)
{
    for (int x = 0; x < 256; x++) {
        uint8_t s = SBOX[x], s2 = xtime8(s), s3 = (uint8_t)(s2 ^ s);
        Te0[x] = ((uint32_t)s2 << 24) | ((uint32_t)s << 16) | ((uint32_t)s << 8) | s3;
        Te1[x] = rotr32(Te0[x], 8);
        Te2[x] = rotr32(Te0[x], 16);
        Te3[x] = rotr32(Te0[x], 24);
    }
}

static uint32_t GETU32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void PUTU32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

typedef struct { uint32_t rk[4 * (MAX_ROUNDS + 1)]; int nr; } aes_key_t;

/* AES-128's own schedule, extended past 10 rounds by continuing the recurrence.
 * Reduced-round runs simply stop early. The schedule is outside every timed loop,
 * so its cost does not enter any figure reported here. */
static void aes_expand(const uint8_t key[16], int nr, aes_key_t *out)
{
    uint32_t rcon = 0x01000000u;
    uint32_t *rk = out->rk;
    out->nr = nr;
    for (int i = 0; i < 4; i++) rk[i] = GETU32(key + 4 * i);
    for (int i = 4; i < 4 * (nr + 1); i++) {
        uint32_t t = rk[i - 1];
        if (i % 4 == 0) {
            t = (t << 8) | (t >> 24);
            t = ((uint32_t)SBOX[(t >> 24) & 0xff] << 24) | ((uint32_t)SBOX[(t >> 16) & 0xff] << 16)
              | ((uint32_t)SBOX[(t >> 8) & 0xff] << 8) | SBOX[t & 0xff];
            t ^= rcon;
            rcon = (uint32_t)xtime8((uint8_t)(rcon >> 24)) << 24;
        }
        rk[i] = rk[i - 4] ^ t;
    }
}

#define AES_ROUND(d, s, rk) \
    d##0 = Te0[s##0 >> 24] ^ Te1[(s##1 >> 16) & 0xff] ^ Te2[(s##2 >> 8) & 0xff] ^ Te3[s##3 & 0xff] ^ (rk)[0]; \
    d##1 = Te0[s##1 >> 24] ^ Te1[(s##2 >> 16) & 0xff] ^ Te2[(s##3 >> 8) & 0xff] ^ Te3[s##0 & 0xff] ^ (rk)[1]; \
    d##2 = Te0[s##2 >> 24] ^ Te1[(s##3 >> 16) & 0xff] ^ Te2[(s##0 >> 8) & 0xff] ^ Te3[s##1 & 0xff] ^ (rk)[2]; \
    d##3 = Te0[s##3 >> 24] ^ Te1[(s##0 >> 16) & 0xff] ^ Te2[(s##1 >> 8) & 0xff] ^ Te3[s##2 & 0xff] ^ (rk)[3]

/* The last round has no MixColumns, exactly as AES specifies. Differentially that
 * changes nothing (MixColumns is linear and invertible), so the bound the SAT model
 * proves for X rounds applies to this. */
#define AES_LASTROUND(d, s, rk) \
    d##0 = ((uint32_t)SBOX[s##0 >> 24] << 24) | ((uint32_t)SBOX[(s##1 >> 16) & 0xff] << 16) \
         | ((uint32_t)SBOX[(s##2 >> 8) & 0xff] << 8) | SBOX[s##3 & 0xff]; \
    d##1 = ((uint32_t)SBOX[s##1 >> 24] << 24) | ((uint32_t)SBOX[(s##2 >> 16) & 0xff] << 16) \
         | ((uint32_t)SBOX[(s##3 >> 8) & 0xff] << 8) | SBOX[s##0 & 0xff]; \
    d##2 = ((uint32_t)SBOX[s##2 >> 24] << 24) | ((uint32_t)SBOX[(s##3 >> 16) & 0xff] << 16) \
         | ((uint32_t)SBOX[(s##0 >> 8) & 0xff] << 8) | SBOX[s##1 & 0xff]; \
    d##3 = ((uint32_t)SBOX[s##3 >> 24] << 24) | ((uint32_t)SBOX[(s##0 >> 16) & 0xff] << 16) \
         | ((uint32_t)SBOX[(s##1 >> 8) & 0xff] << 8) | SBOX[s##2 & 0xff]; \
    d##0 ^= (rk)[0]; d##1 ^= (rk)[1]; d##2 ^= (rk)[2]; d##3 ^= (rk)[3]

static void aes_encrypt1(const aes_key_t *k, const uint8_t in[16], uint8_t out[16])
{
    const uint32_t *rk = k->rk;
    uint32_t s0 = GETU32(in) ^ rk[0], s1 = GETU32(in + 4) ^ rk[1];
    uint32_t s2 = GETU32(in + 8) ^ rk[2], s3 = GETU32(in + 12) ^ rk[3];
    uint32_t t0, t1, t2, t3;
    for (int r = 1; r < k->nr; r++) {
        AES_ROUND(t, s, rk + 4 * r);
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    AES_LASTROUND(t, s, rk + 4 * k->nr);
    PUTU32(out, t0); PUTU32(out + 4, t1); PUTU32(out + 8, t2); PUTU32(out + 12, t3);
}

/* Four independent blocks at once. A single block is latency-bound -- every round
 * depends on the previous one -- so interleaving is the dominant software win, and
 * this is the kernel the AES row of the comparison uses. */
static void aes_encrypt4(const aes_key_t *k, const uint8_t *in, uint8_t *out)
{
    const uint32_t *rk = k->rk;
    uint32_t a0, a1, a2, a3, b0, b1, b2, b3, e0, e1, e2, e3, d0, d1, d2, d3;
    uint32_t ta0, ta1, ta2, ta3, tb0, tb1, tb2, tb3;
    uint32_t te0, te1, te2, te3, td0, td1, td2, td3;
#define LOAD(v, off) v##0 = GETU32(in + (off)) ^ rk[0]; v##1 = GETU32(in + (off) + 4) ^ rk[1]; \
                     v##2 = GETU32(in + (off) + 8) ^ rk[2]; v##3 = GETU32(in + (off) + 12) ^ rk[3]
    LOAD(a, 0); LOAD(b, 16); LOAD(e, 32); LOAD(d, 48);
#undef LOAD
    for (int r = 1; r < k->nr; r++) {
        const uint32_t *p = rk + 4 * r;
        AES_ROUND(ta, a, p); AES_ROUND(tb, b, p); AES_ROUND(te, e, p); AES_ROUND(td, d, p);
        a0 = ta0; a1 = ta1; a2 = ta2; a3 = ta3;
        b0 = tb0; b1 = tb1; b2 = tb2; b3 = tb3;
        e0 = te0; e1 = te1; e2 = te2; e3 = te3;
        d0 = td0; d1 = td1; d2 = td2; d3 = td3;
    }
    const uint32_t *p = rk + 4 * k->nr;
    AES_LASTROUND(ta, a, p); AES_LASTROUND(tb, b, p);
    AES_LASTROUND(te, e, p); AES_LASTROUND(td, d, p);
#define STORE(v, off) PUTU32(out + (off), v##0); PUTU32(out + (off) + 4, v##1); \
                      PUTU32(out + (off) + 8, v##2); PUTU32(out + (off) + 12, v##3)
    STORE(ta, 0); STORE(tb, 16); STORE(te, 32); STORE(td, 48);
#undef STORE
}

/* --- AES-lin444: AES S-box, lin444 layer over four 32-bit words ----------------- */
/*
 * The cipher the QalqanSpeed report calls M, reduced to this project's key model:
 * X rounds of `state ^= rk[r]; SubBytes; L`, then a final `state ^= rk[X]`, with
 * independent round keys. That is the same shape every other variant in this
 * repository uses, and the shape the SAT model proves the bound for. It drops M's
 * two 128-bit modular-add key layers, which makes this slightly *faster* than M as
 * published -- stated plainly because it flatters this row, not the AES one.
 *
 * State layout: word w bit k is state bit 32w + k, byte i is word i/4, byte i%4
 * within it -- matching analysis/present_sat/linear.py so the measured cipher and
 * the analysed one are the same object.
 */

static int LIN_C[3];

static uint32_t rotl32(uint32_t a, int c) { return c ? (a << c) | (a >> (32 - c)) : a; }

static void lin444(uint32_t w[4])
{
    const int c0 = LIN_C[0], c1 = LIN_C[1], c2 = LIN_C[2];
    uint32_t o0 = w[0] ^ rotl32(w[1], c0) ^ rotl32(w[2], c1) ^ rotl32(w[3], c2);
    uint32_t o1 = w[1] ^ rotl32(w[2], c0) ^ rotl32(w[3], c1) ^ rotl32(o0, c2);
    uint32_t o2 = w[2] ^ rotl32(w[3], c0) ^ rotl32(o0, c1) ^ rotl32(o1, c2);
    uint32_t o3 = w[3] ^ rotl32(o0, c0) ^ rotl32(o1, c1) ^ rotl32(o2, c2);
    w[0] = o0; w[1] = o1; w[2] = o2; w[3] = o3;
}

typedef struct { uint32_t rk[4 * (MAX_ROUNDS + 1)]; int nr; } lin_key_t;

/* Fused substitution-and-linear tables: Tl[i][v] is L(S(v) placed in byte i), so one
 * round is 16 lookups XORed together plus the round key. 16 x 256 x 16 B = 64 KiB,
 * which is the "T64KB" kernel of the QalqanSpeed report -- there it beat the smaller
 * L1-resident layout once block interleaving had hidden the latency. */
/* One entry is a whole 128-bit state, so the accumulation across the 16 lookups is a
 * chain of 128-bit XORs rather than 64 scalar ones. Aligned for the vector load. */
static uint32_t Tl[16][256][4] __attribute__((aligned(16)));

static void lin_init_tables(void)
{
    for (int i = 0; i < 16; i++) {
        for (int v = 0; v < 256; v++) {
            uint32_t w[4] = {0, 0, 0, 0};
            w[i / 4] = (uint32_t)SBOX[v] << (8 * (i % 4));
            lin444(w);
            for (int j = 0; j < 4; j++) Tl[i][v][j] = w[j];
        }
    }
}

/* Reference: the definition, byte by byte, with no fused table. The KAT compares the
 * table kernels against this, so a wrong table cannot pass unnoticed. */
static void lin_encrypt_ref(const lin_key_t *k, const uint8_t in[16], uint8_t out[16])
{
    uint32_t w[4];
    for (int i = 0; i < 4; i++)
        w[i] = (uint32_t)in[4 * i] | ((uint32_t)in[4 * i + 1] << 8)
             | ((uint32_t)in[4 * i + 2] << 16) | ((uint32_t)in[4 * i + 3] << 24);
    for (int r = 0; r < k->nr; r++) {
        for (int i = 0; i < 4; i++) w[i] ^= k->rk[4 * r + i];
        for (int i = 0; i < 4; i++) {
            uint32_t v = 0;
            for (int b = 0; b < 4; b++)
                v |= (uint32_t)SBOX[(w[i] >> (8 * b)) & 0xff] << (8 * b);
            w[i] = v;
        }
        lin444(w);
    }
    for (int i = 0; i < 4; i++) w[i] ^= k->rk[4 * k->nr + i];
    for (int i = 0; i < 4; i++) {
        out[4 * i] = (uint8_t)w[i]; out[4 * i + 1] = (uint8_t)(w[i] >> 8);
        out[4 * i + 2] = (uint8_t)(w[i] >> 16); out[4 * i + 3] = (uint8_t)(w[i] >> 24);
    }
}

/* The table entry is a 128-bit value, so the 16-way accumulation is a chain of
 * _mm_xor_si128 rather than 64 scalar XORs. This is SSE2 only -- no GF acceleration,
 * no AES-NI -- and it is what makes this the *best* software kernel for the cipher,
 * which is the comparison the surrounding document asks for. */
#define TL(i, b) _mm_load_si128((const __m128i *)Tl[i][(b)])

#define LIN_ROUND(v, rkv) do { \
    __m128i _x = _mm_xor_si128((v), (rkv)); \
    uint32_t x0 = (uint32_t)_mm_cvtsi128_si32(_x); \
    uint32_t x1 = (uint32_t)_mm_extract_epi32(_x, 1); \
    uint32_t x2 = (uint32_t)_mm_extract_epi32(_x, 2); \
    uint32_t x3 = (uint32_t)_mm_extract_epi32(_x, 3); \
    __m128i _a = _mm_xor_si128(TL(0, x0 & 0xff),         TL(1, (x0 >> 8) & 0xff)); \
    __m128i _b = _mm_xor_si128(TL(2, (x0 >> 16) & 0xff), TL(3, x0 >> 24)); \
    __m128i _c = _mm_xor_si128(TL(4, x1 & 0xff),         TL(5, (x1 >> 8) & 0xff)); \
    __m128i _d = _mm_xor_si128(TL(6, (x1 >> 16) & 0xff), TL(7, x1 >> 24)); \
    __m128i _e = _mm_xor_si128(TL(8, x2 & 0xff),         TL(9, (x2 >> 8) & 0xff)); \
    __m128i _f = _mm_xor_si128(TL(10, (x2 >> 16) & 0xff), TL(11, x2 >> 24)); \
    __m128i _g = _mm_xor_si128(TL(12, x3 & 0xff),        TL(13, (x3 >> 8) & 0xff)); \
    __m128i _h = _mm_xor_si128(TL(14, (x3 >> 16) & 0xff), TL(15, x3 >> 24)); \
    _a = _mm_xor_si128(_a, _b); _c = _mm_xor_si128(_c, _d); \
    _e = _mm_xor_si128(_e, _f); _g = _mm_xor_si128(_g, _h); \
    _a = _mm_xor_si128(_a, _c); _e = _mm_xor_si128(_e, _g); \
    (v) = _mm_xor_si128(_a, _e); \
} while (0)

static void lin_encrypt1(const lin_key_t *k, const uint8_t *in, uint8_t *out)
{
    __m128i v = _mm_loadu_si128((const __m128i *)in);
    for (int r = 0; r < k->nr; r++)
        LIN_ROUND(v, _mm_loadu_si128((const __m128i *)(k->rk + 4 * r)));
    v = _mm_xor_si128(v, _mm_loadu_si128((const __m128i *)(k->rk + 4 * k->nr)));
    _mm_storeu_si128((__m128i *)out, v);
}

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
    aes_expand(key, 10, &k);
    aes_encrypt1(&k, pt, got);
    if (memcmp(got, want, 16) != 0) die("AES does not match the FIPS-197 C.1 vector");

    /* The 4-way kernel must agree with the 1-way one at every round count timed. */
    for (int nr = 4; nr <= 14; nr++) {
        uint8_t buf[64], a[64], b[64];
        for (int i = 0; i < 64; i++) buf[i] = (uint8_t)rng_next();
        aes_expand(key, nr, &k);
        for (int j = 0; j < 4; j++) aes_encrypt1(&k, buf + 16 * j, a + 16 * j);
        aes_encrypt4(&k, buf, b);
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
        aes_expand(key, nr, &k);
        for (int j = 0; j < BS_BLOCKS; j++) aes_encrypt1(&k, buf + 16 * j, a + 16 * j);
        bs_expand_aes_key(&k, bs_km);
        aes_encrypt_bs(&k, buf, b);
        if (memcmp(a, b, sizeof buf) != 0) die("AES bitslice disagrees with AES x1");
    }
    for (int nr = 2; nr <= MAX_ROUNDS; nr++) {
        lin_key_t k;
        k.nr = nr;
        for (int i = 0; i < 4 * (nr + 1); i++) k.rk[i] = (uint32_t)rng_next();
        for (int j = 0; j < BS_BLOCKS; j++) lin_encrypt_ref(&k, buf + 16 * j, a + 16 * j);
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
        for (int j = 0; j < 8; j++) lin_encrypt_ref(&k, buf + 16 * j, a + 16 * j);
        for (int j = 0; j < 8; j++) lin_encrypt1(&k, buf + 16 * j, b + 16 * j);
        if (memcmp(a, b, 128) != 0) die("AES-lin444 table kernel disagrees with the reference");
        lin_encrypt4(&k, buf, b); lin_encrypt4(&k, buf + 64, b + 64);
        if (memcmp(a, b, 128) != 0) die("AES-lin444 x4 disagrees with the reference");
        lin_encrypt8(&k, buf, b);
        if (memcmp(a, b, 128) != 0) die("AES-lin444 x8 disagrees with the reference");
        uint8_t big[256], ba[256], bb[256];
        for (int i = 0; i < 256; i++) big[i] = (uint8_t)rng_next();
        for (int j = 0; j < 16; j++) lin_encrypt_ref(&k, big + 16 * j, ba + 16 * j);
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
        aes_expand(key, nr, &ak);
        BENCH("aes", nr, "table", 1,
              aes_encrypt1(&ak, buf + (size_t)g * 16, out + (size_t)g * 16));
        BENCH("aes", nr, "table-x4", 4,
              aes_encrypt4(&ak, buf + (size_t)g * 64, out + (size_t)g * 64));
        BENCH("aes", nr, "table-x8", 8,
              { aes_encrypt4(&ak, buf + (size_t)g * 128, out + (size_t)g * 128); \
                aes_encrypt4(&ak, buf + (size_t)g * 128 + 64, out + (size_t)g * 128 + 64); });
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
              lin_encrypt1(&lk, buf + (size_t)g * 16, out + (size_t)g * 16));
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
