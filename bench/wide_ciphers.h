/* AES and AES-lin444: the two 128-bit block ciphers benchmarked and analysed
 * alongside the 64-bit PRESENT variants. They share no code with src/, which is
 * 64-bit-block throughout, so they are defined once here, standalone.
 *
 * This header is included by two very different consumers: bench/wide_bench.c,
 * an x86 program that wraps its own AVX2/SSE2 kernels and RDTSC measurement
 * harness around what is defined here, and the Cortex-M4 firmware, which has
 * neither AVX2/SSE2 nor an operating system to call an init routine from. Only
 * portable C lives here -- no intrinsics of any width. wide_bench.c keeps the
 * SSE2 fused-table AES-lin444 kernel (lin_encrypt1) and its Tl table for
 * itself, the same as its AVX2 kernels, because both are exactly the class of
 * thing this header cannot carry: x86-only code, and in Tl's case 64 KiB of
 * mutable state the M4's 64 KiB of CCM cannot spare.
 *
 * Two consequences follow from the firmware consumer:
 *
 *   - No file-scope mutable state is part of the interface. A caller gets a key
 *     schedule and encrypt functions and nothing else to configure or set up
 *     first -- the AES substitution tables below are populated once, lazily,
 *     on first use, behind a private ready flag. That flag is itself static
 *     storage, but it is never read or written by anything outside this file,
 *     never varies with any input, and holds nothing benchmark-specific (no
 *     CSV handle, no RNG stream, no CLI-supplied parameter) -- it is a
 *     memoised constant, not state a benchmark's globals could leak through.
 *     It costs the firmware target 4 KiB of RAM (Te0..Te3, 256 x uint32_t x 4)
 *     once aes_encrypt1/aes_encrypt4 are first called -- worth knowing when
 *     sizing the benchmark harness's own memory budget.
 *
 *   - Every encrypt function takes its round count as an explicit argument
 *     rather than reading it from the key struct, so the same schedule can be
 *     run at whatever round count a caller (a sweep, a test, the firmware)
 *     asks for next.
 *
 * lin444's rotation constants live in lin_key_t.c, a per-instance parameter
 * rather than a global: they belong to the key/cipher instance, the same way
 * rk does, so wide_bench.c's --c0 flag and lin_key_schedule's fixed default
 * (0, 8, 15 -- AES-lin444's own, see wide_bench.c's AES-lin444 comment) both
 * just set a field, with no global for either to fight over.
 *
 * AES-lin444 has no real key schedule to preserve: this benchmark's threat
 * model treats round keys as independent (see wide_bench.c's file comment),
 * so lin_key_schedule below is a deterministic, reproducible expansion of the
 * 16-byte key into that many independent-looking round keys -- enough to make
 * two implementations comparable against each other, which is all a keyed
 * correctness check needs.
 */
#ifndef WIDE_CIPHERS_H
#define WIDE_CIPHERS_H

#include <stdint.h>

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

static inline uint8_t xtime8(uint8_t a) { return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b)); }

/* --- AES: classic T-table, round count parameterised --------------------------- */

static uint32_t Te0[256], Te1[256], Te2[256], Te3[256];
static int aes_tables_ready = 0;

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

/* Idempotent and safe to call more than once (main() calls it explicitly; the
 * encrypt functions below also call it themselves, so a caller that never
 * heard of this function -- a test, the firmware -- still gets correct output
 * from the first call it makes). */
static inline void aes_init_tables(void)
{
    if (aes_tables_ready) return;
    for (int x = 0; x < 256; x++) {
        uint8_t s = SBOX[x], s2 = xtime8(s), s3 = (uint8_t)(s2 ^ s);
        Te0[x] = ((uint32_t)s2 << 24) | ((uint32_t)s << 16) | ((uint32_t)s << 8) | s3;
        Te1[x] = rotr32(Te0[x], 8);
        Te2[x] = rotr32(Te0[x], 16);
        Te3[x] = rotr32(Te0[x], 24);
    }
    aes_tables_ready = 1;
}

static inline uint32_t GETU32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline void PUTU32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

typedef struct { uint32_t rk[4 * (MAX_ROUNDS + 1)]; int nr; } aes_key_t;

/* AES-128's own schedule, extended past 10 rounds by continuing the recurrence.
 * Always expands the full MAX_ROUNDS worth of round keys regardless of which
 * round count a caller will actually run -- the recurrence is a strict prefix
 * (round key i never depends on any j > i), so this costs a few extra idle
 * iterations at low round counts and nothing else, and it means one schedule
 * serves every round count a caller asks aes_encrypt1/aes_encrypt4 for later.
 * out->nr is set to MAX_ROUNDS as a default; callers of the AVX2 bitslice path
 * in wide_bench.c, which still reads k->nr directly, override it explicitly. */
static inline void aes_key_schedule(aes_key_t *out, const uint8_t key[16])
{
    uint32_t rcon = 0x01000000u;
    uint32_t *rk = out->rk;
    out->nr = MAX_ROUNDS;
    for (int i = 0; i < 4; i++) rk[i] = GETU32(key + 4 * i);
    for (int i = 4; i < 4 * (MAX_ROUNDS + 1); i++) {
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

static inline void aes_encrypt1(const aes_key_t *k, int rounds, const uint8_t in[16], uint8_t out[16])
{
    aes_init_tables();
    const uint32_t *rk = k->rk;
    uint32_t s0 = GETU32(in) ^ rk[0], s1 = GETU32(in + 4) ^ rk[1];
    uint32_t s2 = GETU32(in + 8) ^ rk[2], s3 = GETU32(in + 12) ^ rk[3];
    uint32_t t0, t1, t2, t3;
    for (int r = 1; r < rounds; r++) {
        AES_ROUND(t, s, rk + 4 * r);
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    AES_LASTROUND(t, s, rk + 4 * rounds);
    PUTU32(out, t0); PUTU32(out + 4, t1); PUTU32(out + 8, t2); PUTU32(out + 12, t3);
}

/* Four independent blocks at once. A single block is latency-bound -- every round
 * depends on the previous one -- so interleaving is the dominant software win, and
 * this is the kernel the AES row of the comparison uses. */
static inline void aes_encrypt4(const aes_key_t *k, int rounds, const uint8_t *in, uint8_t *out)
{
    aes_init_tables();
    const uint32_t *rk = k->rk;
    uint32_t a0, a1, a2, a3, b0, b1, b2, b3, e0, e1, e2, e3, d0, d1, d2, d3;
    uint32_t ta0, ta1, ta2, ta3, tb0, tb1, tb2, tb3;
    uint32_t te0, te1, te2, te3, td0, td1, td2, td3;
#define LOAD(v, off) v##0 = GETU32(in + (off)) ^ rk[0]; v##1 = GETU32(in + (off) + 4) ^ rk[1]; \
                     v##2 = GETU32(in + (off) + 8) ^ rk[2]; v##3 = GETU32(in + (off) + 12) ^ rk[3]
    LOAD(a, 0); LOAD(b, 16); LOAD(e, 32); LOAD(d, 48);
#undef LOAD
    for (int r = 1; r < rounds; r++) {
        const uint32_t *p = rk + 4 * r;
        AES_ROUND(ta, a, p); AES_ROUND(tb, b, p); AES_ROUND(te, e, p); AES_ROUND(td, d, p);
        a0 = ta0; a1 = ta1; a2 = ta2; a3 = ta3;
        b0 = tb0; b1 = tb1; b2 = tb2; b3 = tb3;
        e0 = te0; e1 = te1; e2 = te2; e3 = te3;
        d0 = td0; d1 = td1; d2 = td2; d3 = td3;
    }
    const uint32_t *p = rk + 4 * rounds;
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

/* c holds the lin444 rotation constants for this key instance -- a per-cipher
 * parameter, not a global, so wide_bench.c's --c0 flag and lin_key_schedule's
 * fixed default can both just set a field with nothing to fight over. */
typedef struct { uint32_t rk[4 * (MAX_ROUNDS + 1)]; int nr; int c[3]; } lin_key_t;

/* See the header comment: round keys are independent by design, so this is a
 * deterministic expansion of the 16-byte key into MAX_ROUNDS + 1 independent-
 * looking round keys via a local xorshift128+ stream -- no static state, seeded
 * only from the key -- rather than a cryptographic schedule. Both 64-bit state
 * words feed every step (s0 takes the *previous* s1, not the freshly updated
 * one), so both halves of the key stay live throughout: an earlier version
 * assigned s0 = s1 after updating s1 in place, which collapsed the generator to
 * a plain 64-bit xorshift over s1 alone -- key bytes 0..7 (s0's seed) then
 * barely affected the output, and any key with bytes 8..15 all zero produced
 * 83 of 84 zero round-key words. Fixed; see task-4-report.md's "Fix round 2"
 * for the numbers. The seed guard zeroes neither half independently, so no
 * 16-byte key -- not just the all-zero one -- can degenerate the stream. c is
 * set to AES-lin444's own constants (0, 8, 15), so a caller starting from a
 * 16-byte key gets the right cipher with no extra step. */
/* Unused by wide_bench.c itself -- it fills lin_key_t.rk directly with random
 * round-key material for the sweep and the KATs, matching this cipher's
 * independent-round-key model without needing a 16-byte key at all. This
 * function exists for callers that do start from a 16-byte key: a test that
 * cross-checks another implementation against aes_encrypt1/lin_encrypt_ref, or
 * the firmware. */
static inline void lin_key_schedule(lin_key_t *out, const uint8_t key[16])
{
    uint64_t s0 = 0, s1 = 0;
    for (int i = 0; i < 8; i++) s0 = (s0 << 8) | key[i];
    for (int i = 0; i < 8; i++) s1 = (s1 << 8) | key[8 + i];
    if (!s0) s0 = 0x9E3779B97F4A7C15ull; /* neither half may be zero: each seeds */
    if (!s1) s1 = 1;                     /* half the state, independently of the other */
    out->nr = MAX_ROUNDS;
    out->c[0] = 0; out->c[1] = 8; out->c[2] = 15;
    for (int i = 0; i < 4 * (MAX_ROUNDS + 1); i++) {
        uint64_t x = s0, y = s1;
        s0 = y;
        x ^= x << 23;
        s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
        uint64_t z = s1 + y;
        out->rk[i] = (uint32_t)(z ^ (z >> 32));
    }
}

static inline uint32_t rotl32(uint32_t a, int c) { return c ? (a << c) | (a >> (32 - c)) : a; }

static inline void lin444(uint32_t w[4], const int c[3])
{
    uint32_t o0 = w[0] ^ rotl32(w[1], c[0]) ^ rotl32(w[2], c[1]) ^ rotl32(w[3], c[2]);
    uint32_t o1 = w[1] ^ rotl32(w[2], c[0]) ^ rotl32(w[3], c[1]) ^ rotl32(o0, c[2]);
    uint32_t o2 = w[2] ^ rotl32(w[3], c[0]) ^ rotl32(o0, c[1]) ^ rotl32(o1, c[2]);
    uint32_t o3 = w[3] ^ rotl32(o0, c[0]) ^ rotl32(o1, c[1]) ^ rotl32(o2, c[2]);
    w[0] = o0; w[1] = o1; w[2] = o2; w[3] = o3;
}

/* Reference: the definition, byte by byte, with no fused table. Portable -- no
 * intrinsics of any width -- so this is the implementation the firmware and any
 * cross-checking test can always fall back on. wide_bench.c's SSE2 fused-table
 * kernel (lin_encrypt1) and its Tl table stay in wide_bench.c -- x86-only code
 * and 64 KiB of mutable state, neither of which belongs in a header the
 * Cortex-M4 firmware includes. */
static inline void lin_encrypt_ref(const lin_key_t *k, int rounds, const uint8_t in[16], uint8_t out[16])
{
    uint32_t w[4];
    for (int i = 0; i < 4; i++)
        w[i] = (uint32_t)in[4 * i] | ((uint32_t)in[4 * i + 1] << 8)
             | ((uint32_t)in[4 * i + 2] << 16) | ((uint32_t)in[4 * i + 3] << 24);
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < 4; i++) w[i] ^= k->rk[4 * r + i];
        for (int i = 0; i < 4; i++) {
            uint32_t v = 0;
            for (int b = 0; b < 4; b++)
                v |= (uint32_t)SBOX[(w[i] >> (8 * b)) & 0xff] << (8 * b);
            w[i] = v;
        }
        lin444(w, k->c);
    }
    for (int i = 0; i < 4; i++) w[i] ^= k->rk[4 * rounds + i];
    for (int i = 0; i < 4; i++) {
        out[4 * i] = (uint8_t)w[i]; out[4 * i + 1] = (uint8_t)(w[i] >> 8);
        out[4 * i + 2] = (uint8_t)(w[i] >> 16); out[4 * i + 3] = (uint8_t)(w[i] >> 24);
    }
}

#endif /* WIDE_CIPHERS_H */
