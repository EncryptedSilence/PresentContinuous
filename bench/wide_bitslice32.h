/* 32-bit bitslice path for the two 128-bit ciphers: 32 blocks of AES or
 * AES-lin444 encrypted in parallel, one state bit of all 32 blocks per
 * uint32_t. src/present_bitslice32.c one cipher family over, and the same
 * reason it exists: a uint64_t is a register pair on Cortex-M4, so a 32-bit
 * word is the width that keeps one gate to one instruction there.
 *
 * Ported from bench/wide_bench.c's AVX2 kernels (aes_encrypt_bs /
 * lin_encrypt_bs) by three mechanical substitutions -- __m256i -> uint32_t,
 * _mm256_xor_si256(a, b) -> (a) ^ (b), present_circuit8_avx2_c2 ->
 * present_circuit8_u32_c2 -- so this is the same S-box circuit and the same
 * linear-layer arithmetic the AVX2 path measures, just 32 blocks wide
 * instead of 256. Every state-bit index, round-key layout, and MixColumns/
 * lin444 formula below is copied unchanged from wide_bench.c; only the
 * transpose (32 blocks instead of 256, a plain double loop instead of a
 * SIMD bit-matrix transpose) and the key expansion (built from the explicit
 * `rounds` argument rather than a global) are new.
 *
 * Two tiers, matching src/present_bitslice32.c's convention exactly:
 *
 *   - aes_encrypt_bs32 / lin_encrypt_bs32 take raw 16-byte blocks in and out
 *     and do everything -- pack, expand the key, encrypt, unpack, exactly
 *     like present_encrypt_bitslice32 does for the 64-bit ciphers. Simple to
 *     call, but on measurement the transpose and key expansion turned out to
 *     dominate: 77% of aes_encrypt_bs32(rounds=5) at -O3 -march=native is the
 *     transpose alone, another ~5% the key expansion, leaving the cipher
 *     itself a small fraction of what this entry point reports. Publishing
 *     that as "AES bitslice speed" would be reporting a transpose benchmark,
 *     and it would break comparability with PRESENT's own bitslice/bitslice-bs
 *     split (bench/bench_main.c, backed by present_encrypt_bitslice32 /
 *     present_encrypt_bitslice32_bs) -- present_bitslice32.c's file comment
 *     says to revisit the double-loop transpose "only if the Cortex-M4
 *     numbers show it dominating." They do.
 *
 *   - aes_encrypt_bs32_bs / lin_encrypt_bs32_bs skip both: the caller packs
 *     once, expands the key once, and calls the _bs form as many times as it
 *     wants over already-bitsliced state, exactly mirroring
 *     present_encrypt_bitslice32_bs's contract (see tests/test_impls.c's use
 *     of it) and wide_bench.c's own AVX2 row, which calls bs_expand_aes_key
 *     once outside its timed BENCH loop rather than paying for it on every
 *     call. Same ping-pong parity contract as present_bitslice32.c's kernels:
 *     state and scratch swap each round, and the return value -- not
 *     necessarily `state` -- says which buffer holds the ciphertext, so a
 *     caller must unpack from the returned pointer, not always from `state`.
 *     aes_encrypt_bs32 / lin_encrypt_bs32 are thin wrappers around this form.
 *
 * The bitsliced round-key array is fixed at WIDE_BS32_KM_WORDS words --
 * (MAX_ROUNDS + 1) * WIDE_BS32_BITS, sized for the largest round count this
 * header will ever run rather than a VLA sized from an unvalidated `rounds`
 * (a negative or oversized `rounds` was undefined behaviour through a VLA,
 * and the firmware's stack budget needs a number fixed at compile time, not
 * one that depends on a runtime argument). Every function that turns
 * `rounds` into an array index clamps it to [0, MAX_ROUNDS] first via
 * wide_bs32_clamp_rounds.
 *
 * Portable C only, like bench/wide_ciphers.h which this builds on: no
 * intrinsics of any width, and no file-scope mutable state, so this header
 * is safe for both an x86 test binary and the Cortex-M4 firmware.
 */
#ifndef WIDE_BITSLICE32_H
#define WIDE_BITSLICE32_H

#include <stdint.h>
#include <string.h>

#include "wide_ciphers.h"
#include "gen/sbox_circuits_u32.h"

#define WIDE_BS32_BLOCKS 32
#define WIDE_BS32_BITS   128

/* Words in a fully-expanded bitsliced round-key array, sized for the largest
 * round count MAX_ROUNDS allows rather than the caller's actual `rounds` --
 * see the file comment. A caller of the _bs entry points that expands its
 * own key material must size its km buffer to this. */
#define WIDE_BS32_KM_WORDS ((MAX_ROUNDS + 1) * WIDE_BS32_BITS)

/* Every function below that indexes a WIDE_BS32_KM_WORDS-sized array by
 * `rounds` calls this first, so a caller-supplied `rounds` outside
 * [0, MAX_ROUNDS] is clamped into range rather than reading or writing past
 * the fixed-size key-material array. */
static inline int wide_bs32_clamp_rounds(int rounds)
{
    if (rounds < 0) return 0;
    if (rounds > MAX_ROUNDS) return MAX_ROUNDS;
    return rounds;
}

/* --- transpose --------------------------------------------------------------------
 *
 * state[bit] holds bit `bit` of all 32 blocks, one per bit position of the word.
 * bit -> byte/within-byte follows the same convention as the AVX2 path (plane j is
 * bit (j % 8) of state byte (j / 8)) and, in turn, aes_encrypt1's GETU32/PUTU32
 * byte order -- both read/write the 16-byte block as big-endian 32-bit words in
 * left-to-right byte order, i.e. byte i of the block is exactly state byte i here.
 */
static inline void wide_bs32_pack(const uint8_t *in, uint32_t *state)
{
    for (int bit = 0; bit < WIDE_BS32_BITS; bit++) {
        uint32_t w = 0;
        for (int blk = 0; blk < WIDE_BS32_BLOCKS; blk++) {
            const uint8_t *p = in + blk * 16;
            w |= (uint32_t)((p[bit >> 3] >> (bit & 7)) & 1u) << blk;
        }
        state[bit] = w;
    }
}

static inline void wide_bs32_unpack(const uint32_t *state, uint8_t *out)
{
    memset(out, 0, (size_t)WIDE_BS32_BLOCKS * 16);
    for (int bit = 0; bit < WIDE_BS32_BITS; bit++)
        for (int blk = 0; blk < WIDE_BS32_BLOCKS; blk++)
            out[blk * 16 + (bit >> 3)] |=
                (uint8_t)(((state[bit] >> blk) & 1u) << (bit & 7));
}

/* --- key material -------------------------------------------------------------
 *
 * Each state-bit plane is either all-blocks-0 or all-blocks-1 for a given round
 * key bit, so it broadcasts to 0 or UINT32_MAX exactly as the AVX2 path
 * broadcasts to an all-zero/all-ones __m256i. km must be WIDE_BS32_KM_WORDS
 * words; a caller of the _bs entry points expands into its own such buffer
 * once and reuses it across many calls, the same way wide_bench.c's AVX2 row
 * calls bs_expand_aes_key once outside its timed loop rather than per call --
 * this is the piece the plain aes_encrypt_bs32/lin_encrypt_bs32 wrappers below
 * pay for on every call and the _bs form does not.
 */
static inline void bs32_set_key_byte(uint32_t *km, int byte, uint8_t v)
{
    for (int j = 0; j < 8; j++) km[8 * byte + j] = ((v >> j) & 1u) ? 0xFFFFFFFFu : 0u;
}

/* AES round key word c is column c with row 0 in the most significant byte, and
 * state byte index is row + 4 * col -- the same indexing GETU32 gives the T-table
 * kernel, which is why the two agree bit for bit (see bs_expand_aes_key in
 * wide_bench.c). */
static inline void bs32_expand_aes_key(const aes_key_t *k, int rounds, uint32_t *km)
{
    rounds = wide_bs32_clamp_rounds(rounds);
    for (int r = 0; r <= rounds; r++)
        for (int c = 0; c < 4; c++) {
            uint32_t w = k->rk[4 * r + c];
            for (int row = 0; row < 4; row++)
                bs32_set_key_byte(km + WIDE_BS32_BITS * r, row + 4 * c,
                                   (uint8_t)(w >> (8 * (3 - row))));
        }
}

/* lin444 round key word j is little-endian over state bytes 4j..4j+3. */
static inline void bs32_expand_lin_key(const lin_key_t *k, int rounds, uint32_t *km)
{
    rounds = wide_bs32_clamp_rounds(rounds);
    for (int r = 0; r <= rounds; r++)
        for (int j = 0; j < 4; j++) {
            uint32_t w = k->rk[4 * r + j];
            for (int b = 0; b < 4; b++)
                bs32_set_key_byte(km + WIDE_BS32_BITS * r, 4 * j + b, (uint8_t)(w >> (8 * b)));
        }
}

static inline void bs32_addkey(uint32_t *st, const uint32_t *km)
{
    for (int j = 0; j < WIDE_BS32_BITS; j++) st[j] ^= km[j];
}

/* --- S-box -----------------------------------------------------------------------
 *
 * The same generated AES S-box circuit the AVX2 path uses (present_circuit8_u32_c2
 * is present_circuit8_avx2_c2's uint32_t retype, produced by
 * tools/gen_retyped_circuits.py) -- one circuit, shared, never a second copy.
 */
static inline void bs32_sub_bytes(uint32_t *st)
{
    for (int i = 0; i < 16; i++) {
        uint32_t *p = st + 8 * i;
        uint32_t y0, y1, y2, y3, y4, y5, y6, y7;
        present_circuit8_u32_c2(&y7, &y6, &y5, &y4, &y3, &y2, &y1, &y0,
                                 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        p[0] = y0; p[1] = y1; p[2] = y2; p[3] = y3;
        p[4] = y4; p[5] = y5; p[6] = y6; p[7] = y7;
    }
}

/* --- AES linear layer -------------------------------------------------------------
 *
 * ShiftRows costs nothing: it only decides which plane group MixColumns reads, so
 * it is folded into the index below rather than moving any data. MixColumns uses
 * b_r = a_r ^ s ^ xtime(a_r ^ a_{r+1}) with s = a_0^a_1^a_2^a_3. The last round has
 * no MixColumns, exactly as AES specifies (see AES_LASTROUND in wide_ciphers.h).
 */
static inline void bs32_aes_lin(const uint32_t *t, uint32_t *st, int last)
{
    for (int c = 0; c < 4; c++) {
        const uint32_t *a[4];
        for (int r = 0; r < 4; r++) a[r] = t + 8 * (r + 4 * ((c + r) & 3));
        if (last) {
            for (int r = 0; r < 4; r++)
                for (int k = 0; k < 8; k++) st[8 * (r + 4 * c) + k] = a[r][k];
            continue;
        }
        uint32_t s[8];
        for (int k = 0; k < 8; k++)
            s[k] = a[0][k] ^ a[1][k] ^ a[2][k] ^ a[3][k];
        for (int r = 0; r < 4; r++) {
            const uint32_t *p = a[r], *q = a[(r + 1) & 3];
            uint32_t u[8], xt[8];
            for (int k = 0; k < 8; k++) u[k] = p[k] ^ q[k];
            /* xtime: shift up one, and fold the carry into bits 0,1,3,4 (0x1b). */
            xt[0] = u[7];             xt[1] = u[0] ^ u[7];
            xt[2] = u[1];             xt[3] = u[2] ^ u[7];
            xt[4] = u[3] ^ u[7];      xt[5] = u[4];
            xt[6] = u[5];             xt[7] = u[6];
            for (int k = 0; k < 8; k++)
                st[8 * (r + 4 * c) + k] = p[k] ^ s[k] ^ xt[k];
        }
    }
}

/* --- lin444 linear layer -----------------------------------------------------------
 *
 * rotl32 by c sends bit p to bit (p + c) mod 32, so bit p of the rotated word is
 * bit (p - c) mod 32 of the original: a pure change of plane index, no data
 * movement. rot[][] is built once per call from k->c, the per-instance rotation
 * constants (see wide_ciphers.h's lin_key_t), rather than the CLI-fed global
 * wide_bench.c's AVX2 kernel reads.
 */
static inline void bs32_lin444(const uint32_t *t, uint32_t *st, int rot[3][32])
{
#define WP(j, p) t[32 * (j) + (p)]
    for (int p = 0; p < 32; p++) {
        int p0 = rot[0][p], p1 = rot[1][p], p2 = rot[2][p];
        st[0 * 32 + p] = WP(0, p) ^ WP(1, p0) ^ WP(2, p1) ^ WP(3, p2);
    }
    for (int p = 0; p < 32; p++) {
        int p0 = rot[0][p], p1 = rot[1][p], p2 = rot[2][p];
        st[1 * 32 + p] = WP(1, p) ^ WP(2, p0) ^ WP(3, p1) ^ st[0 * 32 + p2];
    }
    for (int p = 0; p < 32; p++) {
        int p0 = rot[0][p], p1 = rot[1][p], p2 = rot[2][p];
        st[2 * 32 + p] = WP(2, p) ^ WP(3, p0) ^ st[0 * 32 + p1] ^ st[1 * 32 + p2];
    }
    for (int p = 0; p < 32; p++) {
        int p0 = rot[0][p], p1 = rot[1][p], p2 = rot[2][p];
        st[3 * 32 + p] = WP(3, p) ^ st[0 * 32 + p0] ^ st[1 * 32 + p1] ^ st[2 * 32 + p2];
    }
#undef WP
}

/* --- transpose-free entry points ------------------------------------------------
 *
 * km must already be expanded (bs32_expand_aes_key / bs32_expand_lin_key) into a
 * WIDE_BS32_KM_WORDS-word buffer. state and scratch are both WIDE_BS32_BITS words;
 * on entry state holds the packed plaintext (wide_bs32_pack), and the plane arrays
 * ping-pong between the S-box (in place) and the linear layer (out of place) each
 * round, exactly as present_bitslice32.c's bs32_enc_k* kernels do -- so the return
 * value, not necessarily `state`, is the buffer holding the ciphertext. A caller
 * must wide_bs32_unpack from the returned pointer.
 */
static inline uint32_t *aes_encrypt_bs32_bs(const uint32_t *km, int rounds,
                                             uint32_t *state, uint32_t *scratch)
{
    rounds = wide_bs32_clamp_rounds(rounds);
    uint32_t *cur = state, *nxt = scratch;
    bs32_addkey(cur, km);
    for (int r = 1; r <= rounds; r++) {
        bs32_sub_bytes(cur);
        bs32_aes_lin(cur, nxt, r == rounds);
        bs32_addkey(nxt, km + WIDE_BS32_BITS * r);
        uint32_t *sw = cur; cur = nxt; nxt = sw;
    }
    return cur;
}

static inline uint32_t *lin_encrypt_bs32_bs(const lin_key_t *k, const uint32_t *km,
                                             int rounds, uint32_t *state, uint32_t *scratch)
{
    rounds = wide_bs32_clamp_rounds(rounds);
    uint32_t *cur = state, *nxt = scratch;
    int rot[3][32];
    for (int i = 0; i < 3; i++)
        for (int p = 0; p < 32; p++) rot[i][p] = ((p - k->c[i]) % 32 + 32) % 32;

    for (int r = 0; r < rounds; r++) {
        bs32_addkey(cur, km + WIDE_BS32_BITS * r);
        bs32_sub_bytes(cur);
        bs32_lin444(cur, nxt, rot);
        uint32_t *sw = cur; cur = nxt; nxt = sw;
    }
    bs32_addkey(cur, km + WIDE_BS32_BITS * rounds);
    return cur;
}

/* --- all-in-one entry points ------------------------------------------------------
 *
 * Pack, expand the key, encrypt, unpack -- everything aes_encrypt_bs32_bs /
 * lin_encrypt_bs32_bs need, done here so a caller that does not care about the
 * transpose/key-expansion cost can just pass 16-byte blocks in and out, exactly
 * like present_encrypt_bitslice32 does for the 64-bit ciphers. See the file
 * comment for why the benchmark itself should prefer the _bs form instead.
 */
static inline void aes_encrypt_bs32(const aes_key_t *k, int rounds, const uint8_t *in, uint8_t *out)
{
    uint32_t a[WIDE_BS32_BITS], b[WIDE_BS32_BITS];
    uint32_t km[WIDE_BS32_KM_WORDS];

    bs32_expand_aes_key(k, rounds, km);
    wide_bs32_pack(in, a);
    uint32_t *res = aes_encrypt_bs32_bs(km, rounds, a, b);
    wide_bs32_unpack(res, out);
}

static inline void lin_encrypt_bs32(const lin_key_t *k, int rounds, const uint8_t *in, uint8_t *out)
{
    uint32_t a[WIDE_BS32_BITS], b[WIDE_BS32_BITS];
    uint32_t km[WIDE_BS32_KM_WORDS];

    bs32_expand_lin_key(k, rounds, km);
    wide_bs32_pack(in, a);
    uint32_t *res = lin_encrypt_bs32_bs(k, km, rounds, a, b);
    wide_bs32_unpack(res, out);
}

#endif /* WIDE_BITSLICE32_H */
