/* NEON bitslice path for the two 128-bit ciphers: 128 blocks of AES or
 * AES-lin444 encrypted in parallel, one state bit of all 128 blocks per
 * u64x2 (a 128-bit two-lane NEON vector). bench/wide_bitslice32.h one vector
 * width up: where that header bitslices 32 blocks into a uint32_t for the
 * Cortex-M4's native word, this bitslices 128 blocks into a NEON register for
 * the Cortex-A7.
 *
 * The port is mechanical, and deliberately so: this file exists to make the
 * ARM and x86/M4 numbers comparable, and a different circuit would defeat that.
 * Three substitutions carry wide_bitslice32.h across:
 *
 *     uint32_t                -> u64x2   (the 128-bit NEON vector; GCC vector
 *                                         extensions lower ^ & | to veor/vand/...)
 *     present_circuit8_u32_c2 -> present_circuit8_neon_c2
 *     WIDE_BS32_BLOCKS 32     -> WIDE_NEON_BLOCKS 128
 *
 * present_circuit8_neon_c2 (src/gen/sbox_circuits_neon.h) is the SAME generated
 * AES S-box circuit present_circuit8_u32_c2 is -- byte-for-byte identical gate
 * order, produced from the same tools/gen_retyped_circuits.py source, only the
 * type differs -- so this is the same S-box the AVX2/M4 paths measure, 128
 * blocks wide. Every state-bit index, round-key layout, and MixColumns/lin444
 * formula below is copied unchanged from wide_bitslice32.h. Only the transpose
 * (128 blocks into a two-lane vector, a plain correctness-first double loop
 * rather than the M4 header's delta-swap) is new: the bitslice is predicted to
 * lose to the table path on this core (see docs/platform-estimate.md), so the
 * transpose is written for obvious correctness, not speed.
 *
 * Two tiers, matching wide_bitslice32.h exactly:
 *
 *   - wide_aes_encrypt_neon / wide_lin_encrypt_neon take raw 16-byte blocks in
 *     and out and do everything (pack, expand key, encrypt, unpack).
 *   - wide_aes_encrypt_neon_bs / wide_lin_encrypt_neon_bs skip pack/expand/
 *     unpack: the caller packs once, expands the key once, and calls the _bs
 *     form over already-bitsliced state as many times as it wants. Same
 *     ping-pong parity contract as wide_bitslice32.h: state and scratch swap
 *     each round and the RETURN VALUE -- not necessarily `state` -- names the
 *     buffer holding the ciphertext, so a caller unpacks from the returned
 *     pointer.
 *
 * Slice/lane layout (identical to wide_bitslice32.h, one vector width wider):
 * slice j (0..127) holds bit (j%8) of byte (j/8) of the block, across 128
 * blocks; block b sits at bit b of the 128-bit vector (lane b/64, bit b%64).
 * Byte i of the block is state byte i, matching aes_encrypt1's big-endian byte
 * order and lin_encrypt_ref's word layout.
 *
 * The real code is compiled only where NEON exists; elsewhere (the x86 stub
 * build) the header is empty, exactly like src/gen/sbox_circuits_neon.h, so a
 * consumer must guard its use with #if defined(__ARM_NEON) or gate it at run
 * time through present_have_neon().
 */
#ifndef WIDE_BITSLICE_NEON_H
#define WIDE_BITSLICE_NEON_H

#include <stdint.h>
#include <string.h>

#include "wide_ciphers.h"

#if defined(__ARM_NEON)

#include "gen/sbox_circuits_neon.h"   /* u64x2, present_circuit8_neon_c2 */

#define WIDE_NEON_BLOCKS 128
#define WIDE_NEON_BITS   128

/* Words in a fully-expanded bitsliced round-key array, sized for the largest
 * round count MAX_ROUNDS allows -- see wide_bitslice32.h's identical rationale. */
#define WIDE_NEON_KM_WORDS ((MAX_ROUNDS + 1) * WIDE_NEON_BITS)

static const u64x2 WIDE_NEON_ZERO = { 0, 0 };
static const u64x2 WIDE_NEON_ONES = { (uint64_t)-1, (uint64_t)-1 };

static inline int wide_neon_clamp_rounds(int rounds)
{
    if (rounds < 0) return 0;
    if (rounds > MAX_ROUNDS) return MAX_ROUNDS;
    return rounds;
}

/* --- transpose ---------------------------------------------------------------
 *
 * A plain double loop, correctness-first (see the file comment on why speed is
 * not the goal here). slice j, block b holds bit (j%8) of byte (j/8) of block b;
 * block b lands at bit b of the 128-bit vector -- lane b/64, bit b%64. pack and
 * unpack are exact inverses, and `unpack` only reads `state` (never mutates it),
 * so it honours the ping-pong contract's "a caller may unpack the same buffer
 * more than once" without needing a scratch copy.
 */
static inline void wide_neon_pack(const uint8_t *in, u64x2 *state)
{
    for (int j = 0; j < WIDE_NEON_BITS; j++) {
        int byte = j / 8, bit = j % 8;
        uint64_t lane[2] = { 0, 0 };
        for (int b = 0; b < WIDE_NEON_BLOCKS; b++) {
            uint64_t v = (uint64_t)((in[b * 16 + byte] >> bit) & 1u);
            lane[b / 64] |= v << (b % 64);
        }
        memcpy(&state[j], lane, sizeof lane);
    }
}

static inline void wide_neon_unpack(const u64x2 *state, uint8_t *out)
{
    for (int b = 0; b < WIDE_NEON_BLOCKS; b++) {
        uint8_t *p = out + b * 16;
        for (int byte = 0; byte < 16; byte++) {
            unsigned v = 0;
            for (int bit = 0; bit < 8; bit++) {
                uint64_t lane[2];
                memcpy(lane, &state[8 * byte + bit], sizeof lane);
                v |= (unsigned)((lane[b / 64] >> (b % 64)) & 1u) << bit;
            }
            p[byte] = (uint8_t)v;
        }
    }
}

/* --- key material ------------------------------------------------------------
 *
 * Each state-bit plane is all-blocks-0 or all-blocks-1 for a given round-key
 * bit, so it broadcasts to WIDE_NEON_ZERO or WIDE_NEON_ONES, exactly as the
 * AVX2/u32 paths broadcast to an all-zero/all-ones vector. The AES and lin444
 * key layouts are copied verbatim from wide_bitslice32.h.
 */
static inline void bs_neon_set_key_byte(u64x2 *km, int byte, uint8_t v)
{
    for (int j = 0; j < 8; j++)
        km[8 * byte + j] = ((v >> j) & 1u) ? WIDE_NEON_ONES : WIDE_NEON_ZERO;
}

static inline void bs_neon_expand_aes_key(const aes_key_t *k, int rounds, u64x2 *km)
{
    rounds = wide_neon_clamp_rounds(rounds);
    for (int r = 0; r <= rounds; r++)
        for (int c = 0; c < 4; c++) {
            uint32_t w = k->rk[4 * r + c];
            for (int row = 0; row < 4; row++)
                bs_neon_set_key_byte(km + WIDE_NEON_BITS * r, row + 4 * c,
                                     (uint8_t)(w >> (8 * (3 - row))));
        }
}

static inline void bs_neon_expand_lin_key(const lin_key_t *k, int rounds, u64x2 *km)
{
    rounds = wide_neon_clamp_rounds(rounds);
    for (int r = 0; r <= rounds; r++)
        for (int j = 0; j < 4; j++) {
            uint32_t w = k->rk[4 * r + j];
            for (int b = 0; b < 4; b++)
                bs_neon_set_key_byte(km + WIDE_NEON_BITS * r, 4 * j + b,
                                     (uint8_t)(w >> (8 * b)));
        }
}

static inline void bs_neon_addkey(u64x2 *st, const u64x2 *km)
{
    for (int j = 0; j < WIDE_NEON_BITS; j++) st[j] ^= km[j];
}

/* --- S-box -------------------------------------------------------------------
 *
 * The same generated AES S-box circuit the AVX2/u32 paths use
 * (present_circuit8_neon_c2 is present_circuit8_u32_c2's u64x2 retype) -- one
 * circuit, shared, never a second copy. Identical call structure to
 * wide_bitslice32.h's bs32_sub_bytes.
 */
static inline void bs_neon_sub_bytes(u64x2 *st)
{
    for (int i = 0; i < 16; i++) {
        u64x2 *p = st + 8 * i;
        u64x2 y0, y1, y2, y3, y4, y5, y6, y7;
        present_circuit8_neon_c2(&y7, &y6, &y5, &y4, &y3, &y2, &y1, &y0,
                                  p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        p[0] = y0; p[1] = y1; p[2] = y2; p[3] = y3;
        p[4] = y4; p[5] = y5; p[6] = y6; p[7] = y7;
    }
}

/* --- AES linear layer --------------------------------------------------------
 *
 * ShiftRows costs nothing (it only decides which plane group MixColumns reads,
 * folded into the index). MixColumns is b_r = a_r ^ s ^ xtime(a_r ^ a_{r+1}),
 * s = a_0^a_1^a_2^a_3; the last round has no MixColumns. Copied verbatim from
 * wide_bitslice32.h's bs32_aes_lin.
 */
static inline void bs_neon_aes_lin(const u64x2 *t, u64x2 *st, int last)
{
    for (int c = 0; c < 4; c++) {
        const u64x2 *a[4];
        for (int r = 0; r < 4; r++) a[r] = t + 8 * (r + 4 * ((c + r) & 3));
        if (last) {
            for (int r = 0; r < 4; r++)
                for (int k = 0; k < 8; k++) st[8 * (r + 4 * c) + k] = a[r][k];
            continue;
        }
        u64x2 s[8];
        for (int k = 0; k < 8; k++)
            s[k] = a[0][k] ^ a[1][k] ^ a[2][k] ^ a[3][k];
        for (int r = 0; r < 4; r++) {
            const u64x2 *p = a[r], *q = a[(r + 1) & 3];
            u64x2 u[8], xt[8];
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

/* --- lin444 linear layer -----------------------------------------------------
 *
 * rot[][] is a pure change of plane index (rotl32 of a cipher word by c sends
 * bit p to (p+c) mod 32), built once per call from k->c. Copied verbatim from
 * wide_bitslice32.h's bs32_lin444.
 */
static inline void bs_neon_lin444(const u64x2 *t, u64x2 *st, int rot[3][32])
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

/* --- transpose-free entry points --------------------------------------------
 *
 * km must already be expanded; state and scratch are both WIDE_NEON_BITS words.
 * The planes ping-pong between the S-box (in place) and the linear layer (out of
 * place) each round, so the RETURN VALUE names the ciphertext buffer -- a caller
 * must wide_neon_unpack from it, not always from `state`. Copied verbatim from
 * wide_bitslice32.h's _bs kernels.
 */
static inline u64x2 *wide_aes_encrypt_neon_bs(const u64x2 *km, int rounds,
                                              u64x2 *state, u64x2 *scratch)
{
    rounds = wide_neon_clamp_rounds(rounds);
    u64x2 *cur = state, *nxt = scratch;
    bs_neon_addkey(cur, km);
    for (int r = 1; r <= rounds; r++) {
        bs_neon_sub_bytes(cur);
        bs_neon_aes_lin(cur, nxt, r == rounds);
        bs_neon_addkey(nxt, km + WIDE_NEON_BITS * r);
        u64x2 *sw = cur; cur = nxt; nxt = sw;
    }
    return cur;
}

static inline u64x2 *wide_lin_encrypt_neon_bs(const lin_key_t *k, const u64x2 *km,
                                              int rounds, u64x2 *state, u64x2 *scratch)
{
    rounds = wide_neon_clamp_rounds(rounds);
    u64x2 *cur = state, *nxt = scratch;
    int rot[3][32];
    for (int i = 0; i < 3; i++)
        for (int p = 0; p < 32; p++) rot[i][p] = ((p - k->c[i]) % 32 + 32) % 32;

    for (int r = 0; r < rounds; r++) {
        bs_neon_addkey(cur, km + WIDE_NEON_BITS * r);
        bs_neon_sub_bytes(cur);
        bs_neon_lin444(cur, nxt, rot);
        u64x2 *sw = cur; cur = nxt; nxt = sw;
    }
    bs_neon_addkey(cur, km + WIDE_NEON_BITS * rounds);
    return cur;
}

/* --- all-in-one entry points ------------------------------------------------- */

static inline void wide_aes_encrypt_neon(const aes_key_t *k, int rounds,
                                         const uint8_t *in, uint8_t *out)
{
    u64x2 a[WIDE_NEON_BITS], b[WIDE_NEON_BITS];
    u64x2 km[WIDE_NEON_KM_WORDS];

    bs_neon_expand_aes_key(k, rounds, km);
    wide_neon_pack(in, a);
    u64x2 *res = wide_aes_encrypt_neon_bs(km, rounds, a, b);
    wide_neon_unpack(res, out);
}

static inline void wide_lin_encrypt_neon(const lin_key_t *k, int rounds,
                                         const uint8_t *in, uint8_t *out)
{
    u64x2 a[WIDE_NEON_BITS], b[WIDE_NEON_BITS];
    u64x2 km[WIDE_NEON_KM_WORDS];

    bs_neon_expand_lin_key(k, rounds, km);
    wide_neon_pack(in, a);
    u64x2 *res = wide_lin_encrypt_neon_bs(k, km, rounds, a, b);
    wide_neon_unpack(res, out);
}

#endif /* __ARM_NEON */

#endif /* WIDE_BITSLICE_NEON_H */
