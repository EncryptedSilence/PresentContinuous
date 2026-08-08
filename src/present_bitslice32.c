/* Bitsliced implementation over a 32-bit word: 32 blocks encrypted in parallel.
 *
 * src/present_bitslice.c one word-width down. Same S-box circuits, same linear
 * layer bodies, same kernel-per-(circuit, layer) expansion -- only the type of a
 * slice changes, from uint64_t to uint32_t, so half as many blocks are in flight.
 *
 * That is a loss on a 64-bit host and a win on a 32-bit one, measured: on an
 * STM32F407 this path beats the u64 one by a median 1.2x, in 15 of 15 all-in-one
 * pairs across three build configurations (results/m4-speed.csv;
 * docs/m4-optimizations.md).
 *
 * The margin comes from the transpose, not from the round function. Phase 4 timed
 * both halves separately. present_transpose64, run twice, costs 1.7x to 2.6x per
 * byte what present_bitslice32_pack plus present_bitslice32_unpack cost, in all 15
 * cases -- a 64-word delta-swap runs six stages of two-instruction 64-bit
 * operations against five stages of one-instruction 32-bit ones. That difference is
 * the whole of the all-in-one margin and then some.
 *
 * The round function itself does not behave the way the plan predicted. It is true
 * that a uint64_t is a register pair here, so a 64-bit gate costs two instructions
 * and a state word costs two of the fourteen usable registers -- but for PRESENT-80
 * that is not decisive. With the state already transposed, the u64 kernel is the
 * *faster* of the two (u64/u32 of 0.78 to 0.88 across the three configurations): a
 * pbox round over a 15-gate S-box is dominated by moving state rather than
 * computing it, and doubling the word width halves the loads, stores and loop
 * iterations for the same block count. The gate-synthesis penalty does hold for
 * rounds that are not movement-dominated -- the other four benchmarked ciphers give
 * u64/u32 of 1.06 to 1.25 on their -bs rows -- but not for this one.
 *
 * The gate set is unchanged -- Thumb-2 has BIC and ORN, so the u64 circuits' ~a&b
 * and ~a|b map one gate to one instruction there too.
 *
 * Encryption only. Nothing needs to decrypt on the microcontroller target, and an
 * inverse path that no test exercises on the host is worse than no path at all.
 */

#include "internal.h"
#include "gen/sbox_circuits_u32.h"

/* --- lin444 in bitsliced form ----------------------------------------------------
 *
 * The bodies in lin444_body.h are parameterised by word type and XOR spelling
 * precisely so a third backend costs four lines. Forward direction only.
 */
#include "gen/lin_consts.h"
#include "lin444_body.h"
#include "gen/lin444_bodies.h"

#define U32_XOR(a, b) ((a) ^ (b))

#define SPEC_FWD(TAG, C0, C1, C2) \
    LIN444_SPEC_ONE(bs32_lin444, uint32_t, U32_XOR, TAG, LIN444_FWD_BODY_##TAG)
PRESENT_LIN444_LIST(SPEC_FWD)
#undef SPEC_FWD

/* --- rounds ----------------------------------------------------------------------
 *
 * One function per encryption kernel, as in the 64-bit path: the S-box circuit and
 * the linear layer are both fixed at compile time, so every state index is an
 * immediate and a permutation is register renaming rather than a table lookup.
 */
#define BS32_SBOX_TO(CID, BUF, I, D0, D1, D2, D3)                                     \
    {                                                                                 \
        uint32_t y0, y1, y2, y3;                                                      \
        present_circuit_u32_c##CID(&y3, &y2, &y1, &y0,                                \
                                   cur[4 * (I) + 0], cur[4 * (I) + 1],                \
                                   cur[4 * (I) + 2], cur[4 * (I) + 3]);               \
        BUF[D0] = y0; BUF[D1] = y1; BUF[D2] = y2; BUF[D3] = y3;                       \
    }
#define BS32_SBOX(CID, I, D0, D1, D2, D3) BS32_SBOX_TO(CID, alt, I, D0, D1, D2, D3)

#define BS32_SBOX8_TO(CID, BUF, I, D0, D1, D2, D3, D4, D5, D6, D7)                    \
    {                                                                                 \
        uint32_t y0, y1, y2, y3, y4, y5, y6, y7;                                      \
        present_circuit8_u32_c##CID(&y7, &y6, &y5, &y4, &y3, &y2, &y1, &y0,           \
                                    cur[8 * (I) + 0], cur[8 * (I) + 1],               \
                                    cur[8 * (I) + 2], cur[8 * (I) + 3],               \
                                    cur[8 * (I) + 4], cur[8 * (I) + 5],               \
                                    cur[8 * (I) + 6], cur[8 * (I) + 7]);              \
        BUF[D0] = y0; BUF[D1] = y1; BUF[D2] = y2; BUF[D3] = y3;                       \
        BUF[D4] = y4; BUF[D5] = y5; BUF[D6] = y6; BUF[D7] = y7;                       \
    }
#define BS32_SBOX8(CID, I, D0, D1, D2, D3, D4, D5, D6, D7)                            \
    BS32_SBOX8_TO(CID, alt, I, D0, D1, D2, D3, D4, D5, D6, D7)

/* rk_mask_enc[r][i] is all-ones or all-zeros by construction (see present.h), so
 * the narrowing keeps the mask exactly -- it is not a truncated value. */
#define BS32_KEY(R)                                                                   \
    { const uint64_t *km = ctx->rk_mask_enc[R];                                       \
      for (int i = 0; i < PRESENT_BLOCK_BITS; i++) cur[i] ^= (uint32_t)km[i]; }

/* After an odd number of ping-pong swaps the answer sits in the scratch buffer.
 * Returning the pointer rather than copying it back saves a 256-byte memcpy. */
#define BS32_TAIL return cur;

#define BS32_ENC_PBOX(KID, CID, TAG)                                                  \
static PRESENT_KERNEL_MAYBE_UNUSED                                                    \
uint32_t *bs32_enc_k##KID(const present_ctx_t *ctx, uint32_t *cur, uint32_t *alt)     \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        BS32_KEY(r)                                                                   \
        PRESENT_PBOX_STORE_##TAG(BS32_SBOX, CID)                                      \
        { uint32_t *tmp = cur; cur = alt; alt = tmp; }                                \
    }                                                                                 \
    BS32_KEY(rounds)                                                                  \
    BS32_TAIL                                                                         \
}

#define BS32_ENC_PBOX8(KID, CID, TAG)                                                 \
static PRESENT_KERNEL_MAYBE_UNUSED                                                    \
uint32_t *bs32_enc_k##KID(const present_ctx_t *ctx, uint32_t *cur, uint32_t *alt)     \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        BS32_KEY(r)                                                                   \
        PRESENT_PBOX_STORE8_##TAG(BS32_SBOX8, CID)                                    \
        { uint32_t *tmp = cur; cur = alt; alt = tmp; }                                \
    }                                                                                 \
    BS32_KEY(rounds)                                                                  \
    BS32_TAIL                                                                         \
}

#define BS32_ENC_LIN444(KID, CID, TAG)                                                \
static PRESENT_KERNEL_MAYBE_UNUSED                                                    \
uint32_t *bs32_enc_k##KID(const present_ctx_t *ctx, uint32_t *cur, uint32_t *alt)     \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        BS32_KEY(r)                                                                   \
        for (int i = 0; i < PRESENT_BS_N_SBOXES; i++)                                 \
            BS32_SBOX_TO(CID, cur, i, 4 * i + 0, 4 * i + 1, 4 * i + 2, 4 * i + 3)     \
        bs32_lin444_##TAG(cur, alt);                                                  \
        { uint32_t *tmp = cur; cur = alt; alt = tmp; }                                \
    }                                                                                 \
    BS32_KEY(rounds)                                                                  \
    BS32_TAIL                                                                         \
}

#define BS32_ENC_LIN4448(KID, CID, TAG)                                               \
static PRESENT_KERNEL_MAYBE_UNUSED                                                    \
uint32_t *bs32_enc_k##KID(const present_ctx_t *ctx, uint32_t *cur, uint32_t *alt)     \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        BS32_KEY(r)                                                                   \
        for (int i = 0; i < PRESENT_BLOCK_BITS / 8; i++)                              \
            BS32_SBOX8_TO(CID, cur, i, 8 * i + 0, 8 * i + 1, 8 * i + 2, 8 * i + 3,    \
                          8 * i + 4, 8 * i + 5, 8 * i + 6, 8 * i + 7)                 \
        bs32_lin444_##TAG(cur, alt);                                                  \
        { uint32_t *tmp = cur; cur = alt; alt = tmp; }                                \
    }                                                                                 \
    BS32_KEY(rounds)                                                                  \
    BS32_TAIL                                                                         \
}

#define BS32_ENC(KID, CID, KIND, TAG) BS32_ENC_##KIND(KID, CID, TAG)
PRESENT_KERNEL_ENC_LIST(BS32_ENC)
#undef BS32_ENC

/* --- transposition ---------------------------------------------------------------
 *
 * 32 blocks of 64 bits become 64 words of 32 bits, which is not a square matrix --
 * but it is two square ones. Bit b of a block lands in state[b], and bits 0..31 of
 * a block come from its low half while bits 32..63 come from its high half, so the
 * whole thing is two independent 32x32 bit transposes with no bit crossing between
 * them. That is the shape present_transpose64's recursive butterfly wants, and the
 * reason the original double loop said the butterfly "would need reworking rather
 * than retyping" was the non-square outer shape, not the arithmetic.
 *
 * tr32 below is the standard delta-swap transpose (Hacker's Delight 2nd ed. §7-3,
 * figure 7-6), in LSB-first bit numbering rather than the book's MSB-first: five
 * stages, each swapping a 2^j-wide block of columns between rows 2^j apart, so
 * 32*32 = 1024 bits move in 5 * 16 = 80 delta swaps instead of 1024 shift-mask-or
 * steps. It is its own inverse, which is why pack and unpack are the same routine
 * with the loads and stores exchanged.
 *
 * Why it was worth doing. The original comment said to "revisit only if the
 * Cortex-M4 numbers show it dominating". Phase 4 measured it dominating: the naive
 * pack and unpack together cost 267.7 cycles per byte on an STM32F407 at 168 MHz,
 * 81% of everything present_encrypt_bitslice32 did for PRESENT-80 at 16 rounds, so
 * that row was reporting a transpose rather than a cipher. The delta-swap form
 * costs 34.0 cyc/B, 7.9x less, and moves the published M4 result for PRESENT-80
 * from "the table path wins by 2.4x" to "the bitsliced path wins" -- which is the
 * direction x86 has always shown. Verified bit-identical to the double loop over
 * 20,000 random inputs for both functions before the replacement went in, and
 * covered afterwards by tests/test_impls.c and by the on-device known-answer gate.
 *
 * What those two do and do not catch, since an earlier version of this comment
 * overclaimed it. Composing pack, the kernel and unpack against the reference
 * cipher catches a wrong *bit* order: the round-key masks in ctx->rk_mask_enc and
 * the pbox store indices are both keyed to state-bit position, so permuting bits
 * changes the ciphertext. It does not catch a wrong *lane* order -- a consistent
 * permutation of which block sits in which bit position -- because pack and unpack
 * are the same routine run in opposite directions, so any such permutation cancels
 * and every block still decrypts to its own plaintext. That gap is closed by a
 * separate assertion in tests/test_impls.c which checks the layout against its
 * definition directly: slice j, bit b is bit j of block b.
 */
static void tr32(uint32_t *a)
{
    uint32_t m = 0x0000FFFFu;
    for (int j = 16; j != 0; j >>= 1, m ^= m << j)
        for (int k = 0; k < 32; k = (k + j + 1) & ~j) {
            uint32_t t = ((a[k] >> j) ^ a[k + j]) & m;
            a[k] ^= t << j;
            a[k + j] ^= t;
        }
}

void present_bitslice32_pack(const uint64_t *in, uint32_t *state)
{
    /* Deinterleave into the two halves in place -- state[b] and state[32 + b] are
     * where block b's low and high words go, and tr32 then transposes each 32-word
     * group where it already sits, so this needs no scratch at all. */
    for (int b = 0; b < PRESENT_BITSLICE32_BLOCKS; b++) {
        state[b] = (uint32_t)in[b];
        state[PRESENT_BITSLICE32_BLOCKS + b] = (uint32_t)(in[b] >> 32);
    }
    tr32(state);
    tr32(state + PRESENT_BITSLICE32_BLOCKS);
}

void present_bitslice32_unpack(const uint32_t *state, uint64_t *out)
{
    /* `state` is const and is still live for the caller (the kernels ping-pong and
     * a caller may unpack the same buffer twice), so this one does need a copy. */
    uint32_t lo[PRESENT_BITSLICE32_BLOCKS], hi[PRESENT_BITSLICE32_BLOCKS];

    for (int i = 0; i < PRESENT_BITSLICE32_BLOCKS; i++) {
        lo[i] = state[i];
        hi[i] = state[PRESENT_BITSLICE32_BLOCKS + i];
    }
    tr32(lo);
    tr32(hi);
    for (int b = 0; b < PRESENT_BITSLICE32_BLOCKS; b++)
        out[b] = (uint64_t)lo[b] | ((uint64_t)hi[b] << 32);
}

/* The two entry points below exist twice: once dispatching on the variant at run
 * time, once calling a single kernel chosen at compile time. See PRESENT_ONE_CIPHER
 * in internal.h for what the second form is for and what it requires.
 *
 * They are written out separately rather than sharing one dispatch helper because
 * the run-time form is what every published measurement was taken with, and routing
 * it through a helper that can fail would add a null test to the inside of a timed
 * loop. The bodies are three lines each; the duplication is cheaper than the
 * measurement artefact. */
#ifdef PRESENT_ONE_CIPHER

uint32_t *present_encrypt_bitslice32_bs(const present_ctx_t *ctx, uint32_t *state,
                                        uint32_t *scratch)
{
    return PRESENT_ONE_CIPHER_KERNEL(bs32_enc_k)(ctx, state, scratch);
}

void present_encrypt_bitslice32(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{
    uint32_t a[PRESENT_BLOCK_BITS], b[PRESENT_BLOCK_BITS];
    present_bitslice32_pack(in, a);
    present_bitslice32_unpack(PRESENT_ONE_CIPHER_KERNEL(bs32_enc_k)(ctx, a, b), out);
}

#else

uint32_t *present_encrypt_bitslice32_bs(const present_ctx_t *ctx, uint32_t *state,
                                        uint32_t *scratch)
{
    switch (ctx->var->kernel_enc) {
#define CASE_ENC(KID, CID, KIND, TAG) case KID: return bs32_enc_k##KID(ctx, state, scratch);
    PRESENT_KERNEL_ENC_LIST(CASE_ENC)
#undef CASE_ENC
    default: return state;   /* rejected by present_variant_check */
    }
}

void present_encrypt_bitslice32(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{
    uint32_t a[PRESENT_BLOCK_BITS], b[PRESENT_BLOCK_BITS];
    present_bitslice32_pack(in, a);

    uint32_t *res;
    switch (ctx->var->kernel_enc) {
#define CASE_ENC(KID, CID, KIND, TAG) case KID: res = bs32_enc_k##KID(ctx, a, b); break;
    PRESENT_KERNEL_ENC_LIST(CASE_ENC)
#undef CASE_ENC
    default: return;   /* rejected by present_variant_check; nothing to compute */
    }
    present_bitslice32_unpack(res, out);
}

#endif /* PRESENT_ONE_CIPHER */
