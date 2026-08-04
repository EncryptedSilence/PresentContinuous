/* Bitsliced implementation: 64 blocks encrypted in parallel.
 *
 * State bit i of all 64 blocks lives in one uint64_t, so a *permutation* layer is
 * register renaming rather than bit twiddling, and the S-box becomes a boolean
 * circuit evaluated on as many words as it is wide. The circuits are synthesised
 * per S-box by tools/sbox_synth (4-bit, exhaustive) or tools/sbox_synth8 (8-bit,
 * a BDD heuristic), and specialised here with the X-macro list, so the gate
 * sequence is inlined rather than reached through a function pointer.
 *
 * A general linear layer is not free here, which is why this file compiles one
 * round function per (S-box circuit, linear layer) pair rather than driving
 * everything from the generic column form in the variant descriptor. Cost per
 * round, for 64 blocks:
 *
 *   pbox     64 key XORs + 16 S-box circuits + 0 (the permutation is the store)
 *   pbox8    64 key XORs +  8 S-box circuits + 0 (likewise)
 *   lin444   64 key XORs + 16 S-box circuits + 144, 160 or 192 XORs
 *
 * The widths are not comparable per round: 16 of PRESENT's circuits are 240 gates,
 * 8 of cipher-D's are 8856. Bitslicing pays off exactly when the S-box is small
 * enough that a permutation being free is what dominates, and an 8-bit S-box is
 * not -- cipher-D's table path beats its bitsliced one by 6.5x scalar, 2.8x AVX2,
 * where for PRESENT the bitsliced path wins by 8.4x.
 *
 * 192 rather than the ~560 a dense 64x64 matrix would need, because lin444 is
 * evaluated in its chained form: each output word is three XORs per bit, and the
 * later words reuse the earlier ones. Rotation is free -- in bitsliced form ROTL is
 * just reading a different register index, provided the constant is a literal.
 *
 * Below 192 when the constants let two output words share a pair of operands;
 * analysis/present_sat/slp.py enumerates the sharings and emits the program, so
 * which tier a triple lands in is decided by the constants alone. Note that fewer
 * XORs is not the same as less work: a shared temporary is 16 words that cannot
 * stay in registers, so it trades 16 XORs for 16 stores, and the 144-XOR form
 * measures no faster than the 160-XOR one on either backend.
 *
 * Transposition into and out of bitsliced form is amortised over 31 rounds.
 */

#include <string.h>

#include "internal.h"
#include "gen/sbox_circuits.h"

int present_circuit_gates(int circuit_id)
{
    if (circuit_id < 0 || circuit_id >= PRESENT_N_CIRCUITS) return -1;
    return present_circuit_gates_u64[circuit_id];
}

/* Both backends' circuits for one S-box share this mask by construction, so a
 * single pair of corrected round-key arrays serves the scalar and AVX2 paths. */
int present_circuit_outcomp_mask(int circuit_id)
{
    if (circuit_id < 0 || circuit_id >= PRESENT_N_CIRCUITS) return 0;
    return present_circuit_outcomp[circuit_id];
}

/* The AVX2 circuit is synthesised over a smaller gate set (no ~a|b, no ~(a^b)),
 * so its count is usually a little higher -- but every gate is one instruction. */
int present_circuit_gates_for_avx2(int circuit_id)
{
    if (circuit_id < 0 || circuit_id >= PRESENT_N_CIRCUITS) return -1;
    return present_circuit_gates_avx2[circuit_id];
}

/* --- lin444 in bitsliced form ----------------------------------------------------
 *
 * Bodies live in lin444_body.h, shared with the AVX2 backend. Here they are
 * instantiated once per rotation triple the generator saw, with the constants as
 * literals so every BS() index folds to a register number.
 */
#include "gen/lin_consts.h"
#include "lin444_body.h"
#include "gen/lin444_bodies.h"

#define U64_XOR(a, b) ((a) ^ (b))

#define SPEC_FWD(TAG, C0, C1, C2) \
    LIN444_SPEC_ONE(bs_lin444, uint64_t, U64_XOR, TAG, LIN444_FWD_BODY_##TAG)
#define SPEC_INV(TAG, C0, C1, C2) \
    LIN444_SPEC_ONE(bs_lin444_inv, uint64_t, U64_XOR, TAG, LIN444_INV_BODY_##TAG)
PRESENT_LIN444_LIST(SPEC_FWD)
PRESENT_LIN444_LIST(SPEC_INV)
#undef SPEC_FWD
#undef SPEC_INV

/* --- rounds ----------------------------------------------------------------------
 *
 * One function per kernel, a kernel being a round function with the S-box circuit
 * and the linear layer both fixed at compile time; tools/gen_c.py decides which
 * (circuit, layer) pairs any variant actually needs. Every state index below is
 * therefore an immediate, and in particular a permutation is register renaming
 * rather than a table lookup per bit.
 *
 * Encryption folds the permutation into the S-box store, so the layer is free.
 * Decryption cannot: the inverse layer runs *before* the inverse S-box, so it is a
 * list of 64 constant-index moves.
 */
#define BS_SBOX_TO(CID, BUF, I, D0, D1, D2, D3)                                       \
    {                                                                                 \
        uint64_t y0, y1, y2, y3;                                                      \
        present_circuit_u64_c##CID(&y3, &y2, &y1, &y0,                                \
                                   cur[4 * (I) + 0], cur[4 * (I) + 1],                \
                                   cur[4 * (I) + 2], cur[4 * (I) + 3]);               \
        BUF[D0] = y0; BUF[D1] = y1; BUF[D2] = y2; BUF[D3] = y3;                       \
    }
#define BS_SBOX(CID, I, D0, D1, D2, D3) BS_SBOX_TO(CID, alt, I, D0, D1, D2, D3)
#define BS_MOVE(D, S) alt[D] = cur[S];

/* Same shape one width up. The circuit is two orders of magnitude larger -- 1107
 * gates against 15 -- so unlike the 4-bit case the eight stores are noise and the
 * whole round is S-box. */
#define BS_SBOX8_TO(CID, BUF, I, D0, D1, D2, D3, D4, D5, D6, D7)                      \
    {                                                                                 \
        uint64_t y0, y1, y2, y3, y4, y5, y6, y7;                                      \
        present_circuit8_u64_c##CID(&y7, &y6, &y5, &y4, &y3, &y2, &y1, &y0,           \
                                    cur[8 * (I) + 0], cur[8 * (I) + 1],               \
                                    cur[8 * (I) + 2], cur[8 * (I) + 3],               \
                                    cur[8 * (I) + 4], cur[8 * (I) + 5],               \
                                    cur[8 * (I) + 6], cur[8 * (I) + 7]);              \
        BUF[D0] = y0; BUF[D1] = y1; BUF[D2] = y2; BUF[D3] = y3;                       \
        BUF[D4] = y4; BUF[D5] = y5; BUF[D6] = y6; BUF[D7] = y7;                       \
    }
#define BS_SBOX8(CID, I, D0, D1, D2, D3, D4, D5, D6, D7)                              \
    BS_SBOX8_TO(CID, alt, I, D0, D1, D2, D3, D4, D5, D6, D7)

#define BS_KEY(WHICH, R)                                                              \
    { const uint64_t *km = ctx->rk_mask_##WHICH[R];                                   \
      for (int i = 0; i < PRESENT_BLOCK_BITS; i++) cur[i] ^= km[i]; }

/* After an odd number of ping-pong swaps the answer sits in the scratch buffer.
 * Returning the pointer rather than copying it back saves a 512-byte memcpy. */
#define BS_TAIL return cur;

#define BS_ENC_PBOX(KID, CID, TAG)                                                    \
static uint64_t *bs_enc_k##KID(const present_ctx_t *ctx, uint64_t *cur, uint64_t *alt)  \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        BS_KEY(enc, r)                                                                \
        PRESENT_PBOX_STORE_##TAG(BS_SBOX, CID)                                        \
        { uint64_t *tmp = cur; cur = alt; alt = tmp; }                                \
    }                                                                                 \
    BS_KEY(enc, rounds)                                                               \
    BS_TAIL                                                                           \
}

#define BS_ENC_PBOX8(KID, CID, TAG)                                                   \
static uint64_t *bs_enc_k##KID(const present_ctx_t *ctx, uint64_t *cur, uint64_t *alt)  \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        BS_KEY(enc, r)                                                                \
        PRESENT_PBOX_STORE8_##TAG(BS_SBOX8, CID)                                      \
        { uint64_t *tmp = cur; cur = alt; alt = tmp; }                                \
    }                                                                                 \
    BS_KEY(enc, rounds)                                                               \
    BS_TAIL                                                                           \
}

#define BS_ENC_LIN444(KID, CID, TAG)                                                  \
static uint64_t *bs_enc_k##KID(const present_ctx_t *ctx, uint64_t *cur, uint64_t *alt)  \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        BS_KEY(enc, r)                                                                \
        for (int i = 0; i < PRESENT_BS_N_SBOXES; i++)                                    \
            BS_SBOX_TO(CID, cur, i, 4 * i + 0, 4 * i + 1, 4 * i + 2, 4 * i + 3)       \
        bs_lin444_##TAG(cur, alt);                                                    \
        { uint64_t *tmp = cur; cur = alt; alt = tmp; }                                \
    }                                                                                 \
    BS_KEY(enc, rounds)                                                               \
    BS_TAIL                                                                           \
}

#define BS_DEC_BODY(KID, CID, LAYER)                                                  \
static uint64_t *bs_dec_k##KID(const present_ctx_t *ctx, uint64_t *cur, uint64_t *alt)  \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    BS_KEY(dec, rounds)                                                               \
    for (int r = rounds - 1; r >= 0; r--) {                                           \
        LAYER                                                                         \
        { uint64_t *tmp = cur; cur = alt; alt = tmp; }                                \
        for (int i = 0; i < PRESENT_BS_N_SBOXES; i++)                                    \
            BS_SBOX_TO(CID, cur, i, 4 * i + 0, 4 * i + 1, 4 * i + 2, 4 * i + 3)       \
        BS_KEY(dec, r)                                                                \
    }                                                                                 \
    BS_TAIL                                                                           \
}

#define BS_DEC_PBOX8(KID, CID, TAG)                                                   \
static uint64_t *bs_dec_k##KID(const present_ctx_t *ctx, uint64_t *cur, uint64_t *alt)  \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    BS_KEY(dec, rounds)                                                               \
    for (int r = rounds - 1; r >= 0; r--) {                                           \
        PRESENT_PBOX_MOVEINV_##TAG(BS_MOVE)                                           \
        { uint64_t *tmp = cur; cur = alt; alt = tmp; }                                \
        for (int i = 0; i < PRESENT_BLOCK_BITS / 8; i++)                              \
            BS_SBOX8_TO(CID, cur, i, 8 * i + 0, 8 * i + 1, 8 * i + 2, 8 * i + 3,      \
                        8 * i + 4, 8 * i + 5, 8 * i + 6, 8 * i + 7)                   \
        BS_KEY(dec, r)                                                                \
    }                                                                                 \
    BS_TAIL                                                                           \
}

/* lin444 at 8 bits. Unlike the permutation it cannot fold into the store -- the
 * S-box writes back in place and the layer then runs its XOR chain into the other
 * buffer -- but the layer is the same 64-bit map either way, so the same body serves
 * both widths and only the S-box loop changes. */
#define BS_ENC_LIN4448(KID, CID, TAG)                                                 \
static uint64_t *bs_enc_k##KID(const present_ctx_t *ctx, uint64_t *cur, uint64_t *alt)  \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        BS_KEY(enc, r)                                                                \
        for (int i = 0; i < PRESENT_BLOCK_BITS / 8; i++)                              \
            BS_SBOX8_TO(CID, cur, i, 8 * i + 0, 8 * i + 1, 8 * i + 2, 8 * i + 3,      \
                        8 * i + 4, 8 * i + 5, 8 * i + 6, 8 * i + 7)                   \
        bs_lin444_##TAG(cur, alt);                                                    \
        { uint64_t *tmp = cur; cur = alt; alt = tmp; }                                \
    }                                                                                 \
    BS_KEY(enc, rounds)                                                               \
    BS_TAIL                                                                           \
}

#define BS_DEC_LIN4448(KID, CID, TAG)                                                 \
static uint64_t *bs_dec_k##KID(const present_ctx_t *ctx, uint64_t *cur, uint64_t *alt)  \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    BS_KEY(dec, rounds)                                                               \
    for (int r = rounds - 1; r >= 0; r--) {                                           \
        bs_lin444_inv_##TAG(cur, alt);                                                \
        { uint64_t *tmp = cur; cur = alt; alt = tmp; }                                \
        for (int i = 0; i < PRESENT_BLOCK_BITS / 8; i++)                              \
            BS_SBOX8_TO(CID, cur, i, 8 * i + 0, 8 * i + 1, 8 * i + 2, 8 * i + 3,      \
                        8 * i + 4, 8 * i + 5, 8 * i + 6, 8 * i + 7)                   \
        BS_KEY(dec, r)                                                                \
    }                                                                                 \
    BS_TAIL                                                                           \
}

#define BS_DEC_PBOX(KID, CID, TAG)   BS_DEC_BODY(KID, CID, PRESENT_PBOX_MOVEINV_##TAG(BS_MOVE))
#define BS_DEC_LIN444(KID, CID, TAG) BS_DEC_BODY(KID, CID, bs_lin444_inv_##TAG(cur, alt);)

#define BS_ENC(KID, CID, KIND, TAG) BS_ENC_##KIND(KID, CID, TAG)
#define BS_DEC(KID, CID, KIND, TAG) BS_DEC_##KIND(KID, CID, TAG)
PRESENT_KERNEL_ENC_LIST(BS_ENC)
PRESENT_KERNEL_DEC_LIST(BS_DEC)
#undef BS_ENC
#undef BS_DEC

uint64_t *present_encrypt_bitslice_bs(const present_ctx_t *ctx, uint64_t *state,
                                      uint64_t *scratch)
{
    switch (ctx->var->kernel_enc) {
#define CASE_ENC(KID, CID, KIND, TAG) case KID: return bs_enc_k##KID(ctx, state, scratch);
    PRESENT_KERNEL_ENC_LIST(CASE_ENC)
#undef CASE_ENC
    default: return state;   /* rejected by present_variant_check */
    }
}

uint64_t *present_decrypt_bitslice_bs(const present_ctx_t *ctx, uint64_t *state,
                                      uint64_t *scratch)
{
    switch (ctx->var->kernel_dec) {
#define CASE_DEC(KID, CID, KIND, TAG) case KID: return bs_dec_k##KID(ctx, state, scratch);
    PRESENT_KERNEL_DEC_LIST(CASE_DEC)
#undef CASE_DEC
    default: return state;   /* rejected by present_variant_check */
    }
}

void present_encrypt_bitslice(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{
    uint64_t a[PRESENT_BLOCK_BITS], b[PRESENT_BLOCK_BITS];
    present_transpose64(in, a);

    uint64_t *res;
    switch (ctx->var->kernel_enc) {
#define CASE_ENC(KID, CID, KIND, TAG) case KID: res = bs_enc_k##KID(ctx, a, b); break;
    PRESENT_KERNEL_ENC_LIST(CASE_ENC)
#undef CASE_ENC
    default: return;   /* rejected by present_variant_check; nothing to compute */
    }
    present_transpose64(res, out);
}

void present_decrypt_bitslice(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{
    uint64_t a[PRESENT_BLOCK_BITS], b[PRESENT_BLOCK_BITS];
    present_transpose64(in, a);

    uint64_t *res;
    switch (ctx->var->kernel_dec) {
#define CASE_DEC(KID, CID, KIND, TAG) case KID: res = bs_dec_k##KID(ctx, a, b); break;
    PRESENT_KERNEL_DEC_LIST(CASE_DEC)
#undef CASE_DEC
    default: return;   /* rejected by present_variant_check; nothing to compute */
    }
    present_transpose64(res, out);
}
