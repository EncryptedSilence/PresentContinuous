/* Bitsliced implementation over a 32-bit word: 32 blocks encrypted in parallel.
 *
 * src/present_bitslice.c one word-width down. Same S-box circuits, same linear
 * layer bodies, same kernel-per-(circuit, layer) expansion -- only the type of a
 * slice changes, from uint64_t to uint32_t, so half as many blocks are in flight.
 *
 * That is a loss on a 64-bit host and the point on a 32-bit one. A uint64_t on
 * Cortex-M4 is a register pair, so every gate of the circuit costs two
 * instructions and every state word costs two of the fourteen usable registers;
 * at 32 bits a gate is one instruction and the round function has somewhere to
 * keep its operands. The gate set is unchanged -- Thumb-2 has BIC and ORN, so the
 * u64 circuits' ~a&b and ~a|b map one gate to one instruction there too.
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
static uint32_t *bs32_enc_k##KID(const present_ctx_t *ctx, uint32_t *cur, uint32_t *alt) \
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
static uint32_t *bs32_enc_k##KID(const present_ctx_t *ctx, uint32_t *cur, uint32_t *alt) \
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
static uint32_t *bs32_enc_k##KID(const present_ctx_t *ctx, uint32_t *cur, uint32_t *alt) \
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
static uint32_t *bs32_enc_k##KID(const present_ctx_t *ctx, uint32_t *cur, uint32_t *alt) \
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
 * 32 blocks of 64 bits become 64 words of 32 bits. The obvious double loop: the
 * transpose is amortised over every round, and unlike present_transpose64 this one
 * is not square, so the recursive butterfly would need reworking rather than
 * retyping. Revisit only if the Cortex-M4 numbers show it dominating.
 */
void present_bitslice32_pack(const uint64_t *in, uint32_t *state)
{
    for (int bit = 0; bit < PRESENT_BLOCK_BITS; bit++) {
        uint32_t w = 0;
        for (int blk = 0; blk < PRESENT_BITSLICE32_BLOCKS; blk++)
            w |= (uint32_t)((in[blk] >> bit) & 1u) << blk;
        state[bit] = w;
    }
}

void present_bitslice32_unpack(const uint32_t *state, uint64_t *out)
{
    for (int blk = 0; blk < PRESENT_BITSLICE32_BLOCKS; blk++) {
        uint64_t b = 0;
        for (int bit = 0; bit < PRESENT_BLOCK_BITS; bit++)
            b |= (uint64_t)((state[bit] >> blk) & 1u) << bit;
        out[blk] = b;
    }
}

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
