/* ARM-NEON bitsliced implementation: 128 blocks encrypted in parallel.
 *
 * The scalar path in src/present_bitslice.c keeps bit i of 64 blocks in one
 * uint64_t. This is the same algorithm one lane wider: bit i of 128 blocks lives
 * in one 128-bit NEON register (`u64x2`, two 64-bit lanes), so a round is the same
 * S-box circuits and key XOR over a type twice as wide. On Cortex-A7 that halves
 * the instruction count per block and, more importantly, lets the 64 live
 * bit-planes spill to NEON's sixteen 128-bit registers rather than fighting over
 * the fourteen usable 32-bit GP registers, which is what the scalar 64-bit path
 * does on a 32-bit core.
 *
 * The circuits are the *same* boolean programs as the scalar backend, retyped onto
 * u64x2 by tools/gen_neon_circuits.py: their gate set (& | ^ ~) is exactly what a
 * GCC vector type supports, so every gate is one NEON instruction and the result is
 * bit-for-bit identical to the scalar circuit. No new synthesis, nothing to drift.
 *
 * The linear layers are shared verbatim with the scalar and AVX2 backends through
 * lin444_body.h -- only the element type and the XOR change. A permutation costs
 * nothing here too: it is which register index the S-box output is stored to.
 *
 * Structured to mirror present_bitslice.c line for line so the two stay in step;
 * see that file for the commentary on kernels, ping-pong buffers and the tail.
 */

#include <string.h>

#include "internal.h"

#if defined(__ARM_NEON)

#include "gen/sbox_circuits_neon.h"   /* defines u64x2 and present_circuit*_neon_c* */

int present_have_neon(void) { return 1; }

/* --- lin444 in bitsliced form, instantiated over the vector type ------------------ */
#include "gen/lin_consts.h"
#include "lin444_body.h"
#include "gen/lin444_bodies.h"

#define NEON_XOR(a, b) ((a) ^ (b))

#define SPEC_FWD(TAG, C0, C1, C2) \
    LIN444_SPEC_ONE(neon_lin444, u64x2, NEON_XOR, TAG, LIN444_FWD_BODY_##TAG)
#define SPEC_INV(TAG, C0, C1, C2) \
    LIN444_SPEC_ONE(neon_lin444_inv, u64x2, NEON_XOR, TAG, LIN444_INV_BODY_##TAG)
PRESENT_LIN444_LIST(SPEC_FWD)
PRESENT_LIN444_LIST(SPEC_INV)
#undef SPEC_FWD
#undef SPEC_INV

/* --- rounds ----------------------------------------------------------------------- */
#define NB_SBOX_TO(CID, BUF, I, D0, D1, D2, D3)                                        \
    {                                                                                  \
        u64x2 y0, y1, y2, y3;                                                           \
        present_circuit_neon_c##CID(&y3, &y2, &y1, &y0,                                 \
                                    cur[4 * (I) + 0], cur[4 * (I) + 1],                 \
                                    cur[4 * (I) + 2], cur[4 * (I) + 3]);               \
        BUF[D0] = y0; BUF[D1] = y1; BUF[D2] = y2; BUF[D3] = y3;                         \
    }
#define NB_SBOX(CID, I, D0, D1, D2, D3) NB_SBOX_TO(CID, alt, I, D0, D1, D2, D3)
#define NB_MOVE(D, S) alt[D] = cur[S];

#define NB_SBOX8_TO(CID, BUF, I, D0, D1, D2, D3, D4, D5, D6, D7)                        \
    {                                                                                  \
        u64x2 y0, y1, y2, y3, y4, y5, y6, y7;                                           \
        present_circuit8_neon_c##CID(&y7, &y6, &y5, &y4, &y3, &y2, &y1, &y0,            \
                                     cur[8 * (I) + 0], cur[8 * (I) + 1],               \
                                     cur[8 * (I) + 2], cur[8 * (I) + 3],               \
                                     cur[8 * (I) + 4], cur[8 * (I) + 5],               \
                                     cur[8 * (I) + 6], cur[8 * (I) + 7]);              \
        BUF[D0] = y0; BUF[D1] = y1; BUF[D2] = y2; BUF[D3] = y3;                         \
        BUF[D4] = y4; BUF[D5] = y5; BUF[D6] = y6; BUF[D7] = y7;                         \
    }
#define NB_SBOX8(CID, I, D0, D1, D2, D3, D4, D5, D6, D7)                                \
    NB_SBOX8_TO(CID, alt, I, D0, D1, D2, D3, D4, D5, D6, D7)

/* Round key bit i is the same for all 128 blocks (single key), so the 0/~0 mask
 * word broadcasts to both lanes -- the vector analogue of _mm256_set1_epi64x. */
#define NB_KEY(WHICH, R)                                                               \
    { const uint64_t *km = ctx->rk_mask_##WHICH[R];                                    \
      for (int i = 0; i < PRESENT_BLOCK_BITS; i++) {                                    \
          u64x2 m = {km[i], km[i]}; cur[i] ^= m; } }

#define NB_TAIL return cur;

#define NB_ENC_PBOX(KID, CID, TAG)                                                      \
static u64x2 *neon_enc_k##KID(const present_ctx_t *ctx, u64x2 *cur, u64x2 *alt)         \
{                                                                                      \
    const int rounds = ctx->var->rounds;                                               \
    for (int r = 0; r < rounds; r++) {                                                 \
        NB_KEY(enc, r)                                                                  \
        PRESENT_PBOX_STORE_##TAG(NB_SBOX, CID)                                          \
        { u64x2 *tmp = cur; cur = alt; alt = tmp; }                                     \
    }                                                                                  \
    NB_KEY(enc, rounds)                                                                 \
    NB_TAIL                                                                             \
}

#define NB_ENC_PBOX8(KID, CID, TAG)                                                     \
static u64x2 *neon_enc_k##KID(const present_ctx_t *ctx, u64x2 *cur, u64x2 *alt)         \
{                                                                                      \
    const int rounds = ctx->var->rounds;                                               \
    for (int r = 0; r < rounds; r++) {                                                 \
        NB_KEY(enc, r)                                                                  \
        PRESENT_PBOX_STORE8_##TAG(NB_SBOX8, CID)                                        \
        { u64x2 *tmp = cur; cur = alt; alt = tmp; }                                     \
    }                                                                                  \
    NB_KEY(enc, rounds)                                                                 \
    NB_TAIL                                                                             \
}

#define NB_ENC_LIN444(KID, CID, TAG)                                                    \
static u64x2 *neon_enc_k##KID(const present_ctx_t *ctx, u64x2 *cur, u64x2 *alt)         \
{                                                                                      \
    const int rounds = ctx->var->rounds;                                               \
    for (int r = 0; r < rounds; r++) {                                                 \
        NB_KEY(enc, r)                                                                  \
        for (int i = 0; i < PRESENT_BS_N_SBOXES; i++)                                   \
            NB_SBOX_TO(CID, cur, i, 4 * i + 0, 4 * i + 1, 4 * i + 2, 4 * i + 3)         \
        neon_lin444_##TAG(cur, alt);                                                    \
        { u64x2 *tmp = cur; cur = alt; alt = tmp; }                                     \
    }                                                                                  \
    NB_KEY(enc, rounds)                                                                 \
    NB_TAIL                                                                             \
}

#define NB_DEC_BODY(KID, CID, LAYER)                                                    \
static u64x2 *neon_dec_k##KID(const present_ctx_t *ctx, u64x2 *cur, u64x2 *alt)         \
{                                                                                      \
    const int rounds = ctx->var->rounds;                                               \
    NB_KEY(dec, rounds)                                                                 \
    for (int r = rounds - 1; r >= 0; r--) {                                             \
        LAYER                                                                           \
        { u64x2 *tmp = cur; cur = alt; alt = tmp; }                                     \
        for (int i = 0; i < PRESENT_BS_N_SBOXES; i++)                                   \
            NB_SBOX_TO(CID, cur, i, 4 * i + 0, 4 * i + 1, 4 * i + 2, 4 * i + 3)         \
        NB_KEY(dec, r)                                                                  \
    }                                                                                  \
    NB_TAIL                                                                             \
}

#define NB_DEC_PBOX8(KID, CID, TAG)                                                     \
static u64x2 *neon_dec_k##KID(const present_ctx_t *ctx, u64x2 *cur, u64x2 *alt)         \
{                                                                                      \
    const int rounds = ctx->var->rounds;                                               \
    NB_KEY(dec, rounds)                                                                 \
    for (int r = rounds - 1; r >= 0; r--) {                                             \
        PRESENT_PBOX_MOVEINV_##TAG(NB_MOVE)                                             \
        { u64x2 *tmp = cur; cur = alt; alt = tmp; }                                     \
        for (int i = 0; i < PRESENT_BLOCK_BITS / 8; i++)                                \
            NB_SBOX8_TO(CID, cur, i, 8 * i + 0, 8 * i + 1, 8 * i + 2, 8 * i + 3,        \
                        8 * i + 4, 8 * i + 5, 8 * i + 6, 8 * i + 7)                     \
        NB_KEY(dec, r)                                                                  \
    }                                                                                  \
    NB_TAIL                                                                             \
}

#define NB_ENC_LIN4448(KID, CID, TAG)                                                   \
static u64x2 *neon_enc_k##KID(const present_ctx_t *ctx, u64x2 *cur, u64x2 *alt)         \
{                                                                                      \
    const int rounds = ctx->var->rounds;                                               \
    for (int r = 0; r < rounds; r++) {                                                 \
        NB_KEY(enc, r)                                                                  \
        for (int i = 0; i < PRESENT_BLOCK_BITS / 8; i++)                                \
            NB_SBOX8_TO(CID, cur, i, 8 * i + 0, 8 * i + 1, 8 * i + 2, 8 * i + 3,        \
                        8 * i + 4, 8 * i + 5, 8 * i + 6, 8 * i + 7)                     \
        neon_lin444_##TAG(cur, alt);                                                    \
        { u64x2 *tmp = cur; cur = alt; alt = tmp; }                                     \
    }                                                                                  \
    NB_KEY(enc, rounds)                                                                 \
    NB_TAIL                                                                             \
}

#define NB_DEC_LIN4448(KID, CID, TAG)                                                   \
static u64x2 *neon_dec_k##KID(const present_ctx_t *ctx, u64x2 *cur, u64x2 *alt)         \
{                                                                                      \
    const int rounds = ctx->var->rounds;                                               \
    NB_KEY(dec, rounds)                                                                 \
    for (int r = rounds - 1; r >= 0; r--) {                                             \
        neon_lin444_inv_##TAG(cur, alt);                                                \
        { u64x2 *tmp = cur; cur = alt; alt = tmp; }                                     \
        for (int i = 0; i < PRESENT_BLOCK_BITS / 8; i++)                                \
            NB_SBOX8_TO(CID, cur, i, 8 * i + 0, 8 * i + 1, 8 * i + 2, 8 * i + 3,        \
                        8 * i + 4, 8 * i + 5, 8 * i + 6, 8 * i + 7)                     \
        NB_KEY(dec, r)                                                                  \
    }                                                                                  \
    NB_TAIL                                                                             \
}

#define NB_DEC_PBOX(KID, CID, TAG)   NB_DEC_BODY(KID, CID, PRESENT_PBOX_MOVEINV_##TAG(NB_MOVE))
#define NB_DEC_LIN444(KID, CID, TAG) NB_DEC_BODY(KID, CID, neon_lin444_inv_##TAG(cur, alt);)

#define NB_ENC(KID, CID, KIND, TAG) NB_ENC_##KIND(KID, CID, TAG)
#define NB_DEC(KID, CID, KIND, TAG) NB_DEC_##KIND(KID, CID, TAG)
PRESENT_KERNEL_ENC_LIST(NB_ENC)
PRESENT_KERNEL_DEC_LIST(NB_DEC)
#undef NB_ENC
#undef NB_DEC

/* --- native (state-already-bitsliced) entry points -------------------------------- */
uint64_t *present_encrypt_neon_bs(const present_ctx_t *ctx, uint64_t *state, uint64_t *scratch)
{
    u64x2 *cur = (u64x2 *)state, *alt = (u64x2 *)scratch;
    switch (ctx->var->kernel_enc) {
#define CASE_ENC(KID, CID, KIND, TAG) case KID: return (uint64_t *)neon_enc_k##KID(ctx, cur, alt);
    PRESENT_KERNEL_ENC_LIST(CASE_ENC)
#undef CASE_ENC
    default: return state;
    }
}

uint64_t *present_decrypt_neon_bs(const present_ctx_t *ctx, uint64_t *state, uint64_t *scratch)
{
    u64x2 *cur = (u64x2 *)state, *alt = (u64x2 *)scratch;
    switch (ctx->var->kernel_dec) {
#define CASE_DEC(KID, CID, KIND, TAG) case KID: return (uint64_t *)neon_dec_k##KID(ctx, cur, alt);
    PRESENT_KERNEL_DEC_LIST(CASE_DEC)
#undef CASE_DEC
    default: return state;
    }
}

/* --- pack/unpack: 128 blocks <-> 64 two-lane planes -------------------------------
 * Lane 0 holds blocks 0..63, lane 1 blocks 64..127, so each 64-block group is the
 * existing scalar transpose and the two are then interleaved into the vector. */
void present_neon_pack(const uint64_t *in, uint64_t *state)
{
    uint64_t p0[PRESENT_BLOCK_BITS], p1[PRESENT_BLOCK_BITS];
    present_transpose64(in, p0);
    present_transpose64(in + PRESENT_BLOCK_BITS, p1);
    u64x2 *st = (u64x2 *)state;
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++) {
        u64x2 v = {p0[i], p1[i]};
        st[i] = v;
    }
}

void present_neon_unpack(const uint64_t *state, uint64_t *out)
{
    const u64x2 *st = (const u64x2 *)state;
    uint64_t p0[PRESENT_BLOCK_BITS], p1[PRESENT_BLOCK_BITS];
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++) {
        p0[i] = st[i][0];
        p1[i] = st[i][1];
    }
    present_transpose64(p0, out);
    present_transpose64(p1, out + PRESENT_BLOCK_BITS);
}

void present_encrypt_neon(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{
    _Alignas(16) uint64_t a[PRESENT_BLOCK_BITS * 2], b[PRESENT_BLOCK_BITS * 2];
    present_neon_pack(in, a);
    uint64_t *res = present_encrypt_neon_bs(ctx, a, b);
    present_neon_unpack(res, out);
}

void present_decrypt_neon(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{
    _Alignas(16) uint64_t a[PRESENT_BLOCK_BITS * 2], b[PRESENT_BLOCK_BITS * 2];
    present_neon_pack(in, a);
    uint64_t *res = present_decrypt_neon_bs(ctx, a, b);
    present_neon_unpack(res, out);
}

#else /* no NEON at compile time */

int present_have_neon(void) { return 0; }
void present_encrypt_neon(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{ (void)ctx; (void)in; (void)out; }
void present_decrypt_neon(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{ (void)ctx; (void)in; (void)out; }
void present_neon_pack(const uint64_t *in, uint64_t *state) { (void)in; (void)state; }
void present_neon_unpack(const uint64_t *state, uint64_t *out) { (void)state; (void)out; }
uint64_t *present_encrypt_neon_bs(const present_ctx_t *ctx, uint64_t *state, uint64_t *scratch)
{ (void)ctx; (void)scratch; return state; }
uint64_t *present_decrypt_neon_bs(const present_ctx_t *ctx, uint64_t *state, uint64_t *scratch)
{ (void)ctx; (void)scratch; return state; }

#endif
