/* Bitsliced implementation: 64 blocks encrypted in parallel.
 *
 * State bit i of all 64 blocks lives in one uint64_t, so the pLayer is register
 * renaming rather than bit twiddling, and the S-box becomes a boolean circuit
 * evaluated on four words. The circuits are synthesised per S-box by
 * tools/sbox_synth and specialised here with the X-macro list, so the gate sequence
 * is inlined rather than reached through a function pointer.
 *
 * Cost per round for 64 blocks: 64 key XORs, 16 S-box circuits, 64 permutation
 * moves. Transposition into and out of bitsliced form is amortised over 31 rounds.
 */

#include <string.h>

#include "internal.h"
#include "gen/sbox_circuits.h"

int present_circuit_gates(int circuit_id)
{
    if (circuit_id < 0 || circuit_id >= PRESENT_N_CIRCUITS) return -1;
    return present_circuit_gate_counts[circuit_id];
}

#define DEFINE_ROUNDS(ID)                                                             \
static void bs_enc_##ID(const present_ctx_t *ctx, uint64_t *cur, uint64_t *alt)       \
{                                                                                     \
    const present_variant_t *v = ctx->var;                                            \
    const int rounds = v->rounds;                                                     \
    for (int r = 0; r < rounds; r++) {                                                \
        const uint64_t *km = ctx->rk_mask[r];                                         \
        for (int i = 0; i < PRESENT_BLOCK_BITS; i++) cur[i] ^= km[i];                 \
        for (int i = 0; i < PRESENT_N_SBOXES; i++) {                                  \
            uint64_t y0, y1, y2, y3;                                                  \
            present_circuit_c##ID(&y3, &y2, &y1, &y0,                                 \
                                  cur[4 * i], cur[4 * i + 1],                         \
                                  cur[4 * i + 2], cur[4 * i + 3]);                    \
            cur[4 * i] = y0; cur[4 * i + 1] = y1;                                     \
            cur[4 * i + 2] = y2; cur[4 * i + 3] = y3;                                 \
        }                                                                             \
        for (int i = 0; i < PRESENT_BLOCK_BITS; i++) alt[v->pbox[i]] = cur[i];        \
        { uint64_t *tmp = cur; cur = alt; alt = tmp; }                                \
    }                                                                                 \
    { const uint64_t *km = ctx->rk_mask[rounds];                                      \
      for (int i = 0; i < PRESENT_BLOCK_BITS; i++) cur[i] ^= km[i]; }                 \
    if (rounds & 1) memcpy(alt, cur, sizeof(uint64_t) * PRESENT_BLOCK_BITS);          \
}                                                                                     \
                                                                                      \
static void bs_dec_##ID(const present_ctx_t *ctx, uint64_t *cur, uint64_t *alt)       \
{                                                                                     \
    const present_variant_t *v = ctx->var;                                            \
    const int rounds = v->rounds;                                                     \
    { const uint64_t *km = ctx->rk_mask[rounds];                                      \
      for (int i = 0; i < PRESENT_BLOCK_BITS; i++) cur[i] ^= km[i]; }                 \
    for (int r = rounds - 1; r >= 0; r--) {                                           \
        for (int i = 0; i < PRESENT_BLOCK_BITS; i++) alt[v->pbox_inv[i]] = cur[i];    \
        { uint64_t *tmp = cur; cur = alt; alt = tmp; }                                \
        for (int i = 0; i < PRESENT_N_SBOXES; i++) {                                  \
            uint64_t y0, y1, y2, y3;                                                  \
            present_circuit_c##ID(&y3, &y2, &y1, &y0,                                 \
                                  cur[4 * i], cur[4 * i + 1],                         \
                                  cur[4 * i + 2], cur[4 * i + 3]);                    \
            cur[4 * i] = y0; cur[4 * i + 1] = y1;                                     \
            cur[4 * i + 2] = y2; cur[4 * i + 3] = y3;                                 \
        }                                                                             \
        { const uint64_t *km = ctx->rk_mask[r];                                       \
          for (int i = 0; i < PRESENT_BLOCK_BITS; i++) cur[i] ^= km[i]; }             \
    }                                                                                 \
    if (rounds & 1) memcpy(alt, cur, sizeof(uint64_t) * PRESENT_BLOCK_BITS);          \
}

PRESENT_CIRCUIT_LIST(DEFINE_ROUNDS)

/* After an odd number of ping-pong swaps the result sits in the scratch buffer, so
 * the DEFINE_ROUNDS bodies copy it back; the caller always reads buffer `a`. */

void present_encrypt_bitslice(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{
    uint64_t a[PRESENT_BLOCK_BITS], b[PRESENT_BLOCK_BITS];
    present_transpose64(in, a);

    switch (ctx->var->circuit_enc) {
#define CASE_ENC(ID) case ID: bs_enc_##ID(ctx, a, b); break;
    PRESENT_CIRCUIT_LIST(CASE_ENC)
#undef CASE_ENC
    default: return;
    }
    present_transpose64(a, out);
}

void present_decrypt_bitslice(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{
    uint64_t a[PRESENT_BLOCK_BITS], b[PRESENT_BLOCK_BITS];
    present_transpose64(in, a);

    switch (ctx->var->circuit_dec) {
#define CASE_DEC(ID) case ID: bs_dec_##ID(ctx, a, b); break;
    PRESENT_CIRCUIT_LIST(CASE_DEC)
#undef CASE_DEC
    default: return;
    }
    present_transpose64(a, out);
}
