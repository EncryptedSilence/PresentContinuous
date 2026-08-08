/* Table-driven implementation.
 *
 * sBoxLayer and pLayer are fused into eight 256-entry tables of uint64_t (16 KiB),
 * derived at init time from the variant's sbox and pbox. One encryption round is
 * eight loads and eight XORs plus the key addition, and the same code covers every
 * variant with no per-variant specialisation.
 *
 * Decryption cannot use the same trick: after the inverse pLayer the nibbles are
 * made of bits that came from different input bytes, so the inverse S-box cannot be
 * folded into the permutation tables. Decryption therefore costs eight u64 lookups
 * for the permutation plus eight byte lookups for the inverse S-box.
 */

#include "internal.h"

#define B(s, j) ((unsigned)(((s) >> (8 * (j))) & 0xFF))

static inline uint64_t round_enc(const present_ctx_t *ctx, uint64_t s)
{
    return ctx->enc_tab[0][B(s, 0)] ^ ctx->enc_tab[1][B(s, 1)]
         ^ ctx->enc_tab[2][B(s, 2)] ^ ctx->enc_tab[3][B(s, 3)]
         ^ ctx->enc_tab[4][B(s, 4)] ^ ctx->enc_tab[5][B(s, 5)]
         ^ ctx->enc_tab[6][B(s, 6)] ^ ctx->enc_tab[7][B(s, 7)];
}

#ifndef PRESENT_ENC_ONLY
static inline uint64_t round_dec(const present_ctx_t *ctx, uint64_t s)
{
    uint64_t p = ctx->pinv_tab[0][B(s, 0)] ^ ctx->pinv_tab[1][B(s, 1)]
               ^ ctx->pinv_tab[2][B(s, 2)] ^ ctx->pinv_tab[3][B(s, 3)]
               ^ ctx->pinv_tab[4][B(s, 4)] ^ ctx->pinv_tab[5][B(s, 5)]
               ^ ctx->pinv_tab[6][B(s, 6)] ^ ctx->pinv_tab[7][B(s, 7)];
    uint64_t o = 0;
    for (int j = 0; j < 8; j++)
        o |= (uint64_t)ctx->sinv_byte[B(p, j)] << (8 * j);
    return o;
}

#endif /* PRESENT_ENC_ONLY */

uint64_t present_encrypt_table(const present_ctx_t *ctx, uint64_t s)
{
    const int rounds = ctx->var->rounds;
    for (int r = 0; r < rounds; r++) {
        s ^= ctx->rk[r];
        s = round_enc(ctx, s);
    }
    return s ^ ctx->rk[rounds];
}

/* --- the same thing with the round count fixed at compile time -------------------
 *
 * Declared in present.h, where the contract (and the way to reach these safely) is
 * written out. The body below is character-for-character the loop above with N in
 * place of `rounds`, and it is written as one macro precisely so the two cannot
 * drift into computing different ciphers: there is no second copy of round_enc, no
 * second key-addition order, and no opportunity for a hand-unrolled variant to be
 * subtly wrong in a way the generic path is not.
 *
 * What N buys, on Cortex-M4 at -O3: the two dependent loads of ctx->var->rounds
 * disappear, every ctx->rk[r] becomes a fixed offset from one base register, and
 * the loop becomes a straight line -- so the eight table lookups of one round can
 * be scheduled against the next round's rather than fenced by a backward branch. */
#define PRESENT_DEF_TABLE_FIXED(N)                                          \
    uint64_t present_encrypt_table_r##N(const present_ctx_t *ctx, uint64_t s) \
    {                                                                       \
        for (int r = 0; r < (N); r++) {                                     \
            s ^= ctx->rk[r];                                                \
            s = round_enc(ctx, s);                                          \
        }                                                                   \
        return s ^ ctx->rk[N];                                              \
    }
PRESENT_FIXED_ROUNDS_LIST(PRESENT_DEF_TABLE_FIXED)
#undef PRESENT_DEF_TABLE_FIXED

present_table_fn present_table_fixed_fn(int rounds)
{
    switch (rounds) {
#define PRESENT_CASE_TABLE_FIXED(N) case (N): return present_encrypt_table_r##N;
    PRESENT_FIXED_ROUNDS_LIST(PRESENT_CASE_TABLE_FIXED)
#undef PRESENT_CASE_TABLE_FIXED
    default: return 0;
    }
}

#ifndef PRESENT_ENC_ONLY
uint64_t present_decrypt_table(const present_ctx_t *ctx, uint64_t s)
{
    const int rounds = ctx->var->rounds;
    s ^= ctx->rk[rounds];
    for (int r = rounds - 1; r >= 0; r--) {
        s = round_dec(ctx, s);
        s ^= ctx->rk[r];
    }
    return s;
}
#endif /* PRESENT_ENC_ONLY */
