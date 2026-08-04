/* Table-driven encryption over several independent blocks at once.
 *
 * A single block through the table implementation is latency-bound, not
 * throughput-bound: each round is eight lookups that all index the *current* state,
 * so the next round cannot start until this round's XOR tree finishes. That is
 * roughly an L1 load (~5 cycles) plus a three-deep XOR tree per round, 31 times
 * over, and the eight load slots and eight XOR slots sit mostly idle.
 *
 * Interleaving N independent blocks fills them. This is the single biggest win in
 * the QalqanSpeed work on a structurally similar cipher, and it needs no new tables
 * and no per-variant code -- just enough independent blocks in flight, which any
 * parallel mode (CTR, ECB over a buffer, counter-mode nonces) supplies for free.
 *
 * The state array is small enough to live in registers at N = 4; at N = 8 it is
 * 8 x 64 bits of state plus 8 in-flight loads, which is where register pressure
 * starts to bite. Both are measured rather than assumed.
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

#define DEFINE_LANES(N)                                                               \
void present_encrypt_table_x##N(const present_ctx_t *ctx, const uint64_t *in,          \
                                uint64_t *out)                                        \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    uint64_t s[N];                                                                    \
    for (int i = 0; i < N; i++) s[i] = in[i];                                          \
    for (int r = 0; r < rounds; r++) {                                                \
        const uint64_t k = ctx->rk[r];                                                \
        for (int i = 0; i < N; i++) s[i] ^= k;                                         \
        for (int i = 0; i < N; i++) s[i] = round_enc(ctx, s[i]);                        \
    }                                                                                 \
    { const uint64_t k = ctx->rk[rounds];                                             \
      for (int i = 0; i < N; i++) out[i] = s[i] ^ k; }                                 \
}

DEFINE_LANES(2)
DEFINE_LANES(4)
DEFINE_LANES(8)
DEFINE_LANES(16)
