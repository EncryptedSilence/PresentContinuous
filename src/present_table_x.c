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
 * That is the x86-64 story and results/speed.csv bears it out: over 25 variants
 * table-x4 beats plain table by 1.45x to 2.52x (median 2.34x), and table-x8 beats
 * table-x4 again in 23 of those 25, by up to 1.19x. So on a machine with sixteen
 * 64-bit registers the state array does live in registers at N = 4 and mostly still
 * does at N = 8; the register pressure an earlier version of this comment predicted
 * at N = 8 does not show up as a loss there either.
 *
 * It does not carry to Cortex-M4, and the original version of this comment asserted
 * that it did. On the STM32F407 table-x4 is *slower* than plain table in all 18
 * (cipher, configuration) pairs that have both rows, by 1.05x to 1.63x
 * (results/m4-speed.csv). Nothing here is latency-bound the way it is on x86: the
 * core is in-order and single-issue, so there are no idle slots for a second block
 * to fill, and the interleaving instead multiplies live state against fourteen
 * usable 32-bit registers -- four blocks of 64-bit state is eight registers before
 * any address or in-flight load. The win is real and it is a property of the host,
 * not of the code. N = 8 is not built for the M4 at all.
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
