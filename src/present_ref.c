/* Reference implementation: a direct transcription of the specification.
 *
 * Deliberately unoptimised - the pLayer moves one bit at a time. This is the oracle
 * the other two implementations are tested against, so clarity beats speed here.
 */

#include "internal.h"

/* One S-box applied to each n-bit chunk of the state, for whatever n the variant
 * declares -- 4 for PRESENT, 8 for a byte-oriented variant such as cipher-D. */
static uint64_t sbox_layer_with(const uint8_t *box, const present_variant_t *v, uint64_t s)
{
    const int n = v->sbox_bits;
    const uint64_t mask = ((uint64_t)1 << n) - 1;
    uint64_t t = 0;
    for (int i = 0; i < v->n_sboxes; i++)
        t |= (uint64_t)box[(s >> (n * i)) & mask] << (n * i);
    return t;
}

static uint64_t sbox_layer(const present_variant_t *v, uint64_t s)
{
    return sbox_layer_with(v->sbox, v, s);
}

static uint64_t sbox_layer_inv(const present_variant_t *v, uint64_t s)
{
    return sbox_layer_with(v->sbox_inv, v, s);
}

/* The linear layer straight from its column form: accumulate the contribution of
 * every set input bit. For PRESENT's pLayer each column is a single bit and this
 * is the specification's "bit i moves to position pbox[i]", one bit at a time; for
 * lin444 the columns are dense and the same loop still holds. Deliberately not
 * specialised -- the whole point of this file is to be the oracle for the two
 * implementations that are. */
static uint64_t lin_layer(const uint64_t *col, uint64_t s)
{
    uint64_t t = 0;
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++)
        if ((s >> i) & 1) t ^= col[i];
    return t;
}

uint64_t present_encrypt_ref(const present_ctx_t *ctx, uint64_t s)
{
    const present_variant_t *v = ctx->var;
    for (int r = 0; r < v->rounds; r++) {
        s ^= ctx->rk[r];
        s = sbox_layer(v, s);
        s = lin_layer(v->lin_col, s);
    }
    return s ^ ctx->rk[v->rounds];
}

uint64_t present_decrypt_ref(const present_ctx_t *ctx, uint64_t s)
{
    const present_variant_t *v = ctx->var;
    s ^= ctx->rk[v->rounds];
    for (int r = v->rounds - 1; r >= 0; r--) {
        s = lin_layer(v->lin_col_inv, s);
        s = sbox_layer_inv(v, s);
        s ^= ctx->rk[r];
    }
    return s;
}
