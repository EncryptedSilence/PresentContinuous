/* Reference implementation: a direct transcription of the specification.
 *
 * Deliberately unoptimised - the pLayer moves one bit at a time. This is the oracle
 * the other two implementations are tested against, so clarity beats speed here.
 */

#include "internal.h"

static uint64_t sbox_layer(const present_variant_t *v, uint64_t s)
{
    uint64_t t = 0;
    for (int i = 0; i < PRESENT_N_SBOXES; i++)
        t |= (uint64_t)v->sbox[(s >> (4 * i)) & 0xF] << (4 * i);
    return t;
}

static uint64_t sbox_layer_inv(const present_variant_t *v, uint64_t s)
{
    uint64_t t = 0;
    for (int i = 0; i < PRESENT_N_SBOXES; i++)
        t |= (uint64_t)v->sbox_inv[(s >> (4 * i)) & 0xF] << (4 * i);
    return t;
}

static uint64_t p_layer(const present_variant_t *v, uint64_t s)
{
    uint64_t t = 0;
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++)
        if ((s >> i) & 1) t |= (uint64_t)1 << v->pbox[i];
    return t;
}

static uint64_t p_layer_inv(const present_variant_t *v, uint64_t s)
{
    uint64_t t = 0;
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++)
        if ((s >> i) & 1) t |= (uint64_t)1 << v->pbox_inv[i];
    return t;
}

uint64_t present_encrypt_ref(const present_ctx_t *ctx, uint64_t s)
{
    const present_variant_t *v = ctx->var;
    for (int r = 0; r < v->rounds; r++) {
        s ^= ctx->rk[r];
        s = sbox_layer(v, s);
        s = p_layer(v, s);
    }
    return s ^ ctx->rk[v->rounds];
}

uint64_t present_decrypt_ref(const present_ctx_t *ctx, uint64_t s)
{
    const present_variant_t *v = ctx->var;
    s ^= ctx->rk[v->rounds];
    for (int r = v->rounds - 1; r >= 0; r--) {
        s = p_layer_inv(v, s);
        s = sbox_layer_inv(v, s);
        s ^= ctx->rk[r];
    }
    return s;
}
