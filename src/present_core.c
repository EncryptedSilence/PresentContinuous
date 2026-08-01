/* Context setup: key schedule, derived lookup tables, bitsliced key masks. */

#include <string.h>

#include "internal.h"

static void build_tables(present_ctx_t *ctx)
{
    const present_variant_t *v = ctx->var;

    /* enc_tab[j][b]: take byte j of the state, apply the S-box to both of its
     * nibbles, then scatter the eight resulting bits to their pLayer destinations.
     * Because pbox is a permutation the eight contributions of the eight bytes are
     * disjoint, so one round is eight lookups XORed together. */
    for (int j = 0; j < 8; j++) {
        for (int b = 0; b < 256; b++) {
            unsigned sb = (unsigned)v->sbox[b & 0xF] | ((unsigned)v->sbox[(b >> 4) & 0xF] << 4);
            uint64_t acc = 0;
            for (int k = 0; k < 8; k++)
                if ((sb >> k) & 1) acc |= (uint64_t)1 << v->pbox[j * 8 + k];
            ctx->enc_tab[j][b] = acc;
        }
    }

    /* pinv_tab[j][b]: the inverse pLayer alone. The inverse S-box cannot be fused
     * in, because after the inverse permutation the nibbles are no longer made of
     * bits that came from a single input byte. */
    for (int j = 0; j < 8; j++) {
        for (int b = 0; b < 256; b++) {
            uint64_t acc = 0;
            for (int k = 0; k < 8; k++)
                if ((b >> k) & 1) acc |= (uint64_t)1 << v->pbox_inv[j * 8 + k];
            ctx->pinv_tab[j][b] = acc;
        }
    }

    for (int b = 0; b < 256; b++)
        ctx->sinv_byte[b] = (uint8_t)(v->sbox_inv[b & 0xF] | (v->sbox_inv[(b >> 4) & 0xF] << 4));
}

static void build_key_masks(present_ctx_t *ctx)
{
    for (int r = 0; r <= ctx->var->rounds; r++)
        for (int i = 0; i < PRESENT_BLOCK_BITS; i++)
            ctx->rk_mask[r][i] = (uint64_t)0 - ((ctx->rk[r] >> i) & 1);
}

int present_init(present_ctx_t *ctx, const present_variant_t *v,
                 const uint8_t *key, size_t key_len)
{
    int rc;
    if (!ctx || !v || !key) return -1;
    if ((rc = present_variant_check(v)) != 0) return rc;

    memset(ctx, 0, sizeof(*ctx));
    ctx->var = v;
    if ((rc = present_key_schedule(v, key, key_len, ctx->rk)) != 0) return rc;

    build_tables(ctx);
    build_key_masks(ctx);
    return 0;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int present_init_hex(present_ctx_t *ctx, const present_variant_t *v, const char *hex_key)
{
    uint8_t key[16];
    size_t n = strlen(hex_key);
    if (n % 2 || n / 2 > sizeof(key)) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(hex_key[2 * i]), lo = hexval(hex_key[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        key[i] = (uint8_t)((hi << 4) | lo);
    }
    return present_init(ctx, v, key, n / 2);
}

/* 64x64 bit-matrix transpose, so that out[i] bit k == in[k] bit i.
 *
 * Recursive block swap in six passes. Note this is *not* the transpose from
 * Hacker's Delight verbatim: that one is written for MSB-first bit numbering and
 * swaps the other off-diagonal block, which here would give the anti-transpose.
 * With bit 0 as the least significant bit we swap the high half of row k with the
 * low half of row k+j. The operation is its own inverse.
 */
void present_transpose64(const uint64_t *in, uint64_t *out)
{
    uint64_t a[64];
    uint64_t m = 0x00000000FFFFFFFFull;
    memcpy(a, in, sizeof(a));

    for (int j = 32; j != 0; j >>= 1, m ^= m << j) {
        for (int k = 0; k < 64; k = (k + j + 1) & ~j) {
            uint64_t t = ((a[k] >> j) ^ a[k + j]) & m;
            a[k] ^= t << j;
            a[k + j] ^= t;
        }
    }
    memcpy(out, a, sizeof(a));
}
