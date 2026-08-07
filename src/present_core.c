/* Context setup: key schedule, derived lookup tables, bitsliced key masks. */

#include <string.h>

#include "internal.h"

/* The S-box layer seen a byte at a time: two nibble S-boxes for a 4-bit variant, one
 * whole S-box for an 8-bit one. Every table below is built from this, so the width
 * appears in exactly one place. `dec` may be NULL: an encryption-only build has no
 * ctx->sinv_byte to fill. */
static void byte_sboxes(const present_variant_t *v, uint8_t *enc, uint8_t *dec)
{
    if (v->sbox_bits == 8) {
        memcpy(enc, v->sbox, 256);
        if (dec) memcpy(dec, v->sbox_inv, 256);
        return;
    }
    for (int b = 0; b < 256; b++) {
        enc[b] = (uint8_t)(v->sbox[b & 0xF] | (v->sbox[(b >> 4) & 0xF] << 4));
        if (dec) dec[b] = (uint8_t)(v->sbox_inv[b & 0xF] | (v->sbox_inv[(b >> 4) & 0xF] << 4));
    }
}

static void build_tables(present_ctx_t *ctx)
{
    const present_variant_t *v = ctx->var;
    uint8_t senc[256];
#ifdef PRESENT_ENC_ONLY
    byte_sboxes(v, senc, NULL);
#else
    byte_sboxes(v, senc, ctx->sinv_byte);
#endif

    /* enc_tab[j][b]: take byte j of the state, apply the S-box layer to it, then push
     * the eight resulting bits through the linear layer.
     *
     * This works for any GF(2)-linear layer, not just a permutation: linearity is
     * exactly the statement that L(x) is the XOR of L applied to each byte of x in
     * isolation, so one round stays eight lookups XORed together whatever the layer
     * does. For PRESENT's pLayer the eight contributions happen to be disjoint and
     * the XOR could be an OR; for lin444 they overlap and the XOR matters. Either
     * way the table implementation pays nothing for a denser linear layer -- the
     * whole cost moves into this one-off table build. */
    for (int j = 0; j < 8; j++) {
        for (int b = 0; b < 256; b++) {
            unsigned sb = senc[b];
            uint64_t acc = 0;
            for (int k = 0; k < 8; k++)
                if ((sb >> k) & 1) acc ^= v->lin_col[j * 8 + k];
            ctx->enc_tab[j][b] = acc;
        }
    }

#ifndef PRESENT_ENC_ONLY
    /* pinv_tab[j][b]: the inverse linear layer alone. The inverse S-box cannot be
     * fused in, because afterwards the nibbles are no longer made of bits that came
     * from a single input byte. */
    for (int j = 0; j < 8; j++) {
        for (int b = 0; b < 256; b++) {
            uint64_t acc = 0;
            for (int k = 0; k < 8; k++)
                if ((b >> k) & 1) acc ^= v->lin_col_inv[j * 8 + k];
            ctx->pinv_tab[j][b] = acc;
        }
    }
#endif
}

/* Spread one S-box-wide constant across every S-box position of the state. */
static uint64_t splat_sbox(const present_variant_t *v, int m)
{
    uint64_t x = 0;
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++)
        if ((m >> (i % v->sbox_bits)) & 1) x |= (uint64_t)1 << i;
    return x;
}

/* Bitsliced round keys, and the one place the S-box circuits' output complements
 * are paid for.
 *
 * A synthesised circuit is free to compute S(x) ^ B instead of S(x), for a constant
 * nibble B replicated across the state (see tools/sbox_synth.c). That is worth two
 * gates per S-box on AVX2 for PRESENT's own table, because the circuit's last two
 * gates are NOTs. Nothing needs to be undone at run time:
 *
 *   encryption   ... ^ k_r, S, L ... leaves the state off by L(B) after the layer,
 *                and the next thing it meets is the XOR of k_{r+1}. So fold L(B)
 *                into round keys 1 .. rounds. (Round key 0 is XORed before any
 *                S-box, so it is untouched.)
 *   decryption   ... Linv, Sinv, ^ k_r ... has no layer between the circuit and the
 *                key, so the correction is B itself, folded into keys 0 .. rounds-1.
 *
 * The two directions therefore need different arrays -- and different constants,
 * since S and its inverse are synthesised separately. Only the bitsliced backends
 * read these; the reference and table paths use ctx->rk directly and see plain S.
 */
static void build_key_masks(present_ctx_t *ctx)
{
    const present_variant_t *v = ctx->var;

    /* L(B): the layer is linear, so it is the XOR of the columns B selects. */
    uint64_t corr_enc = 0;
    const uint64_t b_enc = splat_sbox(v, present_circuit_outcomp_mask(v->circuit_enc));
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++)
        if ((b_enc >> i) & 1) corr_enc ^= v->lin_col[i];

#ifndef PRESENT_ENC_ONLY
    const uint64_t corr_dec = splat_sbox(v, present_circuit_outcomp_mask(v->circuit_dec));
#endif

    for (int r = 0; r <= v->rounds; r++) {
        const uint64_t ke = ctx->rk[r] ^ (r > 0 ? corr_enc : 0);
#ifndef PRESENT_ENC_ONLY
        const uint64_t kd = ctx->rk[r] ^ (r < v->rounds ? corr_dec : 0);
#endif
        for (int i = 0; i < PRESENT_BLOCK_BITS; i++) {
            ctx->rk_mask_enc[r][i] = (uint64_t)0 - ((ke >> i) & 1);
#ifndef PRESENT_ENC_ONLY
            ctx->rk_mask_dec[r][i] = (uint64_t)0 - ((kd >> i) & 1);
#endif
        }
    }
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
    /* Large enough for the independent schedule's (rounds + 1) round keys. */
    uint8_t key[(PRESENT_MAX_ROUNDS + 1) * PRESENT_BLOCK_BITS / 8];
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
 *
 * The six passes are grouped into two, so the state crosses the cache twice rather
 * than six times. Passes with j = 32, 16, 8 only ever pair a[k] with a[k + j], so
 * all three stay inside {m, m+8, ..., m+56} for a fixed m -- eight words, which fit
 * in registers. Passes with j = 4, 2, 1 likewise stay inside {8n, ..., 8n+7}. Both
 * triples have the same shape, pair at stride 4 then 2 then 1, so one loop nest
 * serves both. Worth 0.18 cycles per byte on the AVX2 backend, where the same
 * structure is spelled out over __m256i in present_avx2.c -- a third of what the
 * two transposes there cost, and 11% of PRESENT's total.
 */
void present_transpose64(const uint64_t *in, uint64_t *out)
{
    static const uint64_t MASK[6] = {
        0x00000000FFFFFFFFull, 0x0000FFFF0000FFFFull, 0x00FF00FF00FF00FFull,
        0x0F0F0F0F0F0F0F0Full, 0x3333333333333333ull, 0x5555555555555555ull,
    };
    uint64_t a[64];
    memcpy(a, in, sizeof(a));

    for (int phase = 0; phase < 2; phase++) {
        const int step = phase ? 1 : 8;      /* distance between the octet's words */
        for (int g = 0; g < 8; g++) {
            uint64_t r[8];
            const int base = phase ? 8 * g : g;
            for (int i = 0; i < 8; i++) r[i] = a[base + step * i];
            for (int p = 0; p < 3; p++) {
                const uint64_t m = MASK[3 * phase + p];
                const int j = 32 >> (3 * phase + p);  /* 32,16,8 then 4,2,1 */
                const int d = 4 >> p;                 /* stride within the octet */
                for (int k = 0; k < 8; k = (k + d + 1) & ~d) {
                    uint64_t t = ((r[k] >> j) ^ r[k + d]) & m;
                    r[k] ^= t << j;
                    r[k + d] ^= t;
                }
            }
            for (int i = 0; i < 8; i++) a[base + step * i] = r[i];
        }
    }
    memcpy(out, a, sizeof(a));
}
