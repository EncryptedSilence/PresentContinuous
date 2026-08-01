/* Cross-implementation equivalence, for every registered variant.
 *
 * The reference implementation is the oracle. The table and bitsliced paths must
 * agree with it on random inputs, and every implementation must round-trip.
 */

#include <string.h>

#include "present/present.h"
#include "testutil.h"

#define TRIALS 64

static void check_transpose(void)
{
    uint64_t in[64], mid[64], back[64];
    for (int i = 0; i < 64; i++) in[i] = rng_next();
    present_transpose64(in, mid);
    present_transpose64(mid, back);
    CHECK(memcmp(in, back, sizeof(in)) == 0, "transpose is not an involution");

    for (int i = 0; i < 64; i++)
        for (int k = 0; k < 64; k++)
            if (((in[k] >> i) & 1) != ((mid[i] >> k) & 1)) {
                CHECK(0, "transpose wrong at (%d,%d)", i, k);
                return;
            }
}

static void check_variant(const present_variant_t *var)
{
    present_ctx_t ctx;
    uint8_t key[16];
    size_t key_len = (size_t)var->key_bits / 8;

    for (size_t i = 0; i < key_len; i++) key[i] = (uint8_t)(rng_next() >> 32);

    int rc = present_init(&ctx, var, key, key_len);
    CHECK(rc == 0, "%s: present_init failed (%d)", var->name, rc);
    if (rc) return;

    /* single-block paths */
    for (int t = 0; t < TRIALS; t++) {
        uint64_t pt = rng_next();
        uint64_t ct_ref = present_encrypt_ref(&ctx, pt);
        uint64_t ct_tab = present_encrypt_table(&ctx, pt);
        CHECK_EQ64(ct_tab, ct_ref, "%s: table encrypt disagrees with ref", var->name);
        CHECK_EQ64(present_decrypt_ref(&ctx, ct_ref), pt, "%s: ref round-trip", var->name);
        CHECK_EQ64(present_decrypt_table(&ctx, ct_ref), pt, "%s: table round-trip", var->name);
    }

    /* bitsliced path: 64 blocks at a time */
    {
        uint64_t pt[64], ct[64], back[64];
        for (int i = 0; i < 64; i++) pt[i] = rng_next();
        present_encrypt_bitslice(&ctx, pt, ct);
        for (int i = 0; i < 64; i++)
            CHECK_EQ64(ct[i], present_encrypt_ref(&ctx, pt[i]),
                       "%s: bitslice encrypt disagrees with ref at block %d", var->name, i);
        present_decrypt_bitslice(&ctx, ct, back);
        CHECK(memcmp(pt, back, sizeof(pt)) == 0, "%s: bitslice round-trip", var->name);
    }
}

int main(void)
{
    check_transpose();
    for (int i = 0; i < present_n_variants; i++) check_variant(&present_variants[i]);
    return test_summary("test_impls");
}
