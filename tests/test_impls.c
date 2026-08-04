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
    /* Wide enough for the independent schedule, which takes one key per round. */
    uint8_t key[(PRESENT_MAX_ROUNDS + 1) * PRESENT_BLOCK_BITS / 8];
    size_t key_len = present_variant_key_bytes(var);

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

    /* interleaved table paths: same tables, N independent blocks at a time */
    {
        uint64_t pt[16], ct[16];
        for (int i = 0; i < 16; i++) pt[i] = rng_next();
#define CHECK_LANES(N)                                                                \
        do {                                                                          \
            memset(ct, 0, sizeof(ct));                                                \
            present_encrypt_table_x##N(&ctx, pt, ct);                                 \
            for (int i = 0; i < N; i++)                                               \
                CHECK_EQ64(ct[i], present_encrypt_ref(&ctx, pt[i]),                   \
                           "%s: table-x%d disagrees with ref at block %d",            \
                           var->name, N, i);                                          \
        } while (0)
        CHECK_LANES(2);
        CHECK_LANES(4);
        CHECK_LANES(8);
        CHECK_LANES(16);
#undef CHECK_LANES
    }

    /* bitsliced path: 64 blocks at a time. Both S-box widths have one, though the
     * 8-bit circuits come from the BDD heuristic in tools/sbox_synth8 rather than
     * the exhaustive 4-bit search, so this is where they get checked. */
    if (present_variant_has_bitslice(var)) {
        uint64_t pt[64], ct[64], back[64];
        for (int i = 0; i < 64; i++) pt[i] = rng_next();
        present_encrypt_bitslice(&ctx, pt, ct);
        for (int i = 0; i < 64; i++)
            CHECK_EQ64(ct[i], present_encrypt_ref(&ctx, pt[i]),
                       "%s: bitslice encrypt disagrees with ref at block %d", var->name, i);
        present_decrypt_bitslice(&ctx, ct, back);
        CHECK(memcmp(pt, back, sizeof(pt)) == 0, "%s: bitslice round-trip", var->name);

        /* The bitsliced-native entry points skip the transposes, so doing them by
         * hand around the call has to reproduce the all-in-one function exactly. */
        uint64_t st[64], sc[64], *res;
        present_transpose64(pt, st);
        res = present_encrypt_bitslice_bs(&ctx, st, sc);
        present_transpose64(res, back);
        CHECK(memcmp(ct, back, sizeof(ct)) == 0, "%s: bitslice-bs encrypt", var->name);
        present_transpose64(ct, st);
        res = present_decrypt_bitslice_bs(&ctx, st, sc);
        present_transpose64(res, back);
        CHECK(memcmp(pt, back, sizeof(pt)) == 0, "%s: bitslice-bs decrypt", var->name);
    }

    /* AVX2 bitsliced path: 256 blocks at a time, encryption only */
    if (present_have_avx2() && present_variant_has_bitslice(var)) {
        static uint64_t pt[PRESENT_AVX2_BLOCKS], ct[PRESENT_AVX2_BLOCKS];
        for (int i = 0; i < PRESENT_AVX2_BLOCKS; i++) pt[i] = rng_next();
        present_encrypt_avx2(&ctx, pt, ct);
        for (int i = 0; i < PRESENT_AVX2_BLOCKS; i++)
            CHECK_EQ64(ct[i], present_encrypt_ref(&ctx, pt[i]),
                       "%s: avx2 encrypt disagrees with ref at block %d", var->name, i);

        static _Alignas(32) uint64_t st[PRESENT_BLOCK_BITS * 4];
        static _Alignas(32) uint64_t sc[PRESENT_BLOCK_BITS * 4];
        static uint64_t back[PRESENT_AVX2_BLOCKS];
        present_avx2_pack(pt, st);
        present_avx2_unpack(present_encrypt_avx2_bs(&ctx, st, sc), back);
        CHECK(memcmp(ct, back, sizeof(ct)) == 0, "%s: avx2-bs encrypt", var->name);
    }
}

int main(void)
{
    check_transpose();
    for (int i = 0; i < present_n_variants; i++) check_variant(&present_variants[i]);
    return test_summary("test_impls");
}
