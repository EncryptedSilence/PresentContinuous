/* Official PRESENT test vectors (Bogdanov et al., CHES 2007, Appendix).
 *
 * These pin the reference implementation to the real cipher. Everything else in the
 * project is checked against the reference, so if this file passes and test_impls
 * passes, all three implementations are the real PRESENT.
 */

#include <string.h>

#include "present/present.h"
#include "testutil.h"

struct vec {
    const char *key_hex;
    uint64_t plain;
    uint64_t cipher;
};

/* The published table is ordered plaintext-major, so the all-zero-key/all-ones-
 * plaintext row and the all-ones-key/all-zero-plaintext row are easy to transpose
 * by accident. They are written out explicitly here. */
static const struct vec vec80[] = {
    {"00000000000000000000", 0x0000000000000000ull, 0x5579C1387B228445ull},
    {"FFFFFFFFFFFFFFFFFFFF", 0x0000000000000000ull, 0xE72C46C0F5945049ull},
    {"00000000000000000000", 0xFFFFFFFFFFFFFFFFull, 0xA112FFC72F68417Bull},
    {"FFFFFFFFFFFFFFFFFFFF", 0xFFFFFFFFFFFFFFFFull, 0x3333DCD3213210D2ull},
};

static const struct vec vec128[] = {
    {"00000000000000000000000000000000", 0x0000000000000000ull, 0x96DB702A2E6900AFull},
    {"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 0x0000000000000000ull, 0x13238C710272A5D8ull},
    {"00000000000000000000000000000000", 0xFFFFFFFFFFFFFFFFull, 0x3C6019E5E5EDD563ull},
    {"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 0xFFFFFFFFFFFFFFFFull, 0x628D9FBD4218E5B4ull},
};

static void run(const char *variant_name, const struct vec *v, size_t n)
{
    const present_variant_t *var = present_variant_by_name(variant_name);
    CHECK(var != NULL, "variant %s not registered", variant_name);
    if (!var) return;

    for (size_t i = 0; i < n; i++) {
        present_ctx_t ctx;
        int rc = present_init_hex(&ctx, var, v[i].key_hex);
        CHECK(rc == 0, "%s: present_init_hex failed (%d)", variant_name, rc);
        if (rc) continue;

        CHECK_EQ64(present_encrypt_ref(&ctx, v[i].plain), v[i].cipher,
                   "%s vector %zu: encrypt key=%s pt=%016llx", variant_name, i,
                   v[i].key_hex, (unsigned long long)v[i].plain);
        CHECK_EQ64(present_decrypt_ref(&ctx, v[i].cipher), v[i].plain,
                   "%s vector %zu: decrypt", variant_name, i);
    }
}

/* Independent check of the 128-bit key schedule alone, from the SageMath PRESENT
 * reference: key 0x00112233445566778899AABBCCDDEEFF gives round key 0
 * 0x0011223344556677 and round key 31 0x091989a5ae8eab21. This isolates the key
 * schedule from the round function, so a failure points at one or the other. */
static void run_key_schedule(void)
{
    const present_variant_t *var = present_variant_by_name("present-128");
    present_ctx_t ctx;
    CHECK(var != NULL, "present-128 not registered");
    if (!var) return;
    CHECK(present_init_hex(&ctx, var, "00112233445566778899AABBCCDDEEFF") == 0,
          "present_init_hex failed");
    CHECK_EQ64(ctx.rk[0], 0x0011223344556677ull, "present-128 round key 0");
    CHECK_EQ64(ctx.rk[31], 0x091989A5AE8EAB21ull, "present-128 round key 31");
}

int main(void)
{
    run("present-80", vec80, sizeof(vec80) / sizeof(vec80[0]));
    run("present-128", vec128, sizeof(vec128) / sizeof(vec128[0]));
    run_key_schedule();
    return test_summary("test_vectors");
}
