/* The CTR harness's guard on the cipher set.
 *
 * tools/cipher_set.py's module docstring states the rule this file enforces:
 * an FPGA number and a Cortex-M4 number must always name the same cipher at the
 * same round count, and the way that is guaranteed is that nothing restates the
 * list. The host CTR harness is a third consumer of the same seven ciphers, so
 * it obeys the same rule: bench/gen/ctr_cipher_set.h is generated from
 * cipher_set.resolve() (`make bench/gen/ctr_cipher_set.h`), bench/ctr_narrow.c
 * and bench/ctr_wide.c build their registration tables by expanding its lists,
 * and this file checks after the fact that the registry those two files
 * actually assembled still describes those seven ciphers and nothing else.
 *
 * That second half is the same shape as tools/run_m4_bench.py's
 * check_cipher_set(): generating the table is not by itself enough, because a
 * Wave 2 group appended to ctr_registry.c's groups[] is hand-written C that can
 * name a cipher with a typo, or an eighth construction someone added for an
 * experiment. The correctness gate would not catch either -- a group whose
 * ctr-ref and impls share a typo agrees with itself perfectly -- so the check
 * is here, ahead of any measurement, rather than left to the reader of the CSV.
 *
 * The third check crosses the language boundary: for the five 64-bit ciphers,
 * the round count tools/cipher_set.py resolved from the variant JSON must equal
 * the one src/gen/variants_gen.c compiled into present_variants[]. Those are two
 * independent readings of the same JSON file, and if they ever disagree the
 * published rounds column is describing a different cipher from the one that
 * ran. The 128-bit pair has no src/ variant to cross-check against -- it lives
 * in bench/wide_ciphers.h and takes its round count as a call argument -- which
 * is exactly why VARIANT_OVERRIDES exists and why those two numbers reach C
 * only through the generated header.
 */
#include <stdio.h>
#include <string.h>

#include "ctr_backend.h"
#include "gen/ctr_cipher_set.h"
#include "present/variant.h"

typedef struct {
    const char *name;
    int rounds;
    size_t block_bytes;
} ctr_cipher_desc_t;

#define CTR_DESC_ROW(slug, name, rounds, bb) { name, rounds, bb },

static const ctr_cipher_desc_t ctr_cipher_set[] = {
    CTR_CIPHER_LIST(CTR_DESC_ROW)
};

#undef CTR_DESC_ROW

/* CTR_CIPHER_COUNT is the generator's own count of the list it emitted; this
 * pins the table built from it to the same length, so a list that expanded
 * wrong (a lost line continuation, say) is a compile error rather than a
 * quietly shorter set to check against. */
_Static_assert(sizeof ctr_cipher_set / sizeof ctr_cipher_set[0] == CTR_CIPHER_COUNT,
               "bench/gen/ctr_cipher_set.h: CTR_CIPHER_LIST does not expand to "
               "CTR_CIPHER_COUNT entries");

static const ctr_cipher_desc_t *desc_for(const char *cipher)
{
    for (size_t i = 0; i < CTR_CIPHER_COUNT; i++)
        if (!strcmp(ctr_cipher_set[i].name, cipher)) return &ctr_cipher_set[i];
    return NULL;
}

int ctr_cipher_rounds(const char *cipher)
{
    const ctr_cipher_desc_t *d = desc_for(cipher);
    return d ? d->rounds : 0;
}

int ctr_cipher_set_check(char *msg, size_t msg_len)
{
    if (!msg || msg_len == 0) return -1;
    msg[0] = '\0';

    /* 1. Nothing registered may name a cipher outside the set, and a backend
     *    must agree with it about the block width -- a 64-bit backend
     *    registered under a 128-bit cipher's name would process half the bytes
     *    per block and still pass a gate run against a ctr-ref with the same
     *    mistake. */
    for (size_t i = 0; i < ctr_backend_count(); i++) {
        const ctr_backend_t *b = ctr_backend_at(i);
        const ctr_cipher_desc_t *d = desc_for(b->cipher);
        if (!d) {
            snprintf(msg, msg_len,
                     "backend %s names cipher '%s', which is not one of the %d in "
                     "tools/cipher_set.py", b->name, b->cipher, CTR_CIPHER_COUNT);
            return 1;
        }
        if (b->block_bytes != d->block_bytes) {
            snprintf(msg, msg_len,
                     "%s (%s): block_bytes %zu, but tools/cipher_set.py says %zu",
                     b->name, b->cipher, b->block_bytes, d->block_bytes);
            return 1;
        }
        if (b->group_bytes == 0 || b->group_bytes % b->block_bytes != 0) {
            snprintf(msg, msg_len,
                     "%s (%s): group_bytes %zu is not a non-zero multiple of "
                     "block_bytes %zu", b->name, b->cipher,
                     b->group_bytes, b->block_bytes);
            return 1;
        }
    }

    for (size_t i = 0; i < CTR_CIPHER_COUNT; i++) {
        const ctr_cipher_desc_t *d = &ctr_cipher_set[i];

        /* 2. Every cipher in the set must have its oracle. A cipher that lost
         *    its ctr-ref would otherwise just vanish from the CSV. */
        if (!ctr_backend_reference_for(d->name)) {
            snprintf(msg, msg_len,
                     "no ctr-ref backend registered for '%s', which "
                     "tools/cipher_set.py lists at %d rounds", d->name, d->rounds);
            return 1;
        }

        /* 3. For the 64-bit set, the two independent readings of the variant
         *    JSON -- tools/cipher_set.py's and src/gen/variants_gen.c's -- must
         *    agree on the round count. */
        if (d->block_bytes == PRESENT_BLOCK_BITS / 8) {
            const present_variant_t *v = present_variant_by_name(d->name);
            if (!v) {
                snprintf(msg, msg_len,
                         "'%s' is a 64-bit cipher in tools/cipher_set.py but is not "
                         "in present_variants[]", d->name);
                return 1;
            }
            if (v->rounds != d->rounds) {
                snprintf(msg, msg_len,
                         "'%s': tools/cipher_set.py says %d rounds, "
                         "present_variants[] says %d",
                         d->name, d->rounds, v->rounds);
                return 1;
            }
        }
    }

    return 0;
}
