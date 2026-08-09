#ifndef PRESENT_INTERNAL_H
#define PRESENT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "present/present.h"

/* Expands a key into ctx->rk[0 .. rounds]. Returns 0 on success. */
int present_key_schedule(const present_variant_t *v, const uint8_t *key, size_t key_len,
                         uint64_t *rk);

/* Nibble constant B such that bitsliced circuit `circuit_id` computes S(x) ^ B
 * rather than S(x). Defined in present_bitslice.c, where the circuits live;
 * present_core.c cancels it in the round keys. */
int present_circuit_outcomp_mask(int circuit_id);

/* --- PRESENT_ONE_CIPHER: a build that runs exactly one variant --------------------
 *
 * The bitsliced entry points dispatch on ctx->var->kernel_enc, a value the compiler
 * cannot see. That switch is why every one of the sixteen synthesised round
 * functions is reachable in every build: on the Cortex-M4 firmware the two bitslice
 * objects are 71 KB of the 102 KB relocated into SRAM by the sram-noart
 * configuration, and a firmware that exercises a single cipher executes one kernel
 * of the sixteen in each.
 *
 * Defining PRESENT_ONE_CIPHER to a variant slug -- the variant's name with every
 * character outside [0-9A-Za-z] replaced by '_', e.g. -DPRESENT_ONE_CIPHER=cipher_D
 * -- replaces the switch with a direct call to that variant's kernel. The other
 * fifteen are file-scope statics with no remaining reference, so the compiler drops
 * them; this does not depend on --gc-sections.
 *
 * The slug is resolved to a kernel id through PRESENT_KERNEL_ENC_OF_<slug>, which
 * tools/gen_c.py emits into src/gen/lin_consts.h for every variant in the tree, so
 * the mapping stays derived from the same variant data as the registry rather than
 * being restated in a build file.
 *
 * Such a build MUST NOT be handed a context for any other variant: the kernel it
 * calls is fixed, so a mismatched variant silently computes a wrong answer. Nothing
 * checks this at run time -- removing the run-time check is the point -- so it is
 * the firmware's KAT gate that has to cover it, and does: each per-cipher image
 * verifies its own known-answer vectors before it times anything.
 *
 * Never defined for the host build or the test suite, which run all variants through
 * one binary and need the run-time dispatch. PRESENT_ONE_CIPHER_KERNEL(bs32_enc_k)
 * yields the kernel symbol name for a given per-kernel prefix. */
#ifdef PRESENT_ONE_CIPHER
#define PRESENT_CAT_(a, b) a##b
#define PRESENT_CAT(a, b) PRESENT_CAT_(a, b)
#define PRESENT_ONE_CIPHER_KERNEL(prefix) \
    PRESENT_CAT(prefix, PRESENT_CAT(PRESENT_KERNEL_ENC_OF_, PRESENT_ONE_CIPHER))
#endif

/* Every kernel but the selected one is unreferenced by construction in such a
 * build. Dropping them is the entire point, but each would also be reported by
 * -Wunused-function, and 30 warnings that are all expected is a good way to stop
 * reading warnings. Conditional rather than unconditional: in a normal build an
 * unreferenced kernel means the dispatch stopped covering PRESENT_KERNEL_ENC_LIST,
 * which is worth being told about. */
#ifdef PRESENT_ONE_CIPHER
#define PRESENT_KERNEL_MAYBE_UNUSED __attribute__((unused))
#else
#define PRESENT_KERNEL_MAYBE_UNUSED
#endif

#endif /* PRESENT_INTERNAL_H */
