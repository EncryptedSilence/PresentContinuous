/* fw/m4/kat.h -- the on-device correctness gate.
 *
 * Nothing is timed until it is proven correct on the board. The firmware runs
 * every (cipher, implementation) pair it can time against vectors produced by
 * the host build (fw/m4/gen/kat_vectors.h, written by tools/gen_m4_kats.py),
 * and the Phase 4 harness asks kat_ok() before timing each pair: a pair that
 * did not reproduce the host's ciphertext is reported as status=KAT_FAIL with
 * no timing figures at all. A fast implementation that computes the wrong
 * ciphertext is worthless, and a megabytes-per-second number printed next to it
 * is worse than none -- it looks authoritative and means nothing.
 *
 * Implementation names, which are also the CSV's impl column:
 *
 *   ref             present_encrypt_ref            (64-bit ciphers)
 *                   lin_encrypt_ref                (aes-lin444, the portable definition)
 *   table           present_encrypt_table          (64-bit ciphers)
 *                   aes_encrypt1                   (aes, the T-table kernel)
 *   table-x4        present_encrypt_table_x4 / aes_encrypt4
 *   bitslice32      32 blocks, bit transpose included
 *   bitslice32-bs   32 blocks, state already transposed
 *
 * Not every name applies to every cipher: AES has no "ref" row (its scalar
 * kernel is the T-table one) and AES-lin444 has no "table" row (the fused-table
 * kernel in bench/wide_bench.c is SSE2 and stayed on x86). Those pairs are
 * recorded as not-applicable, not as passes.
 */
#ifndef FW_M4_KAT_H
#define FW_M4_KAT_H

/* Run every (cipher, implementation) pair against its vectors and record the
 * outcome. Returns the number of failing pairs -- zero, and only zero, clears
 * the run to publish timings. A vector table the firmware cannot make sense of
 * (a cipher name no variant answers to, a round count that disagrees with the
 * variant descriptor, more ciphers than the fixed table holds) counts as
 * failures too: the gate never reports zero while something is unaccounted for.
 * Safe to call more than once; each call recomputes from scratch. */
int kat_check_all(void);

/* Whether (cipher, impl) is proven correct on this board. Returns 0 unless
 * kat_check_all() has run and that pair passed.
 *
 * For a name this gate does not test for that cipher -- an implementation it
 * has no vector path for, or a row such as "keysetup" that computes no
 * ciphertext -- the answer falls back to the cipher's own verdict: 1 only if
 * every implementation of that cipher that *was* checked passed. So a cipher
 * whose bitsliced kernel is broken gates its key-setup row too, and an unknown
 * cipher gates everything. */
int kat_ok(const char *cipher, const char *impl);

/* One semihosted line per (cipher, implementation) pair, then a summary. Must
 * not be called from inside a timed region -- every line traps to the host. */
void kat_print_results(void);

/* The ciphers the vector table names, in its order. The harness enumerates
 * these rather than restating the cipher list: the list belongs to
 * tools/cipher_set.py, reaches the firmware through the generated vectors, and
 * is never written down a third time. Valid after kat_check_all(). */
int kat_n_ciphers(void);
const char *kat_cipher_name(int i);
int kat_cipher_rounds(int i);

#endif /* FW_M4_KAT_H */
