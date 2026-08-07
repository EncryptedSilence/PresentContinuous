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
 *   bitslice64      64 blocks, bit transpose included    (64-bit ciphers only)
 *   bitslice64-bs   64 blocks, state already transposed  (64-bit ciphers only)
 *
 * Not every name applies to every cipher: AES has no "ref" row (its scalar
 * kernel is the T-table one), AES-lin444 has no "table" row (the fused-table
 * kernel in bench/wide_bench.c is SSE2 and stayed on x86), and neither 128-bit
 * cipher has a bitslice64 row, because the 128-bit bitslice in
 * bench/wide_bitslice32.h has no 64-bit-word form. Those pairs are recorded as
 * not-applicable, not as passes.
 */
#ifndef FW_M4_KAT_H
#define FW_M4_KAT_H

#include <stdint.h>

#include "present/present.h"

/* Run every (cipher, implementation) pair against its vectors and record the
 * outcome. Returns the number of failing pairs -- zero, and only zero, clears
 * the run to publish timings. A vector table the firmware cannot make sense of
 * (a cipher name no variant answers to, a round count that disagrees with the
 * variant descriptor, more ciphers than the fixed table holds) counts as
 * failures too: the gate never reports zero while something is unaccounted for.
 * Safe to call more than once; each call recomputes from scratch. */
int kat_check_all(void);

/* Whether (cipher, impl) is proven correct on this board. Fails closed: it
 * returns 0 unless kat_check_all() has run and that exact pair passed.
 *
 * The one exception is "keysetup", a row the harness times that produces a key
 * schedule rather than a block, so there is no ciphertext to compare. It is
 * answered with the cipher's own verdict -- 1 only if every implementation of
 * that cipher that was checked passed -- so a cipher whose kernel is broken does
 * not get a key-setup figure published either.
 *
 * Every other unrecognised name answers 0 and says so on the semihosting
 * channel, rather than being waved through on the strength of the cipher's other
 * rows. A row this gate never validated must not be timed, and a misspelled impl
 * name in the harness is exactly how an unvalidated row would otherwise acquire
 * a status of ok. Adding an implementation to the benchmark therefore means
 * adding it to fw/m4/kat.c as well. Note that this call may write to the
 * semihosting channel, so like everything else in this header it must stay
 * outside any timed region. */
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

/* 8 for the 64-bit ciphers in src/, 16 for the two 128-bit ones in bench/. Taken
 * from the vector table, so the block size a figure is normalised by is the same
 * one the ciphertext it was cleared against was computed with, and the harness
 * never has to guess it from a cipher's name. Valid after kat_check_all(). */
int kat_cipher_block_bytes(int i);

/* --- CCM storage lent to the benchmark harness -----------------------------
 *
 * The linker script's ASSERT caps CCM at 64 KiB and a present_ctx_t alone is
 * 33,032 B of it (16 KiB of fused S-box/pLayer table, 10.5 KiB of bitsliced
 * round-key masks); the bitsliced 128-bit round-key array is another 10,752 B.
 * The gate and the harness live in one binary, so a second copy of each would
 * need 43,784 B that do not exist. There is therefore exactly one of each in the
 * firmware, declared here and lent out.
 *
 * Sequencing is what makes that safe, and it is not negotiable: kat_check_all()
 * runs to completion first and never runs again, after which nothing in this
 * module reads either buffer -- kat_ok(), kat_print_results() and the accessors
 * above answer from the recorded per-pair status alone. A caller may then use
 * both freely; it must reinitialise them (present_init, bs32_expand_*_key)
 * before its own first use, since it will find the last cipher the gate checked
 * still in them. Calling kat_check_all() again after borrowing would re-derive
 * everything it needs and is also safe, but the harness has no reason to.
 */
present_ctx_t *kat_lend_ctx(void);
uint32_t *kat_lend_bs_km(void);

#endif /* FW_M4_KAT_H */
