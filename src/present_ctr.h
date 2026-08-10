/* Counter blocks generated directly in bitsliced form.
 *
 * This is the piece that makes a bitsliced CTR backend honest rather than a
 * transpose in disguise. A bitsliced kernel wants its input as slices -- slice i
 * is one machine word whose bit k is bit i of block k -- and the obvious way to
 * get there is to materialise the counters as integers and run a 64x64 bit
 * transpose. Doing that would pay the input transpose that counter mode is
 * supposed to avoid, and would make "bitsliced CTR" strictly slower than the
 * table path for no reason.
 *
 * It is avoidable because consecutive counters share all but their low bits. For
 * a group of N = 64 blocks starting at a multiple of 64, bit i of (base + k) for
 * i < 6 is just bit i of k, so slice i is a constant that does not depend on base
 * at all; and for i >= 6 every block in the group shares the bit, so the slice is
 * all-ones or all-zeroes. Six constants and 58 broadcasts, against a transpose's
 * couple of hundred operations.
 *
 * The six constants are the transpose's own masks, which is not a coincidence:
 * slice i of the identity counter block IS the bit-i-of-index pattern.
 *
 * --- why these take an arbitrary base, and not only a multiple of the group ---
 *
 * bench/ctr_backend.h states that ctr0 "is a full 64-bit value and is not
 * guaranteed to be zero or small", and both callers make good on it:
 * tests/test_ctr.c and bench/ctr_bench.c run the correctness gate at
 * ctr0 = 0x00000000FFFFFF80 as well as at 0. That value is a multiple of 32, of
 * 64 and of 128 -- but not of 256, which is the AVX2 kernel's fixed group size.
 * So "assume base is a multiple of the group and assert it" is not an option for
 * the widest backend: the assert fires in `make test`, and under NDEBUG it does
 * not fire and the backend simply computes the wrong keystream.
 *
 * Handling the general case costs a rotate and one extra AND per slice, because
 * adding an unaligned base is a rotate plus a single-bit ripple carry rather
 * than a re-transpose. Writing base = 64*H + L with L = base mod 64:
 *
 *   base + k = 64*(H + c(k)) + ((L + k) mod 64),   c(k) = 1 iff L + k >= 64
 *
 * so the low six slices are the aligned patterns rotated right by L, the carry
 * c(k) is the constant mask of the top L bit positions, and the high slices are
 * that carry rippled into the broadcast bits of H. At L = 0 the rotate is the
 * identity and the carry mask is zero, so the general form collapses exactly
 * onto the "six constants and 58 broadcasts" above -- the cost argument that
 * justifies bitsliced CTR at all survives unchanged, and no caller has to know
 * whether its ctr0 happened to land on a group boundary.
 */
#ifndef PRESENT_CTR_H
#define PRESENT_CTR_H

#include <stdint.h>

/* The 64 slices of the 64 consecutive counters base .. base+63, in the layout
 * present_transpose64() produces: state[i] bit k is bit i of block k. `state`
 * must have room for 64 uint64_t -- one per state bit, not one per block.
 *
 * base is arbitrary; the counters wrap mod 2^64, which is what ctr-ref's
 * `ctr0 + off / 8` does too. */
void present_ctr_counters64(uint64_t *state, uint64_t base);

/* The same for 32 consecutive counters, in the layout present_bitslice32_pack()
 * produces: state[i] bit k is bit i of block k, for i < 64 and k < 32.
 *
 * `state` must have room for 64 uint32_t. That is one word per *state bit*, so
 * it does not shrink with the block count -- see the sizing note in
 * include/present/present.h. Sizing this by the 32 blocks gives half of what
 * present_encrypt_bitslice32_bs() goes on to write. */
void present_ctr_counters32(uint32_t *state, uint64_t base);

/* The vector form: `lanes` 64-bit lanes per slice, so 64 * lanes blocks per
 * group, in the layout both present_avx2_pack() and present_neon_pack() produce
 *
 *     state[lanes * i + g] bit k  is  bit i of block (64 * g + k)
 *
 * i.e. lane g holds the g-th group of 64 blocks, and each lane is internally the
 * plain 64x64 transpose. `state` must have room for 64 * lanes uint64_t.
 *
 * lanes is 4 for present_encrypt_avx2_bs (256 blocks) and 2 for
 * present_encrypt_neon_bs (128 blocks); lanes = 1 is present_ctr_counters64.
 * Verified against those two backends' pack routines rather than assumed --
 * src/present_avx2.c's lane_transpose_4x4 puts in[g*64 + k] in lane g, and
 * src/present_neon.c's present_neon_pack transposes in[0..63] into lane 0 and
 * in[64..127] into lane 1. A backend whose pack differs must not use this. */
void present_ctr_counters64_lanes(uint64_t *state, uint64_t base, int lanes);

#endif /* PRESENT_CTR_H */
