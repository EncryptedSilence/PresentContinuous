/* Bitsliced counter-mode backend on AVX2: ctr-bitslice-avx2, 256 blocks per group.
 *
 * The widest honest CTR number this tree can produce on x86, and the one whose
 * comparison against results/speed.csv's avx2-bs row is the point of the whole
 * exercise: that row times the round function with the state already bitsliced,
 * this one times the operation a caller holding a byte buffer actually performs.
 * Same kernel, same key schedule, same round count; the difference is the two
 * transposes and the byte-oriented XOR, which live inside the loop below and are
 * not going anywhere.
 *
 * No intrinsics here on purpose. Everything this file needs to know about the
 * AVX2 layout is where a slice's four lanes sit in memory, and once that is known
 * the counters are ordinary uint64_t stores -- so the file compiles clean on a
 * machine without AVX2, the vector work stays in src/present_avx2.c where the
 * kernels are, and the build needs no per-file -mavx2. Whether the backend may
 * run is decided at run time through ctr_backend_t.available (present_have_avx2),
 * which is what that hook exists for; on a non-AVX2 build the entry points in
 * src/present_avx2.c are stubs and available() reports 0, so run() is never
 * reached and no #ifdef is needed at any call site.
 *
 * The layout, verified against src/present_avx2.c rather than assumed:
 * lane_transpose_4x4() puts block 64*g + k of the group into lane g, and
 * bit_transpose64x4() then runs present_transpose64's exact six-pass swap inside
 * each lane. So with `state` viewed as uint64_t, state[4*i + g] is lane g of
 * slice i, and its bit k is bit i of block 64*g + k. present_ctr_counters64_lanes
 * writes precisely that.
 */
#include <assert.h>

#include "ctr_backend.h"
#include "ctr_xor.h"
#include "gen/ctr_cipher_set.h"
#include "present/present.h"
#include "present/variant.h"
#include "present_ctr.h"

#define AVX2_LANES  4
#define AVX2_BLOCKS PRESENT_AVX2_BLOCKS                        /* 256 */
#define AVX2_GROUP  (AVX2_BLOCKS * PRESENT_BLOCK_BYTES)        /* 2048 B */

_Static_assert(AVX2_BLOCKS == AVX2_LANES * PRESENT_BITSLICE_BLOCKS,
               "AVX2 group is four 64-block lanes");

static void run_bs_avx2(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const present_ctx_t *ctx = st;
    /* 2 KiB each, 6 KiB total, in automatic storage -- the home
     * bench/ctr_backend.h sanctions for a bitsliced backend's mutable working
     * memory, and inside the timed region by design. CTR_STATE_ALIGN is 64,
     * which more than covers the 32 bytes present_encrypt_avx2_bs wants. */
    _Alignas(CTR_STATE_ALIGN) uint64_t state[AVX2_LANES * PRESENT_BLOCK_BITS];
    _Alignas(CTR_STATE_ALIGN) uint64_t scratch[AVX2_LANES * PRESENT_BLOCK_BITS];
    _Alignas(CTR_STATE_ALIGN) uint64_t ks[AVX2_BLOCKS];

    assert(len % AVX2_GROUP == 0);

    for (size_t off = 0; off < len; off += AVX2_GROUP) {
        present_ctr_counters64_lanes(state, ctr0 + off / PRESENT_BLOCK_BYTES, AVX2_LANES);

        /* The kernel ping-pongs, so unpack whichever buffer it returns.
         * present_avx2_unpack does its bit transpose in place -- it takes a
         * const pointer but casts it away -- which is fine because `res` is one
         * of the two locals above and is dead after this line. */
        uint64_t *res = present_encrypt_avx2_bs(ctx, state, scratch);
        present_avx2_unpack(res, ks);

        /* Big-endian serialisation in place, word-wise via bench/ctr_xor.h --
         * the same helper bench/ctr_narrow.c, bench/ctr_wide.c and the scalar
         * bitsliced backends use, so all four are comparable end to end rather
         * than only in their kernels. This is the step that dominated the pass
         * when it was written byte at a time; see ctr_xor.h. */
        for (int i = 0; i < AVX2_BLOCKS; i++)
            ctr_xor_be64(buf + off + 8 * i, ks[i]);
    }
}

/* --- prepare(): one per cipher, from the generated list ------------------------- */
#define DEFINE_PREPARE(id, name, rounds, bb) \
    static void prepare_avx2_##id(void *state, const uint8_t *key, size_t key_len) \
    { \
        const present_variant_t *v = present_variant_by_name(name); \
        int rc = present_init((present_ctx_t *)state, v, key, key_len); \
        assert(rc == 0 && "present_init failed: bad variant name or key length"); \
        (void)rc; \
    }
CTR_NARROW_CIPHER_LIST(DEFINE_PREPARE)
#undef DEFINE_PREPARE

/* --- registration: five ciphers, one backend kind ------------------------------- */

/* key_bytes patched by the constructor below; see bench/ctr_narrow.c's file
 * comment for why it cannot be a compile-time constant. */
#define AVX2_CIPHER_ROW(cipher_id, cipher_name, rounds, bb) \
    { "ctr-bitslice-avx2", cipher_name, PRESENT_BLOCK_BYTES, AVX2_GROUP, 0, \
      sizeof(present_ctx_t), present_have_avx2, prepare_avx2_##cipher_id, \
      run_bs_avx2 },

ctr_backend_t ctr_backends_avx2[] = {
    CTR_NARROW_CIPHER_LIST(AVX2_CIPHER_ROW)
};

const size_t ctr_backends_avx2_count =
    sizeof(ctr_backends_avx2) / sizeof(ctr_backends_avx2[0]);

__attribute__((constructor))
static void ctr_avx2_init(void)
{
    for (size_t i = 0; i < ctr_backends_avx2_count; i++) {
        const present_variant_t *v = present_variant_by_name(ctr_backends_avx2[i].cipher);
        assert(v && "ctr_avx2_init: registered cipher name is not a known variant");
        ctr_backends_avx2[i].key_bytes = present_variant_key_bytes(v);
    }
}
