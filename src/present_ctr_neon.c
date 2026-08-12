/* Bitsliced counter-mode backend on NEON: ctr-bitslice-neon, 128 blocks per group.
 *
 * The ARM counterpart to src/present_ctr_avx2.c -- read that file's header first;
 * this one is the same argument with the lane count changed from 4 to 2. The point
 * is the same: results/speed-arm.csv's neon-bs row times the round function with
 * the state already bitsliced, and this backend times the operation a caller
 * holding a byte buffer actually performs -- counters generated directly in
 * bitsliced form (present_ctr.h), the kernel, the output transpose, and the
 * byte-oriented XOR, all inside run().
 *
 * No intrinsics here on purpose, for the same reason present_ctr_avx2.c has none:
 * everything this file needs to know about the NEON layout is where a slice's two
 * lanes sit in memory, and once that is known the counters are ordinary uint64_t
 * stores. The vector work stays in src/present_neon.c where the kernels live, and
 * this file needs no per-file -mfpu. Whether the backend may run is decided at run
 * time through ctr_backend_t.available (present_have_neon): on a build without
 * __ARM_NEON the entry points in src/present_neon.c are stubs and available()
 * reports 0, so run() is never reached and no #ifdef is needed at any call site.
 *
 * The layout, per present_ctr.h's present_ctr_counters64_lanes contract and
 * include/present/present.h's own note on present_neon_pack: lane g of a slice
 * holds blocks 64*g .. 64*g+63, i.e. present_neon_pack transposes in[0..63] into
 * lane 0 and in[64..127] into lane 1. So with `state` viewed as uint64_t,
 * state[2*i + g] is lane g of slice i, and its bit k is bit i of block 64*g + k --
 * exactly what present_ctr_counters64_lanes(state, base, 2) writes.
 */
#include <assert.h>

#include "ctr_backend.h"
#include "ctr_xor.h"
#include "gen/ctr_cipher_set.h"
#include "present/present.h"
#include "present/variant.h"
#include "present_ctr.h"

#define NEON_LANES  2
#define NEON_BLOCKS PRESENT_NEON_BLOCKS                        /* 128 */
#define NEON_GROUP  (NEON_BLOCKS * PRESENT_BLOCK_BYTES)        /* 1024 B */

_Static_assert(NEON_BLOCKS == NEON_LANES * PRESENT_BITSLICE_BLOCKS,
               "NEON group is two 64-block lanes");

static void run_bs_neon(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const present_ctx_t *ctx = st;
    /* 1 KiB each, 3 KiB total, in automatic storage -- the home
     * bench/ctr_backend.h sanctions for a bitsliced backend's mutable working
     * memory, and inside the timed region by design. CTR_STATE_ALIGN is 64,
     * which more than covers the 16 bytes present_encrypt_neon_bs wants. */
    _Alignas(CTR_STATE_ALIGN) uint64_t state[NEON_LANES * PRESENT_BLOCK_BITS];
    _Alignas(CTR_STATE_ALIGN) uint64_t scratch[NEON_LANES * PRESENT_BLOCK_BITS];
    _Alignas(CTR_STATE_ALIGN) uint64_t ks[NEON_BLOCKS];

    assert(len % NEON_GROUP == 0);

    for (size_t off = 0; off < len; off += NEON_GROUP) {
        present_ctr_counters64_lanes(state, ctr0 + off / PRESENT_BLOCK_BYTES, NEON_LANES);

        /* The kernel ping-pongs, so unpack whichever buffer it returns.
         * present_neon_unpack does its bit transpose in place -- it takes a const
         * pointer but casts it away -- which is fine because `res` is one of the
         * two locals above and is dead after this line. */
        uint64_t *res = present_encrypt_neon_bs(ctx, state, scratch);
        present_neon_unpack(res, ks);

        /* Big-endian serialisation in place, word-wise via bench/ctr_xor.h --
         * the same helper every other registered backend uses, so all of them
         * are comparable end to end rather than only in their kernels. */
        for (int i = 0; i < NEON_BLOCKS; i++)
            ctr_xor_be64(buf + off + 8 * i, ks[i]);
    }
}

/* --- prepare(): one per cipher, from the generated list ------------------------- */
#define DEFINE_PREPARE(id, name, rounds, bb) \
    static void prepare_neon_##id(void *state, const uint8_t *key, size_t key_len) \
    { \
        const present_variant_t *v = present_variant_by_name(name); \
        int rc = present_init((present_ctx_t *)state, v, key, key_len); \
        assert(rc == 0 && "present_init failed: bad variant name or key length"); \
        (void)rc; \
    }
CTR_NARROW_CIPHER_LIST(DEFINE_PREPARE)
#undef DEFINE_PREPARE

/* --- registration: five ciphers, one backend kind -------------------------------- */

/* key_bytes patched by the constructor below; see bench/ctr_narrow.c's file
 * comment for why it cannot be a compile-time constant. */
#define NEON_CIPHER_ROW(cipher_id, cipher_name, rounds, bb) \
    { "ctr-bitslice-neon", cipher_name, PRESENT_BLOCK_BYTES, NEON_GROUP, 0, \
      sizeof(present_ctx_t), present_have_neon, prepare_neon_##cipher_id, \
      run_bs_neon },

ctr_backend_t ctr_backends_neon[] = {
    CTR_NARROW_CIPHER_LIST(NEON_CIPHER_ROW)
};

const size_t ctr_backends_neon_count =
    sizeof(ctr_backends_neon) / sizeof(ctr_backends_neon[0]);

__attribute__((constructor))
static void ctr_neon_init(void)
{
    for (size_t i = 0; i < ctr_backends_neon_count; i++) {
        const present_variant_t *v = present_variant_by_name(ctr_backends_neon[i].cipher);
        assert(v && "ctr_neon_init: registered cipher name is not a known variant");
        ctr_backends_neon[i].key_bytes = present_variant_key_bytes(v);
    }
}
