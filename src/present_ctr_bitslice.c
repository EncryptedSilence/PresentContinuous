/* Bitsliced counter-mode backends, scalar: ctr-bitslice-u64 and ctr-bitslice-u32.
 *
 * These measure what a byte-oriented caller can actually reach. bench/bench_main.c
 * already reports the -bs rows -- the round function with the state handed to it
 * already transposed and the transpose lifted out of the timed region -- and those
 * are a kernel ceiling: no caller holding a byte buffer can obtain them, because
 * getting into and out of bitsliced form is not optional for such a caller. Here
 * every step is inside run(): the counters are produced (in bitsliced form, which
 * is the one part counter mode genuinely does get for free -- see present_ctr.h),
 * the round function runs, the keystream is transposed back to 64 ordinary blocks,
 * serialised big-endian, and XORed into the buffer in place.
 *
 * The output transpose in particular is NOT hoistable. It is inside the loop and
 * it stays there; that gap against the -bs row is the number this whole protocol
 * exists to stop hiding.
 *
 * Two backends, because the interesting comparison is not x86-only. The u32 path
 * is the one the Cortex-M4 firmware uses and is a median 1.2x faster there
 * (results/m4-speed.csv); on a 64-bit host it should lose to u64 on every cipher,
 * and having both registered is what makes that a measurement rather than a
 * claim. Both are plain C and are always available.
 *
 * Like bench/ctr_narrow.c, run() is generic over the five 64-bit ciphers -- the
 * kernels dispatch on ctx->var->kernel_enc -- and only prepare() is per-cipher,
 * so this file holds two run functions and five prepare functions, not ten.
 */
#include <assert.h>

#include "ctr_backend.h"
#include "gen/ctr_cipher_set.h"
#include "present/present.h"
#include "present/variant.h"
#include "present_ctr.h"

/* --- counter generation ---------------------------------------------------------
 *
 * The derivation, and why base is not assumed to be a multiple of the group, are
 * in present_ctr.h. In brief: slice i of the aligned pattern is bit i of the block
 * index, an unaligned base rotates that pattern and contributes a one-bit carry,
 * and the slices above the group width are the carry rippled into broadcasts of
 * the base's own bits.
 */

/* Slice i of the identity counter block over 64 blocks: bit k is bit i of k.
 * These are literally present_transpose64()'s masks -- the transpose of the
 * counter ramp is the transpose's own bit-selection pattern. */
static const uint64_t ctr_low_slice[6] = {
    0xAAAAAAAAAAAAAAAAull, 0xCCCCCCCCCCCCCCCCull, 0xF0F0F0F0F0F0F0F0ull,
    0xFF00FF00FF00FF00ull, 0xFFFF0000FFFF0000ull, 0xFFFFFFFF00000000ull,
};

/* Over 32 blocks: the same, one width down and one constant shorter. */
static const uint32_t ctr_low_slice32[5] = {
    0xAAAAAAAAu, 0xCCCCCCCCu, 0xF0F0F0F0u, 0xFF00FF00u, 0xFFFF0000u,
};

/* Rotates, written out because a shift by the word width is undefined and n = 0
 * is the common case (an aligned base), not an edge case to be clever about. */
static inline uint64_t rotr64(uint64_t x, unsigned n)
{
    return n ? (x >> n) | (x << (64 - n)) : x;
}

static inline uint32_t rotr32(uint32_t x, unsigned n)
{
    return n ? (x >> n) | (x << (32 - n)) : x;
}

void present_ctr_counters64_lanes(uint64_t *state, uint64_t base, int lanes)
{
    /* base = 64 * hi + lo. Within a lane, block k carries counter base + k
     * (+ 64 * g for lane g, which is exactly a +g on hi), so:
     *   low 6 bits  = (lo + k) mod 64      -> the aligned pattern rotated by lo
     *   carry out   = 1 iff lo + k >= 64   -> the top `lo` bit positions
     *   bits 6 and up = hi + g + carry     -> ripple the carry into broadcasts */
    const unsigned lo = (unsigned)(base & 63);
    const uint64_t carry0 = lo ? ~(uint64_t)0 << (64 - lo) : 0;
    const uint64_t hi = base >> 6;

    for (int i = 0; i < 6; i++) {
        const uint64_t v = rotr64(ctr_low_slice[i], lo);
        for (int g = 0; g < lanes; g++) state[lanes * i + g] = v;
    }

    for (int g = 0; g < lanes; g++) {
        /* Wrapping is intended: the counter is mod 2^64, the same as ctr-ref's
         * own `ctr0 + off / 8`. */
        uint64_t h = hi + (uint64_t)g;
        uint64_t carry = carry0;
        for (int i = 6; i < 64; i++) {
            /* All-ones if bit i-6 of h is set, else all-zeroes. Adding a 0/1
             * carry to h is sum = h ^ carry, carry' = h & carry, bit by bit. */
            const uint64_t a = (uint64_t)0 - ((h >> (i - 6)) & 1);
            state[lanes * i + g] = a ^ carry;
            carry &= a;
        }
    }
}

void present_ctr_counters64(uint64_t *state, uint64_t base)
{
    present_ctr_counters64_lanes(state, base, 1);
}

void present_ctr_counters32(uint32_t *state, uint64_t base)
{
    const unsigned lo = (unsigned)(base & 31);
    uint32_t carry = lo ? ~(uint32_t)0 << (32 - lo) : 0;
    const uint64_t hi = base >> 5;

    for (int i = 0; i < 5; i++) state[i] = rotr32(ctr_low_slice32[i], lo);

    /* 64 slices, not 32: one word per state bit, so the loop runs to
     * PRESENT_BLOCK_BITS even though only 32 blocks are in flight. */
    for (int i = 5; i < PRESENT_BLOCK_BITS; i++) {
        const uint32_t a = (uint32_t)0 - (uint32_t)((hi >> (i - 5)) & 1);
        state[i] = a ^ carry;
        carry &= a;
    }
}

/* --- run(): the whole counter-mode pass, transpose included --------------------- */

#define BS64_BLOCKS PRESENT_BITSLICE_BLOCKS                       /* 64 */
#define BS64_GROUP  (BS64_BLOCKS * PRESENT_BLOCK_BYTES)           /* 512 B */
#define BS32_BLOCKS PRESENT_BITSLICE32_BLOCKS                     /* 32 */
#define BS32_GROUP  (BS32_BLOCKS * PRESENT_BLOCK_BYTES)           /* 256 B */

/* Big-endian serialisation of one group's keystream, XORed in place. This is the
 * byte-oriented half of the honesty: ctr-ref emits bytes, so a bitsliced backend
 * that stopped at 64 uint64_t would not be comparable with it. Identical
 * expression to bench/ctr_narrow.c's, deliberately -- the two loops differ only
 * in where ks[] came from. */
static inline void xor_ks(uint8_t *buf, const uint64_t *ks, int n)
{
    for (int i = 0; i < n; i++)
        for (int b = 0; b < 8; b++)
            buf[8 * i + b] ^= (uint8_t)(ks[i] >> (56 - 8 * b));
}

static void run_bs_u64(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const present_ctx_t *ctx = st;
    /* Automatic storage, which bench/ctr_backend.h names as the only legal home
     * for a bitsliced backend's scratch: `state` is const during run() and run()
     * may not write to anything static. 1.5 KiB, well inside the ~16 KiB the
     * header budgets so the same shape can be built for a Cortex-M4 stack. */
    _Alignas(CTR_STATE_ALIGN) uint64_t state[PRESENT_BLOCK_BITS];
    _Alignas(CTR_STATE_ALIGN) uint64_t scratch[PRESENT_BLOCK_BITS];
    _Alignas(CTR_STATE_ALIGN) uint64_t ks[BS64_BLOCKS];

    /* Guaranteed by the harness, which checks --size against group_bytes per
     * backend before any work; asserted here because there is no partial-group
     * path below and getting it wrong is an out-of-bounds write. Outside the
     * loop, so it costs nothing in the timed region. */
    assert(len % BS64_GROUP == 0);

    for (size_t off = 0; off < len; off += BS64_GROUP) {
        present_ctr_counters64(state, ctr0 + off / PRESENT_BLOCK_BYTES);
        /* The kernel ping-pongs and returns whichever buffer holds the answer --
         * `state` for an even round count, `scratch` for an odd one -- so the
         * return value is what gets transposed, never `state` by assumption. */
        present_transpose64(present_encrypt_bitslice_bs(ctx, state, scratch), ks);
        xor_ks(buf + off, ks, BS64_BLOCKS);
    }
}

static void run_bs_u32(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const present_ctx_t *ctx = st;
    /* PRESENT_BLOCK_BITS words, NOT BS32_BLOCKS: present_encrypt_bitslice32_bs
     * keeps one 32-bit word per state bit, so 32 blocks still need 64 words.
     * Sizing these by the block count gives half of what the kernel writes --
     * the trap include/present/present.h calls out by name. */
    _Alignas(CTR_STATE_ALIGN) uint32_t state[PRESENT_BLOCK_BITS];
    _Alignas(CTR_STATE_ALIGN) uint32_t scratch[PRESENT_BLOCK_BITS];
    _Alignas(CTR_STATE_ALIGN) uint64_t ks[BS32_BLOCKS];

    assert(len % BS32_GROUP == 0);

    for (size_t off = 0; off < len; off += BS32_GROUP) {
        present_ctr_counters32(state, ctr0 + off / PRESENT_BLOCK_BYTES);
        present_bitslice32_unpack(present_encrypt_bitslice32_bs(ctx, state, scratch), ks);
        xor_ks(buf + off, ks, BS32_BLOCKS);
    }
}

/* --- prepare(): one per cipher ---------------------------------------------------
 *
 * Same shape and same reasoning as bench/ctr_narrow.c's: the five 64-bit ciphers
 * come from the generated CTR_NARROW_CIPHER_LIST and are not named here, so a
 * cipher added to or removed from tools/cipher_set.py arrives with its rows and
 * cannot be spelled differently in this file than in the FPGA and M4 results.
 */
#define DEFINE_PREPARE(id, name, rounds, bb) \
    static void prepare_bs_##id(void *state, const uint8_t *key, size_t key_len) \
    { \
        const present_variant_t *v = present_variant_by_name(name); \
        int rc = present_init((present_ctx_t *)state, v, key, key_len); \
        assert(rc == 0 && "present_init failed: bad variant name or key length"); \
        (void)rc; \
    }
CTR_NARROW_CIPHER_LIST(DEFINE_PREPARE)
#undef DEFINE_PREPARE

/* --- registration: five ciphers x two backend kinds = 10 entries ---------------- */

/* key_bytes is 0 here and patched below by a constructor, for the reason
 * bench/ctr_narrow.c's file comment gives at length: present_variant_key_bytes()
 * is the only honest source for it (the cipher-D family's key material IS its
 * round keys, 72 or 48 bytes) and it depends on another translation unit's
 * static initializer, so it cannot be a compile-time constant. */
#define BS_ENTRY(cipher_id, cipher_name, kind_id, kind_name, group_blocks) \
    { kind_name, cipher_name, PRESENT_BLOCK_BYTES, \
      (size_t)(group_blocks) * PRESENT_BLOCK_BYTES, 0, \
      sizeof(present_ctx_t), NULL, prepare_bs_##cipher_id, run_##kind_id },

#define BS_CIPHER_ROW(cipher_id, cipher_name, rounds, bb) \
    BS_ENTRY(cipher_id, cipher_name, bs_u64, "ctr-bitslice-u64", BS64_BLOCKS) \
    BS_ENTRY(cipher_id, cipher_name, bs_u32, "ctr-bitslice-u32", BS32_BLOCKS)

ctr_backend_t ctr_backends_bitslice[] = {
    CTR_NARROW_CIPHER_LIST(BS_CIPHER_ROW)
};

_Static_assert(sizeof(ctr_backends_bitslice) / sizeof(ctr_backends_bitslice[0]) % 2 == 0,
               "ctr_backends_bitslice: two backend kinds per cipher");

const size_t ctr_backends_bitslice_count =
    sizeof(ctr_backends_bitslice) / sizeof(ctr_backends_bitslice[0]);

__attribute__((constructor))
static void ctr_bitslice_init(void)
{
    for (size_t i = 0; i < ctr_backends_bitslice_count; i++) {
        const present_variant_t *v =
            present_variant_by_name(ctr_backends_bitslice[i].cipher);
        assert(v && "ctr_bitslice_init: registered cipher name is not a known variant");
        ctr_backends_bitslice[i].key_bytes = present_variant_key_bytes(v);
    }
}
