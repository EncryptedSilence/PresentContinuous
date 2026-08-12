/* NEON bitsliced CTR backend for the two 128-bit ciphers: ctr-bitslice-neon,
 * 128 blocks (one NEON vector width) per group, for aes-r5 and
 * aes-lin444-0-8-15-r4.
 *
 * The wide counterpart to src/present_ctr_neon.c (the 64-bit PRESENT NEON CTR
 * backend) -- read that file's header first; this is the same argument over the
 * 16-byte block. results/wide-speed-arm.csv's neon row times the round function
 * with the state already bitsliced; this backend times the operation a caller
 * holding a byte buffer actually performs -- counter blocks built, packed into
 * bitsliced form, the kernel, the output transpose, and the byte-oriented XOR,
 * all inside run().
 *
 * Counter generation is honest and deliberately simple: rather than writing the
 * bitsliced counter planes directly (constant low index bits, broadcast high
 * bits, zero top half -- the layout bench/ctr_backend.h describes for the
 * 128-bit block), run() materialises the 128 counter blocks as bytes and calls
 * wide_neon_pack. That folds the same transpose the output side pays into the
 * input side too, which is exactly the cost this measurement is supposed to
 * include (bench/ctr_backend.h: "a backend that assumes its input is already
 * bitsliced measures a kernel ceiling"). This backend is predicted to lose to
 * the table path on the Cortex-A7 (docs/platform-estimate.md); the transpose is
 * written for obvious correctness, not to rescue the number.
 *
 * No intrinsics here -- all the vector work is in bench/wide_bitslice_neon.h.
 * Whether the backend may run is decided at run time through
 * ctr_backend_t.available (present_have_neon): on a build without __ARM_NEON the
 * header is empty and available() reports 0, so run() is never reached and no
 * #ifdef is needed at any call site. The kernel-calling bodies are still guarded
 * with #if defined(__ARM_NEON) so the translation unit compiles on the x86 stub
 * build (where it contributes zero rows).
 */
#include <assert.h>
#include <string.h>

#include "ctr_backend.h"
#include "ctr_xor.h"
#include "gen/ctr_cipher_set.h"
#include "wide_ciphers.h"
#include "wide_bitslice_neon.h"

/* Provided by src/present_neon.c (1 with NEON, 0 without) -- declared here
 * rather than pulling in present/present.h so this wide file keeps its
 * cipher-side dependency to wide_ciphers.h + wide_bitslice_neon.h. */
extern int present_have_neon(void);

#define WIDE_BLOCK_BYTES 16
#define WIDE_KEY_BYTES   16
#define WIDE_NEON_GROUP  (128 * WIDE_BLOCK_BYTES)   /* 2048 B: 128 blocks */

/* The generated round counts, pulled off the per-family lists so no round count
 * is a literal here (each list has exactly one entry, so this reduces to that
 * entry's `rounds` field). */
#define ROUNDS_HELPER(cipher_id, cipher_name, rounds, bb) rounds
#define CTR_AES_ROUNDS (CTR_AES_CIPHER_LIST(ROUNDS_HELPER))
#define CTR_LIN_ROUNDS (CTR_LIN_CIPHER_LIST(ROUNDS_HELPER))

/* --- prepared state: expanded bitsliced round keys (+ the lin_key_t for its
 * rotation constants). Both fit inside CTR_MAX_STATE_BYTES with room to spare. */
#if defined(__ARM_NEON)
typedef struct { u64x2 km[WIDE_NEON_KM_WORDS]; } aes_neon_ctx_t;
typedef struct { u64x2 km[WIDE_NEON_KM_WORDS]; lin_key_t k; } lin_neon_ctx_t;
#else
/* Stub sizes on the x86 build so the ctr_backend_t rows still name a real
 * state_bytes; prepare()/run() are never invoked there (available() == 0). */
typedef struct { uint8_t _pad[(MAX_ROUNDS + 1) * 128 * 16]; } aes_neon_ctx_t;
typedef struct { uint8_t _pad[(MAX_ROUNDS + 1) * 128 * 16 + sizeof(lin_key_t)]; } lin_neon_ctx_t;
#endif

/* --- prepare(): key expansion into bitsliced round keys ---------------------- */

#if defined(__ARM_NEON)
static void aes_expand_into(void *state, const uint8_t *key, int rounds)
{
    aes_neon_ctx_t *ctx = state;
    aes_key_t ak;
    aes_key_schedule(&ak, key);
    bs_neon_expand_aes_key(&ak, rounds, ctx->km);
}
static void lin_expand_into(void *state, const uint8_t *key, int rounds)
{
    lin_neon_ctx_t *ctx = state;
    lin_key_schedule(&ctx->k, key);
    bs_neon_expand_lin_key(&ctx->k, rounds, ctx->km);
}
#else
static void aes_expand_into(void *state, const uint8_t *key, int rounds)
{ (void)state; (void)key; (void)rounds; assert(0 && "no NEON"); }
static void lin_expand_into(void *state, const uint8_t *key, int rounds)
{ (void)state; (void)key; (void)rounds; assert(0 && "no NEON"); }
#endif

#define DEFINE_PREPARE_AES(cipher_id, cipher_name, rounds, bb) \
    static void prepare_##cipher_id(void *state, const uint8_t *key, size_t key_len) \
    { \
        assert(key_len == WIDE_KEY_BYTES && "aes: prepare() expects a 16-byte key"); \
        (void)key_len; \
        aes_expand_into(state, key, (rounds)); \
    }
#define DEFINE_PREPARE_LIN(cipher_id, cipher_name, rounds, bb) \
    static void prepare_##cipher_id(void *state, const uint8_t *key, size_t key_len) \
    { \
        assert(key_len == WIDE_KEY_BYTES && "lin: prepare() expects a 16-byte key"); \
        (void)key_len; \
        lin_expand_into(state, key, (rounds)); \
    }
CTR_AES_CIPHER_LIST(DEFINE_PREPARE_AES)
CTR_LIN_CIPHER_LIST(DEFINE_PREPARE_LIN)
#undef DEFINE_PREPARE_AES
#undef DEFINE_PREPARE_LIN

/* --- run(): counter blocks -> pack -> kernel -> unpack -> XOR ----------------- */

#if defined(__ARM_NEON)
/* Build the 128 big-endian counter blocks for the group starting at block index
 * `base`: bytes 0..7 zero (high 64 bits), bytes 8..15 the counter, exactly as
 * bench/ctr_backend.h and bench/ctr_wide.c specify for the 128-bit block. */
static inline void wide_neon_counter_blocks(uint8_t *in, uint64_t base)
{
    for (int i = 0; i < 128; i++) {
        uint8_t *blk = in + WIDE_BLOCK_BYTES * i;
        memset(blk, 0, 8);
        ctr_store_be64(blk + 8, base + (uint64_t)i);
    }
}

static void run_aes_neon(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const aes_neon_ctx_t *ctx = st;
    _Alignas(CTR_STATE_ALIGN) u64x2 state[WIDE_NEON_BITS];
    _Alignas(CTR_STATE_ALIGN) u64x2 scratch[WIDE_NEON_BITS];
    uint8_t in[128 * WIDE_BLOCK_BYTES], ks[128 * WIDE_BLOCK_BYTES];

    assert(len % WIDE_NEON_GROUP == 0);
    for (size_t off = 0; off < len; off += WIDE_NEON_GROUP) {
        wide_neon_counter_blocks(in, ctr0 + off / WIDE_BLOCK_BYTES);
        wide_neon_pack(in, state);
        u64x2 *res = wide_aes_encrypt_neon_bs(ctx->km, CTR_AES_ROUNDS, state, scratch);
        wide_neon_unpack(res, ks);
        ctr_xor_bytes(buf + off, ks, WIDE_NEON_GROUP);
    }
}

static void run_lin_neon(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const lin_neon_ctx_t *ctx = st;
    _Alignas(CTR_STATE_ALIGN) u64x2 state[WIDE_NEON_BITS];
    _Alignas(CTR_STATE_ALIGN) u64x2 scratch[WIDE_NEON_BITS];
    uint8_t in[128 * WIDE_BLOCK_BYTES], ks[128 * WIDE_BLOCK_BYTES];

    assert(len % WIDE_NEON_GROUP == 0);
    for (size_t off = 0; off < len; off += WIDE_NEON_GROUP) {
        wide_neon_counter_blocks(in, ctr0 + off / WIDE_BLOCK_BYTES);
        wide_neon_pack(in, state);
        u64x2 *res = wide_lin_encrypt_neon_bs(&ctx->k, ctx->km, CTR_LIN_ROUNDS, state, scratch);
        wide_neon_unpack(res, ks);
        ctr_xor_bytes(buf + off, ks, WIDE_NEON_GROUP);
    }
}
#else
static void run_aes_neon(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{ (void)st; (void)buf; (void)len; (void)ctr0; assert(0 && "no NEON"); }
static void run_lin_neon(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{ (void)st; (void)buf; (void)len; (void)ctr0; assert(0 && "no NEON"); }
#endif

/* --- registration: two ciphers, one backend kind ----------------------------- */

#define AES_ROW(cipher_id, cipher_name, rounds, bb) \
    { "ctr-bitslice-neon", cipher_name, WIDE_BLOCK_BYTES, WIDE_NEON_GROUP, \
      WIDE_KEY_BYTES, sizeof(aes_neon_ctx_t), present_have_neon, \
      prepare_##cipher_id, run_aes_neon },
#define LIN_ROW(cipher_id, cipher_name, rounds, bb) \
    { "ctr-bitslice-neon", cipher_name, WIDE_BLOCK_BYTES, WIDE_NEON_GROUP, \
      WIDE_KEY_BYTES, sizeof(lin_neon_ctx_t), present_have_neon, \
      prepare_##cipher_id, run_lin_neon },

const ctr_backend_t ctr_backends_wide_neon[] = {
    CTR_AES_CIPHER_LIST(AES_ROW)
    CTR_LIN_CIPHER_LIST(LIN_ROW)
};

const size_t ctr_backends_wide_neon_count =
    sizeof(ctr_backends_wide_neon) / sizeof(ctr_backends_wide_neon[0]);

_Static_assert(sizeof(aes_neon_ctx_t) <= CTR_MAX_STATE_BYTES, "aes neon state fits");
_Static_assert(sizeof(lin_neon_ctx_t) <= CTR_MAX_STATE_BYTES, "lin neon state fits");
