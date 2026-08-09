/* CTR backends for the two 128-bit ciphers: AES (aes-r5) and AES-lin444
 * (aes-lin444-0-8-15-r4). Self-contained like bench/wide_bench.c: the only
 * dependency is bench/wide_ciphers.h, never src/, which is 64-bit-block
 * throughout. wide_ciphers.h is header-only with `static` functions and is
 * included only here, per its own file comment.
 *
 * wide_ciphers.h currently offers exactly one scalar kernel per cipher --
 * aes_encrypt1 for AES, lin_encrypt_ref for AES-lin444 -- plus one genuinely
 * batched kernel, aes_encrypt4. There is no separate "reference" AES
 * implementation distinct from its table-driven one (unlike src/, which keeps
 * present_encrypt_ref and present_encrypt_table as two independently written
 * paths), and no batched kernel at all for AES-lin444: the header's own
 * comment on lin_encrypt_ref explains that a fused table was tried and
 * measured 2.27x-2.39x *slower* on the Cortex-M4, so none is implemented. That
 * makes ctr-ref and ctr-table identical for both ciphers here -- both wrap the
 * one available scalar kernel -- and ctr-table-x2/x4/x8 batch through
 * aes_encrypt4 where it applies (AES) or simply loop the scalar kernel where
 * no batched kernel exists (AES-lin444, and AES's non-multiple-of-4 remainder).
 * This is an accurate reflection of what this header provides today, not a
 * simplification: a genuine SIMD/bitsliced kernel for either cipher is Wave 2's
 * job, appended to bench/ctr_registry.c's groups[] as its own file.
 */
#include <assert.h>
#include <string.h>

#include "ctr_backend.h"
#include "wide_ciphers.h"

#define WIDE_BLOCK_BYTES 16
#define WIDE_KEY_BYTES 16

/* Round counts for the two reported ciphers, from tools/cipher_set.py's
 * VARIANT_OVERRIDES (aes -> 5 rounds, aes-lin444-0-8-15 -> 4 rounds). Every
 * wide_ciphers.h encrypt function takes its round count as an explicit
 * argument rather than reading it from the key struct (see that header's file
 * comment), specifically so a caller like this one can fix it once here. Not
 * restated anywhere else in C. */
#define AES_R5_ROUNDS 5
#define AES_LIN444_R4_ROUNDS 4

/* --- prepare(): key expansion, both fixed at a 16-byte key ------------------- */

static void prepare_aes(void *state, const uint8_t *key, size_t key_len)
{
    assert(key_len == WIDE_KEY_BYTES && "aes-r5: prepare() expects a 16-byte key");
    (void)key_len;
    aes_key_schedule((aes_key_t *)state, key);
    /* Table construction, counted here rather than left to run()'s first call:
     * aes_init_tables() is idempotent, so a caller that never calls it directly
     * (a test, the firmware) still gets correct output, but leaving it to run()
     * would let the first timed call pay for a global one-time table build. */
    aes_init_tables();
}

static void prepare_lin(void *state, const uint8_t *key, size_t key_len)
{
    assert(key_len == WIDE_KEY_BYTES && "aes-lin444-0-8-15-r4: prepare() expects a 16-byte key");
    (void)key_len;
    lin_key_schedule((lin_key_t *)state, key);
}

/* --- run(): the same two shapes as ctr_narrow.c, over the 16-byte block ------ */

/* Encrypt n independent 16-byte blocks, in[0..16n) -> out[0..16n). The AES
 * adapter batches through aes_encrypt4 wherever n allows and falls back to
 * aes_encrypt1 for the remainder, so one function serves n = 1, 2, 4 and 8; the
 * AES-lin444 adapter has only the scalar kernel to loop, for every n. */
typedef void (*wide_encode_fn)(const void *state, const uint8_t *in, uint8_t *out, int n);

static void aes_encode_n(const void *state, const uint8_t *in, uint8_t *out, int n)
{
    const aes_key_t *k = state;
    int i = 0;
    for (; i + 4 <= n; i += 4)
        aes_encrypt4(k, AES_R5_ROUNDS, in + WIDE_BLOCK_BYTES * i, out + WIDE_BLOCK_BYTES * i);
    for (; i < n; i++)
        aes_encrypt1(k, AES_R5_ROUNDS, in + WIDE_BLOCK_BYTES * i, out + WIDE_BLOCK_BYTES * i);
}

static void lin_encode_n(const void *state, const uint8_t *in, uint8_t *out, int n)
{
    const lin_key_t *k = state;
    for (int i = 0; i < n; i++)
        lin_encrypt_ref(k, AES_LIN444_R4_ROUNDS, in + WIDE_BLOCK_BYTES * i, out + WIDE_BLOCK_BYTES * i);
}

/* Counter mode over the 16-byte block: block i is ctr0 + i, serialised
 * big-endian into the low 64 bits (bytes 8..15); the high 64 bits (bytes 0..7)
 * are always zero, exactly as bench/ctr_backend.h specifies for the 128-bit
 * ciphers. n blocks are built and encoded together, then their keystream is
 * XORed into buf; n = 1 serves the ctr-ref/ctr-table rows below, n = 2/4/8 the
 * ctr-table-xN rows. As with ctr_narrow.c's run_x, len is assumed to be a
 * multiple of n * WIDE_BLOCK_BYTES for whichever n this call was bound to --
 * true for every size this project's harness runs (4096, 16384, 65536 are all
 * multiples of 8 * WIDE_BLOCK_BYTES, the largest n registered here). */
static void run_wide(const void *st, uint8_t *buf, size_t len, uint64_t ctr0,
                     wide_encode_fn encode, int n)
{
    uint8_t in[8 * WIDE_BLOCK_BYTES], ks[8 * WIDE_BLOCK_BYTES];
    for (size_t off = 0; off < len; off += (size_t)n * WIDE_BLOCK_BYTES) {
        for (int i = 0; i < n; i++) {
            uint64_t c = ctr0 + off / WIDE_BLOCK_BYTES + (uint64_t)i;
            uint8_t *blk = in + WIDE_BLOCK_BYTES * i;
            memset(blk, 0, 8);               /* high 64 bits of the counter block */
            for (int b = 0; b < 8; b++)      /* low 64 bits, big-endian */
                blk[8 + b] = (uint8_t)(c >> (56 - 8 * b));
        }
        encode(st, in, ks, n);
        for (int i = 0; i < n; i++)
            for (int b = 0; b < WIDE_BLOCK_BYTES; b++)
                buf[off + WIDE_BLOCK_BYTES * i + b] ^= ks[WIDE_BLOCK_BYTES * i + b];
    }
}

/* One run wrapper per (cipher, n): run_wide needs both the encode function and
 * n bound in, and ctr_backend_t.run has no parameters to bind them through. */
#define WIDE_CIPHERS(X) \
    X(aes, aes_encode_n) \
    X(lin, lin_encode_n)

#define DEFINE_WIDE_RUN_N(cipher_id, encode_fn, n) \
    static void run_##cipher_id##_n##n(const void *st, uint8_t *buf, size_t len, uint64_t ctr0) \
    { run_wide(st, buf, len, ctr0, encode_fn, n); }

#define DEFINE_WIDE_RUNS(cipher_id, encode_fn) \
    DEFINE_WIDE_RUN_N(cipher_id, encode_fn, 1) \
    DEFINE_WIDE_RUN_N(cipher_id, encode_fn, 2) \
    DEFINE_WIDE_RUN_N(cipher_id, encode_fn, 4) \
    DEFINE_WIDE_RUN_N(cipher_id, encode_fn, 8)

WIDE_CIPHERS(DEFINE_WIDE_RUNS)
#undef DEFINE_WIDE_RUNS
#undef DEFINE_WIDE_RUN_N

/* --- registration: two ciphers x five backend kinds = 10 entries ------------- */

const ctr_backend_t ctr_backends_wide[] = {
    { "ctr-ref",      "aes-r5", WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(aes_key_t), NULL, prepare_aes, run_aes_n1 },
    { "ctr-table",    "aes-r5", WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(aes_key_t), NULL, prepare_aes, run_aes_n1 },
    { "ctr-table-x2", "aes-r5", WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(aes_key_t), NULL, prepare_aes, run_aes_n2 },
    { "ctr-table-x4", "aes-r5", WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(aes_key_t), NULL, prepare_aes, run_aes_n4 },
    { "ctr-table-x8", "aes-r5", WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(aes_key_t), NULL, prepare_aes, run_aes_n8 },

    { "ctr-ref",      "aes-lin444-0-8-15-r4", WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(lin_key_t), NULL, prepare_lin, run_lin_n1 },
    { "ctr-table",    "aes-lin444-0-8-15-r4", WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(lin_key_t), NULL, prepare_lin, run_lin_n1 },
    { "ctr-table-x2", "aes-lin444-0-8-15-r4", WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(lin_key_t), NULL, prepare_lin, run_lin_n2 },
    { "ctr-table-x4", "aes-lin444-0-8-15-r4", WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(lin_key_t), NULL, prepare_lin, run_lin_n4 },
    { "ctr-table-x8", "aes-lin444-0-8-15-r4", WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(lin_key_t), NULL, prepare_lin, run_lin_n8 },
};

const size_t ctr_backends_wide_count =
    sizeof(ctr_backends_wide) / sizeof(ctr_backends_wide[0]);

/* The wide ciphers are not in present_variants (see the file comment), so
 * bench/ctr_bench.c cannot get their round count the way it gets the five
 * 64-bit ciphers' -- present_variant_by_name(cipher)->rounds. This is the one
 * accessor that reaches AES_R5_ROUNDS / AES_LIN444_R4_ROUNDS above, so the
 * harness's CSV can report the right rounds column without a second copy of
 * either literal. Returns 0 for any other name. */
int ctr_wide_rounds_for(const char *cipher)
{
    if (!strcmp(cipher, "aes-r5")) return AES_R5_ROUNDS;
    if (!strcmp(cipher, "aes-lin444-0-8-15-r4")) return AES_LIN444_R4_ROUNDS;
    return 0;
}
