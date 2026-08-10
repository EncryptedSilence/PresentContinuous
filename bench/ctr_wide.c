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
#include "ctr_xor.h"
#include "gen/ctr_cipher_set.h"
#include "wide_ciphers.h"

#define WIDE_BLOCK_BYTES 16
#define WIDE_KEY_BYTES 16

/* The two reported names and the round counts they are benchmarked at are the
 * one part of the cipher set that is *not* readable from a variant JSON at run
 * time: tools/cipher_set.py's VARIANT_OVERRIDES renames and re-rounds both, and
 * there is no present_variants[] entry for either to ask. They therefore reach
 * this file the same way they reach the Cortex-M4 firmware -- through a header
 * generated from cipher_set.resolve(), here bench/gen/ctr_cipher_set.h's
 * CTR_AES_CIPHER_LIST / CTR_LIN_CIPHER_LIST -- and are typed nowhere in C.
 * Every wide_ciphers.h encrypt function takes its round count as an explicit
 * argument rather than reading it from the key struct (see that header's file
 * comment), which is what lets the generated number flow straight into the
 * call. Editing VARIANT_OVERRIDES moves the FPGA build, the M4 firmware and
 * this file together. */

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

/* One definition per entry of the generated per-family lists, so `rounds` below
 * is the generated round count and never a literal. */
#define DEFINE_AES_ENCODE(cipher_id, cipher_name, rounds, bb) \
    static void wide_encode_##cipher_id(const void *state, const uint8_t *in, \
                                        uint8_t *out, int n) \
    { \
        const aes_key_t *k = state; \
        int i = 0; \
        for (; i + 4 <= n; i += 4) \
            aes_encrypt4(k, (rounds), in + WIDE_BLOCK_BYTES * i, \
                         out + WIDE_BLOCK_BYTES * i); \
        for (; i < n; i++) \
            aes_encrypt1(k, (rounds), in + WIDE_BLOCK_BYTES * i, \
                         out + WIDE_BLOCK_BYTES * i); \
    }

#define DEFINE_LIN_ENCODE(cipher_id, cipher_name, rounds, bb) \
    static void wide_encode_##cipher_id(const void *state, const uint8_t *in, \
                                        uint8_t *out, int n) \
    { \
        const lin_key_t *k = state; \
        for (int i = 0; i < n; i++) \
            lin_encrypt_ref(k, (rounds), in + WIDE_BLOCK_BYTES * i, \
                            out + WIDE_BLOCK_BYTES * i); \
    }

CTR_AES_CIPHER_LIST(DEFINE_AES_ENCODE)
CTR_LIN_CIPHER_LIST(DEFINE_LIN_ENCODE)

#undef DEFINE_AES_ENCODE
#undef DEFINE_LIN_ENCODE

/* Counter mode over the 16-byte block: block i is ctr0 + i, serialised
 * big-endian into the low 64 bits (bytes 8..15); the high 64 bits (bytes 0..7)
 * are always zero, exactly as bench/ctr_backend.h specifies for the 128-bit
 * ciphers. n blocks are built and encoded together, then their keystream is
 * XORed into buf; n = 1 serves the ctr-ref/ctr-table rows below, n = 2/4/8 the
 * ctr-table-xN rows. As with ctr_narrow.c's run_x, len is a multiple of
 * n * WIDE_BLOCK_BYTES for whichever n this call was bound to -- that product
 * is the backend's group_bytes, which bench/ctr_backend.h makes the caller
 * honour, so there is no partial-group path here. */
static void run_wide(const void *st, uint8_t *buf, size_t len, uint64_t ctr0,
                     wide_encode_fn encode, int n)
{
    uint8_t in[8 * WIDE_BLOCK_BYTES], ks[8 * WIDE_BLOCK_BYTES];
    for (size_t off = 0; off < len; off += (size_t)n * WIDE_BLOCK_BYTES) {
        for (int i = 0; i < n; i++) {
            uint64_t c = ctr0 + off / WIDE_BLOCK_BYTES + (uint64_t)i;
            uint8_t *blk = in + WIDE_BLOCK_BYTES * i;
            memset(blk, 0, 8);                    /* high 64 bits of the counter block */
            ctr_store_be64(blk + 8, c);           /* low 64 bits, big-endian */
        }
        encode(st, in, ks, n);
        /* Word-wise, through the same bench/ctr_xor.h helper the 64-bit
         * backends use. The 128-bit pair has to get this too: if it kept the
         * byte loop while the 64-bit ciphers moved off it, the two widths would
         * carry different fixed overheads and the harness's rule that both
         * process the same number of *bytes* would stop meaning what it says --
         * the cross-width comparison the plan is built on would silently break.
         * ks is already bytes here, so no byte-order conversion is involved. */
        ctr_xor_bytes(buf + off, ks, (size_t)n * WIDE_BLOCK_BYTES);
    }
}

/* ctr-ref's variant: counter block and keystream XOR both written out byte at a
 * time. Same reasoning as bench/ctr_narrow.c's run_1 -- for the 128-bit pair
 * this file's own comment notes that ctr-ref and ctr-table wrap the identical
 * kernel, so keeping one literal form here is what stops the oracle and the
 * measured row being the same code, and makes the gate's comparison between
 * them a real check of the word-wise path. */
static void run_wide_ref(const void *st, uint8_t *buf, size_t len, uint64_t ctr0,
                         wide_encode_fn encode)
{
    uint8_t in[WIDE_BLOCK_BYTES], ks[WIDE_BLOCK_BYTES];
    for (size_t off = 0; off < len; off += WIDE_BLOCK_BYTES) {
        uint64_t c = ctr0 + off / WIDE_BLOCK_BYTES;
        memset(in, 0, 8);                    /* high 64 bits of the counter block */
        for (int b = 0; b < 8; b++)          /* low 64 bits, big-endian */
            in[8 + b] = (uint8_t)(c >> (56 - 8 * b));
        encode(st, in, ks, 1);
        for (int b = 0; b < WIDE_BLOCK_BYTES; b++)
            buf[off + b] ^= ks[b];
    }
}

/* One run wrapper per (cipher, n): run_wide needs both the encode function and
 * n bound in, and ctr_backend_t.run has no parameters to bind them through. */
#define DEFINE_WIDE_RUN_N(cipher_id, n) \
    static void run_##cipher_id##_n##n(const void *st, uint8_t *buf, size_t len, uint64_t ctr0) \
    { run_wide(st, buf, len, ctr0, wide_encode_##cipher_id, n); }

#define DEFINE_WIDE_RUN_REF(cipher_id) \
    static void run_##cipher_id##_ref(const void *st, uint8_t *buf, size_t len, uint64_t ctr0) \
    { run_wide_ref(st, buf, len, ctr0, wide_encode_##cipher_id); }

#define DEFINE_WIDE_RUNS(cipher_id, cipher_name, rounds, bb) \
    DEFINE_WIDE_RUN_REF(cipher_id) \
    DEFINE_WIDE_RUN_N(cipher_id, 1) \
    DEFINE_WIDE_RUN_N(cipher_id, 2) \
    DEFINE_WIDE_RUN_N(cipher_id, 4) \
    DEFINE_WIDE_RUN_N(cipher_id, 8)

CTR_AES_CIPHER_LIST(DEFINE_WIDE_RUNS)
CTR_LIN_CIPHER_LIST(DEFINE_WIDE_RUNS)
#undef DEFINE_WIDE_RUNS
#undef DEFINE_WIDE_RUN_REF
#undef DEFINE_WIDE_RUN_N

/* --- registration: two ciphers x five backend kinds = 10 entries -------------
 *
 * Rows are expanded from the generated per-family lists, so neither reported
 * name is a literal here. group_bytes is group_blocks * block_bytes -- the
 * granularity run_wide's tail-free loop needs, which bench/ctr_backend.h makes
 * the harness enforce per backend. block_bytes stays WIDE_BLOCK_BYTES, the
 * width these kernels actually process, rather than the generated list's bb, so
 * that ctr_cipher_set_check() comparing the two is a real check. */
/* run_suffix picks the run function: _ref is the byte-at-a-time oracle, _nN the
 * word-wise measured form over N blocks. It is spelled out per row rather than
 * derived from group_blocks because ctr-ref and ctr-table share group_blocks 1
 * and must NOT share a run function -- that is what stops the oracle being the
 * same code as the row it validates. */
#define WIDE_ENTRY(cipher_id, cipher_name, key_type, prepare_fn, kind_name, group_blocks, run_suffix) \
    { kind_name, cipher_name, WIDE_BLOCK_BYTES, \
      (size_t)(group_blocks) * WIDE_BLOCK_BYTES, WIDE_KEY_BYTES, sizeof(key_type), \
      NULL, prepare_fn, run_##cipher_id##run_suffix },

#define WIDE_CIPHER_ROWS(cipher_id, cipher_name, key_type, prepare_fn) \
    WIDE_ENTRY(cipher_id, cipher_name, key_type, prepare_fn, "ctr-ref",      1, _ref) \
    WIDE_ENTRY(cipher_id, cipher_name, key_type, prepare_fn, "ctr-table",    1, _n1) \
    WIDE_ENTRY(cipher_id, cipher_name, key_type, prepare_fn, "ctr-table-x2", 2, _n2) \
    WIDE_ENTRY(cipher_id, cipher_name, key_type, prepare_fn, "ctr-table-x4", 4, _n4) \
    WIDE_ENTRY(cipher_id, cipher_name, key_type, prepare_fn, "ctr-table-x8", 8, _n8)

#define AES_ROWS(cipher_id, cipher_name, rounds, bb) \
    WIDE_CIPHER_ROWS(cipher_id, cipher_name, aes_key_t, prepare_aes)
#define LIN_ROWS(cipher_id, cipher_name, rounds, bb) \
    WIDE_CIPHER_ROWS(cipher_id, cipher_name, lin_key_t, prepare_lin)

const ctr_backend_t ctr_backends_wide[] = {
    CTR_AES_CIPHER_LIST(AES_ROWS)
    CTR_LIN_CIPHER_LIST(LIN_ROWS)
};

const size_t ctr_backends_wide_count =
    sizeof(ctr_backends_wide) / sizeof(ctr_backends_wide[0]);

_Static_assert(sizeof(ctr_backends_wide) / sizeof(ctr_backends_wide[0]) % 5 == 0,
               "ctr_backends_wide: five backend kinds per cipher");
