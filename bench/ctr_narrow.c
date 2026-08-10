/* CTR backends for the five 64-bit PRESENT-family constructions.
 *
 * Private state is a present_ctx_t. run() does not care which of the five
 * ciphers it is running: present_encrypt_ref/table/table_xN all read the round
 * count and tables out of ctx->var, so one run function per backend kind
 * (ctr-ref, ctr-table, ctr-table-x{2,4,8,16}) serves all five ciphers. Only
 * prepare() is cipher-specific, because it has to look up the right variant by
 * name.
 *
 * key_bytes is NOT the same for all five: cipher-D and its two lin444
 * derivatives use present_ks_t PRESENT_KS_INDEPENDENT, so their key material
 * IS their round keys -- (rounds + 1) * 8 bytes, computed by
 * present_variant_key_bytes(). That value depends on data (present_variants[])
 * populated by another translation unit's static initializer, so it cannot be
 * a compile-time constant here; a hardcoded 10-or-72-or-48 table would be
 * exactly the kind of restatement of the variant JSON this repo's tooling
 * (tools/cipher_set.py's module docstring) exists to prevent, and would drift
 * silently if a variant's round count ever changed. Instead, key_bytes starts
 * at 0 in the registration table below and a constructor -- guaranteed by the
 * toolchain to run before main() -- patches every entry from
 * present_variant_key_bytes() once, before any test or benchmark can read it.
 * ctr_registry.c's `extern const` declaration only ever reads through this
 * array, so the mismatch between its `const` and this file's non-const
 * definition is benign: nothing outside this translation unit ever writes to
 * it after the constructor runs.
 */
#include <assert.h>
#include <string.h>

#include "ctr_backend.h"
#include "ctr_xor.h"
#include "gen/ctr_cipher_set.h"
#include "present/present.h"
#include "present/variant.h"

/* --- run(): two shapes, generic over every registered variant ------------------ */

/* ctr-ref: one block at a time, with the big-endian serialisation written out
 * literally. This is the correctness oracle every other backend is compared
 * against, so it keeps the form a reader can check against the specification by
 * eye; bench/ctr_xor.h explains why every *measured* backend uses a word-wise
 * store instead, and why having the two forms agree is a real cross-check. The
 * speed of this loop is irrelevant -- ctr-ref is ~700 cyc/B because
 * present_encrypt_ref permutes the block bit by bit, three orders of magnitude
 * away from anything serialisation could account for. */
static void run_1(const void *st, uint8_t *buf, size_t len, uint64_t ctr0,
                  uint64_t (*enc)(const present_ctx_t *, uint64_t))
{
    const present_ctx_t *ctx = st;
    for (size_t off = 0; off < len; off += 8) {
        uint64_t ks = enc(ctx, ctr0 + off / 8);
        for (int b = 0; b < 8; b++)      /* big-endian serialisation */
            buf[off + b] ^= (uint8_t)(ks >> (56 - 8 * b));
    }
}

/* ctr-table: the same loop with the shared word-wise materialisation, so it is
 * not charged a serialisation cost the batched rows below do not pay. */
static void run_1_fast(const void *st, uint8_t *buf, size_t len, uint64_t ctr0,
                       uint64_t (*enc)(const present_ctx_t *, uint64_t))
{
    const present_ctx_t *ctx = st;
    for (size_t off = 0; off < len; off += 8)
        ctr_xor_be64(buf + off, enc(ctx, ctr0 + off / 8));
}

/* ctr-table-xN: N blocks at a time. n <= 16. len is a multiple of n * 8 --
 * that is the backend's group_bytes, which bench/ctr_backend.h makes the caller
 * honour, so there is deliberately no partial-group path here: adding one would
 * make this loop a different shape from run_1's and stop the two measuring the
 * same thing. */
static void run_x(const void *st, uint8_t *buf, size_t len, uint64_t ctr0,
                  void (*enc)(const present_ctx_t *, const uint64_t *, uint64_t *),
                  int n)
{
    const present_ctx_t *ctx = st;
    uint64_t in[16], ks[16];
    for (size_t off = 0; off < len; off += (size_t)n * 8) {
        for (int i = 0; i < n; i++) in[i] = ctr0 + off / 8 + (uint64_t)i;
        enc(ctx, in, ks);
        for (int i = 0; i < n; i++)
            ctr_xor_be64(buf + off + 8 * i, ks[i]);
    }
}

/* One-line binders bolting a concrete encrypt function onto run_1/run_x, since
 * ctr_backend_t.run takes no extra function-pointer argument. Cipher-independent:
 * the same run_ref serves every one of the five ciphers' ctr-ref entries below. */
/* The third column is which materialisation the kind gets: ctr-ref keeps the
 * literal byte loop because it is the oracle, everything measured shares the
 * word-wise one. See run_1 and bench/ctr_xor.h. */
#define NARROW_RUN1_KINDS(X) \
    X(ref,   present_encrypt_ref,   run_1) \
    X(table, present_encrypt_table, run_1_fast)

#define DEFINE_RUN1(id, enc, helper) \
    static void run_##id(const void *st, uint8_t *buf, size_t len, uint64_t ctr0) \
    { helper(st, buf, len, ctr0, enc); }
NARROW_RUN1_KINDS(DEFINE_RUN1)
#undef DEFINE_RUN1

#define NARROW_RUNX_KINDS(X) \
    X(table_x2,  present_encrypt_table_x2,  2) \
    X(table_x4,  present_encrypt_table_x4,  4) \
    X(table_x8,  present_encrypt_table_x8,  8) \
    X(table_x16, present_encrypt_table_x16, 16)

#define DEFINE_RUNX(id, enc, n) \
    static void run_##id(const void *st, uint8_t *buf, size_t len, uint64_t ctr0) \
    { run_x(st, buf, len, ctr0, enc, n); }
NARROW_RUNX_KINDS(DEFINE_RUNX)
#undef DEFINE_RUNX

/* --- prepare(): one per cipher, since each looks up a different variant -------- */

/* The five 64-bit ciphers come from CTR_NARROW_CIPHER_LIST in the generated
 * bench/gen/ctr_cipher_set.h, which tools/cipher_set.py writes from resolve().
 * They are not named here: this file expands whatever that list holds, so a
 * cipher added to or removed from tools/cipher_set.py arrives with its prepare()
 * and its six registration rows, and cannot be spelled differently here than it
 * is in the FPGA and Cortex-M4 result files. None of these five is in
 * VARIANT_OVERRIDES, so the reported name is also the variant JSON's name and
 * present_variant_by_name() takes it unchanged. */
#define DEFINE_PREPARE(id, name, rounds, bb) \
    static void prepare_##id(void *state, const uint8_t *key, size_t key_len) \
    { \
        const present_variant_t *v = present_variant_by_name(name); \
        int rc = present_init((present_ctx_t *)state, v, key, key_len); \
        assert(rc == 0 && "present_init failed: bad variant name or key length"); \
        (void)rc; \
    }
CTR_NARROW_CIPHER_LIST(DEFINE_PREPARE)
#undef DEFINE_PREPARE

/* --- registration: five ciphers x six backend kinds = 30 entries -------------- */

/* key_bytes is left 0 here and patched by ctr_narrow_init() below -- see the
 * file comment. Every other field is a compile-time constant.
 *
 * group_blocks is how many blocks the kind's run() consumes per iteration, so
 * group_bytes is group_blocks * block_bytes: 1 block for run_1, n for run_x's
 * n. bench/ctr_bench.c rejects a --size that is not a multiple of it, which is
 * what keeps run_x's tail-free loop in bounds. */
#define NARROW_ENTRY(cipher_id, cipher_name, kind_id, kind_name, group_blocks) \
    { kind_name, cipher_name, PRESENT_BLOCK_BYTES, \
      (size_t)(group_blocks) * PRESENT_BLOCK_BYTES, 0, \
      sizeof(present_ctx_t), NULL, prepare_##cipher_id, run_##kind_id },

/* block_bytes is PRESENT_BLOCK_BYTES -- what these kernels actually process --
 * and not the generated list's bb, so that ctr_cipher_set_check() comparing the
 * two is a real check rather than a tautology. */
#define NARROW_CIPHER_ROW(cipher_id, cipher_name, rounds, bb) \
    NARROW_ENTRY(cipher_id, cipher_name, ref,       "ctr-ref",        1) \
    NARROW_ENTRY(cipher_id, cipher_name, table,     "ctr-table",      1) \
    NARROW_ENTRY(cipher_id, cipher_name, table_x2,  "ctr-table-x2",   2) \
    NARROW_ENTRY(cipher_id, cipher_name, table_x4,  "ctr-table-x4",   4) \
    NARROW_ENTRY(cipher_id, cipher_name, table_x8,  "ctr-table-x8",   8) \
    NARROW_ENTRY(cipher_id, cipher_name, table_x16, "ctr-table-x16", 16)

/* Not const: ctr_narrow_init() patches key_bytes once, before main(). See the
 * file comment for why this cannot be a plain compile-time initializer. */
ctr_backend_t ctr_backends_narrow[] = {
    CTR_NARROW_CIPHER_LIST(NARROW_CIPHER_ROW)
};

/* The generated list drives both the prepare() definitions and the rows above,
 * so this cannot silently register a short table. */
_Static_assert(sizeof(ctr_backends_narrow) / sizeof(ctr_backends_narrow[0]) % 6 == 0,
               "ctr_backends_narrow: six backend kinds per cipher");

const size_t ctr_backends_narrow_count =
    sizeof(ctr_backends_narrow) / sizeof(ctr_backends_narrow[0]);

__attribute__((constructor))
static void ctr_narrow_init(void)
{
    for (size_t i = 0; i < ctr_backends_narrow_count; i++) {
        const present_variant_t *v = present_variant_by_name(ctr_backends_narrow[i].cipher);
        assert(v && "ctr_narrow_init: registered cipher name is not a known variant");
        ctr_backends_narrow[i].key_bytes = present_variant_key_bytes(v);
    }
}
