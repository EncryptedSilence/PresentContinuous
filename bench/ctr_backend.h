/* One CTR backend: a complete counter-mode pass over a byte buffer.
 *
 * The split between prepare() and run() is the point of this interface.
 * prepare() is key expansion plus any table construction: for a video session
 * that is a once-per-session cost, so it is measured, but separately and never
 * inside run(). run() is the operation the main table reports -- generate
 * counters, encrypt them, materialise the keystream as bytes, XOR into the
 * buffer, store -- and it must contain every step of that, including any
 * transpose a bitsliced backend needs. A backend that assumes its input is
 * already bitsliced measures a kernel ceiling, and kernel ceilings belong in
 * bench/bench_main.c, not here.
 *
 * Counter definition, which ctr-ref establishes and every other backend must
 * reproduce byte for byte: block i is the integer ctr0 + i; its keystream bytes
 * are that block serialised big-endian. For the 128-bit ciphers the counter
 * occupies the low 64 bits of the 16-byte block and the high 64 bits are zero.
 * ctr0 is a full 64-bit value and is not guaranteed to be zero or small: the
 * correctness gate runs every backend at ctr0 = 0 and again at a ctr0 chosen to
 * carry across byte boundaries partway through the buffer, so a backend that
 * ignores ctr0, or that keeps its counter in 32 bits, fails rather than ships.
 */
#ifndef CTR_BACKEND_H
#define CTR_BACKEND_H

#include <stddef.h>
#include <stdint.h>

/* Large enough for the biggest backend state in the tree: a present_ctx_t
 * (66,056 B with decryption, 33,032 B without) with headroom for a bitsliced
 * round-key expansion. Registration asserts state_bytes against it. */
#define CTR_MAX_STATE_BYTES 262144

/* Large enough for the longest key any registered backend asks for. Sized by the
 * same rule bench/bench_main.c uses, (PRESENT_MAX_ROUNDS + 1) * 8, so a variant
 * added later with more rounds cannot overflow a caller's buffer. The longest
 * key in the current set is cipher-D's 72 bytes -- see key_bytes below. */
#define CTR_MAX_KEY_BYTES 256

/* Alignment, in bytes, that every caller of prepare()/run() guarantees for the
 * `state` pointer. This is a promise made *to* backends, not a per-backend
 * request: bench/ctr_bench.c and tests/test_ctr.c declare their state buffers
 * _Alignas(CTR_STATE_ALIGN), and any future caller must do the same -- a bare
 * malloc(b->state_bytes) is NOT sufficient (glibc gives 16 on x86-64) and is a
 * bug in the caller, not in the backend.
 *
 * 64 rather than 32 so it covers every vector unit this project can plausibly
 * reach -- NEON wants 16, AVX2 wants 32, AVX-512 wants 64 -- and lands on a
 * cache line, which keeps a backend's state off a line shared with anything
 * else during a timed run. A backend may therefore use aligned loads and stores
 * (vmovdqa, vld1q/vst1q) against its own state without checking. */
#define CTR_STATE_ALIGN 64

typedef struct {
    /* "ctr-ref", "ctr-table-x4", "ctr-bitslice-avx2", ... Unique within a cipher. */
    const char *name;
    /* The reported cipher name, exactly as tools/cipher_set.py resolves it:
     * "present-80-r16", "present-80-lin444-297-r7", "cipher-D",
     * "cipher-D-lin444-297-r5", "cipher-D-lin444-297-aes-r5", "aes-r5",
     * "aes-lin444-0-8-15-r4". */
    const char *cipher;
    /* 8 for the five 64-bit constructions, 16 for the two 128-bit ones. */
    size_t block_bytes;
    /* Bytes this backend's run() consumes per loop iteration, and therefore the
     * granularity `len` must be a multiple of. Always a whole multiple of
     * block_bytes; equal to block_bytes for a backend that walks one block at a
     * time.
     *
     * This field exists because "a multiple of block_bytes" is not what a real
     * backend needs. A batched or bitsliced kernel transposes a fixed group of
     * blocks per iteration and has no partial-group path: ctr-table-x16 does 16
     * 8-byte blocks (128 B), and the bitsliced kernels this interface is being
     * frozen for do 32, 64, 128 or 256 blocks at once -- up to 2048 B for a
     * 256-block AVX2 group. A backend states its group here and the harness
     * refuses a --size that is not a multiple of it, per backend. Without this
     * field the only alternatives were a magic constant in the harness (which
     * silently stops covering the largest registered group the moment a bigger
     * one is added -- a straight out-of-bounds write in the timed region) or
     * making every backend grow tail handling the reference does not have,
     * which would stop the reference and the backend running the same loop. */
    size_t group_bytes;
    /* Key length prepare() expects, which is present_variant_key_bytes(v) for
     * the 64-bit set and 16 for the 128-bit set.
     *
     * This is NOT 10-or-16. Three of the five 64-bit constructions -- cipher-D
     * and the two cipher-D-lin444-297 variants -- declare key_schedule
     * "independent", so their key material IS the round keys: (rounds + 1) * 8
     * bytes, read with no truncation, and present_key_schedule rejects any other
     * length outright. cipher-D at 8 rounds wants 72 bytes; the two r5 variants
     * want 48. Their variant JSONs say key_bits 576 and 384 respectively.
     * bench/bench_main.c sizes its own key buffer at
     * (PRESENT_MAX_ROUNDS + 1) * PRESENT_BLOCK_BITS / 8 for exactly this reason.
     *
     * The same fact is why the spec excludes the cipher-D family from the
     * master-key search kernel: independent round-key material has no master key
     * to search for. */
    size_t key_bytes;
    /* Bytes of backend-private state prepare() writes. <= CTR_MAX_STATE_BYTES.
     * The caller guarantees the buffer is CTR_STATE_ALIGN-aligned. */
    size_t state_bytes;
    /* 1 if this backend can run on this build and this CPU; NULL means always.
     * This is what keeps an AVX2 backend out of an ARM run without an #ifdef at
     * every call site. */
    int (*available)(void);
    /* Key expansion and table construction. Timed, but separately from run().
     * `state` points at state_bytes of CTR_STATE_ALIGN-aligned writable memory
     * and is the only place prepare() may leave anything behind. */
    void (*prepare)(void *state, const uint8_t *key, size_t key_len);
    /* The timed operation. len is a multiple of group_bytes (and therefore of
     * block_bytes) and the XOR is in place.
     *
     * Memory rules, which say where a bitsliced backend's scratch legally lives
     * -- read these before writing one:
     *
     *  - `state` is what prepare() produced. It is const during run() on
     *    purpose: run() must be repeatable, so the same state can be timed for
     *    as many trials as the harness likes and can be shared by two calls
     *    without one perturbing the other. It is CTR_STATE_ALIGN-aligned, so
     *    aligned vector loads against it are safe.
     *  - Mutable working memory -- the two ping-pong buffers a bitsliced kernel
     *    such as present_encrypt_avx2_bs() wants, the transposed block group,
     *    the materialised keystream -- lives in run()'s own *automatic* storage,
     *    declared _Alignas(CTR_STATE_ALIGN) where the kernel needs alignment.
     *    That is the sanctioned home for it and it is inside the timed region,
     *    which is the point: the transpose is part of what this benchmark
     *    measures. Keep the total under about 16 KiB so the same backend can be
     *    built for a Cortex-M4 stack; a 256-block AVX2 group needs 2 KiB per
     *    ping-pong buffer, so the budget is not tight.
     *  - run() must not allocate, must not write to any object with static or
     *    thread storage duration (that would make two backends' timings depend
     *    on each other and would not be thread-safe), and must not touch memory
     *    outside `state`, buf[0..len) and its own locals. Reading immutable
     *    static data -- a const S-box table, a round constant -- is fine.
     */
    void (*run)(const void *state, uint8_t *buf, size_t len, uint64_t ctr0);
} ctr_backend_t;

/* The registry. bench/ctr_registry.c concatenates the per-ISA groups; these
 * three functions are the only supported way to reach them. */
size_t ctr_backend_count(void);
const ctr_backend_t *ctr_backend_at(size_t i);
/* The ctr-ref backend for `cipher`, or NULL. This is the correctness oracle. */
const ctr_backend_t *ctr_backend_reference_for(const char *cipher);

/* --- the cipher set (bench/ctr_cipher_set.c) ---------------------------------
 *
 * The seven ciphers and their round counts come from tools/cipher_set.py, via
 * the generated bench/gen/ctr_cipher_set.h. They are not restated in C, and
 * these two functions are how the harness and the test reach them. */

/* Round count `cipher` is benchmarked at, or 0 if the name is not one of the
 * seven. This is the CSV's rounds column: never a literal at the call site. */
int ctr_cipher_rounds(const char *cipher);

/* Cross-checks the assembled registry against the generated cipher set, the
 * same way tools/run_m4_bench.py's check_cipher_set() checks the board's rows:
 * every registered backend must name one of the seven, every one of the seven
 * must have a ctr-ref backend, and every 64-bit cipher's round count must be
 * the one src/'s own variant table reports. Returns 0 on agreement; on any
 * disagreement returns non-zero and writes a one-line description into
 * msg[0..msg_len). Callers run this before any measurement. */
int ctr_cipher_set_check(char *msg, size_t msg_len);

#endif /* CTR_BACKEND_H */
