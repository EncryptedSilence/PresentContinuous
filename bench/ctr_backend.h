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
    /* Bytes of backend-private state prepare() writes. <= CTR_MAX_STATE_BYTES. */
    size_t state_bytes;
    /* 1 if this backend can run on this build and this CPU; NULL means always.
     * This is what keeps an AVX2 backend out of an ARM run without an #ifdef at
     * every call site. */
    int (*available)(void);
    /* Key expansion and table construction. Timed, but separately from run(). */
    void (*prepare)(void *state, const uint8_t *key, size_t key_len);
    /* The timed operation. len is a multiple of block_bytes and the XOR is in
     * place. Must not allocate, and must not touch anything outside `state` and
     * buf[0..len). */
    void (*run)(const void *state, uint8_t *buf, size_t len, uint64_t ctr0);
} ctr_backend_t;

/* The registry. bench/ctr_registry.c concatenates the per-ISA groups; these
 * three functions are the only supported way to reach them. */
size_t ctr_backend_count(void);
const ctr_backend_t *ctr_backend_at(size_t i);
/* The ctr-ref backend for `cipher`, or NULL. This is the correctness oracle. */
const ctr_backend_t *ctr_backend_reference_for(const char *cipher);

#endif /* CTR_BACKEND_H */
