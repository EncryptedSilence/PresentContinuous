/* PRESENT and PRESENT-like variants: three implementations behind one context.
 *
 * Blocks are uint64_t. Bit 0 of the block is the least significant bit of the state,
 * matching the bit numbering used by the specification's pLayer and by the SAT model.
 */
#ifndef PRESENT_H
#define PRESENT_H

#include <stddef.h>
#include <stdint.h>

#include "present/variant.h"

#define PRESENT_BLOCK_BYTES 8
#define PRESENT_BITSLICE_BLOCKS 64

typedef struct {
    const present_variant_t *var;

    /* Round keys: rounds + 1 of them (the last one is the final whitening key). */
    uint64_t rk[PRESENT_MAX_ROUNDS + 1];
    /* Bitsliced round keys: rk_mask[r][i] is all-ones iff bit i of rk[r] is set. */
    uint64_t rk_mask[PRESENT_MAX_ROUNDS + 1][PRESENT_BLOCK_BITS];

    /* Fused sBoxLayer + pLayer, indexed by byte position and byte value. */
    uint64_t enc_tab[8][256];
    /* Inverse pLayer only; the inverse S-box cannot be fused into it (see README). */
    uint64_t pinv_tab[8][256];
    uint8_t sinv_byte[256];
} present_ctx_t;

/* key_len must be 10 (80-bit) or 16 (128-bit) and match the variant.
 * key[0] is the most significant key byte. Returns 0 on success. */
int present_init(present_ctx_t *ctx, const present_variant_t *v,
                 const uint8_t *key, size_t key_len);

/* Convenience: initialise from a hex string of the right length. Returns 0 on success. */
int present_init_hex(present_ctx_t *ctx, const present_variant_t *v, const char *hex_key);

/* --- reference implementation: bit-by-bit pLayer, obviously correct, slow --- */
uint64_t present_encrypt_ref(const present_ctx_t *ctx, uint64_t block);
uint64_t present_decrypt_ref(const present_ctx_t *ctx, uint64_t block);

/* --- table implementation: 8 fused lookups per round, generic over variants --- */
uint64_t present_encrypt_table(const present_ctx_t *ctx, uint64_t block);
uint64_t present_decrypt_table(const present_ctx_t *ctx, uint64_t block);

/* --- bitsliced implementation: 64 blocks at a time ---
 * in/out are arrays of 64 blocks. Transposition is done internally. */
void present_encrypt_bitslice(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);
void present_decrypt_bitslice(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);

/* Number of distinct bitslice S-box circuits that were synthesised, and the gate
 * count of each; used by the benchmark report. */
int present_circuit_gates(int circuit_id);

/* 64x64 bit transpose, exposed for tests. */
void present_transpose64(const uint64_t *in, uint64_t *out);

#endif /* PRESENT_H */
