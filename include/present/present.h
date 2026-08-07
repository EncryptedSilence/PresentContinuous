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
    /* Bitsliced round keys: rk_mask_enc[r][i] is all-ones iff bit i of rk[r] is set,
     * corrected for the S-box circuit's output complements -- see present_core.c.
     * Encryption and decryption need different corrections, so there are two. */
    uint64_t rk_mask_enc[PRESENT_MAX_ROUNDS + 1][PRESENT_BLOCK_BITS];
    uint64_t rk_mask_dec[PRESENT_MAX_ROUNDS + 1][PRESENT_BLOCK_BITS];

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

/* --- table implementation over N independent blocks at once ---
 * in/out are arrays of N blocks. Same tables, same results; the point is to fill
 * the load and ALU slots that one latency-bound block leaves idle. */
void present_encrypt_table_x2(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);
void present_encrypt_table_x4(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);
void present_encrypt_table_x8(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);
void present_encrypt_table_x16(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);

/* --- bitsliced implementation: 64 blocks at a time ---
 * in/out are arrays of 64 blocks. Transposition is done internally. */
void present_encrypt_bitslice(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);
void present_decrypt_bitslice(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);

/* --- 32-bit bitsliced implementation: 32 blocks at a time, encryption only ---
 * The same circuits and the same linear-layer bodies as the 64-bit path, one
 * word-width down. This is the path used on 32-bit targets (Cortex-M4), where a
 * uint64_t is a register pair and every gate would otherwise cost two
 * instructions. in/out are arrays of 32 blocks. */
#define PRESENT_BITSLICE32_BLOCKS 32
void present_bitslice32_pack(const uint64_t *in, uint32_t *state);
void present_bitslice32_unpack(const uint32_t *state, uint64_t *out);
uint32_t *present_encrypt_bitslice32_bs(const present_ctx_t *ctx, uint32_t *state,
                                        uint32_t *scratch);
void present_encrypt_bitslice32(const present_ctx_t *ctx, const uint64_t *in,
                                uint64_t *out);

/* --- AVX2 bitsliced implementation: 256 blocks at a time, encryption only ---
 * present_have_avx2() reports whether this build has it; without AVX2 the encrypt
 * function is a no-op stub. in/out are arrays of 256 blocks. */
#define PRESENT_AVX2_BLOCKS 256
int present_have_avx2(void);
void present_encrypt_avx2(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);

/* --- ARM-NEON bitsliced implementation: 128 blocks at a time ---
 * Same shape as the AVX2 path one lane narrower (two 64-bit lanes per register).
 * present_have_neon() reports whether this build has it; without NEON the entry
 * points are no-op stubs. in/out are arrays of 128 blocks. */
#define PRESENT_NEON_BLOCKS 128
int present_have_neon(void);
void present_encrypt_neon(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);
void present_decrypt_neon(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);
void present_neon_pack(const uint64_t *in, uint64_t *state);
void present_neon_unpack(const uint64_t *state, uint64_t *out);
uint64_t *present_encrypt_neon_bs(const present_ctx_t *ctx, uint64_t *state, uint64_t *scratch);
uint64_t *present_decrypt_neon_bs(const present_ctx_t *ctx, uint64_t *state, uint64_t *scratch);

/* --- bitsliced-native entry points ---
 *
 * The two transposes are a fixed ~0.5 cycles per byte, a third of PRESENT's total
 * at 31 rounds. A caller that already holds the state bitsliced does not pay them,
 * and in counter mode that is the normal case: the counters can be produced in
 * bitsliced form directly, since all but the low bits are shared between blocks.
 *
 * `state` and `scratch` are each PRESENT_BLOCK_BITS words per 64 blocks, 32-byte
 * aligned for the AVX2 pair. The round function ping-pongs between the two buffers
 * and returns the one holding the answer rather than copying it back, so the
 * result is `state` for an even round count and `scratch` for an odd one.
 *
 * pack/unpack are the transposes these entry points skip, exposed so a caller can
 * cross the boundary when it has to -- and so the tests can check that going
 * through them reproduces the all-in-one functions exactly. */
void present_avx2_pack(const uint64_t *in, uint64_t *state);
void present_avx2_unpack(const uint64_t *state, uint64_t *out);
uint64_t *present_encrypt_avx2_bs(const present_ctx_t *ctx, uint64_t *state, uint64_t *scratch);
uint64_t *present_encrypt_bitslice_bs(const present_ctx_t *ctx, uint64_t *state,
                                      uint64_t *scratch);
uint64_t *present_decrypt_bitslice_bs(const present_ctx_t *ctx, uint64_t *state,
                                      uint64_t *scratch);

/* Number of distinct bitslice S-box circuits that were synthesised, and the gate
 * count of each; used by the benchmark report. The two backends search different
 * gate sets, so the counts differ. */
int present_circuit_gates(int circuit_id);
int present_circuit_gates_for_avx2(int circuit_id);

/* 64x64 bit transpose, exposed for tests. */
void present_transpose64(const uint64_t *in, uint64_t *out);

#endif /* PRESENT_H */
