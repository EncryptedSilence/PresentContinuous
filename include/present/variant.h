/* Variant descriptor: what makes one PRESENT-like cipher differ from another.
 *
 * Descriptors are generated from variants/ *.json by tools/gen_variants.py, so the
 * C implementations and the SAT analysis always agree on what a variant is.
 */
#ifndef PRESENT_VARIANT_H
#define PRESENT_VARIANT_H

#include <stdint.h>

#define PRESENT_BLOCK_BITS 64
#define PRESENT_SBOX_BITS 4
#define PRESENT_N_SBOXES (PRESENT_BLOCK_BITS / PRESENT_SBOX_BITS)
#define PRESENT_MAX_ROUNDS 31

typedef enum {
    PRESENT_KS_80 = 0,
    PRESENT_KS_128 = 1
} present_ks_t;

typedef struct {
    const char *name;
    const char *description;

    /* sbox[x] is the 4-bit S-box; sbox_inv is its inverse. Both generated. */
    uint8_t sbox[16];
    uint8_t sbox_inv[16];

    /* pbox[i] is the destination of state bit i (bit 0 = LSB); pbox_inv its inverse. */
    uint8_t pbox[PRESENT_BLOCK_BITS];
    uint8_t pbox_inv[PRESENT_BLOCK_BITS];

    int rounds;
    int key_bits;
    present_ks_t key_schedule;

    /* Index into the generated bitslice circuit table, for sbox and sbox_inv. */
    int circuit_enc;
    int circuit_dec;
} present_variant_t;

/* Registry, defined in the generated src/gen/variants_gen.c */
extern const present_variant_t present_variants[];
extern const int present_n_variants;

const present_variant_t *present_variant_by_name(const char *name);

/* Returns 0 if the descriptor is self-consistent (permutations, inverses, key size),
 * otherwise a negative error code. Used by the test suite and by present_init. */
int present_variant_check(const present_variant_t *v);

#endif /* PRESENT_VARIANT_H */
