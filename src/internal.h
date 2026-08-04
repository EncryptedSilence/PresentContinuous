#ifndef PRESENT_INTERNAL_H
#define PRESENT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "present/present.h"

/* Expands a key into ctx->rk[0 .. rounds]. Returns 0 on success. */
int present_key_schedule(const present_variant_t *v, const uint8_t *key, size_t key_len,
                         uint64_t *rk);

/* Nibble constant B such that bitsliced circuit `circuit_id` computes S(x) ^ B
 * rather than S(x). Defined in present_bitslice.c, where the circuits live;
 * present_core.c cancels it in the round keys. */
int present_circuit_outcomp_mask(int circuit_id);

#endif /* PRESENT_INTERNAL_H */
