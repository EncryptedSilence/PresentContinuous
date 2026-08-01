#ifndef PRESENT_INTERNAL_H
#define PRESENT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "present/present.h"

/* Expands a key into ctx->rk[0 .. rounds]. Returns 0 on success. */
int present_key_schedule(const present_variant_t *v, const uint8_t *key, size_t key_len,
                         uint64_t *rk);

#endif /* PRESENT_INTERNAL_H */
