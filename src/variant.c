#include <string.h>

#include "present/variant.h"

const present_variant_t *present_variant_by_name(const char *name)
{
    for (int i = 0; i < present_n_variants; i++)
        if (strcmp(present_variants[i].name, name) == 0) return &present_variants[i];
    return NULL;
}

int present_variant_check(const present_variant_t *v)
{
    int seen_sbox[16];
    int seen[PRESENT_BLOCK_BITS];

    if (!v) return -1;

    /* sbox is a permutation of 0..15 */
    memset(seen_sbox, 0, sizeof(seen_sbox));
    for (int i = 0; i < 16; i++) {
        if (v->sbox[i] > 15) return -2;
        if (seen_sbox[v->sbox[i]]++) return -2;
    }
    /* sbox_inv really inverts it */
    for (int i = 0; i < 16; i++)
        if (v->sbox_inv[v->sbox[i]] != i) return -3;

    /* pbox is a permutation of 0..63 */
    memset(seen, 0, sizeof(seen));
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++) {
        if (v->pbox[i] >= PRESENT_BLOCK_BITS) return -4;
        if (seen[v->pbox[i]]++) return -4;
    }
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++)
        if (v->pbox_inv[v->pbox[i]] != i) return -5;

    if (v->rounds < 1 || v->rounds > PRESENT_MAX_ROUNDS) return -6;

    if (v->key_schedule == PRESENT_KS_80) {
        if (v->key_bits != 80) return -7;
    } else if (v->key_schedule == PRESENT_KS_128) {
        if (v->key_bits != 128) return -7;
    } else {
        return -8;
    }
    return 0;
}
