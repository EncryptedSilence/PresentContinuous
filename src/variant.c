#include <string.h>

#include "present/variant.h"

const present_variant_t *present_variant_by_name(const char *name)
{
    for (int i = 0; i < present_n_variants; i++)
        if (strcmp(present_variants[i].name, name) == 0) return &present_variants[i];
    return NULL;
}

size_t present_variant_key_bytes(const present_variant_t *v)
{
    return v ? (size_t)v->key_bits / 8 : 0;
}

int present_variant_has_bitslice(const present_variant_t *v)
{
    return v && v->kernel_enc != PRESENT_NO_KERNEL && v->kernel_dec != PRESENT_NO_KERNEL;
}

int present_variant_check(const present_variant_t *v)
{
    int seen_sbox[PRESENT_MAX_SBOX_ENTRIES];
    int seen[PRESENT_BLOCK_BITS];

    if (!v) return -1;

    if (v->sbox_bits != 4 && v->sbox_bits != 8) return -12;
    if (v->n_sboxes != PRESENT_BLOCK_BITS / v->sbox_bits) return -12;
    const int n_entries = 1 << v->sbox_bits;

    /* sbox is a permutation of 0 .. 2^sbox_bits - 1 */
    memset(seen_sbox, 0, sizeof(seen_sbox));
    for (int i = 0; i < n_entries; i++) {
        if (v->sbox[i] >= n_entries) return -2;
        if (seen_sbox[v->sbox[i]]++) return -2;
    }
    /* sbox_inv really inverts it */
    for (int i = 0; i < n_entries; i++)
        if (v->sbox_inv[v->sbox[i]] != i) return -3;

    /* pbox is a permutation of 0..63 */
    memset(seen, 0, sizeof(seen));
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++) {
        if (v->pbox[i] >= PRESENT_BLOCK_BITS) return -4;
        if (seen[v->pbox[i]]++) return -4;
    }
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++)
        if (v->pbox_inv[v->pbox[i]] != i) return -5;

    /* The linear layer really is invertible, and lin_col_inv really inverts it.
     * Checked on a basis, which is enough for a linear map: 64 applications of
     * lin_col_inv to a column, negligible next to building the lookup tables.
     * A wrong inverse here would silently break decryption for every variant. */
    for (int i = 0; i < PRESENT_BLOCK_BITS; i++) {
        uint64_t x = v->lin_col[i], back = 0;
        while (x) {
            int b = __builtin_ctzll(x);
            x &= x - 1;
            back ^= v->lin_col_inv[b];
        }
        if (back != ((uint64_t)1 << i)) return -9;
    }

    if (v->lin_kind == PRESENT_LIN_PBOX) {
        /* Consistency between the two representations of the same permutation. */
        for (int i = 0; i < PRESENT_BLOCK_BITS; i++)
            if (v->lin_col[i] != ((uint64_t)1 << v->pbox[i])) return -10;
    } else if (v->lin_kind != PRESENT_LIN_444) {
        return -11;
    }

    if (v->rounds < 1 || v->rounds > PRESENT_MAX_ROUNDS) return -6;

    if (v->key_schedule == PRESENT_KS_80) {
        if (v->key_bits != 80) return -7;
    } else if (v->key_schedule == PRESENT_KS_128) {
        if (v->key_bits != 128) return -7;
    } else if (v->key_schedule == PRESENT_KS_INDEPENDENT) {
        /* One round key per round plus the final whitening key, no expansion. */
        if (v->key_bits != (v->rounds + 1) * PRESENT_BLOCK_BITS) return -7;
    } else {
        return -8;
    }

    /* The PRESENT key schedules apply the variant's own S-box, so they need a 4-bit
     * one. An 8-bit S-box is only meaningful with a schedule that does not use it. */
    if (v->sbox_bits != 4 && v->key_schedule != PRESENT_KS_INDEPENDENT) return -13;
    return 0;
}
