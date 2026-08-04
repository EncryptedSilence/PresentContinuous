/* PRESENT key schedules, parameterised by the variant's S-box.
 *
 * Bit numbering follows the specification: the key is k_{n-1} ... k_0 with k_0 the
 * least significant bit, and round key K_i is the leftmost 64 bits of the register.
 * A round counter of i is mixed in when producing K_{i+1}, for i = 1 .. rounds.
 */

#include <string.h>

#include "present/present.h"

/* The 80- and 128-bit key registers rotate across a 64-bit boundary, so a wide
 * integer keeps the schedule readable. __extension__ keeps -Wpedantic quiet about
 * a type that ISO C does not define but every supported compiler provides. */
__extension__ typedef unsigned __int128 u128;

#define MASK80 ((((u128)1) << 80) - 1)

static void schedule80(const present_variant_t *v, u128 K, uint64_t *rk, int rounds)
{
    K &= MASK80;
    for (int i = 0; i <= rounds; i++) {
        rk[i] = (uint64_t)(K >> 16);
        if (i == rounds) break;

        /* 1. rotate the 80-bit register left by 61 */
        K = ((K << 61) | (K >> 19)) & MASK80;
        /* 2. S-box the top nibble */
        {
            unsigned top = (unsigned)((K >> 76) & 0xF);
            K = (K & ~(((u128)0xF) << 76)) | (((u128)v->sbox[top]) << 76);
        }
        /* 3. XOR the round counter into bits 19..15 */
        K ^= ((u128)(unsigned)(i + 1)) << 15;
    }
}

static void schedule128(const present_variant_t *v, u128 K, uint64_t *rk, int rounds)
{
    for (int i = 0; i <= rounds; i++) {
        rk[i] = (uint64_t)(K >> 64);
        if (i == rounds) break;

        /* 1. rotate the 128-bit register left by 61 */
        K = (K << 61) | (K >> 67);
        /* 2. S-box the top two nibbles */
        {
            unsigned a = (unsigned)((K >> 124) & 0xF);
            unsigned b = (unsigned)((K >> 120) & 0xF);
            K = (K & ~(((u128)0xFF) << 120))
                | (((u128)v->sbox[a]) << 124) | (((u128)v->sbox[b]) << 120);
        }
        /* 3. XOR the round counter into bits 66..62 */
        K ^= ((u128)(unsigned)(i + 1)) << 62;
    }
}

/* No schedule: the caller supplies the round keys themselves, most significant byte
 * first, one 64-bit key per round plus the final whitening key. A design that treats
 * its schedule as out of scope -- or an analysis that wants independent round keys --
 * gets exactly what it asks for, and the differential model, which never sees a key
 * at all, is unaffected either way. */
static void schedule_independent(const uint8_t *key, uint64_t *rk, int rounds)
{
    for (int i = 0; i <= rounds; i++) {
        uint64_t k = 0;
        for (int j = 0; j < 8; j++) k = (k << 8) | key[8 * i + j];
        rk[i] = k;
    }
}

int present_key_schedule(const present_variant_t *v, const uint8_t *key, size_t key_len,
                         uint64_t *rk)
{
    if (key_len != present_variant_key_bytes(v)) return -1;

    if (v->key_schedule == PRESENT_KS_INDEPENDENT) {
        schedule_independent(key, rk, v->rounds);
        return 0;
    }

    u128 K = 0;
    for (size_t i = 0; i < key_len; i++) K = (K << 8) | key[i];

    if (v->key_schedule == PRESENT_KS_80) schedule80(v, K, rk, v->rounds);
    else schedule128(v, K, rk, v->rounds);
    return 0;
}
