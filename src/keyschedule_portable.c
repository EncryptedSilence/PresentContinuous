/* PRESENT key schedules, parameterised by the variant's S-box.
 *
 * Portable drop-in for src/keyschedule.c: identical behaviour, but the 128-bit
 * register is emulated with two uint64_t words on targets without __int128
 * (e.g. 32-bit ARMv7). On x86-64 the native-__int128 path below is bit-for-bit
 * the original file, so nothing changes there.
 */

#include <string.h>

#include "present/present.h"

#if defined(__SIZEOF_INT128__)

/* ---- native path: verbatim from the repo ---------------------------------- */
__extension__ typedef unsigned __int128 u128;

#define MASK80 ((((u128)1) << 80) - 1)

static void schedule80(const present_variant_t *v, u128 K, uint64_t *rk, int rounds)
{
    K &= MASK80;
    for (int i = 0; i <= rounds; i++) {
        rk[i] = (uint64_t)(K >> 16);
        if (i == rounds) break;
        K = ((K << 61) | (K >> 19)) & MASK80;
        {
            unsigned top = (unsigned)((K >> 76) & 0xF);
            K = (K & ~(((u128)0xF) << 76)) | (((u128)v->sbox[top]) << 76);
        }
        K ^= ((u128)(unsigned)(i + 1)) << 15;
    }
}

static void schedule128(const present_variant_t *v, u128 K, uint64_t *rk, int rounds)
{
    for (int i = 0; i <= rounds; i++) {
        rk[i] = (uint64_t)(K >> 64);
        if (i == rounds) break;
        K = (K << 61) | (K >> 67);
        {
            unsigned a = (unsigned)((K >> 124) & 0xF);
            unsigned b = (unsigned)((K >> 120) & 0xF);
            K = (K & ~(((u128)0xFF) << 120))
                | (((u128)v->sbox[a]) << 124) | (((u128)v->sbox[b]) << 120);
        }
        K ^= ((u128)(unsigned)(i + 1)) << 62;
    }
}

static void load_key(u128 *K, const uint8_t *key, size_t key_len)
{
    u128 k = 0;
    for (size_t i = 0; i < key_len; i++) k = (k << 8) | key[i];
    *K = k;
}

#else

/* ---- portable path: 128-bit register as {hi, lo}, value = hi*2^64 + lo ----- */
typedef struct { uint64_t hi, lo; } u128;

static inline u128 shl128(u128 x, unsigned n)
{
    u128 r;
    if (n == 0) return x;
    if (n < 64) {
        r.hi = (x.hi << n) | (x.lo >> (64 - n));
        r.lo = x.lo << n;
    } else {
        r.hi = x.lo << (n - 64);
        r.lo = 0;
    }
    return r;
}

static inline u128 shr128(u128 x, unsigned n)
{
    u128 r;
    if (n == 0) return x;
    if (n < 64) {
        r.lo = (x.lo >> n) | (x.hi << (64 - n));
        r.hi = x.hi >> n;
    } else {
        r.lo = x.hi >> (n - 64);
        r.hi = 0;
    }
    return r;
}

static inline u128 or128(u128 a, u128 b) { return (u128){a.hi | b.hi, a.lo | b.lo}; }
static inline u128 xor128(u128 a, u128 b) { return (u128){a.hi ^ b.hi, a.lo ^ b.lo}; }
static inline u128 and128(u128 a, u128 b) { return (u128){a.hi & b.hi, a.lo & b.lo}; }
static inline u128 from64(uint64_t x) { return (u128){0, x}; }

/* mask of the low 80 bits: all of lo, low 16 bits of hi */
static const u128 MASK80 = {0xFFFFull, 0xFFFFFFFFFFFFFFFFull};

static void schedule80(const present_variant_t *v, u128 K, uint64_t *rk, int rounds)
{
    K = and128(K, MASK80);
    for (int i = 0; i <= rounds; i++) {
        /* rk[i] = (uint64_t)(K >> 16) */
        rk[i] = (K.lo >> 16) | (K.hi << 48);
        if (i == rounds) break;
        /* K = ((K<<61)|(K>>19)) & MASK80 */
        K = and128(or128(shl128(K, 61), shr128(K, 19)), MASK80);
        /* S-box the top nibble (bits 76..79 -> hi bits 12..15) */
        {
            unsigned top = (unsigned)((K.hi >> 12) & 0xF);
            K.hi = (K.hi & ~(0xFull << 12)) | ((uint64_t)v->sbox[top] << 12);
        }
        /* XOR round counter into bits 15..19 (all within lo) */
        K.lo ^= (uint64_t)(unsigned)(i + 1) << 15;
    }
}

static void schedule128(const present_variant_t *v, u128 K, uint64_t *rk, int rounds)
{
    for (int i = 0; i <= rounds; i++) {
        rk[i] = K.hi;                       /* (uint64_t)(K >> 64) */
        if (i == rounds) break;
        K = or128(shl128(K, 61), shr128(K, 67));
        {
            unsigned a = (unsigned)((K.hi >> 60) & 0xF);   /* bits 124..127 */
            unsigned b = (unsigned)((K.hi >> 56) & 0xF);   /* bits 120..123 */
            K.hi = (K.hi & ~(0xFFull << 56))
                 | ((uint64_t)v->sbox[a] << 60)
                 | ((uint64_t)v->sbox[b] << 56);
        }
        /* XOR round counter into bits 62..66, which straddle the word boundary */
        K.lo ^= (uint64_t)(unsigned)(i + 1) << 62;
        K.hi ^= (uint64_t)(unsigned)(i + 1) >> 2;
    }
}

static void load_key(u128 *K, const uint8_t *key, size_t key_len)
{
    u128 k = {0, 0};
    for (size_t i = 0; i < key_len; i++) k = or128(shl128(k, 8), from64(key[i]));
    *K = k;
}

#endif /* __SIZEOF_INT128__ */

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

    u128 K;
    load_key(&K, key, key_len);

    if (v->key_schedule == PRESENT_KS_80) schedule80(v, K, rk, v->rounds);
    else schedule128(v, K, rk, v->rounds);
    return 0;
}
