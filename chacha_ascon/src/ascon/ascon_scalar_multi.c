/* Ascon-AEAD128 on N independent messages with plain 64-bit scalar code, the N
 * states advanced in lock-step so their dependency chains interleave.
 *
 * Why this exists: a single Ascon state is latency-bound on a wide out-of-order
 * core. One round's critical path is ~9 dependent single-cycle ops (constant,
 * x2^=x1, andn, xor, t1^=t0, then rotate-xor-rotate-xor in the linear layer),
 * while its ~38 ops would issue in ~8 cycles on five integer ports -- so one
 * stream leaves the core partly idle, and a second independent stream fills it
 * for nearly free. Portable C: on x86-64 with -march=native gcc emits rorx/andn;
 * on 32-bit ARM it is the 64-bit-on-32-bit baseline the bit-interleaved code
 * is compared against. Little-endian hosts only (as is every target here). */
#include <string.h>
#include "ascon_aead.h"

#define IV_AEAD128 0x00001000808c0001ULL
#define ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

typedef struct { uint64_t x[5]; } st;

static inline __attribute__((always_inline)) void round1(st *s, uint64_t c)
{
    uint64_t x0 = s->x[0], x1 = s->x[1], x2 = s->x[2], x3 = s->x[3], x4 = s->x[4];
    x2 ^= c;
    x0 ^= x4; x4 ^= x3; x2 ^= x1;
    uint64_t t0 = x0 ^ (~x1 & x2);
    uint64_t t2 = x2 ^ (~x3 & x4);
    uint64_t t4 = x4 ^ (~x0 & x1);
    uint64_t t1 = x1 ^ (~x2 & x3);
    uint64_t t3 = x3 ^ (~x4 & x0);
    t1 ^= t0; t3 ^= t2; t0 ^= t4;
    s->x[0] = t0 ^ ROR(t0, 19) ^ ROR(t0, 28);
    s->x[1] = t1 ^ ROR(t1, 61) ^ ROR(t1, 39);
    s->x[2] = ~(t2 ^ ROR(t2, 1) ^ ROR(t2, 6));
    s->x[3] = t3 ^ ROR(t3, 10) ^ ROR(t3, 17);
    s->x[4] = t4 ^ ROR(t4, 7) ^ ROR(t4, 41);
}

static const uint8_t RC[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
                               0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

static inline uint64_t ld64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static inline void st64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

/* 0..15 bytes, padded with 0x01 after the last one, as two rate words. */
static inline void ld_pad(const uint8_t *p, size_t n, uint64_t *lo, uint64_t *hi)
{
    uint8_t b[16] = {0};
    if (n) memcpy(b, p, n);
    b[n] = 1;
    *lo = ld64(b);
    *hi = ld64(b + 8);
}

#define FOR_L for (int l = 0; l < N; l++)
static inline __attribute__((always_inline))
void encN(const ascon_job *j, size_t mlen, size_t adlen, const int N)
{
    st s[4];
    uint64_t k0[4], k1[4];
    FOR_L {
        k0[l] = ld64(j[l].key);
        k1[l] = ld64(j[l].key + 8);
        s[l].x[0] = IV_AEAD128;
        s[l].x[1] = k0[l];
        s[l].x[2] = k1[l];
        s[l].x[3] = ld64(j[l].nonce);
        s[l].x[4] = ld64(j[l].nonce + 8);
    }
    for (int i = 0; i < 12; i++) FOR_L round1(&s[l], RC[i]);
    FOR_L { s[l].x[3] ^= k0[l]; s[l].x[4] ^= k1[l]; }
    if (adlen) {
        size_t off = 0;
        for (; off + 16 <= adlen; off += 16) {
            FOR_L { s[l].x[0] ^= ld64(j[l].ad + off); s[l].x[1] ^= ld64(j[l].ad + off + 8); }
            for (int i = 4; i < 12; i++) FOR_L round1(&s[l], RC[i]);
        }
        FOR_L {
            uint64_t lo, hi;
            ld_pad(j[l].ad + off, adlen - off, &lo, &hi);
            s[l].x[0] ^= lo; s[l].x[1] ^= hi;
        }
        for (int i = 4; i < 12; i++) FOR_L round1(&s[l], RC[i]);
    }
    FOR_L s[l].x[4] ^= 0x8000000000000000ULL;
    size_t off = 0;
    for (; off + 16 <= mlen; off += 16) {
        FOR_L {
            s[l].x[0] ^= ld64(j[l].m + off);
            s[l].x[1] ^= ld64(j[l].m + off + 8);
            st64(j[l].c + off, s[l].x[0]);
            st64(j[l].c + off + 8, s[l].x[1]);
        }
        for (int i = 4; i < 12; i++) FOR_L round1(&s[l], RC[i]);
    }
    FOR_L {
        size_t n = mlen - off;
        uint64_t lo, hi;
        ld_pad(j[l].m + off, n, &lo, &hi);
        s[l].x[0] ^= lo; s[l].x[1] ^= hi;
        if (n) {
            uint8_t b[16];
            st64(b, s[l].x[0]);
            st64(b + 8, s[l].x[1]);
            memcpy(j[l].c + off, b, n);
        }
        s[l].x[2] ^= k0[l];
        s[l].x[3] ^= k1[l];
    }
    for (int i = 0; i < 12; i++) FOR_L round1(&s[l], RC[i]);
    FOR_L {
        st64(j[l].c + mlen, s[l].x[3] ^ k0[l]);
        st64(j[l].c + mlen + 8, s[l].x[4] ^ k1[l]);
    }
}

static void enc1(const ascon_job *j, size_t m, size_t a) { encN(j, m, a, 1); }
static void enc2(const ascon_job *j, size_t m, size_t a) { encN(j, m, a, 2); }
static void enc4(const ascon_job *j, size_t m, size_t a) { encN(j, m, a, 4); }

void ascon_multi_scalar_x1(const ascon_job *jobs, size_t n, size_t mlen, size_t adlen)
{
    for (size_t i = 0; i < n; i++) enc1(jobs + i, mlen, adlen);
}

void ascon_multi_scalar_x2(const ascon_job *jobs, size_t n, size_t mlen, size_t adlen)
{
    size_t i = 0;
    for (; i + 2 <= n; i += 2) enc2(jobs + i, mlen, adlen);
    for (; i < n; i++) enc1(jobs + i, mlen, adlen);
}

void ascon_multi_scalar_x4(const ascon_job *jobs, size_t n, size_t mlen, size_t adlen)
{
    size_t i = 0;
    for (; i + 4 <= n; i += 4) enc4(jobs + i, mlen, adlen);
    for (; i + 2 <= n; i += 2) enc2(jobs + i, mlen, adlen);
    for (; i < n; i++) enc1(jobs + i, mlen, adlen);
}
