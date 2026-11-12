/* Ascon-AEAD128 on two independent messages in ARMv7 NEON (Cortex-A7): state
 * word i of message l is 64-bit lane l of x[i] (uint64x2_t), so a round is the
 * scalar round applied lane-wise -- no shuffles. 64-bit rotations are
 * VSHL + VSRI. On the A7 a Q op costs two cycles (64-bit NEON datapath), so the
 * second lane is not free arithmetic; what it buys is independent work to fill
 * the NEON pipeline's result latency, which a single 64-bit state cannot
 * (compare ascon-c/neon, one message in D registers). Partial blocks go
 * through 16-byte stack buffers; lanes run in lock-step, so all jobs in one
 * call share mlen and adlen (the ascon_multi_fn contract). */
#include <arm_neon.h>
#include <string.h>
#include "ascon_aead.h"

void ascon_multi_scalar_x1(const ascon_job *, size_t, size_t, size_t);

#define IV_AEAD128 0x00001000808c0001ULL

#define ROR(x, n) vsriq_n_u64(vshlq_n_u64((x), 64 - (n)), (x), (n))

typedef struct { uint64x2_t x0, x1, x2, x3, x4; } st2;

static inline __attribute__((always_inline)) void round2(st2 *s, uint64_t c)
{
    uint64x2_t x0 = s->x0, x1 = s->x1, x2 = s->x2, x3 = s->x3, x4 = s->x4;
    x2 = veorq_u64(x2, vdupq_n_u64(c));
    x0 = veorq_u64(x0, x4); x4 = veorq_u64(x4, x3); x2 = veorq_u64(x2, x1);
    uint64x2_t t0 = veorq_u64(x0, vbicq_u64(x2, x1));
    uint64x2_t t1 = veorq_u64(x1, vbicq_u64(x3, x2));
    uint64x2_t t2 = veorq_u64(x2, vbicq_u64(x4, x3));
    uint64x2_t t3 = veorq_u64(x3, vbicq_u64(x0, x4));
    uint64x2_t t4 = veorq_u64(x4, vbicq_u64(x1, x0));
    t1 = veorq_u64(t1, t0); t3 = veorq_u64(t3, t2); t0 = veorq_u64(t0, t4);
    s->x0 = veorq_u64(t0, veorq_u64(ROR(t0, 19), ROR(t0, 28)));
    s->x1 = veorq_u64(t1, veorq_u64(ROR(t1, 61), ROR(t1, 39)));
    s->x2 = vreinterpretq_u64_u32(vmvnq_u32(vreinterpretq_u32_u64(
                veorq_u64(t2, veorq_u64(ROR(t2, 1), ROR(t2, 6))))));
    s->x3 = veorq_u64(t3, veorq_u64(ROR(t3, 10), ROR(t3, 17)));
    s->x4 = veorq_u64(t4, veorq_u64(ROR(t4, 7), ROR(t4, 41)));
}

static const uint8_t RC[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
                               0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};

static inline uint64_t ld64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static inline void st64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }
/* one 64-bit word of each lane: 8 bytes at p0 (lane 0) and p1 (lane 1) */
static inline uint64x2_t ld2(const uint8_t *p0, const uint8_t *p1)
{
    return vcombine_u64(vreinterpret_u64_u8(vld1_u8(p0)), vreinterpret_u64_u8(vld1_u8(p1)));
}
static inline void st2w(uint8_t *p0, uint8_t *p1, uint64x2_t v)
{
    vst1_u8(p0, vreinterpret_u8_u64(vget_low_u64(v)));
    vst1_u8(p1, vreinterpret_u8_u64(vget_high_u64(v)));
}

#define P12(s) do { for (int i = 0; i < 12; i++) round2(&(s), RC[i]); } while (0)
#define P8(s)  do { for (int i = 4; i < 12; i++) round2(&(s), RC[i]); } while (0)

/* 0..15 bytes padded with 0x01, as two 16-byte buffers (one per lane) */
static inline void pad2(const uint8_t *a, const uint8_t *b, size_t n, uint8_t ba[16], uint8_t bb[16])
{
    memset(ba, 0, 16); memset(bb, 0, 16);
    if (n) { memcpy(ba, a, n); memcpy(bb, b, n); }
    ba[n] = 1; bb[n] = 1;
}

static void enc2(const ascon_job *j, size_t mlen, size_t adlen)
{
    const ascon_job *a = j, *b = j + 1;
    const uint64x2_t k0 = ld2(a->key, b->key), k1 = ld2(a->key + 8, b->key + 8);
    st2 s;
    s.x0 = vdupq_n_u64(IV_AEAD128);
    s.x1 = k0;
    s.x2 = k1;
    s.x3 = ld2(a->nonce, b->nonce);
    s.x4 = ld2(a->nonce + 8, b->nonce + 8);
    P12(s);
    s.x3 = veorq_u64(s.x3, k0);
    s.x4 = veorq_u64(s.x4, k1);
    uint8_t ba[16], bb[16];
    if (adlen) {
        size_t off = 0;
        for (; off + 16 <= adlen; off += 16) {
            s.x0 = veorq_u64(s.x0, ld2(a->ad + off, b->ad + off));
            s.x1 = veorq_u64(s.x1, ld2(a->ad + off + 8, b->ad + off + 8));
            P8(s);
        }
        pad2(a->ad + off, b->ad + off, adlen - off, ba, bb);
        s.x0 = veorq_u64(s.x0, ld2(ba, bb));
        s.x1 = veorq_u64(s.x1, ld2(ba + 8, bb + 8));
        P8(s);
    }
    s.x4 = veorq_u64(s.x4, vdupq_n_u64(0x8000000000000000ULL));
    size_t off = 0;
    for (; off + 16 <= mlen; off += 16) {
        s.x0 = veorq_u64(s.x0, ld2(a->m + off, b->m + off));
        s.x1 = veorq_u64(s.x1, ld2(a->m + off + 8, b->m + off + 8));
        st2w(a->c + off, b->c + off, s.x0);
        st2w(a->c + off + 8, b->c + off + 8, s.x1);
        P8(s);
    }
    size_t n = mlen - off;
    pad2(a->m + off, b->m + off, n, ba, bb);
    s.x0 = veorq_u64(s.x0, ld2(ba, bb));
    s.x1 = veorq_u64(s.x1, ld2(ba + 8, bb + 8));
    if (n) {
        st2w(ba, bb, s.x0);
        st2w(ba + 8, bb + 8, s.x1);
        memcpy(a->c + off, ba, n);
        memcpy(b->c + off, bb, n);
    }
    s.x2 = veorq_u64(s.x2, k0);
    s.x3 = veorq_u64(s.x3, k1);
    P12(s);
    st2w(a->c + mlen, b->c + mlen, veorq_u64(s.x3, k0));
    st2w(a->c + mlen + 8, b->c + mlen + 8, veorq_u64(s.x4, k1));
}

void ascon_multi_neon_x2(const ascon_job *jobs, size_t n, size_t mlen, size_t adlen)
{
    size_t i = 0;
    for (; i + 2 <= n; i += 2) enc2(jobs + i, mlen, adlen);
    if (i < n) ascon_multi_scalar_x1(jobs + i, 1, mlen, adlen);
}
