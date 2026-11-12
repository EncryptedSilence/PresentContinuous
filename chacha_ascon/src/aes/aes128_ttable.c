/* AES-128-CTR and AES-256-CTR, portable 32-bit T-table implementation ("ttable"): the classic
 * Daemen-Rijmen "fast software" round (AES proposal, section 5.2) with four 1 KB
 * tables T0..T3 combining SubBytes, ShiftRows and MixColumns, in little-endian
 * word order (state word c = column c, byte r of the column in bits 8r..8r+7),
 * so no byte swaps on either x86 or ARM. Last round: plain S-box bytes.
 * One block at a time. Tables are built in RAM from the S-box on first setup
 * (setup is not timed). Not constant time. */
#include <string.h>
#include "blockctr.h"

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "word XOR below assumes a little-endian host"
#endif

extern const uint8_t aes_sbox[256];
static uint32_t T0[256], T1[256], T2[256], T3[256];
static int tables_ready;

static uint32_t rotl8(uint32_t x) { return (x << 8) | (x >> 24); }
static uint32_t ld32le(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void build_tables(void)
{
    for (int x = 0; x < 256; x++) {
        uint32_t s = aes_sbox[x], s2 = ((s << 1) ^ ((s >> 7) * 0x1b)) & 0xff, s3 = s2 ^ s;
        /* column (2s, s, s, 3s): the MixColumns image of s in row 0 */
        T0[x] = s2 | s << 8 | s << 16 | s3 << 24;
        T1[x] = rotl8(T0[x]);
        T2[x] = rotl8(T1[x]);
        T3[x] = rotl8(T2[x]);
    }
    tables_ready = 1;
}


void aes128_setup_ttable(void *vctx, const uint8_t *key)
{
    if (!tables_ready) build_tables();
    aes128_ctx e;
    aes128_key_expand(&e, key);
    aes128_tt_ctx *c = vctx;
    for (int i = 0; i < 44; i++) c->rk[i] = ld32le(&e.rk[0][0] + 4 * i);
}

#define B0(x) ((x) & 0xff)
#define B1(x) (((x) >> 8) & 0xff)
#define B2(x) (((x) >> 16) & 0xff)
#define B3(x) ((x) >> 24)

/* nr = 10 (AES-128) or 14 (AES-256); always inlined with a constant nr, so each
 * caller gets the same code a fixed-round loop would compile to. */
static inline __attribute__((always_inline)) void enc_words(const uint32_t *rk, const int nr, uint32_t s[4])
{
    uint32_t s0 = s[0] ^ rk[0], s1 = s[1] ^ rk[1], s2 = s[2] ^ rk[2], s3 = s[3] ^ rk[3];
    for (int r = 1; r < nr; r++) {
        const uint32_t *k = rk + 4 * r;
        uint32_t t0 = T0[B0(s0)] ^ T1[B1(s1)] ^ T2[B2(s2)] ^ T3[B3(s3)] ^ k[0];
        uint32_t t1 = T0[B0(s1)] ^ T1[B1(s2)] ^ T2[B2(s3)] ^ T3[B3(s0)] ^ k[1];
        uint32_t t2 = T0[B0(s2)] ^ T1[B1(s3)] ^ T2[B2(s0)] ^ T3[B3(s1)] ^ k[2];
        uint32_t t3 = T0[B0(s3)] ^ T1[B1(s0)] ^ T2[B2(s1)] ^ T3[B3(s2)] ^ k[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    const uint32_t *k = rk + 4 * nr;
#define LAST(a, b, c, d) ((uint32_t)aes_sbox[B0(a)] | (uint32_t)aes_sbox[B1(b)] << 8 | \
                          (uint32_t)aes_sbox[B2(c)] << 16 | (uint32_t)aes_sbox[B3(d)] << 24)
    s[0] = LAST(s0, s1, s2, s3) ^ k[0];
    s[1] = LAST(s1, s2, s3, s0) ^ k[1];
    s[2] = LAST(s2, s3, s0, s1) ^ k[2];
    s[3] = LAST(s3, s0, s1, s2) ^ k[3];
#undef LAST
}

static inline __attribute__((always_inline)) void ctr_ttable(const uint32_t *rk, const int nr, uint8_t *out,
                                                             const uint8_t *in, size_t len,
                                                             const uint8_t nonce[12], uint32_t ctr)
{
    uint32_t n0 = ld32le(nonce), n1 = ld32le(nonce + 4), n2 = ld32le(nonce + 8);
    for (size_t off = 0; off < len; off += 16, ctr++) {
        uint32_t s[4] = {n0, n1, n2, __builtin_bswap32(ctr)};
        enc_words(rk, nr, s);
        size_t n = len - off < 16 ? len - off : 16;
        if (n == 16) {
            uint32_t w[4];
            memcpy(w, in + off, 16);
            for (int i = 0; i < 4; i++) w[i] ^= s[i]; /* little-endian host */
            memcpy(out + off, w, 16);
        } else {
            for (size_t i = 0; i < n; i++) out[off + i] = (uint8_t)(in[off + i] ^ (s[i / 4] >> (8 * (i % 4))));
        }
    }
}

void aes128_ctr_ttable(const void *vctx, uint8_t *out, const uint8_t *in, size_t len,
                       const uint8_t nonce[12], uint32_t ctr)
{
    ctr_ttable(((const aes128_tt_ctx *)vctx)->rk, 10, out, in, len, nonce, ctr);
}

/* AES-256: 15 round keys, FIPS-197 w[0..59] as little-endian words (ctx 240 B). */
void aes256_setup_ttable(void *vctx, const uint8_t *key)
{
    if (!tables_ready) build_tables();
    aes256_ctx e;
    aes256_key_expand(&e, key);
    uint32_t *rk = vctx;
    for (int i = 0; i < 60; i++) rk[i] = ld32le(&e.rk[0][0] + 4 * i);
}

void aes256_ctr_ttable(const void *vctx, uint8_t *out, const uint8_t *in, size_t len,
                       const uint8_t nonce[12], uint32_t ctr)
{
    ctr_ttable((const uint32_t *)vctx, 14, out, in, len, nonce, ctr);
}
