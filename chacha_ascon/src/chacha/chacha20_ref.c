/* Portable ChaCha20, written from RFC 8439 section 2. The oracle for every other
 * implementation in tests/test_chacha20.c alongside the RFC's own vectors. */
#include <string.h>
#include "chacha20.h"

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d)                          \
    a += b; d ^= a; d = ROTL32(d, 16);          \
    c += d; b ^= c; b = ROTL32(b, 12);          \
    a += b; d ^= a; d = ROTL32(d, 8);           \
    c += d; b ^= c; b = ROTL32(b, 7)

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

void chacha20_block_ref(uint32_t out[16], const uint32_t in[16])
{
    uint32_t x[16];
    memcpy(x, in, sizeof x);
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++)
        out[i] = x[i] + in[i];
}

void chacha20_xor_ref(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t key[32], const uint8_t nonce[12], uint32_t counter)
{
    uint32_t st[16], ks[16];
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (int i = 0; i < 8; i++)
        st[4 + i] = load32_le(key + 4 * i);
    st[12] = counter;
    for (int i = 0; i < 3; i++)
        st[13 + i] = load32_le(nonce + 4 * i);
    while (len > 0) {
        chacha20_block_ref(ks, st);
        size_t n = len < 64 ? len : 64;
        for (size_t i = 0; i < n; i++)
            out[i] = in[i] ^ (uint8_t)(ks[i / 4] >> (8 * (i % 4)));
        out += n; in += n; len -= n;
        st[12]++;
    }
}
