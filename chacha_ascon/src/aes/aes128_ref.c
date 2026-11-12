/* AES-128 and AES-256 (FIPS-197), portable C reference: key expansion (shared by every AES
 * implementation in this study -- their contexts start with the same 176 bytes of
 * round keys in FIPS-197 byte order, which is also the order AES-NI expects), a
 * byte-oriented block function written straight from the specification (the
 * oracle of tests/test_bc.c), and the counter-mode driver around it ("ref").
 * Not constant time (table S-box); a reference, not a candidate. */
#include <string.h>
#include "blockctr.h"

const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

void aes128_key_expand(aes128_ctx *ctx, const uint8_t key[16])
{
    uint8_t *w = &ctx->rk[0][0];
    memcpy(w, key, 16);
    uint8_t rcon = 1;
    for (int i = 4; i < 44; i++) {
        uint8_t t[4] = {w[4 * i - 4], w[4 * i - 3], w[4 * i - 2], w[4 * i - 1]};
        if (i % 4 == 0) { /* RotWord, SubWord, Rcon */
            uint8_t t0 = t[0];
            t[0] = (uint8_t)(aes_sbox[t[1]] ^ rcon);
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[t0];
            rcon = xtime(rcon);
        }
        for (int j = 0; j < 4; j++) w[4 * i + j] = (uint8_t)(w[4 * i - 16 + j] ^ t[j]);
    }
}

/* AES-256: Nk = 8, Nr = 14 (FIPS-197 5.2: SubWord also when i mod 8 == 4). */
void aes256_key_expand(aes256_ctx *ctx, const uint8_t key[32])
{
    uint8_t *w = &ctx->rk[0][0];
    memcpy(w, key, 32);
    uint8_t rcon = 1;
    for (int i = 8; i < 60; i++) {
        uint8_t t[4] = {w[4 * i - 4], w[4 * i - 3], w[4 * i - 2], w[4 * i - 1]};
        if (i % 8 == 0) { /* RotWord, SubWord, Rcon */
            uint8_t t0 = t[0];
            t[0] = (uint8_t)(aes_sbox[t[1]] ^ rcon);
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[t0];
            rcon = xtime(rcon);
        } else if (i % 8 == 4) { /* SubWord */
            for (int j = 0; j < 4; j++) t[j] = aes_sbox[t[j]];
        }
        for (int j = 0; j < 4; j++) w[4 * i + j] = (uint8_t)(w[4 * i - 32 + j] ^ t[j]);
    }
}

/* State s[r + 4c] (column-major, the input byte order); nr = 10 or 14 rounds. */
static void aes_encrypt_rk(const uint8_t (*rk)[16], int nr, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = (uint8_t)(in[i] ^ rk[0][i]);
    for (int r = 1; r <= nr; r++) {
        for (int i = 0; i < 16; i++) t[i] = aes_sbox[s[i]];               /* SubBytes */
        for (int c = 0; c < 4; c++)                                        /* ShiftRows */
            for (int row = 0; row < 4; row++) s[row + 4 * c] = t[row + 4 * ((c + row) & 3)];
        if (r < nr)                                                        /* MixColumns */
            for (int c = 0; c < 4; c++) {
                uint8_t *a = &s[4 * c], a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];
                uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                a[0] = (uint8_t)(a0 ^ x ^ xtime((uint8_t)(a0 ^ a1)));
                a[1] = (uint8_t)(a1 ^ x ^ xtime((uint8_t)(a1 ^ a2)));
                a[2] = (uint8_t)(a2 ^ x ^ xtime((uint8_t)(a2 ^ a3)));
                a[3] = (uint8_t)(a3 ^ x ^ xtime((uint8_t)(a3 ^ a0)));
            }
        for (int i = 0; i < 16; i++) s[i] ^= rk[r][i];                     /* AddRoundKey */
    }
    memcpy(out, s, 16);
}
void aes128_encrypt_block_ref(const aes128_ctx *ctx, const uint8_t in[16], uint8_t out[16])
{ aes_encrypt_rk(ctx->rk, 10, in, out); }
void aes256_encrypt_block_ref(const aes256_ctx *ctx, const uint8_t in[16], uint8_t out[16])
{ aes_encrypt_rk(ctx->rk, 14, in, out); }

void aes128_setup_ref(void *ctx, const uint8_t *key) { aes128_key_expand(ctx, key); }

void aes128_ctr_ref(const void *vctx, uint8_t *out, const uint8_t *in, size_t len,
                    const uint8_t nonce[12], uint32_t ctr)
{
    uint8_t blk[16], ks[16];
    for (size_t off = 0; off < len; off += 16, ctr++) {
        bc_counter_block(blk, nonce, ctr);
        aes128_encrypt_block_ref(vctx, blk, ks);
        size_t n = len - off < 16 ? len - off : 16;
        for (size_t i = 0; i < n; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
    }
}

void aes256_setup_ref(void *ctx, const uint8_t *key) { aes256_key_expand(ctx, key); }

void aes256_ctr_ref(const void *vctx, uint8_t *out, const uint8_t *in, size_t len,
                    const uint8_t nonce[12], uint32_t ctr)
{
    uint8_t blk[16], ks[16];
    for (size_t off = 0; off < len; off += 16, ctr++) {
        bc_counter_block(blk, nonce, ctr);
        aes256_encrypt_block_ref(vctx, blk, ks);
        size_t n = len - off < 16 ? len - off : 16;
        for (size_t i = 0; i < n; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
    }
}
