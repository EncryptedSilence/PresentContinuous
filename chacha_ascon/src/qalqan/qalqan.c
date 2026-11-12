/* Copied unmodified (below this comment) from /home/leo/projects/QalqanSpeed/qalqan.c,
 * QalqanSpeed commit 1813b14 (the user's reference, verified against СТ РК 4009-2025
 * Appendix A). Used here as the reference block function of qalqan-ctr. */
/* qalqan.c - Qalqan-256/128 block cipher, ENCRYPTION only. See qalqan.h.
 *
 * Verified byte-for-byte against the reference implementation over 200k random
 * (key, plaintext) pairs. Sample: key = 00 01 .. 1f, plaintext = 00 10 20 .. f0
 *   -> ciphertext = de 71 b5 f8 64 6a 6a 5d 77 fd b1 fa 28 5a 38 89
 */
#include "qalqan.h"

/* --- S-box --------------------------------------------------------------- */
static const uint8_t SB[256] = {
    0xd1,0xb5,0xa6,0x74,0x2f,0xb2,0x03,0x77,0xae,0xb3,0x60,0x95,0xfd,0xf8,0xc7,0xf0,
    0x2b,0xce,0xa5,0x91,0x4c,0x6f,0xf3,0x4f,0x82,0x01,0x45,0x76,0x9f,0xed,0x41,0xfb,
    0xac,0x4e,0x5e,0x04,0xeb,0xf9,0xf1,0x3a,0x1f,0xe2,0x8e,0xe7,0x85,0x35,0xdb,0x52,
    0x78,0xa1,0xfc,0xa2,0xde,0x68,0x02,0x4d,0xf6,0xdd,0xcf,0xa3,0xdc,0x6b,0x81,0x44,
    0x2a,0x5d,0x1e,0xe0,0x53,0x71,0x3b,0xc1,0xcc,0x9d,0x80,0xd5,0x84,0x00,0x24,0x4b,
    0xb6,0x83,0x0d,0x87,0x7e,0x86,0xca,0x96,0xbe,0x5a,0xe6,0xd0,0xd4,0xd8,0x55,0xc0,
    0x05,0xe5,0xe9,0x5b,0x47,0xe4,0x2d,0x34,0x13,0x88,0x48,0x32,0x38,0xb9,0xda,0xc9,
    0x42,0x29,0xd7,0xf2,0x9b,0x6d,0xe8,0x8d,0x12,0x7c,0x8c,0x3f,0xbc,0x3c,0x1b,0xc5,
    0x69,0x22,0x97,0xaa,0x73,0x0a,0x0c,0x8a,0x90,0x31,0xc4,0x33,0xe1,0x8b,0x9c,0x63,
    0x5f,0xf5,0xf7,0xff,0x79,0x49,0xd3,0xc6,0x7b,0x1a,0x39,0xc8,0x6e,0x72,0xd9,0xc3,
    0x62,0x28,0xbd,0xbb,0xfa,0x2e,0xbf,0x43,0x06,0x0b,0x7a,0x64,0x5c,0x92,0x37,0x3d,
    0x66,0x26,0x51,0xef,0x0f,0xa9,0x14,0x70,0x16,0x17,0x10,0x19,0x93,0x09,0x59,0x15,
    0xfe,0x4a,0xcb,0x2c,0xcd,0xb8,0x94,0xab,0xdf,0xa7,0x0e,0x30,0xaf,0x56,0x23,0xb1,
    0xb0,0x58,0x7d,0xc2,0x1d,0x50,0x20,0x61,0x25,0x89,0xa0,0x6c,0x11,0x54,0x98,0xb7,
    0x18,0x21,0xad,0x3e,0xd2,0xea,0x40,0xd6,0xf4,0xa4,0x8f,0xa8,0x08,0x57,0xba,0xee,
    0x75,0x6a,0x07,0x99,0x7f,0x1c,0xe3,0x46,0x67,0xec,0x27,0x36,0xb4,0x65,0x9e,0x9a
};

/* --- portable little-endian word helpers --------------------------------- */
static uint32_t ld32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void st32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;        p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t rotl32(uint32_t x, unsigned s) {  /* s is always 1, 14 or 17 (never 0/32) */
    return (uint32_t)((x << s) | (x >> (32 - s)));
}
static uint32_t sbox_word(uint32_t w) {
    return (uint32_t)SB[w & 0xff]            | ((uint32_t)SB[(w >> 8)  & 0xff] << 8) |
          ((uint32_t)SB[(w >> 16) & 0xff] << 16) | ((uint32_t)SB[(w >> 24) & 0xff] << 24);
}

/* --- key schedule -------------------------------------------------------- */
/* Reference Kexp specialized to klen=32, blen=16 (16 round keys). */
void qalqan_key_setup(const uint8_t key[32], qalqan_ctx *ctx) {
    uint8_t rk[16 * 16];
    uint8_t r0[17], r1[15];
    int s = 17;  /* SHIFT */

    for (int i = 0; i < 15; i++) { r0[i] = key[2 * i]; r1[i] = key[2 * i + 1]; }
    r0[15] = key[30];
    r0[16] = key[31];

    for (int r = 0; r < 16; r++) {
        for (int k = 0; k < 16 + s; k++) {
            uint8_t t0 = (uint8_t)(SB[r0[0]] + r0[1] + SB[r0[3]] + r0[7] + SB[r0[12]] + r0[16]);
            uint8_t t1 = (uint8_t)(SB[r1[0]] + r1[3] + SB[r1[9]] + r1[12] + SB[r1[14]]);
            for (int i = 0; i < 14; i++) { r0[i] = r0[i + 1]; r1[i] = r1[i + 1]; }
            r0[14] = r0[15];
            r0[15] = r0[16];
            if (k >= s) rk[r * 16 + k - s] = (uint8_t)(t0 + r1[4]);
            r0[16] = t0;
            r1[14] = t1;
        }
        s = 0;
    }

    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 4; j++)
            ctx->rk[i][j] = ld32(&rk[16 * i + 4 * j]);
}

/* --- block encryption ---------------------------------------------------- */
/* Round keys 0 and 15 are added modulo 2^128 (little-endian); keys 1..14 are XORed.
 * Each of the 15 S-box+linear rounds applies the byte S-box then the linear layer
 * (lin344 with rotation constants c = {1,17,14}). */
void qalqan_encrypt_block(const qalqan_ctx *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint32_t w0 = ld32(in), w1 = ld32(in + 4), w2 = ld32(in + 8), w3 = ld32(in + 12);
    uint64_t t;

    /* + round key 0 (mod 2^128, little-endian limb ripple) */
    t = (uint64_t)w0 + ctx->rk[0][0];                w0 = (uint32_t)t;
    t = (uint64_t)w1 + ctx->rk[0][1] + (t >> 32);    w1 = (uint32_t)t;
    t = (uint64_t)w2 + ctx->rk[0][2] + (t >> 32);    w2 = (uint32_t)t;
    t = (uint64_t)w3 + ctx->rk[0][3] + (t >> 32);    w3 = (uint32_t)t;

    for (int i = 0; i <= 14; i++) {
        if (i) {  /* rounds 1..14 XOR their round key */
            w0 ^= ctx->rk[i][0]; w1 ^= ctx->rk[i][1];
            w2 ^= ctx->rk[i][2]; w3 ^= ctx->rk[i][3];
        }
        w0 = sbox_word(w0); w1 = sbox_word(w1);
        w2 = sbox_word(w2); w3 = sbox_word(w3);

        uint32_t d0 = w0 ^ rotl32(w1, 1) ^ rotl32(w2, 17) ^ rotl32(w3, 14);
        uint32_t d1 = w1 ^ rotl32(w2, 1) ^ rotl32(w3, 17) ^ rotl32(d0, 14);
        uint32_t d2 = w2 ^ rotl32(w3, 1) ^ rotl32(d0, 17) ^ rotl32(d1, 14);
        uint32_t d3 = w3 ^ rotl32(d0, 1) ^ rotl32(d1, 17) ^ rotl32(d2, 14);
        w0 = d0; w1 = d1; w2 = d2; w3 = d3;
    }

    /* + round key 15 (mod 2^128) */
    t = (uint64_t)w0 + ctx->rk[15][0];               w0 = (uint32_t)t;
    t = (uint64_t)w1 + ctx->rk[15][1] + (t >> 32);   w1 = (uint32_t)t;
    t = (uint64_t)w2 + ctx->rk[15][2] + (t >> 32);   w2 = (uint32_t)t;
    t = (uint64_t)w3 + ctx->rk[15][3] + (t >> 32);   w3 = (uint32_t)t;

    st32(out, w0); st32(out + 4, w1); st32(out + 8, w2); st32(out + 12, w3);
}
