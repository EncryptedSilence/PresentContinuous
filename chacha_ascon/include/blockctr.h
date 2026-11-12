/* 128-bit block ciphers in counter mode: AES-128, AES-256 (FIPS-197) and Qalqan-256/128
 * (СТ РК 4009-2025). One contract for every implementation on every platform:
 *
 *   counter block j = nonce[0..11] || BE32(ctr + j mod 2^32)   (SP 800-38A / GCM layout)
 *   out[i] = in[i] ^ E_K(counter block floor(i/16))[i mod 16],  i < len
 *
 * Any len (partial final block allowed); out == in allowed, partial overlap not.
 * The 32-bit counter wraps mod 2^32 and never carries into the nonce.
 *
 * Key expansion is separate from the (timed) xor operation: setup() turns the key
 * into an implementation-specific context of ctx_size bytes, which the caller
 * provides 64-byte aligned (BC_CTX_ALIGN). xor_fn() only reads the context.
 *
 * Qalqan maps a 16-byte block to four little-endian 32-bit words, as the
 * reference does (src/qalqan/qalqan.c); the counter block is built as bytes per
 * the contract above and loaded that way. */
#ifndef CA_BLOCKCTR_H
#define CA_BLOCKCTR_H
#include <stddef.h>
#include <stdint.h>

#define BC_CTX_ALIGN 64

typedef void (*bc_setup_fn)(void *ctx, const uint8_t *key);
typedef void (*bc_xor_fn)(const void *ctx, uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t nonce[12], uint32_t ctr);

typedef struct {
    const char *cipher;     /* "aes128-ctr", "aes256-ctr" or "qalqan-ctr" */
    const char *name;       /* "ref", "aesni-x8", "gfni-x16", ... */
    unsigned lanes;         /* 16-byte blocks per inner iteration */
    unsigned key_len;       /* 16 (AES-128) or 32 (AES-256, Qalqan) */
    size_t ctx_size;
    bc_setup_fn setup;
    bc_xor_fn xor_fn;
    int (*available)(void); /* NULL = always */
} bc_impl;

/* Registry for this build (x86 or ARM), NULL-terminated by name. */
extern const bc_impl bc_impls[];

/* ---- portable reference pieces (src/aes/aes128_ref.c, src/qalqan/) ---- */
typedef struct { uint8_t rk[11][16]; } aes128_ctx; /* FIPS-197 w[0..43] as bytes */
typedef struct { uint32_t rk[44]; } aes128_tt_ctx;  /* the same, as little-endian words */
void aes128_key_expand(aes128_ctx *ctx, const uint8_t key[16]);
void aes128_encrypt_block_ref(const aes128_ctx *ctx, const uint8_t in[16], uint8_t out[16]);
typedef struct { uint8_t rk[15][16]; } aes256_ctx; /* FIPS-197 w[0..59] as bytes */
void aes256_key_expand(aes256_ctx *ctx, const uint8_t key[32]);
void aes256_encrypt_block_ref(const aes256_ctx *ctx, const uint8_t in[16], uint8_t out[16]);

/* The counter block for block index j (relative to ctr). */
static inline void bc_counter_block(uint8_t blk[16], const uint8_t nonce[12], uint32_t ctr)
{
    for (int i = 0; i < 12; i++) blk[i] = nonce[i];
    blk[12] = (uint8_t)(ctr >> 24);
    blk[13] = (uint8_t)(ctr >> 16);
    blk[14] = (uint8_t)(ctr >> 8);
    blk[15] = (uint8_t)ctr;
}
#endif
