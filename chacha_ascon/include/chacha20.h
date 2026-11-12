/* ChaCha20 as specified in RFC 8439: 256-bit key, 96-bit nonce, 32-bit block
 * counter, 20 rounds. Every implementation exposes the same operation:
 *
 *   out[i] = in[i] ^ keystream[i], i < len, keystream starting at block `counter`.
 *
 * out == in is allowed (the benchmark encrypts in place); partial overlap is not.
 * len may be anything, but the caller must keep counter + ceil(len/64) <= 2^32:
 * RFC 8439 forbids the 32-bit counter from wrapping, and no implementation here
 * carries it into the nonce word. */
#ifndef CA_CHACHA20_H
#define CA_CHACHA20_H
#include <stddef.h>
#include <stdint.h>

typedef void (*chacha20_xor_fn)(uint8_t *out, const uint8_t *in, size_t len,
                                const uint8_t key[32], const uint8_t nonce[12],
                                uint32_t counter);

typedef struct {
    const char *name;        /* "ref", "avx2-x8", ... */
    chacha20_xor_fn xor_fn;
    int (*available)(void);  /* NULL = always */
    unsigned lanes;          /* 64-byte blocks computed per inner iteration */
} chacha20_impl;

/* The one-block function every wide implementation falls back to for its tail. */
void chacha20_block_ref(uint32_t out[16], const uint32_t in[16]);
void chacha20_xor_ref(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);

/* Registry for this build (x86 or ARM), NULL-terminated by name. */
extern const chacha20_impl chacha20_impls[];
#endif
