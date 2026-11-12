/* Ascon-AEAD128 (NIST SP 800-232): 128-bit key, 128-bit nonce, 128-bit tag,
 * 16-byte rate, p^12 for initialisation/finalisation and p^8 per data block.
 *
 * Single-stream interface: the eBACS crypto_aead_encrypt shape every ascon-c
 * implementation already has, so they can be benchmarked unmodified --
 *   c[0 .. mlen+16) = ciphertext || tag.
 * c == m (in place) is tested for every implementation before it is benchmarked.
 *
 * Multi-stream interface: `n` independent messages of the same length, each with
 * its own key, nonce, associated data and output. This is the operation a SIMD
 * or GPU implementation of a sequential (duplex) mode actually accelerates: one
 * Ascon message cannot be parallelised, many can. */
#ifndef CA_ASCON_AEAD_H
#define CA_ASCON_AEAD_H
#include <stddef.h>
#include <stdint.h>

typedef int (*ascon_enc_fn)(unsigned char *c, unsigned long long *clen,
                            const unsigned char *m, unsigned long long mlen,
                            const unsigned char *ad, unsigned long long adlen,
                            const unsigned char *nsec, const unsigned char *npub,
                            const unsigned char *k);
typedef int (*ascon_dec_fn)(unsigned char *m, unsigned long long *mlen,
                            unsigned char *nsec, const unsigned char *c,
                            unsigned long long clen, const unsigned char *ad,
                            unsigned long long adlen, const unsigned char *npub,
                            const unsigned char *k);

typedef struct {
    uint8_t *c;            /* mlen + 16 bytes: ciphertext || tag */
    const uint8_t *m;
    const uint8_t *ad;
    const uint8_t *nonce;  /* 16 bytes */
    const uint8_t *key;    /* 16 bytes */
} ascon_job;

typedef void (*ascon_multi_fn)(const ascon_job *jobs, size_t n, size_t mlen, size_t adlen);

typedef struct {
    const char *name;      /* "ascon-c/opt64", "avx2-x4", ... */
    ascon_enc_fn enc;      /* single-stream; NULL for multi-only */
    ascon_dec_fn dec;      /* NULL if not provided */
    ascon_multi_fn multi;  /* NULL for single-only */
    int (*available)(void);
    unsigned lanes;        /* messages processed together by `multi` */
} ascon_impl;

extern const ascon_impl ascon_impls[];

/* Drive a single-stream implementation over a job list -- the baseline the
 * multi-stream paths are compared against. */
void ascon_multi_by_single(ascon_enc_fn enc, const ascon_job *jobs, size_t n,
                           size_t mlen, size_t adlen);
#endif
