/* Test vectors for the full-round FPGA cores (chacha_ascon/fpga/rtl), produced by the
 * KAT-verified host reference implementations:
 *   AES-128/256-CTR, Qalqan-CTR   aes128_ctr_ref / aes256_ctr_ref / qalqan_ctr_ref
 *                                  (include/blockctr.h: block j = nonce[0..11] || BE32(ctr+j))
 *   ChaCha20                       chacha20_xor_ref (RFC 8439, 32-bit block counter)
 *   Ascon-AEAD128                  ascon-c ref (SP 800-232), with tag
 *   PRESENT-80/31-CTR              present_encrypt_ref, block j = BE64(ctr + j) (bench/ctr_backend.h)
 *
 * Output: one file per cipher in the directory given as argv[1], whitespace-separated hex
 * tokens read by the testbenches with $fscanf("%h"). Every multi-byte value is written
 * in memory byte order, first byte = most significant hex digits.
 *
 * Block-cipher / ChaCha20 files:  ncases, then per case
 *     key  nonce  ctr0  nblk  ks[0] .. ks[nblk-1]          (ks = keystream block)
 * Ascon file:  ncases, then per case
 *     key  nonce  adlen  mlen  ad-blocks  m-blocks  c-blocks  tag
 *   (16-byte blocks, the last one zero-padded at its end; ceil(len/16) of each) */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdalign.h>
#include <string.h>

#include "blockctr.h"
#include "chacha20.h"
#include "present/present.h"

void aes128_setup_ref(void *, const uint8_t *);
void aes128_ctr_ref(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);
void aes256_setup_ref(void *, const uint8_t *);
void aes256_ctr_ref(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);
void qalqan_setup_ref(void *, const uint8_t *);
void qalqan_ctr_ref(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);
int ascon_c_ref_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m,
                        unsigned long long mlen, const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);

static uint64_t rng = 0x243f6a8885a308d3ull;
static uint8_t rnd8(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return (uint8_t)(rng >> 24);
}
static void rnd(uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) p[i] = rnd8(); }

static void hex(FILE *f, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", p[i]);
    fputc('\n', f);
}
static void hexu(FILE *f, uint64_t v, int bytes) /* bytes <= 8 */
{
    uint8_t b[8];
    for (int i = 0; i < bytes; i++) b[i] = (uint8_t)(v >> (8 * (bytes - 1 - i)));
    hex(f, b, bytes);
}
static FILE *open_out(const char *dir, const char *name)
{
    char p[1024];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE *f = fopen(p, "w");
    if (!f) { perror(p); exit(1); }
    return f;
}

enum { NBLK = 40 };
typedef void (*setup_fn)(void *, const uint8_t *);
typedef void (*ctr_fn)(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);

/* 16-byte-block CTR ciphers. Case 0 is the block KAT run through CTR: nonce||ctr = the
 * KAT plaintext, so keystream block 0 = E_K(pt). */
static void bc_file(const char *dir, const char *name, int keylen, setup_fn setup, ctr_fn ctr,
                    const uint8_t *kat_key, const uint8_t *kat_pt)
{
    FILE *f = open_out(dir, name);
    static const uint32_t ctrs[] = {0, 0xffffffe0u /* wraps mod 2^32 inside the run */, 0x12345678u, 7};
    const int nc = 1 + 4;
    fprintf(f, "%x\n", nc);
    alignas(64) static uint8_t ctx[4096];
    uint8_t key[32], nonce[12], zero[16 * NBLK], ks[16 * NBLK];
    memset(zero, 0, sizeof zero);
    for (int c = 0; c < nc; c++) {
        uint32_t c0;
        if (c == 0) {
            memcpy(key, kat_key, keylen);
            memcpy(nonce, kat_pt, 12);
            c0 = (uint32_t)kat_pt[12] << 24 | kat_pt[13] << 16 | kat_pt[14] << 8 | kat_pt[15];
        } else {
            rnd(key, keylen); rnd(nonce, 12); c0 = ctrs[c - 1];
        }
        setup(ctx, key);
        ctr(ctx, ks, zero, sizeof ks, nonce, c0);
        hex(f, key, keylen);
        hex(f, nonce, 12);
        hexu(f, c0, 4);
        fprintf(f, "%x\n", NBLK);
        for (int j = 0; j < NBLK; j++) hex(f, ks + 16 * j, 16);
    }
    fclose(f);
}

static void chacha_file(const char *dir)
{
    FILE *f = open_out(dir, "chacha20.vec");
    static const uint32_t ctrs[] = {1, 0, 0xfffffff0u, 0x01020304u};
    const int nc = 4;
    fprintf(f, "%x\n", nc);
    uint8_t key[32], nonce[12], zero[64 * NBLK], ks[64 * NBLK];
    memset(zero, 0, sizeof zero);
    for (int c = 0; c < nc; c++) {
        if (c == 0) {  /* RFC 8439 2.4.2 key and nonce */
            for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
            static const uint8_t n[12] = {0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0};
            memcpy(nonce, n, 12);
        } else {
            rnd(key, 32); rnd(nonce, 12);
        }
        chacha20_xor_ref(ks, zero, sizeof ks, key, nonce, ctrs[c]);
        hex(f, key, 32);
        hex(f, nonce, 12);
        hexu(f, ctrs[c], 4);
        fprintf(f, "%x\n", NBLK);
        for (int j = 0; j < NBLK; j++) hex(f, ks + 64 * j, 64);
    }
    fclose(f);
}

static void present_file(const char *dir)
{
    FILE *f = open_out(dir, "present80.vec");
    const present_variant_t *v = present_variant_by_name("present-80");
    if (!v || v->rounds != 31) { fprintf(stderr, "present-80 variant missing\n"); exit(1); }
    static const uint64_t ctrs[] = {0, 0xffffffffffffffe0ull, 0x00000000ffffffecull, 0x0123456789abcdefull};
    const int nc = 5;
    fprintf(f, "%x\n", nc);
    for (int c = 0; c < nc; c++) {
        uint8_t key[10];
        uint64_t c0;
        present_ctx_t ctx;
        if (c == 0) { memset(key, 0, 10); c0 = 0; } /* paper vector: E_0(0) = 5579c1387b228445 */
        else { rnd(key, 10); c0 = ctrs[c - 1]; }
        if (present_init(&ctx, v, key, 10)) { fprintf(stderr, "present_init\n"); exit(1); }
        hex(f, key, 10);
        static const uint8_t no_nonce[12];  /* the whole 64-bit block is the counter */
        hex(f, no_nonce, 12);
        hexu(f, c0, 8);
        fprintf(f, "%x\n", NBLK);
        for (int j = 0; j < NBLK; j++) hexu(f, present_encrypt_ref(&ctx, c0 + (uint64_t)j), 8);
    }
    fclose(f);
}

static void ascon_file(const char *dir)
{
    FILE *f = open_out(dir, "ascon128.vec");
    static const struct { unsigned ad, m; } lens[] = {
        {0, 0}, {0, 1}, {0, 15}, {0, 16}, {0, 17}, {0, 64}, {0, 100}, {1, 0}, {16, 16},
        {7, 33}, {31, 48}, {48, 5}, {0, 1024}};
    const int nc = sizeof lens / sizeof lens[0];
    fprintf(f, "%x\n", nc);
    for (int c = 0; c < nc; c++) {
        unsigned al = lens[c].ad, ml = lens[c].m;
        uint8_t key[16], nonce[16], *ad = calloc(al + 16, 1), *m = calloc(ml + 16, 1), *ct = calloc(ml + 32, 1);
        if (c == 0) { for (int i = 0; i < 16; i++) key[i] = (uint8_t)i, nonce[i] = (uint8_t)i; } /* LWC KAT Count 1 */
        else { rnd(key, 16); rnd(nonce, 16); }
        rnd(ad, al); rnd(m, ml);
        unsigned long long clen;
        ascon_c_ref_encrypt(ct, &clen, m, ml, ad, al, NULL, nonce, key);
        uint8_t tag[16];
        memcpy(tag, ct + ml, 16);
        memset(ct + ml, 0, 16);  /* zero padding of the last ciphertext block */
        hex(f, key, 16);
        hex(f, nonce, 16);
        fprintf(f, "%x\n%x\n", al, ml);
        for (unsigned o = 0; o < al; o += 16) hex(f, ad + o, 16);
        for (unsigned o = 0; o < ml; o += 16) hex(f, m + o, 16);
        for (unsigned o = 0; o < ml; o += 16) hex(f, ct + o, 16);
        hex(f, tag, 16);
        free(ad); free(m); free(ct);
    }
    fclose(f);
}

static void unhex(const char *h, uint8_t *o) { for (size_t i = 0; i < strlen(h) / 2; i++) sscanf(h + 2 * i, "%2hhx", &o[i]); }

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s OUTDIR\n", argv[0]); return 2; }
    uint8_t k[32], pt[16];
    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", k);
    unhex("00112233445566778899aabbccddeeff", pt);
    bc_file(argv[1], "aes128.vec", 16, aes128_setup_ref, aes128_ctr_ref, k, pt); /* FIPS-197 C.1 */
    bc_file(argv[1], "aes256.vec", 32, aes256_setup_ref, aes256_ctr_ref, k, pt); /* FIPS-197 C.3 */
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(16 * i);                        /* Qalqan sample */
    bc_file(argv[1], "qalqan.vec", 32, qalqan_setup_ref, qalqan_ctr_ref, k, pt);
    chacha_file(argv[1]);
    present_file(argv[1]);
    ascon_file(argv[1]);
    printf("vectors written to %s\n", argv[1]);
    return 0;
}
