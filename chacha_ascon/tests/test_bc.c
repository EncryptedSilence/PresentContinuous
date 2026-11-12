/* Known-answer and cross-implementation tests for every block-cipher CTR
 * implementation (include/blockctr.h) registered in this build: AES-128-CTR,
 * AES-256-CTR and Qalqan-CTR. Runs on the x86 host, under qemu-arm for the Cortex-A7/M4 builds
 * and under AddressSanitizer (make asan-test). Exit status 0 only if every check
 * of every available implementation passes; an implementation this CPU lacks is
 * reported as skipped, never as passed.
 *
 *   1. The reference block functions against published vectors:
 *      AES-128: FIPS-197 Appendix C.1; AES-256: C.3; Qalqan: СТ РК 4009-2025 Appendix A, the
 *      QalqanSpeed anchor vector (key 00..1f, pt 00 10 .. f0) and the 8 golden
 *      vectors of QalqanSpeed arm-a7/tests/golden/qalqan_kat.txt.
 *   2. Every implementation on the same vectors THROUGH ITS CTR PATH: a block
 *      vector (pt, ct) is CTR with nonce = pt[0..11], ctr = BE32(pt[12..15]) over
 *      a zero message. Run once as a lone 16-byte block (tail path) and once as
 *      block 0 of a message of 2L+1 blocks + 3 bytes (L = the impl's lane count:
 *      the wide path). AES-128 also SP 800-38A F.5.1 (CTR-AES128.Encrypt,
 *      4 blocks, initial counter f0f1..feff: its low 32 bits fcfdfeff do not
 *      overflow in 4 blocks, so it is a 32-bit-counter vector); AES-256 likewise
 *      SP 800-38A F.5.5 (CTR-AES256.Encrypt, same counter and plaintext).
 *   3. Every implementation against a reference CTR built here on the reference
 *      block function: lengths 0, 1, 15, 16, 17, ... up to 4 KiB + 7, plus
 *      k*16L-1, k*16L, k*16L+1 (k = 1..3) and 16L + 8L + 5 for each impl's L;
 *      counters 0, 0x12345678, 0xFFFFFFF0 (wraps mid-message) and 0xFFFFFFFF;
 *      out of place, in place, misaligned out of place (in+3, out+5) and misaligned
 *      in place (offset 1..3, varying with the length). The
 *      input must be unchanged (out of place), the bytes before a misaligned
 *      output untouched, and a canary after every output intact.
 * Every buffer is its own heap allocation of exactly the size used (+ canary in
 * the normal build), so ASan catches any access past a tail. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blockctr.h"
#pragma GCC diagnostic ignored "-Wunused-function" /* kat_common.h: only kat_bytes/hex_exact used */
#include "kat_common.h"
#include "qalqan.h"

static int failures;
#define CHECK(cond, ...)                                     \
    do {                                                     \
        if (!(cond)) {                                       \
            if (failures < 30) {                             \
                printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
                printf(__VA_ARGS__);                         \
                printf("\n");                                \
            }                                                \
            failures++;                                      \
        }                                                    \
    } while (0)

#if defined(__SANITIZE_ADDRESS__)
#define CANARY 0
#else
#define CANARY 16
#endif

static uint8_t *xalloc(size_t n)
{
    if (n > ((size_t)1 << 24)) { fprintf(stderr, "allocation too large\n"); exit(2); }
    uint8_t *p = malloc(n + CANARY ? n + CANARY : 1);
    if (!p) { fprintf(stderr, "out of memory\n"); exit(2); }
    memset(p + n, 0xC5, CANARY);
    return p;
}
static int canary_ok(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < CANARY; i++)
        if (p[n + i] != 0xC5) return 0;
    return 1;
}

/* ------------------------------------------------------------ vectors */
typedef struct { const char *key, *pt, *ct; } bvec;

static const bvec aes_vecs[] = {
    /* FIPS-197 Appendix C.1 */
    {"000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"},
};
static const bvec aes256_vecs[] = {
    /* FIPS-197 Appendix C.3 */
    {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff",
     "8ea2b7ca516745bfeafc49904b496089"},
};
static const bvec qalqan_vecs[] = {
    /* СТ РК 4009-2025 Appendix A */
    {"9ac3bb84151e6a09ce75907b4decf8a985537ab78c341816179cda24b7aa69a2",
     "00000000000000000000000000000000", "c16e4eda12c31a8de78824f7c19cf945"},
    /* QalqanSpeed anchor (qalqan.c header) */
    {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "00102030405060708090a0b0c0d0e0f0", "de71b5f8646a6a5d77fdb1fa285a3889"},
    /* QalqanSpeed arm-a7/tests/golden/qalqan_kat.txt */
    {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "8a9b986c53df5ba9d52c4fa360b93480"},
    {"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "a1a2a3a4a5a6a7a8a9aaabacadaeafb0", "507ae3e1fae5021c92290137227b4c5a"},
    {"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "a2a3a4a5a6a7a8a9aaabacadaeafb0b1", "efa41383fe3ec81b987e81d89f805aa8"},
    {"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f", "a3a4a5a6a7a8a9aaabacadaeafb0b1b2", "04f9015788a5fce6a2aa3a0de8a3c58a"},
    {"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "a4a5a6a7a8a9aaabacadaeafb0b1b2b3", "651f9729db6570ff7efff288ed30b455"},
    {"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "a5a6a7a8a9aaabacadaeafb0b1b2b3b4", "c9547fb2ed03e1de7d470cb13f3aef90"},
    {"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf", "a6a7a8a9aaabacadaeafb0b1b2b3b4b5", "fbf37cbd7eecd6ee3dacc15f11b5146d"},
    {"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "a7a8a9aaabacadaeafb0b1b2b3b4b5b6", "383cd1957aa155f1e92a419a76828ae2"},
};
#define NVEC(a) (sizeof(a) / sizeof((a)[0]))

/* NIST SP 800-38A F.5.1 CTR-AES128.Encrypt */
static const char *sp_key = "2b7e151628aed2a6abf7158809cf4f3c";
static const char *sp_ctr = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
/* SP 800-38A F.5.5 CTR-AES256.Encrypt (counter and plaintext as F.5.1) */
static const char *sp256_key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
static const char *sp256_ct = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
                              "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6";

/* cipher kinds: 0 = AES-128, 1 = Qalqan, 2 = AES-256 */
enum { K_AES128, K_QALQAN, K_AES256 };
static const char *const kind_name[] = {"aes128", "qalqan", "aes256"};
static const bvec *kind_vecs(int k, size_t *n)
{
    if (k == K_QALQAN) { *n = NVEC(qalqan_vecs); return qalqan_vecs; }
    if (k == K_AES256) { *n = NVEC(aes256_vecs); return aes256_vecs; }
    *n = NVEC(aes_vecs);
    return aes_vecs;
}
static unsigned kind_keylen(int k) { return k == K_AES128 ? 16u : 32u; }
static const char *sp_pt = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                           "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
static const char *sp_ct = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
                           "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee";

/* ------------------------------------------------- reference CTR (oracle) */
typedef struct { int kind; aes128_ctx aes; aes256_ctx a256; qalqan_ctx q; } oracle;

static void oracle_setup(oracle *o, int kind, const uint8_t *key)
{
    o->kind = kind;
    if (kind == K_QALQAN) qalqan_key_setup(key, &o->q);
    else if (kind == K_AES256) aes256_key_expand(&o->a256, key);
    else aes128_key_expand(&o->aes, key);
}
static void oracle_block(const oracle *o, const uint8_t in[16], uint8_t out[16])
{
    if (o->kind == K_QALQAN) qalqan_encrypt_block(&o->q, in, out);
    else if (o->kind == K_AES256) aes256_encrypt_block_ref(&o->a256, in, out);
    else aes128_encrypt_block_ref(&o->aes, in, out);
}
static void oracle_ctr(const oracle *o, uint8_t *out, const uint8_t *in, size_t len, const uint8_t nonce[12], uint32_t ctr)
{
    uint8_t blk[16], ks[16];
    for (size_t j = 0; j * 16 < len; j++) {
        bc_counter_block(blk, nonce, ctr + (uint32_t)j);
        oracle_block(o, blk, ks);
        for (size_t i = 0; i < 16 && j * 16 + i < len; i++) out[j * 16 + i] = (uint8_t)(in[j * 16 + i] ^ ks[i]);
    }
}

static void *ctx_new(const bc_impl *im, const uint8_t *key)
{
    size_t sz = (im->ctx_size + BC_CTX_ALIGN - 1) / BC_CTX_ALIGN * BC_CTX_ALIGN;
    void *c = aligned_alloc(BC_CTX_ALIGN, sz);
    if (!c) { fprintf(stderr, "out of memory\n"); exit(2); }
    im->setup(c, key);
    return c;
}

/* ------------------------------------------------------------ 1. block KATs */
static void ref_block_kats(void)
{
    for (int q = 0; q < 3; q++) {
        size_t nv;
        const bvec *v = kind_vecs(q, &nv);
        for (size_t i = 0; i < nv; i++) {
            uint8_t key[32], pt[16], ct[16], out[16];
            oracle o;
            hex_exact(v[i].key, key, kind_keylen(q));
            hex_exact(v[i].pt, pt, 16);
            hex_exact(v[i].ct, ct, 16);
            oracle_setup(&o, q, key);
            oracle_block(&o, pt, out);
            CHECK(!memcmp(out, ct, 16), "%s reference block KAT #%lu", kind_name[q], (unsigned long)i);
        }
    }
}

/* ---------------------------------------------- 2. KATs through the CTR path */
static void impl_kats(const bc_impl *im, int q)
{
    size_t nv;
    const bvec *v = kind_vecs(q, &nv);
    size_t big = 16 * (2 * (size_t)im->lanes + 1) + 3;
    for (size_t i = 0; i < nv; i++) {
        uint8_t key[32], pt[16], ct[16];
        hex_exact(v[i].key, key, im->key_len);
        hex_exact(v[i].pt, pt, 16);
        hex_exact(v[i].ct, ct, 16);
        void *ctx = ctx_new(im, key);
        uint32_t ctr = (uint32_t)pt[12] << 24 | (uint32_t)pt[13] << 16 | (uint32_t)pt[14] << 8 | pt[15];
        for (int pass = 0; pass < 2; pass++) {
            size_t n = pass ? big : 16;
            uint8_t *zero = xalloc(n), *out = xalloc(n);
            memset(zero, 0, n);
            im->xor_fn(ctx, out, zero, n, pt, ctr);
            CHECK(!memcmp(out, ct, 16), "%s/%s: KAT #%lu through CTR, len %lu", im->cipher, im->name, (unsigned long)i, (unsigned long)n);
            CHECK(canary_ok(out, n), "%s/%s: KAT write past end", im->cipher, im->name);
            free(zero);
            free(out);
        }
        free(ctx);
    }
    if (q != K_QALQAN) {
        uint8_t key[32], cb[16], pt[64], ct[64];
        hex_exact(q == K_AES256 ? sp256_key : sp_key, key, kind_keylen(q));
        hex_exact(sp_ctr, cb, 16);
        hex_exact(sp_pt, pt, 64);
        hex_exact(q == K_AES256 ? sp256_ct : sp_ct, ct, 64);
        void *ctx = ctx_new(im, key);
        uint32_t ctr = (uint32_t)cb[12] << 24 | (uint32_t)cb[13] << 16 | (uint32_t)cb[14] << 8 | cb[15];
        uint8_t *in = xalloc(64), *out = xalloc(64);
        memcpy(in, pt, 64);
        im->xor_fn(ctx, out, in, 64, cb, ctr);
        CHECK(!memcmp(out, ct, 64) && canary_ok(out, 64), "%s/%s: SP 800-38A F.5.1/F.5.5", im->cipher, im->name);
        im->xor_fn(ctx, in, in, 64, cb, ctr); /* in place */
        CHECK(!memcmp(in, ct, 64) && canary_ok(in, 64), "%s/%s: SP 800-38A F.5.1/F.5.5 in place", im->cipher, im->name);
        free(in);
        free(out);
        free(ctx);
    }
}

/* -------------------------------------------- 3. against the reference CTR */
static void impl_vs_oracle(const bc_impl *im, int q, int *runs)
{
    static const size_t fixed[] = {0, 1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 100, 127, 128, 129,
                                   255, 256, 257, 383, 384, 385, 511, 512, 513, 1000, 1024, 4096, 4103};
    static const uint32_t ctrs[] = {0, 0x12345678u, 0xFFFFFFF0u, 0xFFFFFFFFu};
    size_t lens[64], nl = 0;
    for (size_t i = 0; i < NVEC(fixed); i++) lens[nl++] = fixed[i];
    size_t L16 = 16 * (size_t)im->lanes;
    for (size_t k = 1; k <= 3; k++) {
        lens[nl++] = k * L16 - 1;
        lens[nl++] = k * L16;
        lens[nl++] = k * L16 + 1;
    }
    lens[nl++] = L16 + L16 / 2 + 5;

    uint8_t key[32], nonce[12];
    kat_bytes(0xB10C0000u + (uint32_t)q, key, 32);
    void *ctx = ctx_new(im, key);
    oracle o;
    oracle_setup(&o, q, key);
    for (size_t li = 0; li < nl; li++) {
        size_t n = lens[li];
        if (n > 65536) { fprintf(stderr, "length table\n"); exit(2); }
        uint8_t *pt = xalloc(n), *want = xalloc(n);
        kat_bytes(0x5EED0000u + (uint32_t)n, pt, n);
        for (size_t ci = 0; ci < NVEC(ctrs); ci++) {
            kat_bytes(0xA0A00000u + (uint32_t)(li * 8 + ci), nonce, 12);
            oracle_ctr(&o, want, pt, n, nonce, ctrs[ci]);
            for (int mode = 0; mode < 4; mode++) {
                uint8_t *in, *out, *alloc_in = NULL, *alloc_out;
                size_t out_off = 0;
                if (mode == 0) {
                    alloc_in = xalloc(n);
                    memcpy(alloc_in, pt, n);
                    in = alloc_in;
                    out = alloc_out = xalloc(n);
                } else if (mode == 1) {
                    alloc_out = xalloc(n);
                    memcpy(alloc_out, pt, n);
                    in = out = alloc_out;
                } else if (mode == 3) {
                    /* in place at a misaligned address, offset 1..3 varying with len */
                    out_off = 1 + n % 3;
                    alloc_out = xalloc(n + out_off);
                    memset(alloc_out, 0x3C, out_off);
                    memcpy(alloc_out + out_off, pt, n);
                    in = out = alloc_out + out_off;
                } else {
                    alloc_in = xalloc(n + 3);
                    memcpy(alloc_in + 3, pt, n);
                    in = alloc_in + 3;
                    out_off = 5;
                    alloc_out = xalloc(n + 5);
                    memset(alloc_out, 0x3C, 5);
                    out = alloc_out + 5;
                }
                im->xor_fn(ctx, out, in, n, nonce, ctrs[ci]);
                CHECK(!memcmp(out, want, n), "%s/%s: vs reference CTR len %lu ctr %08x mode %d",
                      im->cipher, im->name, (unsigned long)n, (unsigned)ctrs[ci], mode);
                CHECK(canary_ok(alloc_out, n + out_off), "%s/%s: write past end len %lu ctr %08x mode %d",
                      im->cipher, im->name, (unsigned long)n, (unsigned)ctrs[ci], mode);
                if (mode == 0) CHECK(!memcmp(in, pt, n), "%s/%s: input modified len %lu", im->cipher, im->name, (unsigned long)n);
                if (mode == 2)
                    CHECK(!memcmp(in, pt, n), "%s/%s: input modified len %lu (misaligned)", im->cipher, im->name, (unsigned long)n);
                if (mode >= 2) {
                    int pre = 1;
                    for (size_t i = 0; i < out_off; i++) pre &= alloc_out[i] == 0x3C;
                    CHECK(pre, "%s/%s: write before output len %lu", im->cipher, im->name, (unsigned long)n);
                }
                free(alloc_out);
                free(alloc_in);
                (*runs)++;
            }
        }
        free(pt);
        free(want);
    }
    free(ctx);
}

int main(void)
{
    int tested = 0, skipped = 0;
    ref_block_kats();
    printf("reference block functions: %s (AES-128 %lu, AES-256 %lu, Qalqan %lu vectors)\n", failures ? "FAILED" : "ok",
           (unsigned long)NVEC(aes_vecs), (unsigned long)NVEC(aes256_vecs), (unsigned long)NVEC(qalqan_vecs));
    for (const bc_impl *im = bc_impls; im->name; im++) {
        if (im->available && !im->available()) {
            printf("%-10s %-16s SKIPPED (not available)\n", im->cipher, im->name);
            skipped++;
            continue;
        }
        int q = !strcmp(im->cipher, "qalqan-ctr") ? K_QALQAN : !strcmp(im->cipher, "aes256-ctr") ? K_AES256 : K_AES128;
        CHECK(q != K_AES128 || !strcmp(im->cipher, "aes128-ctr"), "unknown cipher %s", im->cipher);
        CHECK(im->key_len == kind_keylen(q), "%s/%s key_len", im->cipher, im->name);
        int before = failures, runs = 0;
        impl_kats(im, q);
        impl_vs_oracle(im, q, &runs);
        printf("%-10s %-16s L=%-2u %s (%d CTR runs vs reference)\n", im->cipher, im->name, im->lanes,
               failures == before ? "ok" : "FAILED", runs);
        fflush(stdout);
        tested++;
    }
    printf("%d block-cipher CTR implementations tested, %d skipped, %d failures\n", tested, skipped, failures);
    return failures ? 1 : 0;
}
