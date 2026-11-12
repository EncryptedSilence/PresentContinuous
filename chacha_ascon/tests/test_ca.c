/* Known-answer and cross-implementation tests for every ChaCha20 and Ascon-AEAD128
 * implementation registered in this build. Runs unchanged on the x86 host, under
 * qemu-arm for the Cortex-A7 and Cortex-M4 builds, and under AddressSanitizer
 * (make asan-test). Exit status 0 only if every check of every available
 * implementation passes; an implementation not available on this CPU is reported
 * as skipped, never as passed.
 *
 * ChaCha20:
 *   - RFC 8439 2.4.2 (the 114-byte "sunscreen" encryption) and A.1 vectors 1-2;
 *   - 206 long vectors (0..65536 bytes, counters up to just below 2^32) from the
 *     `cryptography` oracle, each run out of place, in place, and misaligned.
 * Ascon-AEAD128:
 *   - all 1089 NIST SP 800-232 KAT vectors: encrypt, in-place encrypt, decrypt
 *     (when provided) and rejection of a one-bit tag forgery;
 *   - 346 long vectors (to 64 KiB, with and without AD) from pyascon;
 *   - every multi-stream impl on BOTH vector sets, at job counts 1, L, L+1 and
 *     2L+1 (L = its lane count) so full groups and every remainder path run, lane 0
 *     carrying the KAT vector and the other lanes distinct inputs checked against a
 *     single-stream impl that already passed the KATs.
 *
 * Every input and output lives in its own heap allocation of exactly the size the
 * contract allows (ciphertext||tag for Ascon), so an ASan build catches any read or
 * write past a tail; in the normal build each output is followed by a canary that
 * is checked after every call. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ascon_aead.h"
#include "chacha20.h"
#include "kat_common.h"

extern const unsigned long kat_chacha20_long_len, kat_ascon_long_len, kat_ascon_lwc_len;
extern const unsigned char kat_chacha20_long[], kat_ascon_long[], kat_ascon_lwc[];

static int failures;

/* KAT_MAX_LEN: the on-board Cortex-M4 build (128 KiB SRAM) cannot hold the buffers
 * of the 8 KiB..64 KiB long vectors, so it sets a cap; long vectors with a longer
 * message are counted (the record count check still covers them) and reported as
 * skipped, never as passed. Every other build runs everything. */
#ifdef KAT_MAX_LEN
static int len_skipped;
#endif
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

/* Canary: CANARY bytes of 0xC5 after every output, unless the ASan build, where the
 * allocation is exact and ASan's redzone does the job. */
#if defined(__SANITIZE_ADDRESS__)
#define CANARY 0
#else
#define CANARY 16
#endif

static uint8_t *xalloc(size_t n)
{
    /* Exactly n (+ canary) bytes, so under ASan p[n] is already out of bounds;
     * n == 0 still gets a unique non-NULL pointer of size 1 that is never touched. */
    size_t sz = n + CANARY;
    if (sz < n) { fprintf(stderr, "allocation size overflow\n"); exit(2); }
    uint8_t *p = malloc(sz ? sz : 1);
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

static kat_src src(const unsigned char *p, unsigned long n)
{
    kat_src s = {(const char *)p, (const char *)p + n};
    return s;
}

/* ---------------------------------------------------------------- ChaCha20 */

static int chacha_rfc(const chacha20_impl *im)
{
    int before = failures;
    static const char pt[] = "Ladies and Gentlemen of the class of '99: If I could offer you "
                             "only one tip for the future, sunscreen would be it.";
    static const uint8_t ct_head[16] = {0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
                                        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81};
    static const uint8_t ct_tail[2] = {0x87, 0x4d};
    uint8_t key[32], nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    size_t n = sizeof pt - 1; /* 114 */
    uint8_t *out = xalloc(1024), *zero = xalloc(1024);
    im->xor_fn(out, (const uint8_t *)pt, n, key, nonce, 1);
    CHECK(!memcmp(out, ct_head, 16) && !memcmp(out + n - 2, ct_tail, 2), "%s: RFC 8439 2.4.2", im->name);
    static const uint8_t ks1[16] = {0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
                                    0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28};
    static const uint8_t ks2[16] = {0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
                                    0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d};
    memset(key, 0, 32);
    memset(nonce, 0, 12);
    memset(zero, 0, 1024);
    im->xor_fn(out, zero, 1024, key, nonce, 0);
    CHECK(!memcmp(out, ks1, 16), "%s: RFC 8439 A.1 #1", im->name);
    CHECK(!memcmp(out + 64, ks2, 16), "%s: RFC 8439 A.1 #2", im->name);
    CHECK(canary_ok(out, 1024), "%s: RFC write past end", im->name);
    free(out);
    free(zero);
    return failures == before;
}

static int chacha_long(const chacha20_impl *im)
{
    int before = failures, count = 0;
    kat_src s = src(kat_chacha20_long, kat_chacha20_long_len);
    kat_rec r;
    while (kat_next(&s, &r)) {
        uint8_t key[32], nonce[12];
        hex_exact(kat_get(&r, "Key"), key, 32);
        hex_exact(kat_get(&r, "Nonce"), nonce, 12);
        uint32_t ctr = kat_u32(kat_get(&r, "Counter"));
        uint32_t seed = kat_u32(kat_get(&r, "Seed"));
        size_t n = kat_size(kat_get(&r, "Len"));
#ifdef KAT_MAX_LEN
        if (n > KAT_MAX_LEN) { len_skipped++; count++; kat_free(&r); continue; }
#endif
        const char *cth = kat_get(&r, "CT"), *ctf = kat_get(&r, "CTFNV");
        CHECK(!!cth != !!ctf, "chacha KAT Count=%s: exactly one of CT/CTFNV", kat_get(&r, "Count"));
        uint8_t *want = xalloc(n);
        if (cth) CHECK(hex2bin(cth, want, n) == n, "chacha KAT Count=%s: CT length", kat_get(&r, "Count"));
        uint64_t want_fnv = ctf ? kat_num(ctf, 16) : 0;
        uint8_t *pt = xalloc(n);
        kat_bytes(seed, pt, n);
        /* three placements: out of place, in place, misaligned (by 3) out of place */
        for (int mode = 0; mode < 3; mode++) {
            uint8_t *in, *out, *alloc_in = NULL, *alloc_out;
            if (mode == 1) {
                alloc_out = xalloc(n);
                memcpy(alloc_out, pt, n);
                in = out = alloc_out;
            } else if (mode == 0) {
                in = pt;
                out = alloc_out = xalloc(n);
            } else {
                alloc_in = xalloc(n + 3);
                memcpy(alloc_in + 3, pt, n);
                in = alloc_in + 3;
                alloc_out = xalloc(n + 5);
                out = alloc_out + 5;
            }
            im->xor_fn(out, in, n, key, nonce, ctr);
            int ok = cth ? !memcmp(out, want, n) : fnv1a64(out, n) == want_fnv;
            CHECK(ok, "%s: long KAT Count=%s Len=%zu mode=%d", im->name, kat_get(&r, "Count"), n, mode);
            CHECK(canary_ok(alloc_out, n + (mode == 2 ? 5 : 0)), "%s: write past end Len=%zu mode=%d", im->name, n, mode);
            free(alloc_out);
            free(alloc_in);
        }
        free(pt);
        free(want);
        count++;
        kat_free(&r);
    }
    CHECK(count == 206, "chacha long KAT count %d", count);
    return failures == before;
}

/* ------------------------------------------------------------------- Ascon */

/* One Ascon vector, from either file: inputs plus expected ct||tag (full bytes, or
 * a digest of the ciphertext with the tag in full). */
typedef struct {
    uint8_t key[16], nonce[16], tag[16];
    uint8_t *pt, *ad, *ct; /* exact-size heap copies; ct NULL when only a digest */
    size_t n, an;
    uint64_t ct_fnv;
    const char *count;
} avec;

static int avec_from_lwc(const kat_rec *r, avec *v)
{
    hex_exact(kat_get(r, "Key"), v->key, 16);
    hex_exact(kat_get(r, "Nonce"), v->nonce, 16);
    uint8_t tmp[128];
    v->n = hex2bin(kat_get(r, "PT"), tmp, sizeof tmp);
    v->pt = xalloc(v->n);
    memcpy(v->pt, tmp, v->n);
    v->an = hex2bin(kat_get(r, "AD"), tmp, sizeof tmp);
    v->ad = xalloc(v->an);
    memcpy(v->ad, tmp, v->an);
    size_t cn = hex2bin(kat_get(r, "CT"), tmp, sizeof tmp);
    if (cn != v->n + 16) { fprintf(stderr, "LWC KAT Count=%s: CT length\n", kat_get(r, "Count")); exit(2); }
    v->ct = xalloc(v->n);
    memcpy(v->ct, tmp, v->n);
    memcpy(v->tag, tmp + v->n, 16);
    v->count = kat_get(r, "Count");
    return 1;
}

static int avec_from_long(const kat_rec *r, avec *v)
{
    hex_exact(kat_get(r, "Key"), v->key, 16);
    hex_exact(kat_get(r, "Nonce"), v->nonce, 16);
    hex_exact(kat_get(r, "Tag"), v->tag, 16);
    uint32_t seed = kat_u32(kat_get(r, "Seed"));
    v->n = kat_size(kat_get(r, "Len"));
    v->an = kat_size(kat_get(r, "ADLen"));
    v->pt = xalloc(v->n);
    kat_bytes(seed, v->pt, v->n);
    v->ad = xalloc(v->an);
    kat_bytes(seed ^ 0x5A5A5A5Au, v->ad, v->an);
    const char *cth = kat_get(r, "CT"), *ctf = kat_get(r, "CTFNV");
    if (!!cth == !!ctf) { fprintf(stderr, "ascon KAT: exactly one of CT/CTFNV\n"); exit(2); }
    v->ct = NULL;
    if (cth) {
        v->ct = xalloc(v->n);
        if (hex2bin(cth, v->ct, v->n) != v->n) { fprintf(stderr, "ascon KAT: CT length\n"); exit(2); }
    } else {
        v->ct_fnv = kat_num(ctf, 16);
    }
    v->count = kat_get(r, "Count");
    return 1;
}

static void avec_free(avec *v)
{
    free(v->pt);
    free(v->ad);
    free(v->ct);
}

static int avec_match(const avec *v, const uint8_t *ct_tag)
{
    if (memcmp(ct_tag + v->n, v->tag, 16)) return 0;
    return v->ct ? !memcmp(ct_tag, v->ct, v->n) : fnv1a64(ct_tag, v->n) == v->ct_fnv;
}

static void ascon_single_vec(const ascon_impl *im, const avec *v, int idx)
{
    unsigned long long clen = 0, mlen = 0;
    uint8_t *out = xalloc(v->n + 16);
    im->enc(out, &clen, v->pt, v->n, v->ad, v->an, 0, v->nonce, v->key);
    CHECK(clen == v->n + 16 && avec_match(v, out), "%s: KAT Count=%s Len=%zu AD=%zu enc", im->name, v->count, v->n, v->an);
    CHECK(canary_ok(out, v->n + 16), "%s: write past ct||tag Count=%s", im->name, v->count);
    uint8_t *inpl = xalloc(v->n + 16); /* in place: plaintext in the first n bytes */
    memcpy(inpl, v->pt, v->n);
    im->enc(inpl, &clen, inpl, v->n, v->ad, v->an, 0, v->nonce, v->key);
    CHECK(avec_match(v, inpl), "%s: KAT Count=%s in-place enc", im->name, v->count);
    CHECK(canary_ok(inpl, v->n + 16), "%s: in-place write past end Count=%s", im->name, v->count);
    if (im->dec) {
        uint8_t *dec = xalloc(v->n);
        int rc = im->dec(dec, &mlen, 0, out, v->n + 16, v->ad, v->an, v->nonce, v->key);
        CHECK(rc == 0 && mlen == v->n && !memcmp(dec, v->pt, v->n), "%s: KAT Count=%s dec", im->name, v->count);
        CHECK(canary_ok(dec, v->n), "%s: dec write past end Count=%s", im->name, v->count);
        out[v->n + 15 - (idx % 16)] ^= (uint8_t)(1u << (idx % 8)); /* forge one tag bit */
        rc = im->dec(dec, &mlen, 0, out, v->n + 16, v->ad, v->an, v->nonce, v->key);
        CHECK(rc != 0, "%s: KAT Count=%s forged tag accepted", im->name, v->count);
        free(dec);
    }
    free(out);
    free(inpl);
}

/* Multi-stream run of `njobs` lanes: lane 0 is the vector itself, lanes j > 0 are
 * derived (distinct key, nonce, message, AD of the same lengths) and checked against
 * `oracle`. Run out of place and in place. */
static void ascon_multi_vec(const ascon_impl *im, ascon_enc_fn oracle, const avec *v, size_t njobs)
{
    ascon_job *jobs = calloc(njobs, sizeof *jobs);
    uint8_t **msg = calloc(njobs, sizeof *msg), **ad = calloc(njobs, sizeof *ad),
            **out = calloc(njobs, sizeof *out), **ref = calloc(njobs, sizeof *ref),
            (*key)[16] = calloc(njobs, 16), (*non)[16] = calloc(njobs, 16);
    for (size_t j = 0; j < njobs; j++) {
        msg[j] = xalloc(v->n);
        ad[j] = xalloc(v->an);
        if (j == 0) {
            memcpy(key[0], v->key, 16);
            memcpy(non[0], v->nonce, 16);
            memcpy(msg[0], v->pt, v->n);
            memcpy(ad[0], v->ad, v->an);
        } else {
            kat_bytes(0x1000u * (uint32_t)j + 1, key[j], 16);
            kat_bytes(0x1000u * (uint32_t)j + 2, non[j], 16);
            kat_bytes(0x1000u * (uint32_t)j + 3, msg[j], v->n);
            kat_bytes(0x1000u * (uint32_t)j + 4, ad[j], v->an);
        }
        out[j] = xalloc(v->n + 16);
        ref[j] = xalloc(v->n + 16);
        unsigned long long clen;
        oracle(ref[j], &clen, msg[j], v->n, ad[j], v->an, 0, non[j], key[j]);
        jobs[j] = (ascon_job){out[j], msg[j], ad[j], non[j], key[j]};
    }
    im->multi(jobs, njobs, v->n, v->an);
    CHECK(avec_match(v, out[0]), "%s: multi lane 0 vs KAT Count=%s Len=%zu AD=%zu jobs=%zu", im->name, v->count, v->n, v->an, njobs);
    for (size_t j = 0; j < njobs; j++) {
        CHECK(!memcmp(ref[j], out[j], v->n + 16), "%s: multi lane %zu vs oracle Len=%zu AD=%zu jobs=%zu", im->name, j, v->n, v->an, njobs);
        CHECK(canary_ok(out[j], v->n + 16), "%s: multi write past end lane %zu jobs=%zu", im->name, j, njobs);
    }
    /* in place: each lane's plaintext copied into an exact ct||tag slot */
    for (size_t j = 0; j < njobs; j++) {
        memcpy(out[j], msg[j], v->n);
        jobs[j].m = jobs[j].c = out[j];
    }
    im->multi(jobs, njobs, v->n, v->an);
    for (size_t j = 0; j < njobs; j++)
        CHECK(!memcmp(ref[j], out[j], v->n + 16) && canary_ok(out[j], v->n + 16),
              "%s: multi in-place lane %zu Len=%zu jobs=%zu", im->name, j, v->n, njobs);
    for (size_t j = 0; j < njobs; j++) {
        free(msg[j]); free(ad[j]); free(out[j]); free(ref[j]);
    }
    free(jobs); free(msg); free(ad); free(out); free(ref); free(key); free(non);
}

/* Runs `single` or `multi` checks over one embedded KAT file. */
static int ascon_file(const ascon_impl *im, ascon_enc_fn oracle, int lwc, int expect)
{
    int before = failures, count = 0;
    kat_src s = lwc ? src(kat_ascon_lwc, kat_ascon_lwc_len) : src(kat_ascon_long, kat_ascon_long_len);
    kat_rec r;
    while (kat_next(&s, &r)) {
#ifdef KAT_MAX_LEN
        if (!lwc && kat_size(kat_get(&r, "Len")) > KAT_MAX_LEN) { len_skipped++; count++; kat_free(&r); continue; }
#endif
        avec v;
        if (lwc) avec_from_lwc(&r, &v); else avec_from_long(&r, &v);
        if (im->enc) {
            ascon_single_vec(im, &v, count);
        } else {
            const size_t L = im->lanes;
            size_t counts[4] = {1, L, L + 1, 2 * L + 1};
            for (int c = 0; c < 4; c++) {
                if (c && counts[c] == counts[c - 1]) continue;
                ascon_multi_vec(im, oracle, &v, counts[c]);
            }
        }
        avec_free(&v);
        count++;
        kat_free(&r);
    }
    CHECK(count == expect, "%s KAT count %d != %d", lwc ? "LWC" : "long", count, expect);
    return failures == before;
}

int main(void)
{
    int skipped = 0, tested = 0;
    for (const chacha20_impl *im = chacha20_impls; im->name; im++) {
        if (im->available && !im->available()) { printf("chacha20 %-22s SKIPPED (not available)\n", im->name); skipped++; continue; }
        int ok = chacha_rfc(im);
        ok &= chacha_long(im);
        printf("chacha20 %-22s %s\n", im->name, ok ? "ok" : "FAILED");
        fflush(stdout);
        tested++;
    }
    ascon_enc_fn oracle = 0;
    for (const ascon_impl *im = ascon_impls; im->name; im++) {
        if (!im->enc) continue;
        if (im->available && !im->available()) { printf("ascon    %-22s SKIPPED (not available)\n", im->name); skipped++; continue; }
        int ok = ascon_file(im, 0, 1, 1089);
        ok &= ascon_file(im, 0, 0, 346);
        printf("ascon    %-22s %s\n", im->name, ok ? "ok" : "FAILED");
        fflush(stdout);
        if (ok && !oracle) oracle = im->enc;
        tested++;
    }
    for (const ascon_impl *im = ascon_impls; im->name; im++) {
        if (!im->multi) continue;
        if (im->available && !im->available()) { printf("ascon    %-22s SKIPPED (not available)\n", im->name); skipped++; continue; }
        int ok = oracle != 0;
        CHECK(ok, "no single-stream implementation passed the KATs to serve as oracle");
        if (ok) {
            ok &= ascon_file(im, oracle, 1, 1089);
            ok &= ascon_file(im, oracle, 0, 346);
        }
        printf("ascon    %-22s %s\n", im->name, ok ? "ok" : "FAILED");
        fflush(stdout);
        tested++;
    }
    printf("%d implementations tested, %d skipped, %d failures\n", tested, skipped, failures);
#ifdef KAT_MAX_LEN
    printf("KAT_MAX_LEN=%lu: %d long-vector runs (summed over implementations) skipped as too large for this build\n",
           (unsigned long)KAT_MAX_LEN, len_skipped);
#endif
    return failures ? 1 : 0;
}
