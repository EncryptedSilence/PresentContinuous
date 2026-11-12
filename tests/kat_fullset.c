/* Published known-answer vectors for the full-round cipher set
 * (CTR_CIPHER_SET=full: present-80 at 31 rounds, aes-128 at 10 rounds).
 *
 * The CTR harness's own gate (ctr_bench step 4, tests/test_ctr.c) checks every
 * backend against its cipher's ctr-ref, which is only as right as ctr-ref. This
 * program anchors ctr-ref and every other backend to external vectors:
 *
 *   - FIPS-197 Appendix C.1 (AES-128 single block) through aes_encrypt1/4 at 10 rounds;
 *   - NIST SP 800-38A F.5.1 CTR-AES128.Encrypt (4 blocks, 128-bit counter from
 *     f0f1..ff) through aes_encrypt1 at 10 rounds;
 *   - every registered aes-128 CTR backend over the harness's counter layout
 *     (block i = 0^64 || be64(ctr0 + i)), against keystream produced by
 *     `openssl enc -aes-128-ctr -K 2b7e1516..4f3c -iv 0000000000000000f8f9fafbfcfdfeff`;
 *   - every registered present-80 CTR backend against the four PRESENT-80
 *     vectors of Bogdanov et al. (CHES 2007), Appendix I: with ctr0 = plaintext,
 *     the first keystream block is E_K(plaintext).
 *
 * Exits 0 only if every check ran and passed; a cipher missing from the
 * registry is a failure, not a skip, because this program exists for the full set. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctr_backend.h"
#include "wide_ciphers.h"

static int failures, checks;

static void expect(const char *what, const uint8_t *got, const uint8_t *want, size_t n)
{
    checks++;
    if (memcmp(got, want, n) == 0) {
        printf("ok   %s\n", what);
        return;
    }
    failures++;
    printf("FAIL %s\n  got  ", what);
    for (size_t i = 0; i < n; i++) printf("%02x", got[i]);
    printf("\n  want ");
    for (size_t i = 0; i < n; i++) printf("%02x", want[i]);
    printf("\n");
}

static void hex(uint8_t *out, const char *s)
{
    for (size_t i = 0; s[2 * i]; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void aes_vectors(void)
{
    uint8_t key[16], pt[16], ct[16], out[64];
    aes_key_t k;

    /* FIPS-197 C.1 */
    hex(key, "000102030405060708090a0b0c0d0e0f");
    hex(pt, "00112233445566778899aabbccddeeff");
    hex(ct, "69c4e0d86a7b0430d8cdb78070b4c55a");
    aes_key_schedule(&k, key);
    aes_encrypt1(&k, 10, pt, out);
    expect("FIPS-197 C.1 AES-128 aes_encrypt1 r=10", out, ct, 16);
    uint8_t pt4[64], ct4[64];
    for (int i = 0; i < 4; i++) { memcpy(pt4 + 16 * i, pt, 16); memcpy(ct4 + 16 * i, ct, 16); }
    aes_encrypt4(&k, 10, pt4, out);
    expect("FIPS-197 C.1 AES-128 aes_encrypt4 r=10", out, ct4, 64);

    /* SP 800-38A F.5.1 CTR-AES128.Encrypt */
    uint8_t p[64], c[64], ctr[16];
    hex(key, "2b7e151628aed2a6abf7158809cf4f3c");
    hex(ctr, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    hex(p, "6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
           "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710");
    hex(c, "874d6191b620e3261bef6864990db6ce" "9806f66b7970fdff8617187bb9fffdff"
           "5ae4df3edbd5d35e5b4f09020db03eab" "1e031dda2fbe03d1792170a0f3009cee");
    aes_key_schedule(&k, key);
    for (int b = 0; b < 4; b++) {
        uint8_t ks[16];
        aes_encrypt1(&k, 10, ctr, ks);
        for (int j = 0; j < 16; j++) out[16 * b + j] = p[16 * b + j] ^ ks[j];
        for (int j = 15; j >= 0 && ++ctr[j] == 0; j--) {}
    }
    expect("SP 800-38A F.5.1 CTR-AES128 (aes_encrypt1 r=10)", out, c, 64);
}

static uint8_t *state;

static void aes_backends(void)
{
    /* openssl enc -aes-128-ctr -K 2b7e..4f3c -iv 0000000000000000f8f9fafbfcfdfeff
     * on 64 zero bytes. */
    uint8_t key[16], want[64];
    hex(key, "2b7e151628aed2a6abf7158809cf4f3c");
    hex(want, "0e06300f60ece5edccda3f276af837d2" "289f92fdbb45c41052e4cf907f1b8b14"
              "399cf100d9edf4364e5fce03f8e19a9a" "d04ba69284cb20cc2369901ecd2f3b1e");
    int seen = 0;
    for (size_t i = 0; i < ctr_backend_count(); i++) {
        const ctr_backend_t *b = ctr_backend_at(i);
        if (strcmp(b->cipher, "aes-128") || (b->available && !b->available())) continue;
        size_t len = b->group_bytes;
        while (len < 64) len += b->group_bytes;
        uint8_t *buf = calloc(1, len);
        b->prepare(state, key, sizeof key);
        b->run(state, buf, len, 0xf8f9fafbfcfdfeffULL);
        char what[128];
        snprintf(what, sizeof what, "aes-128 %s vs openssl aes-128-ctr keystream (4 blocks)", b->name);
        expect(what, buf, want, 64);
        free(buf);
        seen++;
    }
    if (!seen) { failures++; printf("FAIL no available aes-128 backend registered\n"); }
}

static void present_backends(void)
{
    static const struct { const char *key, *pt, *ct; } V[] = {
        { "00000000000000000000", "0000000000000000", "5579c1387b228445" },
        { "ffffffffffffffffffff", "0000000000000000", "e72c46c0f5945049" },
        { "00000000000000000000", "ffffffffffffffff", "a112ffc72f68417b" },
        { "ffffffffffffffffffff", "ffffffffffffffff", "3333dcd3213210d2" },
    };
    int seen = 0;
    for (size_t i = 0; i < ctr_backend_count(); i++) {
        const ctr_backend_t *b = ctr_backend_at(i);
        if (strcmp(b->cipher, "present-80") || (b->available && !b->available())) continue;
        seen++;
        for (size_t v = 0; v < sizeof V / sizeof V[0]; v++) {
            uint8_t key[10], ptb[8], ct[8];
            hex(key, V[v].key); hex(ptb, V[v].pt); hex(ct, V[v].ct);
            uint64_t pt = 0;
            for (int j = 0; j < 8; j++) pt = (pt << 8) | ptb[j];
            uint8_t *buf = calloc(1, b->group_bytes);
            if (b->key_bytes != sizeof key) {
                failures++;
                printf("FAIL present-80 %s: key_bytes %zu, expected 10\n", b->name, b->key_bytes);
                free(buf);
                break;
            }
            b->prepare(state, key, sizeof key);
            b->run(state, buf, b->group_bytes, pt);
            char what[160];
            snprintf(what, sizeof what, "present-80 %s r=31 key=%s pt=%s -> %s",
                     b->name, V[v].key, V[v].pt, V[v].ct);
            expect(what, buf, ct, 8);
            free(buf);
        }
    }
    if (!seen) { failures++; printf("FAIL no available present-80 backend registered\n"); }
}

int main(void)
{
    state = aligned_alloc(CTR_STATE_ALIGN, CTR_MAX_STATE_BYTES);
    if (!state) return 2;
    aes_vectors();
    aes_backends();
    present_backends();
    printf("%s: %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    free(state);
    return failures ? 1 : 0;
}
