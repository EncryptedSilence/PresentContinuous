/* KAT gate for the CUDA benchmark's host oracles, linked into ca_gpu itself so
 * the oracle is checked by the very binary that relies on it (not only by a
 * separately built test_ca that may be stale).
 *
 *   chacha20_xor_avx2_x8  vs  kat/chacha20_long.txt   (206 vectors, RFC 8439 oracle)
 *   ascon_multi_avx2_x8   vs  kat/LWC_AEAD_KAT_128_128.txt (1089 vectors), each vector
 *                         run as 9 jobs so the 8-lane group and the remainder path
 *                         both produce it.
 * Exits non-zero on any mismatch or on a short file. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ascon_aead.h"
#include "chacha20.h"
#include "../tests/kat_common.h"

extern const unsigned long kat_chacha20_long_len, kat_ascon_lwc_len;
extern const unsigned char kat_chacha20_long[], kat_ascon_lwc[];
void ascon_multi_avx2_x8(const ascon_job *jobs, size_t n, size_t mlen, size_t adlen);

static void die(const char *what, const char *count)
{
    fprintf(stderr, "FAIL oracle gate: %s (Count=%s)\n", what, count ? count : "?");
    exit(1);
}

int oracle_gate(void)
{
    int nc = 0, na = 0;
    kat_src s = {(const char *)kat_chacha20_long, (const char *)kat_chacha20_long + kat_chacha20_long_len};
    kat_rec r;
    while (kat_next(&s, &r)) {
        uint8_t key[32], nonce[12];
        hex_exact(kat_get(&r, "Key"), key, 32);
        hex_exact(kat_get(&r, "Nonce"), nonce, 12);
        uint32_t ctr = kat_u32(kat_get(&r, "Counter")), seed = kat_u32(kat_get(&r, "Seed"));
        size_t n = kat_size(kat_get(&r, "Len"));
        const char *cth = kat_get(&r, "CT"), *ctf = kat_get(&r, "CTFNV");
        if (!!cth == !!ctf) die("chacha: exactly one of CT/CTFNV", kat_get(&r, "Count"));
        uint8_t *buf = malloc(n ? n : 1), *want = malloc(n ? n : 1);
        kat_bytes(seed, buf, n);
        chacha20_xor_avx2_x8(buf, buf, n, key, nonce, ctr);
        int ok;
        if (cth) {
            if (hex2bin(cth, want, n) != n) die("chacha: CT length", kat_get(&r, "Count"));
            ok = !memcmp(buf, want, n);
        } else {
            ok = fnv1a64(buf, n) == kat_num(ctf, 16);
        }
        if (!ok) die("chacha20_xor_avx2_x8 ciphertext", kat_get(&r, "Count"));
        free(buf); free(want);
        kat_free(&r);
        nc++;
    }
    if (nc != 206) die("chacha KAT count != 206", NULL);

    s = (kat_src){(const char *)kat_ascon_lwc, (const char *)kat_ascon_lwc + kat_ascon_lwc_len};
    while (kat_next(&s, &r)) {
        uint8_t key[16], nonce[16], pt[64], ad[64], ct[96], out[9][96];
        hex_exact(kat_get(&r, "Key"), key, 16);
        hex_exact(kat_get(&r, "Nonce"), nonce, 16);
        size_t m = hex2bin(kat_get(&r, "PT"), pt, sizeof pt);
        size_t a = hex2bin(kat_get(&r, "AD"), ad, sizeof ad);
        if (hex2bin(kat_get(&r, "CT"), ct, sizeof ct) != m + 16) die("ascon: CT length", kat_get(&r, "Count"));
        ascon_job jobs[9];
        for (int j = 0; j < 9; j++) jobs[j] = (ascon_job){out[j], pt, ad, nonce, key};
        ascon_multi_avx2_x8(jobs, 9, m, a);
        for (int j = 0; j < 9; j++)
            if (memcmp(out[j], ct, m + 16)) die("ascon_multi_avx2_x8 ciphertext||tag", kat_get(&r, "Count"));
        kat_free(&r);
        na++;
    }
    if (na != 1089) die("ascon LWC KAT count != 1089", NULL);
    return nc + na;
}
