/* Host oracle for the two 128-bit ciphers' Cortex-M4 known-answer vectors.
 *
 * tools/gen_m4_kats.py gets the 64-bit ciphers' expected ciphertexts from
 * build/present-cli, which already encrypts a named block under a named key.
 * The 128-bit ciphers have no such CLI: bench/wide_bench.c encrypts random
 * blocks under a random key and reports megabytes per second, so it can attest
 * that the host implementations agree with each other and with FIPS-197 C.1
 * (it dies otherwise, and the generator runs it for exactly that reason), but
 * it cannot be asked for the ciphertext of a particular block.
 *
 * This is that missing accessor and nothing else: a thin argv wrapper around
 * bench/wide_ciphers.h's aes_key_schedule/aes_encrypt1 and
 * lin_key_schedule/lin_encrypt_ref. No cipher code is defined here -- a second
 * copy of AES written to check the first one would only prove the two copies
 * agree. The vectors this prints are therefore produced by the same host
 * implementations `make test` cross-checks against the bitsliced path in
 * tests/test_wide_bitslice32.c.
 *
 *   m4_kat_oracle aes|lin <rounds> <key-hex-32> <pt-hex-32>   -> 32 hex digits
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wide_ciphers.h"

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse16(const char *hex, uint8_t out[16])
{
    if (strlen(hex) != 32) return -1;
    for (int i = 0; i < 16; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s aes|lin <rounds> <key-hex-32> <pt-hex-32>\n", argv[0]);
        return 2;
    }

    const int rounds = atoi(argv[2]);
    if (rounds < 1 || rounds > MAX_ROUNDS) {
        fprintf(stderr, "rounds must be 1..%d\n", MAX_ROUNDS);
        return 2;
    }

    uint8_t key[16], pt[16], ct[16];
    if (parse16(argv[3], key) || parse16(argv[4], pt)) {
        fprintf(stderr, "key and plaintext must each be 32 hex digits\n");
        return 2;
    }

    if (!strcmp(argv[1], "aes")) {
        aes_key_t k;
        aes_key_schedule(&k, key);
        k.nr = rounds;
        aes_encrypt1(&k, rounds, pt, ct);
    } else if (!strcmp(argv[1], "lin")) {
        lin_key_t k;
        lin_key_schedule(&k, key);
        k.nr = rounds;
        lin_encrypt_ref(&k, rounds, pt, ct);
    } else {
        fprintf(stderr, "unknown cipher %s (expected aes or lin)\n", argv[1]);
        return 2;
    }

    for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
    printf("\n");
    return 0;
}
