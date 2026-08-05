/* Simple avalanche experiment for the equal-margin cipher set in
 * docs/speed-at-equal-security.md.
 *
 * For each trial, a replayable PRNG supplies a fresh key and plaintext. The program
 * encrypts the plaintext, flips each input bit in turn, encrypts again with the
 * same key, and counts which output bits changed.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "present/present.h"

#define DEFAULT_E 1000000ull
#define DEFAULT_EPSILON 0.01
#define MAX_WIDE_ROUNDS 20

static const uint8_t AES_SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

typedef struct {
    uint64_t s;
} rng_t;

static uint64_t rng_next(rng_t *rng)
{
    uint64_t x = rng->s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng->s = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static void rng_bytes(rng_t *rng, uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n;) {
        uint64_t x = rng_next(rng);
        for (int j = 0; j < 8 && i < n; j++, i++) {
            buf[i] = (uint8_t)x;
            x >>= 8;
        }
    }
}

static uint64_t rng_nonzero_seed(void)
{
    uint64_t x = (uint64_t)time(NULL);
    x ^= (uint64_t)clock() << 32;
    return x ? x : 0x123456789ABCDEFull;
}

static uint64_t parse_u64(const char *s, const char *what)
{
    char *end = NULL;
    errno = 0;
    uint64_t v = strtoull(s, &end, 0);
    if (errno || !end || *end) {
        fprintf(stderr, "bad %s: %s\n", what, s);
        exit(2);
    }
    return v;
}

static uint8_t xtime8(uint8_t a)
{
    return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b));
}

static uint32_t getu32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void putu32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

typedef struct {
    uint32_t rk[4 * (MAX_WIDE_ROUNDS + 1)];
    int nr;
} aes_key_t;

static void aes_expand(const uint8_t key[16], int nr, aes_key_t *out)
{
    uint32_t rcon = 0x01000000u;
    uint32_t *rk = out->rk;
    out->nr = nr;
    for (int i = 0; i < 4; i++) rk[i] = getu32(key + 4 * i);
    for (int i = 4; i < 4 * (nr + 1); i++) {
        uint32_t t = rk[i - 1];
        if (i % 4 == 0) {
            t = (t << 8) | (t >> 24);
            t = ((uint32_t)AES_SBOX[(t >> 24) & 0xff] << 24)
              | ((uint32_t)AES_SBOX[(t >> 16) & 0xff] << 16)
              | ((uint32_t)AES_SBOX[(t >> 8) & 0xff] << 8)
              | AES_SBOX[t & 0xff];
            t ^= rcon;
            rcon = (uint32_t)xtime8((uint8_t)(rcon >> 24)) << 24;
        }
        rk[i] = rk[i - 4] ^ t;
    }
}

static uint32_t aes_col(uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3, uint32_t rk)
{
    uint8_t a0 = AES_SBOX[s0 >> 24];
    uint8_t a1 = AES_SBOX[(s1 >> 16) & 0xff];
    uint8_t a2 = AES_SBOX[(s2 >> 8) & 0xff];
    uint8_t a3 = AES_SBOX[s3 & 0xff];
    uint8_t sum = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
    uint8_t b0 = (uint8_t)(a0 ^ sum ^ xtime8((uint8_t)(a0 ^ a1)));
    uint8_t b1 = (uint8_t)(a1 ^ sum ^ xtime8((uint8_t)(a1 ^ a2)));
    uint8_t b2 = (uint8_t)(a2 ^ sum ^ xtime8((uint8_t)(a2 ^ a3)));
    uint8_t b3 = (uint8_t)(a3 ^ sum ^ xtime8((uint8_t)(a3 ^ a0)));
    return ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) |
           ((uint32_t)b2 << 8) | b3 | rk;
}

static uint32_t aes_last_col(uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3,
                             uint32_t rk)
{
    uint32_t v = ((uint32_t)AES_SBOX[s0 >> 24] << 24)
               | ((uint32_t)AES_SBOX[(s1 >> 16) & 0xff] << 16)
               | ((uint32_t)AES_SBOX[(s2 >> 8) & 0xff] << 8)
               | AES_SBOX[s3 & 0xff];
    return v ^ rk;
}

static void aes_encrypt(const aes_key_t *k, const uint8_t in[16], uint8_t out[16])
{
    const uint32_t *rk = k->rk;
    uint32_t s0 = getu32(in) ^ rk[0];
    uint32_t s1 = getu32(in + 4) ^ rk[1];
    uint32_t s2 = getu32(in + 8) ^ rk[2];
    uint32_t s3 = getu32(in + 12) ^ rk[3];
    for (int r = 1; r < k->nr; r++) {
        uint32_t t0 = aes_col(s0, s1, s2, s3, rk[4 * r]);
        uint32_t t1 = aes_col(s1, s2, s3, s0, rk[4 * r + 1]);
        uint32_t t2 = aes_col(s2, s3, s0, s1, rk[4 * r + 2]);
        uint32_t t3 = aes_col(s3, s0, s1, s2, rk[4 * r + 3]);
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    uint32_t t0 = aes_last_col(s0, s1, s2, s3, rk[4 * k->nr]);
    uint32_t t1 = aes_last_col(s1, s2, s3, s0, rk[4 * k->nr + 1]);
    uint32_t t2 = aes_last_col(s2, s3, s0, s1, rk[4 * k->nr + 2]);
    uint32_t t3 = aes_last_col(s3, s0, s1, s2, rk[4 * k->nr + 3]);
    putu32(out, t0);
    putu32(out + 4, t1);
    putu32(out + 8, t2);
    putu32(out + 12, t3);
}

typedef struct {
    uint32_t rk[4 * (MAX_WIDE_ROUNDS + 1)];
    int nr;
    int c[3];
} lin_key_t;

static uint32_t rotl32(uint32_t x, int n)
{
    return n ? (x << n) | (x >> (32 - n)) : x;
}

static void lin444(uint32_t w[4], const int c[3])
{
    uint32_t o0 = w[0] ^ rotl32(w[1], c[0]) ^ rotl32(w[2], c[1]) ^ rotl32(w[3], c[2]);
    uint32_t o1 = w[1] ^ rotl32(w[2], c[0]) ^ rotl32(w[3], c[1]) ^ rotl32(o0, c[2]);
    uint32_t o2 = w[2] ^ rotl32(w[3], c[0]) ^ rotl32(o0, c[1]) ^ rotl32(o1, c[2]);
    uint32_t o3 = w[3] ^ rotl32(o0, c[0]) ^ rotl32(o1, c[1]) ^ rotl32(o2, c[2]);
    w[0] = o0; w[1] = o1; w[2] = o2; w[3] = o3;
}

static void lin_encrypt(const lin_key_t *k, const uint8_t in[16], uint8_t out[16])
{
    uint32_t w[4];
    for (int i = 0; i < 4; i++)
        w[i] = (uint32_t)in[4 * i] | ((uint32_t)in[4 * i + 1] << 8)
             | ((uint32_t)in[4 * i + 2] << 16) | ((uint32_t)in[4 * i + 3] << 24);
    for (int r = 0; r < k->nr; r++) {
        for (int i = 0; i < 4; i++) w[i] ^= k->rk[4 * r + i];
        for (int i = 0; i < 4; i++) {
            uint32_t v = 0;
            for (int b = 0; b < 4; b++)
                v |= (uint32_t)AES_SBOX[(w[i] >> (8 * b)) & 0xff] << (8 * b);
            w[i] = v;
        }
        lin444(w, k->c);
    }
    for (int i = 0; i < 4; i++) w[i] ^= k->rk[4 * k->nr + i];
    for (int i = 0; i < 4; i++) {
        out[4 * i] = (uint8_t)w[i];
        out[4 * i + 1] = (uint8_t)(w[i] >> 8);
        out[4 * i + 2] = (uint8_t)(w[i] >> 16);
        out[4 * i + 3] = (uint8_t)(w[i] >> 24);
    }
}

static void flip_bit(uint8_t *buf, int bit)
{
    buf[bit / 8] ^= (uint8_t)(1u << (bit % 8));
}

static void count_diff(uint64_t *table, int in_bit, const uint8_t *a, const uint8_t *b,
                       int block_bits)
{
    for (int byte = 0; byte < block_bits / 8; byte++) {
        uint8_t d = (uint8_t)(a[byte] ^ b[byte]);
        while (d) {
            int bit = __builtin_ctz((unsigned)d);
            table[(size_t)in_bit * (size_t)block_bits + (size_t)(8 * byte + bit)]++;
            d &= (uint8_t)(d - 1);
        }
    }
}

static int pass_rate(uint64_t count, uint64_t trials, double eps)
{
    double rate = (double)count / (double)trials;
    return rate >= 0.5 - eps && rate <= 0.5 + eps;
}

static void emit_csv(FILE *csv, const char *name, int rounds, int block_bits, int key_bits,
                     uint64_t seed, uint64_t E, double eps, const uint64_t *table)
{
    for (int in = 0; in < block_bits; in++) {
        for (int out = 0; out < block_bits; out++) {
            uint64_t count = table[(size_t)in * (size_t)block_bits + (size_t)out];
            fprintf(csv, "%s,%d,%d,%d,%" PRIu64 ",0x%016" PRIx64 ",%.6f,cell,%d,%d,"
                         "%" PRIu64 ",%" PRIu64 ",%.9f,%d\n",
                    name, rounds, block_bits, key_bits, E, seed, eps, in, out, count, E,
                    (double)count / (double)E, pass_rate(count, E, eps));
        }
    }
    for (int out = 0; out < block_bits; out++) {
        uint64_t count = 0;
        for (int in = 0; in < block_bits; in++)
            count += table[(size_t)in * (size_t)block_bits + (size_t)out];
        uint64_t trials = E * (uint64_t)block_bits;
        fprintf(csv, "%s,%d,%d,%d,%" PRIu64 ",0x%016" PRIx64 ",%.6f,output,,%d,"
                     "%" PRIu64 ",%" PRIu64 ",%.9f,%d\n",
                name, rounds, block_bits, key_bits, E, seed, eps, out, count, trials,
                (double)count / (double)trials, pass_rate(count, trials, eps));
    }
}

static void run_present_variant(FILE *csv, rng_t *rng, const char *name, uint64_t seed,
                                uint64_t E, double eps)
{
    const present_variant_t *v = present_variant_by_name(name);
    if (!v) {
        fprintf(stderr, "unknown variant: %s\n", name);
        exit(1);
    }
    const int n = PRESENT_BLOCK_BITS;
    uint64_t *table = calloc((size_t)n * (size_t)n, sizeof(uint64_t));
    if (!table) {
        fprintf(stderr, "oom\n");
        exit(1);
    }

    uint8_t key[(PRESENT_MAX_ROUNDS + 1) * PRESENT_BLOCK_BITS / 8];
    size_t key_len = present_variant_key_bytes(v);
    for (uint64_t e = 0; e < E; e++) {
        rng_bytes(rng, key, key_len);
        present_ctx_t ctx;
        if (present_init(&ctx, v, key, key_len) != 0) {
            fprintf(stderr, "init failed for %s\n", name);
            exit(1);
        }
        uint64_t pt = rng_next(rng);
        uint64_t etalon = present_encrypt_table(&ctx, pt);
        for (int in = 0; in < n; in++) {
            uint64_t got = present_encrypt_table(&ctx, pt ^ ((uint64_t)1 << in));
            uint64_t diff = got ^ etalon;
            while (diff) {
                int out = __builtin_ctzll(diff);
                table[(size_t)in * (size_t)n + (size_t)out]++;
                diff &= diff - 1;
            }
        }
    }
    emit_csv(csv, name, v->rounds, n, v->key_bits, seed, E, eps, table);
    free(table);
}

static void random_lin_key(rng_t *rng, lin_key_t *k, int rounds, const int c[3])
{
    k->nr = rounds;
    k->c[0] = c[0];
    k->c[1] = c[1];
    k->c[2] = c[2];
    for (int i = 0; i < 4 * (rounds + 1); i++)
        k->rk[i] = (uint32_t)rng_next(rng);
}

static void run_aes(FILE *csv, rng_t *rng, uint64_t seed, uint64_t E, double eps)
{
    const int n = 128, rounds = 5, key_bits = 128;
    uint64_t *table = calloc((size_t)n * (size_t)n, sizeof(uint64_t));
    if (!table) {
        fprintf(stderr, "oom\n");
        exit(1);
    }
    uint8_t key[16], pt[16], etalon[16], in[16], got[16];
    for (uint64_t e = 0; e < E; e++) {
        rng_bytes(rng, key, sizeof(key));
        rng_bytes(rng, pt, sizeof(pt));
        aes_key_t k;
        aes_expand(key, rounds, &k);
        aes_encrypt(&k, pt, etalon);
        for (int bit = 0; bit < n; bit++) {
            memcpy(in, pt, sizeof(in));
            flip_bit(in, bit);
            aes_encrypt(&k, in, got);
            count_diff(table, bit, etalon, got, n);
        }
    }
    emit_csv(csv, "aes", rounds, n, key_bits, seed, E, eps, table);
    free(table);
}

static void run_aes_lin444(FILE *csv, rng_t *rng, uint64_t seed, uint64_t E, double eps)
{
    const int n = 128, rounds = 4, c[3] = {0, 8, 15};
    const int key_bits = 128 * (rounds + 1);
    uint64_t *table = calloc((size_t)n * (size_t)n, sizeof(uint64_t));
    if (!table) {
        fprintf(stderr, "oom\n");
        exit(1);
    }
    uint8_t pt[16], etalon[16], in[16], got[16];
    for (uint64_t e = 0; e < E; e++) {
        lin_key_t k;
        random_lin_key(rng, &k, rounds, c);
        rng_bytes(rng, pt, sizeof(pt));
        lin_encrypt(&k, pt, etalon);
        for (int bit = 0; bit < n; bit++) {
            memcpy(in, pt, sizeof(in));
            flip_bit(in, bit);
            lin_encrypt(&k, in, got);
            count_diff(table, bit, etalon, got, n);
        }
    }
    emit_csv(csv, "aes-lin444-0-8-15", rounds, n, key_bits, seed, E, eps, table);
    free(table);
}

typedef void (*run_fn)(FILE *, rng_t *, uint64_t, uint64_t, double);

static void run_named(FILE *csv, rng_t *rng, const char *name, uint64_t seed, uint64_t E,
                      double eps)
{
    fprintf(stderr, "avalanche: %s, E=%" PRIu64 "\n", name, E);
    if (!strcmp(name, "aes")) run_aes(csv, rng, seed, E, eps);
    else if (!strcmp(name, "aes-lin444-0-8-15")) run_aes_lin444(csv, rng, seed, E, eps);
    else run_present_variant(csv, rng, name, seed, E, eps);
}

int main(int argc, char **argv)
{
    const char *csv_path = "results/avalanche.csv";
    const char *only = NULL;
    uint64_t E = DEFAULT_E;
    uint64_t seed = rng_nonzero_seed();
    double eps = DEFAULT_EPSILON;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv_path = argv[++i];
        else if (!strcmp(argv[i], "--E") && i + 1 < argc) E = parse_u64(argv[++i], "E");
        else if (!strcmp(argv[i], "--seed") && i + 1 < argc) seed = parse_u64(argv[++i], "seed");
        else if (!strcmp(argv[i], "--epsilon") && i + 1 < argc) eps = strtod(argv[++i], NULL);
        else if (!strcmp(argv[i], "--cipher") && i + 1 < argc) only = argv[++i];
        else {
            fprintf(stderr, "usage: %s [--csv PATH] [--E N] [--seed N] [--epsilon X] "
                            "[--cipher NAME]\n", argv[0]);
            return 2;
        }
    }
    if (E == 0 || seed == 0 || eps < 0.0 || eps > 0.5) {
        fprintf(stderr, "E and seed must be nonzero; epsilon must be in [0, 0.5]\n");
        return 2;
    }

    FILE *csv = fopen(csv_path, "w");
    if (!csv) {
        perror(csv_path);
        return 1;
    }
    fprintf(csv, "cipher,rounds,block_bits,key_bits,E,seed,epsilon,criterion,input_bit,"
                 "output_bit,count,trials,rate,pass\n");

    rng_t rng = { seed };
    static const char *ciphers[] = {
        "present-80-lin444-297-r7",
        "present-80-r16",
        "cipher-D-lin444-297-aes-r5",
        "aes-lin444-0-8-15",
        "aes",
        "cipher-D-lin444-297-r5",
        "cipher-D",
        NULL
    };

    if (only) {
        run_named(csv, &rng, only, seed, E, eps);
    } else {
        for (int i = 0; ciphers[i]; i++)
            run_named(csv, &rng, ciphers[i], seed, E, eps);
    }

    fclose(csv);
    fprintf(stderr, "wrote %s (seed 0x%016" PRIx64 ")\n", csv_path, seed);
    return 0;
}
