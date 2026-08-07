/* Speed tests for every registered variant and implementation.
 *
 * Reported figures
 *   cycles/byte  TSC ticks per plaintext byte. On modern x86 the TSC runs at a
 *                fixed nominal rate, not the actual core clock, so this is a
 *                *nominal* cycle count. It is stable and comparable between runs
 *                on the same machine, which is what matters for comparing variants.
 *   MB/s         measured against CLOCK_MONOTONIC; no such caveat.
 *   ns/op        wall time per operation (per block, or per key setup).
 *
 * Protocol: warm up, then run TRIALS independent trials and report the median.
 * The median is robust against scheduler noise; min is also reported so you can see
 * how much noise there was. Pin the process (taskset -c 2 ./build/bench) for the
 * tightest numbers.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#define HAVE_RDTSC 1
#endif

#include "internal.h"
#include "gen/lin_consts.h"

#define TRIALS 15
#define BLOCKS 8192 /* 64 KiB of plaintext: stays in L1/L2 */
#define WARMUP 3

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t cycles(void)
{
#ifdef HAVE_RDTSC
    return __rdtsc();
#else
    return now_ns();
#endif
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

typedef struct {
    double cyc_median, cyc_min;
    double ns_median;
} stats_t;

static stats_t summarize(double *cyc, double *ns, int n)
{
    stats_t s;
    qsort(cyc, (size_t)n, sizeof(double), cmp_double);
    qsort(ns, (size_t)n, sizeof(double), cmp_double);
    s.cyc_median = cyc[n / 2];
    s.cyc_min = cyc[0];
    s.ns_median = ns[n / 2];
    return s;
}

static uint64_t rng_state = 0x123456789ABCDEFull;
static uint64_t rng_next(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

/* Written but never read: stops the optimiser deleting the work we are timing. */
static volatile uint64_t bench_sink;

static FILE *csv;

static void emit(const present_variant_t *v, const char *impl, const char *mode,
                 stats_t s, double bytes_per_op, int gates)
{
    double cpb = s.cyc_median / bytes_per_op;
    double mbps = bytes_per_op / s.ns_median * 1000.0; /* bytes/ns -> MB/s (1e6 B) */
    printf("  %-9s %-11s %8.2f %8.2f %10.1f %10.2f\n", impl, mode, cpb,
           s.cyc_min / bytes_per_op, mbps, s.ns_median);
    if (csv)
        fprintf(csv, "%s,%s,%s,%d,%d,%d,%.4f,%.4f,%.2f,%.4f\n", v->name, impl, mode,
                v->rounds, v->key_bits, gates, cpb, s.cyc_min / bytes_per_op, mbps,
                s.ns_median);
}

/* --- individual benchmarks --------------------------------------------------- */

static void bench_latency(const present_ctx_t *ctx, const char *impl,
                          uint64_t (*fn)(const present_ctx_t *, uint64_t))
{
    double cyc[TRIALS], ns[TRIALS];
    uint64_t sink = 0;

    for (int t = -WARMUP; t < TRIALS; t++) {
        uint64_t b = 0x0123456789ABCDEFull;
        uint64_t c0 = cycles(), n0 = now_ns();
        for (int i = 0; i < BLOCKS; i++) b = fn(ctx, b); /* serial dependency */
        uint64_t c1 = cycles(), n1 = now_ns();
        sink ^= b;
        if (t >= 0) {
            cyc[t] = (double)(c1 - c0) / BLOCKS;
            ns[t] = (double)(n1 - n0) / BLOCKS;
        }
    }
    bench_sink = sink;
    emit(ctx->var, impl, "latency", summarize(cyc, ns, TRIALS), 8.0, 0);
}

static void bench_throughput(const present_ctx_t *ctx, const char *impl,
                             uint64_t (*fn)(const present_ctx_t *, uint64_t),
                             uint64_t *buf)
{
    double cyc[TRIALS], ns[TRIALS];
    uint64_t sink = 0;

    for (int t = -WARMUP; t < TRIALS; t++) {
        uint64_t c0 = cycles(), n0 = now_ns();
        for (int i = 0; i < BLOCKS; i++) sink ^= fn(ctx, buf[i]);
        uint64_t c1 = cycles(), n1 = now_ns();
        if (t >= 0) {
            cyc[t] = (double)(c1 - c0) / BLOCKS;
            ns[t] = (double)(n1 - n0) / BLOCKS;
        }
    }
    bench_sink = sink;
    emit(ctx->var, impl, "throughput", summarize(cyc, ns, TRIALS), 8.0, 0);
}

/* The bitsliced round function on its own, with the state already transposed.
 *
 * Same shape as bench_multi -- same buffer, same trial count, same normalisation --
 * except that the pack happens once, outside the timing loop. What it isolates is
 * the two transposes: a fixed cost per call that does not scale with the round
 * count, and that a counter-mode caller holding bitsliced counters never pays.
 *
 * Each group is re-packed from `buf` before being timed... it is not: packing per
 * group would put the transpose back in. Instead one group is packed once and
 * encrypted `groups` times. That is the same work per call as bench_multi does,
 * from L1 rather than from a 64 KiB stream, which is exactly the difference being
 * measured and is why this row is reported separately rather than as "the" number.
 */
static void bench_bitsliced(const present_ctx_t *ctx, const char *impl, int lanes,
                            uint64_t *(*fn)(const present_ctx_t *, uint64_t *, uint64_t *),
                            void (*pack)(const uint64_t *, uint64_t *),
                            uint64_t *buf, int gates)
{
    double cyc[TRIALS], ns[TRIALS];
    uint64_t sink = 0;
    const int groups = BLOCKS / lanes;
    const size_t words = (size_t)PRESENT_BLOCK_BITS * (lanes / 64);
    static _Alignas(32) uint64_t st[PRESENT_BLOCK_BITS * 4];
    static _Alignas(32) uint64_t sc[PRESENT_BLOCK_BITS * 4];
    static _Alignas(32) uint64_t seed[PRESENT_BLOCK_BITS * 4];

    if (pack) pack(buf, seed);
    else present_transpose64(buf, seed);

    for (int t = -WARMUP; t < TRIALS; t++) {
        uint64_t c0 = cycles(), n0 = now_ns();
        for (int g = 0; g < groups; g++) {
            memcpy(st, seed, words * sizeof(uint64_t));
            sink ^= fn(ctx, st, sc)[0];
        }
        uint64_t c1 = cycles(), n1 = now_ns();
        if (t >= 0) {
            cyc[t] = (double)(c1 - c0) / (groups * lanes);
            ns[t] = (double)(n1 - n0) / (groups * lanes);
        }
    }
    bench_sink = sink;
    emit(ctx->var, impl, "throughput", summarize(cyc, ns, TRIALS), 8.0, gates);
}

/* Any implementation that takes `lanes` independent blocks at a time: the
 * interleaved table paths, the bitsliced path, the AVX2 path. Measured identically
 * so the numbers are comparable -- same buffer, same trial count, same normalisation
 * to bytes of plaintext. */
static void bench_multi(const present_ctx_t *ctx, const char *impl, int lanes,
                        void (*fn)(const present_ctx_t *, const uint64_t *, uint64_t *),
                        uint64_t *buf, uint64_t *out, int gates)
{
    double cyc[TRIALS], ns[TRIALS];
    uint64_t sink = 0;
    const int groups = BLOCKS / lanes;

    for (int t = -WARMUP; t < TRIALS; t++) {
        uint64_t c0 = cycles(), n0 = now_ns();
        for (int g = 0; g < groups; g++)
            fn(ctx, buf + (size_t)g * lanes, out + (size_t)g * lanes);
        uint64_t c1 = cycles(), n1 = now_ns();
        sink ^= out[0];
        if (t >= 0) {
            cyc[t] = (double)(c1 - c0) / (groups * lanes);
            ns[t] = (double)(n1 - n0) / (groups * lanes);
        }
    }
    bench_sink = sink;
    emit(ctx->var, impl, "throughput", summarize(cyc, ns, TRIALS), 8.0, gates);
}

static void bench_keysetup(const present_variant_t *v, const uint8_t *key, size_t key_len)
{
    double cyc[TRIALS], ns[TRIALS];
    const int reps = 2000;
    uint64_t sink = 0;

    /* key schedule alone */
    for (int t = -WARMUP; t < TRIALS; t++) {
        uint64_t rk[PRESENT_MAX_ROUNDS + 1];
        uint64_t c0 = cycles(), n0 = now_ns();
        for (int i = 0; i < reps; i++) {
            present_key_schedule(v, key, key_len, rk);
            sink ^= rk[0];
        }
        uint64_t c1 = cycles(), n1 = now_ns();
        if (t >= 0) { cyc[t] = (double)(c1 - c0) / reps; ns[t] = (double)(n1 - n0) / reps; }
    }
    bench_sink = sink;
    emit(v, "-", "keyschedule", summarize(cyc, ns, TRIALS), 1.0, 0);

    /* full context init, which also builds the 16 KiB of lookup tables */
    for (int t = -WARMUP; t < TRIALS; t++) {
        present_ctx_t c;
        uint64_t c0 = cycles(), n0 = now_ns();
        for (int i = 0; i < reps / 10; i++) { present_init(&c, v, key, key_len); sink ^= c.rk[0]; }
        uint64_t c1 = cycles(), n1 = now_ns();
        if (t >= 0) {
            cyc[t] = (double)(c1 - c0) / (reps / 10);
            ns[t] = (double)(n1 - n0) / (reps / 10);
        }
    }
    bench_sink = sink;
    emit(v, "-", "ctxinit", summarize(cyc, ns, TRIALS), 1.0, 0);
}

int main(int argc, char **argv)
{
    const char *csv_path = NULL;
    const char *only = NULL;
    const char *only_impl = NULL;

    for (int i = 1; i < argc - 1; i += 2) {
        if (!strcmp(argv[i], "--csv")) csv_path = argv[i + 1];
        else if (!strcmp(argv[i], "--variant")) only = argv[i + 1];
        else if (!strcmp(argv[i], "--impl")) only_impl = argv[i + 1];
        else {
            fprintf(stderr, "usage: %s [--csv PATH] [--variant NAME] [--impl NAME]\n", argv[0]);
            return 2;
        }
    }

    if (csv_path) {
        csv = fopen(csv_path, "w");
        if (!csv) { perror(csv_path); return 1; }
        fprintf(csv, "variant,impl,mode,rounds,key_bits,sbox_gates,"
                     "cycles_per_byte,cycles_per_byte_min,mb_per_sec,ns_per_op\n");
    }

    uint64_t *buf = malloc(sizeof(uint64_t) * BLOCKS);
    uint64_t *out = malloc(sizeof(uint64_t) * BLOCKS);
    if (!buf || !out) { fprintf(stderr, "oom\n"); return 1; }
    for (int i = 0; i < BLOCKS; i++) buf[i] = rng_next();

    printf("PRESENT_mod speed tests: %d blocks/trial, %d trials, median reported\n",
           BLOCKS, TRIALS);
#ifndef HAVE_RDTSC
    printf("note: no TSC on this platform, 'cycles' columns hold nanoseconds\n");
#endif

    for (int vi = 0; vi < present_n_variants; vi++) {
        const present_variant_t *v = &present_variants[vi];
        if (only && strcmp(v->name, only)) continue;

        uint8_t key[(PRESENT_MAX_ROUNDS + 1) * PRESENT_BLOCK_BITS / 8];
        size_t key_len = present_variant_key_bytes(v);
        for (size_t i = 0; i < key_len; i++) key[i] = (uint8_t)(rng_next() >> 24);

        present_ctx_t ctx;
        if (present_init(&ctx, v, key, key_len) != 0) {
            fprintf(stderr, "init failed for %s\n", v->name);
            continue;
        }

        /* Every variant has a bitsliced round function, but the guard stays: a
         * variant added without a synthesised circuit should lose those rows rather
         * than silently time a stub that returns its input. */
        const int bs = present_variant_has_bitslice(v);
        const int g64 = bs ? present_circuit_gates(v->circuit_enc) : 0;
        const int gav = bs ? present_circuit_gates_for_avx2(v->circuit_enc) : 0;

        char layer[64];
        if (v->lin_kind == PRESENT_LIN_444)
            snprintf(layer, sizeof(layer), "lin444(%d,%d,%d) %d XORs/round",
                     v->lin_c0[0], v->lin_c0[1], v->lin_c0[2],
                     present_lin444_xors(v->lin_c0, 0));
        else
            snprintf(layer, sizeof(layer), "pbox, free");
        if (bs)
            printf("\n%s  (%d rounds, %d-bit key, %d-bit S-box circuit %d gates u64 / "
                   "%d avx2, %s)\n", v->name, v->rounds, v->key_bits, v->sbox_bits,
                   g64, gav, layer);
        else
            printf("\n%s  (%d rounds, %d-bit key, %d-bit S-box, no circuit, %s)\n",
                   v->name, v->rounds, v->key_bits, v->sbox_bits, layer);
        printf("  %-9s %-11s %8s %8s %10s %10s\n", "impl", "mode", "cyc/B", "min", "MB/s", "ns/op");

        /* --impl narrows the run to one row. Comparing two variants means taking a
         * median over repeated runs, and the reference implementation alone is
         * ~1400 cyc/B -- a thousand times the row being compared. */
#define WANT(nm) (!only_impl || !strcmp(only_impl, nm))
        if (bs && present_have_avx2() && WANT("avx2"))
            bench_multi(&ctx, "avx2", PRESENT_AVX2_BLOCKS,
                        present_encrypt_avx2, buf, out, gav);
        if (bs && present_have_avx2() && WANT("avx2-bs"))
            bench_bitsliced(&ctx, "avx2-bs", PRESENT_AVX2_BLOCKS,
                            present_encrypt_avx2_bs, present_avx2_pack, buf, gav);
        if (bs && present_have_neon() && WANT("neon"))
            bench_multi(&ctx, "neon", PRESENT_NEON_BLOCKS,
                        present_encrypt_neon, buf, out, g64);
        if (bs && present_have_neon() && WANT("neon-bs"))
            bench_bitsliced(&ctx, "neon-bs", PRESENT_NEON_BLOCKS,
                            present_encrypt_neon_bs, present_neon_pack, buf, g64);
        if (bs && WANT("bitslice"))
            bench_multi(&ctx, "bitslice", PRESENT_BITSLICE_BLOCKS,
                        present_encrypt_bitslice, buf, out, g64);
        if (bs && WANT("bitslice-bs"))
            bench_bitsliced(&ctx, "bitslice-bs", PRESENT_BITSLICE_BLOCKS,
                            present_encrypt_bitslice_bs, NULL, buf, g64);
        if (WANT("table-x16")) bench_multi(&ctx, "table-x16", 16, present_encrypt_table_x16, buf, out, 0);
        if (WANT("table-x8"))  bench_multi(&ctx, "table-x8", 8, present_encrypt_table_x8, buf, out, 0);
        if (WANT("table-x4"))  bench_multi(&ctx, "table-x4", 4, present_encrypt_table_x4, buf, out, 0);
        if (WANT("table-x2"))  bench_multi(&ctx, "table-x2", 2, present_encrypt_table_x2, buf, out, 0);
        if (WANT("table"))     bench_throughput(&ctx, "table", present_encrypt_table, buf);
        if (WANT("table-dec")) bench_throughput(&ctx, "table-dec", present_decrypt_table, buf);
        if (WANT("table"))     bench_latency(&ctx, "table", present_encrypt_table);
        if (WANT("keyschedule")) bench_keysetup(v, key, key_len);
        if (WANT("ref"))       bench_throughput(&ctx, "ref", present_encrypt_ref, buf);
        if (WANT("ref"))       bench_latency(&ctx, "ref", present_encrypt_ref);
        #undef WANT
    }

    if (csv) { fclose(csv); fprintf(stderr, "\nwrote %s\n", csv_path); }
    free(buf);
    free(out);
    return 0;
}
