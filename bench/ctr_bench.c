/* CTR-mode speed harness: times a complete counter-mode pass over a byte
 * buffer for every registered bench/ctr_backend.h backend, not a bare round
 * function. See that header's file comment for the prepare()/run() split this
 * measures.
 *
 * Usage: ./build/ctr_bench --csv PATH [--size 65536] [--trials 15]
 *                           [--cipher NAME] [--impl NAME]
 *
 * Protocol, in order (mirrors bench/bench_main.c's warm-up-then-median
 * approach, with prepare() timed separately from run() -- see below):
 *   1. Fill one buffer of --size bytes with the same xorshift tests/test_ctr.c
 *      uses.
 *   2. Correctness gate: every backend that will be measured must reproduce
 *      its cipher's ctr-ref output byte for byte, over the actual --size
 *      buffer. Any mismatch prints the offending backend and exits 1 --
 *      before the CSV file is even opened. A partial CSV is worse than none:
 *      that is the failure mode results/m4-speed.csv's header warns about,
 *      and it is exactly what the deliberately-broken-backend check in
 *      task-1-report.md exercises.
 *   3. prepare(): 2000 repetitions per trial, median of --trials, into
 *      prepare_ns.
 *   4. run(): 3 warmup trials, then --trials timed trials, median reported.
 *      cycles via __rdtsc() on x86 for a secondary column; "NA" elsewhere,
 *      never a nanosecond count relabelled as cycles (see the tsc_per_byte
 *      field below).
 *   5. One CSV row per backend.
 */
#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#define HAVE_RDTSC 1
#endif

#include "ctr_backend.h"
#include "present/present.h"
#include "present/variant.h"

#define DEFAULT_SIZE 65536
#define DEFAULT_TRIALS 15
#define WARMUP 3
#define PREPARE_REPS 2000

/* Declared, not redeclared: bench/ctr_wide.c is the one place permitted to
 * hardcode the wide ciphers' round counts (from tools/cipher_set.py's
 * VARIANT_OVERRIDES -- see that file's AES_R5_ROUNDS / AES_LIN444_R4_ROUNDS).
 * The CSV's rounds column needs that number too, so it asks through this
 * accessor rather than restating 5 and 4 here. */
int ctr_wide_rounds_for(const char *cipher);

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
    return 0;
#endif
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double median_of(double *v, int n)
{
    qsort(v, (size_t)n, sizeof(double), cmp_double);
    return v[n / 2];
}

/* Same xorshift as tests/test_ctr.c, so a plaintext or key filled here and one
 * filled there are bit-for-bit the same for the same seed. */
static void fill_from(uint8_t *p, size_t n, uint64_t seed)
{
    uint64_t x = seed;
    for (size_t i = 0; i < n; i++) {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        p[i] = (uint8_t)(x * 0x2545F4914F6CDD1Dull >> 56);
    }
}

static void fill(uint8_t *p, size_t n) { fill_from(p, n, 0x0123456789ABCDEFull); }

/* present_variant_by_name() answers this for the five 64-bit ciphers; the two
 * 128-bit ones are not in present_variants (they live in wide_ciphers.h, per
 * bench/ctr_wide.c's file comment), so those fall through to
 * ctr_wide_rounds_for(). Either way, the round count is read from the same
 * single source of truth every other consumer uses -- never hardcoded here. */
static int backend_rounds(const ctr_backend_t *b)
{
    const present_variant_t *v = present_variant_by_name(b->cipher);
    if (v) return v->rounds;
    int r = ctr_wide_rounds_for(b->cipher);
    if (r <= 0) {
        fprintf(stderr, "ctr_bench: %s: cannot resolve a round count for cipher '%s'\n",
                b->name, b->cipher);
        exit(1);
    }
    return r;
}

static _Alignas(32) uint8_t g_state[CTR_MAX_STATE_BYTES];
static uint8_t g_key[CTR_MAX_KEY_BYTES];

int main(int argc, char **argv)
{
    const char *csv_path = NULL;
    size_t size = DEFAULT_SIZE;
    int trials = DEFAULT_TRIALS;
    const char *only_cipher = NULL;
    const char *only_impl = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv_path = argv[++i];
        else if (!strcmp(argv[i], "--size") && i + 1 < argc) size = (size_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--trials") && i + 1 < argc) trials = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cipher") && i + 1 < argc) only_cipher = argv[++i];
        else if (!strcmp(argv[i], "--impl") && i + 1 < argc) only_impl = argv[++i];
        else {
            fprintf(stderr,
                    "usage: %s --csv PATH [--size 65536] [--trials 15] "
                    "[--cipher NAME] [--impl NAME]\n", argv[0]);
            return 1;
        }
    }
    if (!csv_path) {
        fprintf(stderr, "ctr_bench: --csv PATH is required\n");
        return 1;
    }
    if (trials < 1) {
        fprintf(stderr, "ctr_bench: --trials must be >= 1\n");
        return 1;
    }
    if (size == 0) {
        fprintf(stderr, "ctr_bench: --size must be > 0\n");
        return 1;
    }

    /* Fail loudly at the boundary rather than corrupt memory quietly: every
     * registered backend's key_bytes/state_bytes must fit the buffers every
     * caller (this harness, tests/test_ctr.c) sizes against these macros. */
    for (size_t i = 0; i < ctr_backend_count(); i++) {
        const ctr_backend_t *b = ctr_backend_at(i);
        if (b->key_bytes > CTR_MAX_KEY_BYTES) {
            fprintf(stderr,
                    "ctr_bench: %s (%s): key_bytes %zu exceeds CTR_MAX_KEY_BYTES %d\n",
                    b->name, b->cipher, b->key_bytes, CTR_MAX_KEY_BYTES);
            return 1;
        }
        if (b->state_bytes > CTR_MAX_STATE_BYTES) {
            fprintf(stderr,
                    "ctr_bench: %s (%s): state_bytes %zu exceeds CTR_MAX_STATE_BYTES %d\n",
                    b->name, b->cipher, b->state_bytes, CTR_MAX_STATE_BYTES);
            return 1;
        }
        /* run_x/run_wide (bench/ctr_narrow.c, bench/ctr_wide.c) group blocks up
         * to 16 at a time (narrow) or 8 at a time (wide, 16-byte blocks) with no
         * partial-group handling, same as their brief-verbatim bodies -- so
         * --size must be a multiple of 128 bytes for every registered backend to
         * stay in bounds. Every size this project publishes (4096, 16384, 65536)
         * satisfies this; a caller who passes something else gets a clear error
         * here rather than a silent out-of-bounds write in run(). */
        if (size % 128 != 0) {
            fprintf(stderr, "ctr_bench: --size %zu is not a multiple of 128 bytes\n", size);
            return 1;
        }
        if (size % b->block_bytes != 0) {
            fprintf(stderr, "ctr_bench: --size %zu is not a multiple of %s's block_bytes (%zu)\n",
                    size, b->cipher, b->block_bytes);
            return 1;
        }
    }

    uint8_t *buf_ref = malloc(size);
    uint8_t *buf_got = malloc(size);
    uint8_t *buf_run = malloc(size);
    if (!buf_ref || !buf_got || !buf_run) {
        fprintf(stderr, "ctr_bench: out of memory allocating %zu-byte buffers\n", size);
        return 1;
    }

    fill_from(g_key, sizeof g_key, 0xFEDCBA9876543210ull);

    size_t n = ctr_backend_count();
    const ctr_backend_t **selected = malloc(n * sizeof *selected);
    if (!selected) {
        fprintf(stderr, "ctr_bench: out of memory\n");
        return 1;
    }
    size_t nsel = 0;
    for (size_t i = 0; i < n; i++) {
        const ctr_backend_t *b = ctr_backend_at(i);
        if (only_cipher && strcmp(b->cipher, only_cipher)) continue;
        if (only_impl && strcmp(b->name, only_impl)) continue;
        if (b->available && !b->available()) continue;
        selected[nsel++] = b;
    }
    if (nsel == 0) {
        fprintf(stderr, "ctr_bench: no backends matched --cipher/--impl\n");
        return 1;
    }

    /* --- Correctness gate: every selected backend against its cipher's
     * ctr-ref, over the actual --size buffer, before the CSV file is even
     * opened. See the file comment: a partial CSV is worse than none. */
    for (size_t i = 0; i < nsel; i++) {
        const ctr_backend_t *b = selected[i];
        const ctr_backend_t *ref = ctr_backend_reference_for(b->cipher);
        if (!ref) {
            fprintf(stderr, "ctr_bench: %s: no ctr-ref backend registered for cipher '%s'\n",
                    b->name, b->cipher);
            return 1;
        }

        fill(buf_ref, size);
        memcpy(buf_got, buf_ref, size);

        ref->prepare(g_state, g_key, ref->key_bytes);
        ref->run(g_state, buf_ref, size, 0);

        b->prepare(g_state, g_key, b->key_bytes);
        b->run(g_state, buf_got, size, 0);

        if (memcmp(buf_ref, buf_got, size) != 0) {
            fprintf(stderr,
                    "ctr_bench: CORRECTNESS GATE FAILED: %s (%s): ciphertext differs "
                    "from ctr-ref -- refusing to write %s\n", b->name, b->cipher, csv_path);
            return 1;
        }
    }

    FILE *csv = fopen(csv_path, "w");
    if (!csv) {
        fprintf(stderr, "ctr_bench: cannot open %s: %s\n", csv_path, strerror(errno));
        return 1;
    }
    fprintf(csv, "cipher,impl,size_bytes,block_bytes,rounds,mbit_per_sec,ns_median,"
                 "ns_min,prepare_ns,tsc_per_byte\n");

    double *tmp = malloc((size_t)trials * sizeof(double));
    double *tmp2 = malloc((size_t)trials * sizeof(double));
    if (!tmp || !tmp2) {
        fprintf(stderr, "ctr_bench: out of memory\n");
        fclose(csv);
        return 1;
    }

    printf("ctr_bench: %zu-byte buffer, %d trials, %zu backend%s\n",
           size, trials, nsel, nsel == 1 ? "" : "s");

    for (size_t i = 0; i < nsel; i++) {
        const ctr_backend_t *b = selected[i];
        int rounds = backend_rounds(b);

        /* --- prepare(): 2000 reps/trial, --trials trials, median. --- */
        for (int t = 0; t < trials; t++) {
            uint64_t n0 = now_ns();
            for (int r = 0; r < PREPARE_REPS; r++)
                b->prepare(g_state, g_key, b->key_bytes);
            uint64_t n1 = now_ns();
            tmp[t] = (double)(n1 - n0) / PREPARE_REPS;
        }
        double prepare_ns = median_of(tmp, trials);

        /* state must hold a real key schedule before run() is timed. */
        b->prepare(g_state, g_key, b->key_bytes);

        /* --- run(): 3 warmup trials, then --trials timed trials, median. --- */
        for (int t = -WARMUP; t < trials; t++) {
            fill(buf_run, size); /* untimed: keeps the buffer's content sane */
            uint64_t c0 = cycles(), n0 = now_ns();
            b->run(g_state, buf_run, size, 0);
            uint64_t c1 = cycles(), n1 = now_ns();
            if (t >= 0) {
                tmp[t] = (double)(n1 - n0);
                tmp2[t] = (double)(c1 - c0);
            }
        }
        qsort(tmp, (size_t)trials, sizeof(double), cmp_double);
        double ns_median = tmp[trials / 2];
        double ns_min = tmp[0];
        double cyc_median = median_of(tmp2, trials);

        double mbit_per_sec = (double)size * 8 / ns_median * 1000.0;

        char tsc_field[32];
#ifdef HAVE_RDTSC
        snprintf(tsc_field, sizeof tsc_field, "%.4f", cyc_median / (double)size);
#else
        snprintf(tsc_field, sizeof tsc_field, "NA");
#endif

        fprintf(csv, "%s,%s,%zu,%zu,%d,%.4f,%.4f,%.4f,%.4f,%s\n",
                b->cipher, b->name, size, b->block_bytes, rounds,
                mbit_per_sec, ns_median, ns_min, prepare_ns, tsc_field);
        printf("  %-28s %-16s r=%-3d %10.2f Mbit/s  ns=%10.1f  prepare_ns=%10.1f  tsc/B=%s\n",
               b->cipher, b->name, rounds, mbit_per_sec, ns_median, prepare_ns, tsc_field);
    }

    fclose(csv);
    free(tmp);
    free(tmp2);
    free(selected);
    free(buf_ref);
    free(buf_got);
    free(buf_run);
    return 0;
}
