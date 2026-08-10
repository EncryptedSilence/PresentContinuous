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
 *   1. Check the registry against tools/cipher_set.py's seven ciphers, and
 *      check every backend's declared key/state sizes against the shared
 *      buffers.
 *   2. Allocate, select the backends to measure, resolve each one's ctr-ref
 *      oracle and round count, and check --size against each one's (and each
 *      oracle's) group_bytes. Everything that can fail happens before the
 *      output file is touched -- see "no partial CSV" below.
 *   3. Fill one buffer of --size bytes with the same xorshift tests/test_ctr.c
 *      uses.
 *   4. Correctness gate: every backend that will be measured must reproduce
 *      its cipher's ctr-ref output byte for byte, at three different ctr0 values,
 *      and each cipher's ctr-ref must itself change the buffer and invert
 *      itself. Any mismatch prints the offending backend and exits 1.
 *   5. prepare(): 2000 repetitions per trial, median of --trials, into
 *      prepare_ns.
 *   6. run(): 3 warmup trials, then --trials timed trials, median reported.
 *      cycles via __rdtsc() on x86 for a secondary column; "NA" elsewhere,
 *      never a nanosecond count relabelled as cycles.
 *   7. One CSV row per backend.
 *
 * No partial CSV, ever. results/m4-speed.csv's header warns about exactly this
 * failure: a truncated table reads as a complete one to every downstream
 * script. Two mechanisms, because the gate alone only covers the failure it
 * checks for:
 *   - every fallible step -- argument validation, the cipher-set check, round
 *     resolution, allocation, the gate -- runs before the destination is
 *     opened, so those failures leave the previously published file untouched;
 *   - rows are written to PATH.tmp and rename()d onto PATH only after the last
 *     one is flushed. rename() is atomic on POSIX, so a crash, a Ctrl-C or an
 *     OOM kill midway through the ~11-second timing loop also leaves the old
 *     file whole. Opening PATH itself with "w" would truncate it up front and
 *     destroy good published data for the whole run.
 */
#define _POSIX_C_SOURCE 200809L

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

#define DEFAULT_SIZE 65536
#define DEFAULT_TRIALS 15
#define WARMUP 3
#define PREPARE_REPS 2000

/* The gate runs every backend at each of these counter origins.
 *
 * 0 alone is not a test of ctr0 at all: a backend that ignored the argument
 * and started its own counter at 0 would agree with ctr-ref everywhere. The
 * second value is chosen to make the counter carry out of its low 32 bits a
 * few blocks into the buffer -- 0xFFFFFF80 + 128 crosses 2^32 -- which is the
 * mistake a SIMD backend is most likely to make, keeping counters in 32-bit
 * lanes because that is what packs.
 *
 * The third is not a multiple of 64, which the first two both are. A bitsliced
 * backend produces its counters directly as slices; for a base aligned to its
 * block group those slices are constants, and for any other base it must rotate
 * them and ripple a carry. Without this value that path never runs in a
 * registered backend at all. 0xFFFFFFA5 is 37 mod 64 and still carries out of
 * the low 32 bits partway through the buffer, so it exercises the rotate and the
 * carry together. Each costs one extra pass over the buffer. */
static const uint64_t GATE_CTR0[] = {
    0, 0x00000000FFFFFF80ull, 0x00000000FFFFFFA5ull,
};
#define N_GATE_CTR0 (sizeof GATE_CTR0 / sizeof GATE_CTR0[0])

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

#ifdef HAVE_RDTSC
static uint64_t cycles(void) { return __rdtsc(); }
#endif

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

/* CTR_STATE_ALIGN, not a bare array: bench/ctr_backend.h promises backends that
 * `state` is aligned for the widest vector store they might use, and this is
 * where that promise is kept for the harness. */
static _Alignas(CTR_STATE_ALIGN) uint8_t g_state[CTR_MAX_STATE_BYTES];
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

    /* The cipher set, before anything else: a group appended to
     * ctr_registry.c's groups[] whose cipher name has a typo would otherwise
     * sail through the correctness gate (its own ctr-ref carries the same
     * typo, so it agrees with itself) and land in the CSV under a name no
     * other target in this project has ever measured. */
    {
        char why[256];
        if (ctr_cipher_set_check(why, sizeof why)) {
            fprintf(stderr, "ctr_bench: registry disagrees with tools/cipher_set.py: %s\n", why);
            return 1;
        }
    }

    /* Fail loudly at the boundary rather than corrupt memory quietly: every
     * registered backend's key_bytes/state_bytes must fit the buffers every
     * caller (this harness, tests/test_ctr.c) sizes against these macros. This
     * covers every registered backend, not just the selected ones, so a
     * --cipher-filtered run still reports a mis-sized neighbour. */
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
    }

    size_t n = ctr_backend_count();
    const ctr_backend_t **selected = malloc(n * sizeof *selected);
    const ctr_backend_t **refs = malloc(n * sizeof *refs);
    int *rounds = malloc(n * sizeof *rounds);
    uint8_t *buf_ref = malloc(size);
    uint8_t *buf_got = malloc(size);
    uint8_t *buf_run = malloc(size);
    double *tmp = malloc((size_t)trials * sizeof(double));
#ifdef HAVE_RDTSC
    double *tmp2 = malloc((size_t)trials * sizeof(double));
#endif
    char *tmp_path = malloc(strlen(csv_path) + sizeof ".tmp");
    if (!selected || !refs || !rounds || !buf_ref || !buf_got || !buf_run || !tmp || !tmp_path
#ifdef HAVE_RDTSC
        || !tmp2
#endif
       ) {
        fprintf(stderr, "ctr_bench: out of memory allocating %zu-byte buffers\n", size);
        return 1;
    }
    /* Written to, and rename()d onto csv_path, only once every row is on disk. */
    sprintf(tmp_path, "%s.tmp", csv_path);

    fill_from(g_key, sizeof g_key, 0xFEDCBA9876543210ull);

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

    /* Resolve every oracle and every round count now, before the output file
     * exists. Round resolution used to happen inside the row loop, where a
     * cipher whose rounds could not be resolved aborted the run with rows
     * already written. */
    for (size_t i = 0; i < nsel; i++) {
        refs[i] = ctr_backend_reference_for(selected[i]->cipher);
        if (!refs[i]) {
            fprintf(stderr, "ctr_bench: %s: no ctr-ref backend registered for cipher '%s'\n",
                    selected[i]->name, selected[i]->cipher);
            return 1;
        }
        rounds[i] = ctr_cipher_rounds(selected[i]->cipher);
        if (rounds[i] <= 0) {
            fprintf(stderr, "ctr_bench: %s: cannot resolve a round count for cipher '%s'\n",
                    selected[i]->name, selected[i]->cipher);
            return 1;
        }
    }

    /* --size must divide evenly into each selected backend's block group, and
     * into that of the ctr-ref it will be gated against -- the oracle runs over
     * the same buffer and is not necessarily in `selected` when --impl filtered
     * it out. The check is per backend against its own group_bytes rather than
     * against one constant for the whole harness: a bitsliced backend's group
     * is 512 bytes or more, and a constant sized for today's largest group
     * stops covering the largest group the moment a bigger one is registered --
     * which is a plain out-of-bounds write inside the timed region, with a
     * throughput number reported for it. See ctr_backend_t.group_bytes. */
    for (size_t i = 0; i < nsel; i++) {
        const ctr_backend_t *pair[2] = { selected[i], refs[i] };
        for (int j = 0; j < 2; j++) {
            if (size % pair[j]->group_bytes != 0) {
                fprintf(stderr,
                        "ctr_bench: --size %zu is not a multiple of %s (%s)'s group_bytes "
                        "(%zu = %zu blocks of %zu bytes)\n",
                        size, pair[j]->name, pair[j]->cipher, pair[j]->group_bytes,
                        pair[j]->group_bytes / pair[j]->block_bytes, pair[j]->block_bytes);
                return 1;
            }
        }
    }

    /* --- Correctness gate: every selected backend against its cipher's
     * ctr-ref, over the actual --size buffer, before the CSV file is even
     * opened. See the file comment: a partial CSV is worse than none. */
    for (size_t i = 0; i < nsel; i++) {
        const ctr_backend_t *b = selected[i];
        const ctr_backend_t *ref = refs[i];

        for (size_t c = 0; c < N_GATE_CTR0; c++) {
            fill(buf_ref, size);
            memcpy(buf_got, buf_ref, size);

            ref->prepare(g_state, g_key, ref->key_bytes);
            ref->run(g_state, buf_ref, size, GATE_CTR0[c]);

            b->prepare(g_state, g_key, b->key_bytes);
            b->run(g_state, buf_got, size, GATE_CTR0[c]);

            if (memcmp(buf_ref, buf_got, size) != 0) {
                fprintf(stderr,
                        "ctr_bench: CORRECTNESS GATE FAILED: %s (%s) at ctr0=0x%016llx: "
                        "ciphertext differs from ctr-ref -- refusing to write %s\n",
                        b->name, b->cipher, (unsigned long long)GATE_CTR0[c], csv_path);
                return 1;
            }
        }

        /* Agreement with ctr-ref is only worth something if ctr-ref itself did
         * something. For the 128-bit pair, ctr-ref and ctr-table are the same
         * kernel and AES-lin444's xN rows loop that same kernel, so a
         * lin_encrypt_ref that emitted zero blocks would leave all five rows
         * agreeing perfectly, unchanged buffers and an enormous published
         * throughput for a backend that did nothing. Pin each cipher's ctr-ref
         * to changing the buffer and to being its own inverse; the pin runs
         * once per backend, which is cheap next to the pass above. */
        fill(buf_ref, size);
        memcpy(buf_got, buf_ref, size);
        ref->prepare(g_state, g_key, ref->key_bytes);
        ref->run(g_state, buf_got, size, 0);
        if (memcmp(buf_ref, buf_got, size) == 0) {
            fprintf(stderr,
                    "ctr_bench: CORRECTNESS GATE FAILED: ctr-ref (%s) left the buffer "
                    "unchanged -- refusing to write %s\n", ref->cipher, csv_path);
            return 1;
        }
        ref->run(g_state, buf_got, size, 0);
        if (memcmp(buf_ref, buf_got, size) != 0) {
            fprintf(stderr,
                    "ctr_bench: CORRECTNESS GATE FAILED: ctr-ref (%s) is not an "
                    "involution -- refusing to write %s\n", ref->cipher, csv_path);
            return 1;
        }
    }

    FILE *csv = fopen(tmp_path, "w");
    if (!csv) {
        fprintf(stderr, "ctr_bench: cannot open %s: %s\n", tmp_path, strerror(errno));
        return 1;
    }
    fprintf(csv, "cipher,impl,size_bytes,block_bytes,rounds,mbit_per_sec,ns_median,"
                 "ns_min,prepare_ns,tsc_per_byte\n");

    printf("ctr_bench: %zu-byte buffer, %d trials, %zu backend%s\n",
           size, trials, nsel, nsel == 1 ? "" : "s");

    for (size_t i = 0; i < nsel; i++) {
        const ctr_backend_t *b = selected[i];

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
#ifdef HAVE_RDTSC
            uint64_t c0 = cycles();
#endif
            uint64_t n0 = now_ns();
            b->run(g_state, buf_run, size, 0);
            uint64_t n1 = now_ns();
#ifdef HAVE_RDTSC
            uint64_t c1 = cycles();
#endif
            if (t >= 0) {
                tmp[t] = (double)(n1 - n0);
#ifdef HAVE_RDTSC
                tmp2[t] = (double)(c1 - c0);
#endif
            }
        }
        qsort(tmp, (size_t)trials, sizeof(double), cmp_double);
        double ns_median = tmp[trials / 2];
        double ns_min = tmp[0];

        double mbit_per_sec = (double)size * 8 / ns_median * 1000.0;

        /* On a target with no TSC this column is the string NA and no cycle
         * count is computed, measured or allocated for. Writing a nanosecond
         * figure under a cycles heading is what made the raw cycles column of
         * results/wide-speed-arm.csv unusable. */
        char tsc_field[32];
#ifdef HAVE_RDTSC
        double cyc_median = median_of(tmp2, trials);
        snprintf(tsc_field, sizeof tsc_field, "%.4f", cyc_median / (double)size);
#else
        snprintf(tsc_field, sizeof tsc_field, "NA");
#endif

        fprintf(csv, "%s,%s,%zu,%zu,%d,%.4f,%.4f,%.4f,%.4f,%s\n",
                b->cipher, b->name, size, b->block_bytes, rounds[i],
                mbit_per_sec, ns_median, ns_min, prepare_ns, tsc_field);
        printf("  %-28s %-16s r=%-3d %10.2f Mbit/s  ns=%10.1f  prepare_ns=%10.1f  tsc/B=%s\n",
               b->cipher, b->name, rounds[i], mbit_per_sec, ns_median, prepare_ns, tsc_field);
    }

    /* fclose flushes; a full disk shows up here and must not be rename()d over
     * a good published file as if it had succeeded. Both conditions are
     * evaluated -- fclose runs even when ferror already failed, so the stream is
     * always closed and the tmp file always removed. */
    int write_failed = ferror(csv) != 0;
    if (fclose(csv) != 0) write_failed = 1;
    if (write_failed) {
        fprintf(stderr, "ctr_bench: writing %s failed: %s\n", tmp_path, strerror(errno));
        remove(tmp_path);
        return 1;
    }
    if (rename(tmp_path, csv_path) != 0) {
        fprintf(stderr, "ctr_bench: cannot rename %s onto %s: %s\n",
                tmp_path, csv_path, strerror(errno));
        remove(tmp_path);
        return 1;
    }

    free(tmp);
#ifdef HAVE_RDTSC
    free(tmp2);
#endif
    free(tmp_path);
    free(rounds);
    free(selected);
    free(refs);
    free(buf_ref);
    free(buf_got);
    free(buf_run);
    return 0;
}
