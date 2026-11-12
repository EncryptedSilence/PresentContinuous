/* Throughput of every ChaCha20 / Ascon-AEAD128 implementation in this build.
 *
 * The operation timed is the complete one a caller sees, the analogue of the
 * PRESENT counter-mode campaigns' "complete CTR" (results/v2):
 *   ChaCha20       -- XOR the keystream into a frame in place (counter setup,
 *                     keystream, XOR, store; key/nonce passed per call);
 *   Ascon-AEAD128  -- encrypt a frame in place and write its tag (init p^12,
 *                     p^8 per 16 bytes, final p^12), no associated data;
 *   AES-128-CTR,   -- XOR the CTR keystream into a frame in place (counter
 *   Qalqan-CTR        blocks, block cipher, XOR, store; include/blockctr.h). Key
 *                     expansion is done once, outside the timing, as in the
 *                     PRESENT campaigns; the nonce is passed per call.
 * Every call processes JOBS frames of the given size (independent keys and nonces
 * for Ascon): single-stream impls one frame after another, multi-stream impls all
 * at once. So both see the same working set (JOBS x size, at most 1.5 MiB, i.e.
 * warm in the P-core's 2 MiB L2: these are warm-buffer figures, the analogue of
 * the PRESENT campaigns' 4/16/64 KiB frames, not DRAM streaming rates). The rate
 * is total bytes / time. For a multi-stream impl that is the aggregate per-core
 * rate of a server with many concurrent sessions -- NOT the speed of one message,
 * which the single-stream rows answer.
 *
 * Clocks. The TSC on this host ticks at a fixed nominal rate (~2.4 GHz on the
 * i9-14900HX, see docs/measurement-environment.md), not the core clock, and
 * perf counters are not available (perf_event_paranoid = 4). So two numbers are
 * reported: tsc_cyc_per_byte, comparable with the PRESENT x86 tables, and
 * core_cyc_per_byte = ns/B x the core frequency DURING the timed trials. That
 * frequency comes from a sampler thread on another CPU reading the measured CPU's
 * cpufreq scaling_cur_freq every 5 ms while the trials run; under intel_pstate
 * that file is the APERF/MPERF ratio over the last tick, i.e. the clock the core
 * actually ran the workload at (AVX2 licence and power limits included). A chain
 * of dependent register adds timed before and after each cell is kept as an
 * independent cross-check (core_ghz_probe), since it measures a scalar load.
 * The core figure is what compares with published cycles/byte.
 *
 * Usage: bench_ca [--trials N] [--csv FILE] [--only SUBSTR]   (SUBSTR: impl name; for
 * the block ciphers also the cipher name, e.g. --only qalqan)
 * Run pinned: taskset -c 2 build/ca/x86/bench_ca --csv chacha_ascon/results/x86/bench.csv */
#define _GNU_SOURCE
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

#include "ascon_aead.h"
#include "blockctr.h"
#include "chacha20.h"

static double now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    return t.tv_sec * 1e9 + t.tv_nsec;
}

/* Core clock in GHz: 2^26 dependent register adds take 2^26 core cycles. */
static double core_ghz(void)
{
    double best = 0;
    for (int rep = 0; rep < 3; rep++) {
        /* register-register adds: Golden/Raptor Cove eliminate chains of
         * add-immediate at rename, so `add $1` would report ~4x the clock. */
        uint64_t x = 0, n = 1u << 26, one = 1;
        double t0 = now_ns();
        __asm__ volatile("1:\n\t"
                         "add %2, %0\n\tadd %2, %0\n\tadd %2, %0\n\tadd %2, %0\n\t"
                         "add %2, %0\n\tadd %2, %0\n\tadd %2, %0\n\tadd %2, %0\n\t"
                         "sub $8, %1\n\tjnz 1b"
                         : "+r"(x), "+r"(n) : "r"(one));
        double g = (double)(1u << 26) / (now_ns() - t0);
        if (g > best) best = g;
    }
    return best;
}

/* ---- frequency sampler ----
 * All shared state is behind `smu`. The measuring thread starts a window by
 * setting `sampling` under the lock and ends it by clearing it and copying the
 * samples out, also under the lock, so no sample can land after the copy.
 * intel_pstate is in active mode on this host, where scaling_cur_freq is the
 * average frequency since the previous read (kernel admin-guide/pm/intel_pstate). */
static pthread_mutex_t smu = PTHREAD_MUTEX_INITIALIZER;
static int sampling, sampler_quit;
static double samples[4096];
static int nsamples;
static char freq_path[128];

static void *sampler(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&smu);
        int quit = sampler_quit, on = sampling && nsamples < 4096;
        pthread_mutex_unlock(&smu);
        if (quit) break;
        if (on) {
            FILE *f = fopen(freq_path, "r");
            long khz = 0;
            if (f) { if (fscanf(f, "%ld", &khz) != 1) khz = 0; fclose(f); }
            pthread_mutex_lock(&smu);
            if (khz > 0 && sampling && nsamples < 4096) samples[nsamples++] = khz / 1e6;
            pthread_mutex_unlock(&smu);
        }
        usleep(5000);
    }
    return NULL;
}

static void sampling_start(void)
{
    pthread_mutex_lock(&smu);
    nsamples = 0;
    sampling = 1;
    pthread_mutex_unlock(&smu);
}

/* Ends the window; copies the samples into out[] and returns their count. */
static int sampling_stop(double *out)
{
    pthread_mutex_lock(&smu);
    sampling = 0;
    int n = nsamples;
    memcpy(out, samples, (size_t)n * sizeof *out);
    pthread_mutex_unlock(&smu);
    return n;
}

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

typedef struct {
    const char *cipher, *impl, *mode;
    unsigned lanes;
    size_t size;
} cell;

static FILE *csv;
static int trials = 15;

/* Times `fn(arg)` processing `bytes` bytes per call. Each trial repeats the call
 * enough times to last >= 10 ms; the median over trials is reported. */
static void measure(const cell *c, size_t bytes, void (*fn)(void *), void *arg)
{
    double ghz0 = core_ghz();
    for (int w = 0; w < 5; w++) fn(arg);
    int reps = 1;
    for (;;) {
        double t0 = now_ns();
        for (int i = 0; i < reps; i++) fn(arg);
        if (now_ns() - t0 > 10e6) break; /* >= 10 ms per trial: >= 2 frequency samples */
        reps *= 2;
    }
    double ns[64], tsc[64];
    static double snap[4096];
    sampling_start();
    for (int t = 0; t < trials; t++) {
        uint64_t c0 = __rdtsc();
        double t0 = now_ns();
        for (int i = 0; i < reps; i++) fn(arg);
        double t1 = now_ns();
        uint64_t c1 = __rdtsc();
        ns[t] = (t1 - t0) / ((double)reps * bytes);
        tsc[t] = (double)(c1 - c0) / ((double)reps * bytes);
    }
    int ns_ = sampling_stop(snap);
    double ghz1 = core_ghz();
    qsort(ns, trials, sizeof ns[0], cmp_d);
    qsort(tsc, trials, sizeof tsc[0], cmp_d);
    qsort(snap, ns_, sizeof snap[0], cmp_d);
    /* No workload samples -> no core-cycle figure (NaN), never the scalar probe. */
    double ghz_run = ns_ ? snap[ns_ / 2] : NAN;
    double nsb = ns[trials / 2], ghz = ghz_run;
    double mbit = 8e3 / nsb; /* bytes/ns = GB/s; x8000 = Mbit/s */
    printf("%-10s %-22s %-6s L=%-2u %6zu B  %8.3f tsc-cyc/B  %7.3f core-cyc/B  %9.1f Mbit/s  (min %.3f max %.3f ns/B, run %.2f GHz [%d samples], probe %.2f/%.2f)\n",
           c->cipher, c->impl, c->mode, c->lanes, c->size, tsc[trials / 2], nsb * ghz, mbit,
           ns[0], ns[trials - 1], ghz_run, ns_, ghz0, ghz1);
    if (csv)
        fprintf(csv, "x86,%s,%s,%s,%u,%zu,%d,%.5f,%.5f,%.5f,%.5f,%.5f,%.1f,%.3f,%d,%.3f,%.3f\n",
                c->cipher, c->impl, c->mode, c->lanes, c->size, trials, nsb, ns[0], ns[trials - 1],
                tsc[trials / 2], nsb * ghz, mbit, ghz_run, ns_, ghz0, ghz1);
    fflush(stdout);
}

/* ---- workloads ---- */
static uint8_t key32[32], nonce12[12];
#define JOBS 24
typedef struct { const chacha20_impl *im; uint8_t *buf; size_t len; } chacha_arg;
static void run_chacha(void *p)
{
    chacha_arg *a = p;
    for (int j = 0; j < JOBS; j++)
        a->im->xor_fn(a->buf + (size_t)j * (a->len + 64), a->buf + (size_t)j * (a->len + 64), a->len,
                      key32, nonce12, 0);
}

typedef struct { const bc_impl *im; const void *ctx; uint8_t *buf; size_t len; } bc_arg;
static void run_bc(void *p)
{
    bc_arg *a = p;
    for (int j = 0; j < JOBS; j++)
        a->im->xor_fn(a->ctx, a->buf + (size_t)j * (a->len + 64), a->buf + (size_t)j * (a->len + 64), a->len,
                      nonce12, 0);
}

typedef struct { const ascon_impl *im; ascon_job jobs[JOBS]; size_t n, len; } ascon_arg;
static void run_ascon_single(void *p)
{
    ascon_arg *a = p;
    unsigned long long clen;
    for (int j = 0; j < JOBS; j++)
        a->im->enc(a->jobs[j].c, &clen, a->jobs[j].m, a->len, 0, 0, 0, a->jobs[j].nonce, a->jobs[j].key);
}
static void run_ascon_multi(void *p)
{
    ascon_arg *a = p;
    a->im->multi(a->jobs, a->n, a->len, 0);
}

int main(int argc, char **argv)
{
    const char *only = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--trials") && i + 1 < argc) trials = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc) {
            csv = fopen(argv[++i], "w");
            if (!csv) { perror("csv"); return 1; }
        } else if (!strcmp(argv[i], "--only") && i + 1 < argc) only = argv[++i];
        else { fprintf(stderr, "usage: %s [--trials N] [--csv FILE] [--only SUBSTR]\n", argv[0]); return 2; }
    }
    if (trials < 3 || trials > 64) trials = 15;
    snprintf(freq_path, sizeof freq_path, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", sched_getcpu());
    {   /* the sampler runs on any CPU but this one */
        cpu_set_t set;
        CPU_ZERO(&set);
        int me = sched_getcpu(), other = me == 0 ? 1 : 0;
        CPU_SET(other, &set);
        pthread_t th;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setaffinity_np(&at, sizeof set, &set);
        if (pthread_create(&th, &at, sampler, NULL)) { perror("sampler"); return 1; }
        pthread_detach(th);
    }
    if (csv)
        fprintf(csv, "target,cipher,impl,mode,lanes,size_bytes,trials,ns_per_byte,ns_per_byte_min,"
                     "ns_per_byte_max,tsc_cyc_per_byte,core_cyc_per_byte,mbit_per_sec,core_ghz_run,freq_samples,"
                     "core_ghz_probe_before,core_ghz_probe_after\n");
    for (int i = 0; i < 32; i++) key32[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 12; i++) nonce12[i] = (uint8_t)(i * 13 + 5);
    static const size_t sizes[] = {4096, 16384, 65536};
    uint8_t *buf = aligned_alloc(64, (size_t)JOBS * (65536 + 64));
    memset(buf, 0xA5, (size_t)JOBS * (65536 + 64));
    static uint8_t keys[JOBS][16], nonces[JOBS][16];
    for (int j = 0; j < JOBS; j++)
        for (int i = 0; i < 16; i++) { keys[j][i] = (uint8_t)(j * 31 + i); nonces[j][i] = (uint8_t)(j * 17 + 3 * i); }

    for (const chacha20_impl *im = chacha20_impls; im->name; im++) {
        if ((im->available && !im->available()) || (only && !strstr(im->name, only))) continue;
        for (int s = 0; s < 3; s++) {
            chacha_arg a = {im, buf, sizes[s]};
            cell c = {"chacha20", im->name, "single", im->lanes, sizes[s]};
            measure(&c, sizes[s] * JOBS, run_chacha, &a);
        }
    }
    for (const ascon_impl *im = ascon_impls; im->name; im++) {
        if ((im->available && !im->available()) || (only && !strstr(im->name, only))) continue;
        for (int s = 0; s < 3; s++) {
            ascon_arg a;
            a.im = im;
            a.len = sizes[s];
            a.n = JOBS;
            for (int j = 0; j < JOBS; j++) {
                a.jobs[j].m = buf + (size_t)j * (sizes[s] + 64);
                a.jobs[j].c = buf + (size_t)j * (sizes[s] + 64);
                a.jobs[j].ad = NULL;
                a.jobs[j].nonce = nonces[j];
                a.jobs[j].key = keys[j];
            }
            cell c = {"ascon128", im->name, im->multi ? "multi" : "single", im->lanes, sizes[s]};
            measure(&c, sizes[s] * a.n, im->multi ? run_ascon_multi : run_ascon_single, &a);
        }
    }
    for (const bc_impl *im = bc_impls; im->name; im++) {
        if ((im->available && !im->available()) ||
            (only && !strstr(im->name, only) && !strstr(im->cipher, only))) continue;
        size_t csz = (im->ctx_size + BC_CTX_ALIGN - 1) / BC_CTX_ALIGN * BC_CTX_ALIGN;
        void *ctx = aligned_alloc(BC_CTX_ALIGN, csz);
        if (!ctx) { perror("ctx"); return 1; }
        im->setup(ctx, key32); /* AES-128 uses the first 16 bytes */
        for (int s = 0; s < 3; s++) {
            bc_arg a = {im, ctx, buf, sizes[s]};
            cell c = {im->cipher, im->name, "single", im->lanes, sizes[s]};
            measure(&c, sizes[s] * JOBS, run_bc, &a);
        }
        free(ctx);
    }
    if (csv) fclose(csv);
    free(buf);
    return 0;
}
