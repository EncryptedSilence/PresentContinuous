/* Throughput of every ChaCha20 / Ascon-AEAD128 / AES-128-CTR / Qalqan-CTR
 * implementation of the Cortex-A7 build, measured natively on the board
 * (OrangePi R1, Allwinner H2+, Linux). Built by arm/Makefile.board on the board.
 *
 * The operation timed is the same complete one as bench_ca.c on x86: ChaCha20 and
 * the block ciphers XOR their keystream into a frame in place (key expansion
 * outside the timing, nonce per call); Ascon-AEAD128 encrypts a frame in place and
 * writes its tag, no associated data. Each call processes JOBS frames (independent
 * keys/nonces for Ascon): single-stream impls one after another, multi-stream
 * impls `lanes` at a time. JOBS x 4096 B = 32 KiB, so the largest working set is
 * L1-sized (32 KiB D-cache) to L2-warm (512 KiB shared): warm-buffer figures.
 *
 * Clocks. The core cycle count of every trial is read from the PMU cycle counter
 * through perf_event_open (user-mode cycles of this thread) when the kernel offers
 * it; the wall-clock time of the same trial is always recorded, and cycles/byte
 * from it uses the CPU's scaling_cur_freq read before and after the cell (the
 * board is pinned to the performance governor at 1296 MHz for a campaign, and a
 * cell whose two readings differ is flagged). Median over trials is reported.
 *
 * Usage: bench_a7 [--trials N] [--csv FILE] [--only SUBSTR]
 * Run pinned: taskset -c 3 ./bench_a7 --csv a7-board.csv */
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "ascon_aead.h"
#include "blockctr.h"
#include "chacha20.h"

static double now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    return t.tv_sec * 1e9 + t.tv_nsec;
}

static int perf_fd = -1;
static void perf_open(void)
{
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_HARDWARE;
    a.size = sizeof a;
    a.config = PERF_COUNT_HW_CPU_CYCLES;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    perf_fd = (int)syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
    if (perf_fd >= 0) {
        ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    }
}
static uint64_t cycles(void)
{
    uint64_t v = 0;
    if (perf_fd < 0 || read(perf_fd, &v, sizeof v) != sizeof v) return 0;
    return v;
}

static char freq_path[128];
static long cur_khz(void)
{
    FILE *f = fopen(freq_path, "r");
    long khz = 0;
    if (f) { if (fscanf(f, "%ld", &khz) != 1) khz = 0; fclose(f); }
    return khz;
}
static long temp_mc(void)
{
    FILE *f = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
    long t = 0;
    if (f) { if (fscanf(f, "%ld", &t) != 1) t = 0; fclose(f); }
    return t;
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

/* Times fn(arg) processing `bytes` bytes per call. Each trial repeats the call
 * enough times to last >= 20 ms; the median over trials is reported. */
static void measure(const cell *c, size_t bytes, void (*fn)(void *), void *arg)
{
    for (int w = 0; w < 3; w++) fn(arg);
    int reps = 1;
    for (;;) {
        double t0 = now_ns();
        for (int i = 0; i < reps; i++) fn(arg);
        if (now_ns() - t0 > 20e6) break;
        reps *= 2;
    }
    long khz0 = cur_khz(), t0c = temp_mc();
    double ns[64], cyc[64];
    for (int t = 0; t < trials; t++) {
        uint64_t c0 = cycles();
        double t0 = now_ns();
        for (int i = 0; i < reps; i++) fn(arg);
        double t1 = now_ns();
        uint64_t c1 = cycles();
        ns[t] = (t1 - t0) / ((double)reps * bytes);
        cyc[t] = (double)(c1 - c0) / ((double)reps * bytes);
    }
    long khz1 = cur_khz(), t1c = temp_mc();
    qsort(ns, trials, sizeof ns[0], cmp_d);
    qsort(cyc, trials, sizeof cyc[0], cmp_d);
    double nsb = ns[trials / 2], pmu = perf_fd >= 0 ? cyc[trials / 2] : -1;
    double wall_cpb = khz0 == khz1 && khz0 > 0 ? nsb * khz0 / 1e6 : -1;
    double mbit = 8e3 / nsb;
    printf("%-10s %-22s %-6s L=%-2u %6zu B  %8.2f c/B (pmu)  %8.2f c/B (wall@%ld MHz)  %8.1f Mbit/s"
           "  (min %.3f max %.3f ns/B, %.1f/%.1f C)%s\n",
           c->cipher, c->impl, c->mode, c->lanes, c->size, pmu, wall_cpb, khz0 / 1000, mbit, ns[0],
           ns[trials - 1], t0c / 1e3, t1c / 1e3, khz0 != khz1 ? "  CLOCK CHANGED" : "");
    if (csv)
        fprintf(csv, "a7,%s,%s,%s,%u,%zu,%d,%.5f,%.5f,%.5f,%.4f,%.4f,%.2f,%ld,%ld,%.1f,%.1f\n", c->cipher,
                c->impl, c->mode, c->lanes, c->size, trials, nsb, ns[0], ns[trials - 1], pmu, wall_cpb, mbit,
                khz0, khz1, t0c / 1e3, t1c / 1e3);
    fflush(stdout);
    if (csv) fflush(csv);
}

/* ---- workloads ---- */
static uint8_t key32[32], nonce12[12];
#define JOBS 8
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

static int skip(const char *cipher, const char *impl, const char *only)
{
    return only && !strstr(impl, only) && !strstr(cipher, only);
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
    perf_open();
    printf("cpu %d, %ld kHz, perf cycles %s\n", sched_getcpu(), cur_khz(), perf_fd >= 0 ? "on" : "UNAVAILABLE");
    if (csv)
        fprintf(csv, "target,cipher,impl,mode,lanes,size_bytes,trials,ns_per_byte,ns_per_byte_min,ns_per_byte_max,"
                     "pmu_cyc_per_byte,wall_cyc_per_byte,mbit_per_sec,khz_before,khz_after,temp_c_before,temp_c_after\n");
    for (int i = 0; i < 32; i++) key32[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 12; i++) nonce12[i] = (uint8_t)(i * 13 + 5);
    static const size_t sizes[] = {64, 1536, 4096};
    const int NS = sizeof sizes / sizeof sizes[0];
    uint8_t *buf = aligned_alloc(64, (size_t)JOBS * (4096 + 64));
    memset(buf, 0xA5, (size_t)JOBS * (4096 + 64));
    static uint8_t keys[JOBS][16], nonces[JOBS][16];
    for (int j = 0; j < JOBS; j++)
        for (int i = 0; i < 16; i++) { keys[j][i] = (uint8_t)(j * 31 + i); nonces[j][i] = (uint8_t)(j * 17 + 3 * i); }

    for (const chacha20_impl *im = chacha20_impls; im->name; im++) {
        if ((im->available && !im->available()) || skip("chacha20", im->name, only)) continue;
        for (int s = 0; s < NS; s++) {
            chacha_arg a = {im, buf, sizes[s]};
            cell c = {"chacha20", im->name, "single", im->lanes, sizes[s]};
            measure(&c, sizes[s] * JOBS, run_chacha, &a);
        }
    }
    for (const ascon_impl *im = ascon_impls; im->name; im++) {
        if ((im->available && !im->available()) || skip("ascon128", im->name, only)) continue;
        for (int s = 0; s < NS; s++) {
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
        if ((im->available && !im->available()) || skip(im->cipher, im->name, only)) continue;
        size_t csz = (im->ctx_size + BC_CTX_ALIGN - 1) / BC_CTX_ALIGN * BC_CTX_ALIGN;
        void *ctx = aligned_alloc(BC_CTX_ALIGN, csz);
        if (!ctx) { perror("ctx"); return 1; }
        im->setup(ctx, key32); /* AES-128 uses the first 16 bytes */
        for (int s = 0; s < NS; s++) {
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
