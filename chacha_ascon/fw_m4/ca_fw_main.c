/* On-board Cortex-M4 (STM32F407, 168 MHz) measurement of every ChaCha20 /
 * Ascon-AEAD128 implementation and every block-cipher CTR implementation
 * (AES-128-CTR, Qalqan-CTR; include/blockctr.h) in the M4 build. Same harness rules as the
 * project's PRESENT firmware (fw/m4/bench_m4_main.c):
 *
 *   Correctness first. tests/test_ca.c -- every KAT file, every placement, every
 *   lane count, the same code the qemu gate runs -- executes on the board before
 *   anything is timed. One exception, forced by 128 KiB of SRAM: long vectors
 *   longer than KAT_MAX_LEN (4097 B; the 8 KiB..64 KiB ones, 8 records per
 *   implementation) are skipped here and reported as skipped; they run under qemu
 *   for the same sources. Then tests/test_bc.c (every bc_impl: block KATs,
 *   SP 800-38A, and the reference-CTR comparison over all lengths incl.
 *   partial tails, counter wrap, in place, misaligned, canaries) runs in full,
 *   also the same code as the qemu gate. If either reports any failure, no
 *   timing row is printed at all (KAT_END status = the sum of both failure
 *   counts, status line KAT_FAIL), so a number cannot outlive a failing
 *   implementation. Last, bc_guard_test() runs every bc_impl with its buffers
 *   butted against MPU no-access regions, which catches out-of-range reads
 *   (the canaries only catch writes).
 *
 *   The clock is measured. system_init() brings the core to 168 MHz, enables
 *   flash prefetch + ART (configuration "product": code in flash, 5 wait
 *   states), and measures SYSCLK against the 32.768 kHz LSE; the header states
 *   the measured value. cycles/byte needs no clock; Mbit/s uses the measured one
 *   and is left empty if the measurement is not in tolerance.
 *
 *   The timed operation is the one the qemu model priced (bench/bench_arm.c):
 *   one call of the implementation's entry point, ChaCha20 XOR, Ascon
 *   encrypt+tag with no AD, or block-cipher CTR XOR (key setup done once,
 *   outside the timing), for 64 / 1536 / 4096-byte messages, multi-stream
 *   Ascon implementations given `lanes` messages (a CTR implementation's lanes
 *   are blocks per inner iteration of one message, payload = msg); DWT CYCCNT around the call with
 *   interrupts masked, one warm call first, then TRIALS timed calls; min and
 *   median reported. The empty-measurement overhead (CYCCNT read pair) is
 *   measured and subtracted.
 *
 * Output: CSV over semihosting (st-util prints it), parsed by tools/m4_board.py. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "ascon_aead.h"
#include "blockctr.h"
#include "chacha20.h"
#include "semihost.h"
#include "system_init.h"
#include "timing.h"

int test_main(void);    /* tests/test_ca.c, compiled with -Dmain=test_main */
int test_bc_main(void); /* tests/test_bc.c, compiled with -Dmain=test_bc_main */

/* ---- minimal newlib-nano system layer: stdout -> SYS_WRITE0, heap in SRAM ---- */
extern char _ebss, _estack;
#define STACK_RESERVE (16 * 1024)
void *_sbrk(ptrdiff_t inc)
{
    static char *brk = &_ebss;
    char *old = brk;
    if (brk + inc > &_estack - STACK_RESERVE) { errno = ENOMEM; return (void *)-1; }
    brk += inc;
    return old;
}
int _write(int fd, const char *p, int n)
{
    (void)fd;
    static char b[129];
    int done = 0;
    while (done < n) {
        int k = n - done < 128 ? n - done : 128;
        memcpy(b, p + done, k);
        b[k] = 0;
        for (int i = 0; i < k; i++) if (!b[i]) b[i] = ' ';  /* SYS_WRITE0 stops at NUL */
        sh_write0(b);
        done += k;
    }
    return n;
}
int _read(int fd, char *p, int n) { (void)fd; (void)p; (void)n; return 0; }
int _close(int fd) { (void)fd; return -1; }
int _fstat(int fd, struct stat *st) { (void)fd; st->st_mode = S_IFCHR; return 0; }
int _isatty(int fd) { (void)fd; return 1; }
int _lseek(int fd, int off, int wh) { (void)fd; (void)off; (void)wh; return 0; }
int _getpid(void) { return 1; }
int _kill(int pid, int sig) { (void)pid; (void)sig; errno = EINVAL; return -1; }
void _exit(int code)
{
    printf("EXIT %d\n", code);
    fflush(stdout);
    sh_exit();
    for (;;) { }
}

/* ---- timing ---- */
#define TRIALS 7
#define MAXL 4
/* Timing buffers come from the heap after the KAT run has freed everything, so
 * they are in SRAM (as in config product) without shrinking the KAT heap. */
static uint8_t (*buf_in)[4096 + 16], (*buf_out)[4096 + 32];

static uint32_t overhead;

static void sort_u32(uint32_t *a, int n)
{
    for (int i = 1; i < n; i++)
        for (int j = i; j > 0 && a[j - 1] > a[j]; j--) { uint32_t t = a[j]; a[j] = a[j - 1]; a[j - 1] = t; }
}

static void row(const char *cipher, const char *impl, unsigned lanes, size_t msg, size_t total,
                uint32_t *c, uint32_t hz)
{
    sort_u32(c, TRIALS);
    uint32_t mn = c[0] - overhead, med = c[TRIALS / 2] - overhead;
    double cpb = (double)med / total;
    char mbit[32] = "";
    if (system_clock_meas_status() == SYSCLK_MEAS_OK)
        snprintf(mbit, sizeof mbit, "%.3f", (double)total * 8 / ((double)med / hz) / 1e6);
    printf("%s,%s,%u,%lu,%lu,%lu,%lu,%.3f,%.3f,%.4f,%s\n", cipher, impl, lanes, (unsigned long)msg,
           (unsigned long)total, (unsigned long)med, (unsigned long)mn, cpb, (double)mn / total, cpb / 8, mbit);
}

/* ---- MPU read/write-bounds gate for the block-cipher CTR kernels ----
 * test_bc's canaries catch a stray write but not a stray read, and the M4
 * assembly kernels are not ASan-instrumented. Here every bc_impl runs with its
 * input and its output butted against 32-byte MPU regions with no access at
 * all (AP=000, also for privileged code): one directly before the data, one
 * directly after. Any load or store outside [in, in+len) / [out, out+len) that
 * reaches a neighbouring 32 bytes raises MemManage; the handler prints
 * MPU_GUARD_FAULT and ends the run at sh_exit, so the run has no KAT_END
 * status=0 and tools/m4_board.py writes nothing. Each length is run butted
 * against the end guard (so odd lengths also start misaligned), butted against
 * the start guard, and both again in place. GUARD_SELFTEST builds a firmware
 * that reads one byte past the end on purpose, to show the gate fires. */
#define REG32(a) (*(volatile uint32_t *)(a))
#define SCB_VTOR   REG32(0xE000ED08u)
#define SCB_SHCSR  REG32(0xE000ED24u)
#define MPU_TYPE   REG32(0xE000ED90u)
#define MPU_CTRL   REG32(0xE000ED94u)
#define MPU_RNR    REG32(0xE000ED98u)
#define MPU_RBAR   REG32(0xE000ED9Cu)
#define MPU_RASR   REG32(0xE000EDA0u)
#define GUARD 32u
#define GDATA (4096u + 64u) /* multiple of 32 */
#define NVECT 128u          /* >= 16 + 82 STM32F407 IRQs, table aligned to 512 */
static uint8_t garena[2][GUARD + GDATA + GUARD] __attribute__((aligned(32)));
static uint32_t vtab_sram[NVECT] __attribute__((aligned(512)));
static const char *volatile guard_cur = "?";

static void guard_fault(void)
{
    sh_write0("MPU_GUARD_FAULT impl=");
    sh_write0(guard_cur);
    sh_write0("\n");
    sh_exit();
    for (;;) { }
}

static void mpu_region(uint32_t n, const void *base)
{
    MPU_RNR = n;
    MPU_RBAR = (uint32_t)base;
    MPU_RASR = (1u << 28) /* XN */ | (0u << 24) /* AP: no access */ | (4u << 1) /* 2^(4+1)=32 B */ | 1u;
}

static int bc_guard_test(void)
{
    if (((MPU_TYPE >> 8) & 0xff) < 4) { printf("bc MPU guard: FAILED (no MPU)\n"); return 1; }
    const uint32_t *v = (const uint32_t *)SCB_VTOR;
    for (unsigned i = 0; i < NVECT; i++) vtab_sram[i] = v[i];
    vtab_sram[3] = vtab_sram[4] = vtab_sram[5] = vtab_sram[6] = (uint32_t)guard_fault; /* thumb bit set by the linker */
    uint32_t old_vtor = SCB_VTOR;
    __asm volatile("dsb" ::: "memory");
    SCB_VTOR = (uint32_t)vtab_sram;
    SCB_SHCSR |= 1u << 16; /* MEMFAULTENA */
    for (int a = 0; a < 2; a++) {
        mpu_region(2 * a, garena[a]);
        mpu_region(2 * a + 1, garena[a] + GUARD + GDATA);
    }
    MPU_CTRL = 5; /* ENABLE | PRIVDEFENA: everything else keeps the default map */
    __asm volatile("dsb\n\tisb" ::: "memory");
#ifdef GUARD_SELFTEST
    guard_cur = "selftest-read-past-end";
    printf("guard selftest: reading one byte past the end\n");
    fflush(stdout);
    (void)*(volatile uint8_t *)(garena[0] + GUARD + GDATA);
    printf("guard selftest: NOT CAUGHT\n");
#endif
    static const size_t lens[] = {1, 2, 3, 7, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 95, 96, 97,
                                  127, 128, 129, 255, 256, 257, 1000, 1536, 4095, 4096, 4103};
    static uint8_t gctx[512] __attribute__((aligned(BC_CTX_ALIGN)));
    uint8_t key[32], nonce[12];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x5a ^ i);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(0xa5 ^ i);
    uint8_t *lo_in = garena[0] + GUARD, *lo_out = garena[1] + GUARD;
    uint8_t *hi_in = lo_in + GDATA, *hi_out = lo_out + GDATA;
    unsigned runs = 0;
    int fails = 0;
    for (const bc_impl *im = bc_impls; im->name; im++) {
        if (im->available && !im->available()) continue;
        if (im->ctx_size > sizeof gctx) { printf("bc MPU guard: FAILED (ctx %s)\n", im->name); fails++; continue; }
        guard_cur = im->name;
        im->setup(gctx, key);
        for (unsigned li = 0; li < sizeof lens / sizeof lens[0]; li++) {
            size_t n = lens[li];
            if (n > GDATA) { fails++; continue; }
            static const uint32_t ctrs[] = {0, 0xFFFFFFFFu};
            for (unsigned c = 0; c < 2; c++) {
                im->xor_fn(gctx, hi_out - n, hi_in - n, n, nonce, ctrs[c]); /* butted against the end */
                im->xor_fn(gctx, lo_out, lo_in, n, nonce, ctrs[c]);         /* butted against the start */
                im->xor_fn(gctx, hi_out - n, hi_out - n, n, nonce, ctrs[c]); /* in place, end */
                im->xor_fn(gctx, lo_out, lo_out, n, nonce, ctrs[c]);         /* in place, start */
                runs += 4;
            }
        }
    }
    guard_cur = "?";
    MPU_CTRL = 0;
    __asm volatile("dsb\n\tisb" ::: "memory");
    SCB_VTOR = old_vtor;
    __asm volatile("dsb\n\tisb" ::: "memory");
    printf("bc MPU guard: %s (%u runs, 32-byte no-access regions before and after in and out)\n",
           fails ? "FAILED" : "ok", runs);
    return fails;
}

int main(void)
{
    uint32_t hz = system_measure_sysclk_hz();
    printf("# board: STM32F407 (Cortex-M4F), config product: code in flash, 5 WS, prefetch+ART on\n");
    printf("# clock: source=%s pll=%d measured_hz=%lu meas_status=%d (1=ok)\n",
           system_clock_source() == SYSCLK_SRC_HSE ? "HSE" : "HSI", system_pll_status(), (unsigned long)hz,
           system_clock_meas_status());

    printf("KAT_BEGIN\n");
    fflush(stdout);
    int fails = test_main();  /* 0 only if every implementation passed every vector */
    fflush(stdout);
    fails += test_bc_main();   /* likewise for every block-cipher CTR implementation */
    fflush(stdout);
    fails += bc_guard_test();  /* no CTR kernel touches a byte outside its buffers */
    printf("KAT_END status=%d\n", fails);
    if (fails) {
        printf("STATUS KAT_FAIL -- nothing timed\n");
        fflush(stdout);
        sh_exit();
        for (;;) { }
    }

    buf_in = malloc(sizeof *buf_in * MAXL);
    buf_out = malloc(sizeof *buf_out * MAXL);
    if (!buf_in || !buf_out) { printf("STATUS NO_MEMORY\n"); fflush(stdout); sh_exit(); for (;;) { } }
    printf("# buffers: in=%p out=%p\n", (void *)buf_in, (void *)buf_out);

    /* empty measurement: the CYCCNT read pair itself */
    uint32_t e[TRIALS];
    for (int i = 0; i < TRIALS; i++) { uint32_t s = cyc_begin(); e[i] = cyc_end(s); }
    sort_u32(e, TRIALS);
    overhead = e[0];
    printf("# timer_overhead_cycles=%lu (subtracted), trials=%d, reported=median (min also)\n",
           (unsigned long)overhead, TRIALS);

    uint8_t key[32], nonce[16];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 16; i++) nonce[i] = (uint8_t)(i * 5 + 3);
    for (int l = 0; l < MAXL; l++)
        for (int i = 0; i < 4096 + 16; i++) buf_in[l][i] = (uint8_t)(i * 31 + l * 101);
    static const size_t sizes[] = {64, 1536, 4096};
    uint32_t sum = 0, c[TRIALS];

    printf("CSV_BEGIN\n");
    printf("cipher,impl,lanes,msg_bytes,payload_bytes,cycles_median,cycles_min,cycles_per_byte,"
           "cycles_per_byte_min,cycles_per_bit,mbit_per_sec\n");
    for (const chacha20_impl *im = chacha20_impls; im->name; im++)
        for (unsigned s = 0; s < 3; s++) {
            size_t n = sizes[s];
            im->xor_fn(buf_out[0], buf_in[0], n, key, nonce, 1);
            for (int t = 0; t < TRIALS; t++) {
                uint32_t st = cyc_begin();
                im->xor_fn(buf_out[0], buf_in[0], n, key, nonce, 1);
                c[t] = cyc_end(st);
            }
            sum += buf_out[0][n - 1];
            row("chacha20", im->name, im->lanes, n, n, c, hz);
        }
    for (const ascon_impl *im = ascon_impls; im->name; im++)
        for (unsigned s = 0; s < 3; s++) {
            size_t n = sizes[s];
            unsigned L = im->enc ? 1 : im->lanes;
            ascon_job jobs[MAXL];
            for (unsigned l = 0; l < L; l++) jobs[l] = (ascon_job){buf_out[l], buf_in[l], NULL, nonce, key};
            unsigned long long clen;
            if (im->enc) im->enc(buf_out[0], &clen, buf_in[0], n, NULL, 0, NULL, nonce, key);
            else im->multi(jobs, L, n, 0);
            for (int t = 0; t < TRIALS; t++) {
                uint32_t st = cyc_begin();
                if (im->enc) im->enc(buf_out[0], &clen, buf_in[0], n, NULL, 0, NULL, nonce, key);
                else im->multi(jobs, L, n, 0);
                c[t] = cyc_end(st);
            }
            sum += buf_out[0][n + 15];
            row("ascon128", im->name, L, n, (size_t)L * n, c, hz);
        }
    static uint8_t bc_ctx[512] __attribute__((aligned(BC_CTX_ALIGN)));
    for (const bc_impl *im = bc_impls; im->name; im++) {
        if (im->available && !im->available()) continue; /* reported SKIPPED by the KAT run */
        if (im->ctx_size > sizeof bc_ctx) { printf("STATUS BC_CTX_TOO_SMALL %s\n", im->name); break; }
        im->setup(bc_ctx, key); /* key expansion: not timed */
        for (unsigned s = 0; s < 3; s++) {
            size_t n = sizes[s];
            im->xor_fn(bc_ctx, buf_out[0], buf_in[0], n, nonce, 1);
            for (int t = 0; t < TRIALS; t++) {
                uint32_t st = cyc_begin();
                im->xor_fn(bc_ctx, buf_out[0], buf_in[0], n, nonce, 1);
                c[t] = cyc_end(st);
            }
            sum += buf_out[0][n - 1];
            row(im->cipher, im->name, im->lanes, n, n, c, hz);
        }
    }
    printf("CSV_END checksum=%08lx\n", (unsigned long)sum);
    fflush(stdout);
    sh_exit();
    for (;;) { }
}
