/* fw/m4/ctr_m4_main.c -- the complete counter-mode workload on the STM32F407.
 *
 * This is the byte-oriented question the whole Cortex-M4 side of the paper exists
 * to answer: not "how fast is the round function once the state is already
 * bitsliced" (that is fw/m4/bench_m4_main.c, the kernel ceiling), but "how many
 * bytes of real video can this device actually process in counter mode" -- with the
 * counters generated, the keystream materialised big-endian, and the XOR done in
 * place, every step inside the timed region. A bitsliced backend pays its transpose
 * here; a table backend pays its serialisation. That is the honest number, and it is
 * the one the 12 Mbit/s verdict is derived from.
 *
 * One cipher per image, via -DM4_ONE_CIPHER=<slug> (fw/m4/one_cipher.h), so an
 * image's .text is that cipher's code and nothing else -- the same per-cipher split
 * fw/m4/bench_m4_main.c uses. The 64 KiB working buffer is XORed in place in SRAM;
 * the ~33 KiB encryption context (PRESENT_ENC_ONLY) is borrowed from CCM. In-place
 * is what makes it fit: a separate output buffer would want another 64 KiB and there
 * is not another 64 KiB.
 *
 * Two build shapes from this one file:
 *
 *   the tuning image   (no -DM4_CTR_WINNER)  times every applicable CTR backend for
 *                      this cipher and emits one row each. This is the portfolio the
 *                      winner is chosen from, on the correct operation.
 *
 *   the published image (-DM4_CTR_WINNER=<fn> -DM4_CTR_WINNER_NAME='"ctr-..."') puts
 *                      exactly the winning backend behind `ctr_timed_kernel`, the
 *                      symbol Task 2 pins to 0x08010000 in .timed so a published
 *                      figure cannot depend on which routine happened to precede it.
 *                      The winner is frozen from the committed tuning table before
 *                      this image is measured; DWT is deterministic, so the published
 *                      row reproduces the tuning row rather than re-deciding it.
 *
 * Nothing is timed until it is proven correct on the board: kat_check_all() clears
 * the underlying kernels against the host's vectors, and ctr_selfcheck() then clears
 * the counter-mode wrapping (counter generation, transpose, keystream XOR) of every
 * backend against ctr-ref, the byte-at-a-time oracle. A backend that reproduces a
 * different keystream is emitted as KAT_FAIL with no timings.
 *
 * Built with -DPRESENT_ENC_ONLY, linking src/keyschedule_portable.c and never
 * src/keyschedule.c (which uses __int128, absent on this target).
 */
#include <stdint.h>
#include <string.h>

#include "kat.h"
#include "semihost.h"
#include "system_init.h"
#include "timing.h"

#include "present/present.h"
#include "present/variant.h"
#include "present_ctr.h"   /* present_ctr_counters64 / present_ctr_counters32 */
#include "ctr_xor.h"       /* bench/ctr_xor.h: ctr_xor_be64, ctr_store_be64, ctr_xor_bytes */
#include "wide_ciphers.h"  /* AES and AES-lin444: the 128-bit pair */

#include "one_cipher.h"

/* A CTR image is one cipher, so exactly one family is compiled in. The combined
 * shape (all three families) is bench_m4_main.c's; this file always narrows. */
#ifndef M4_ONE_CIPHER
#error "ctr_m4_main.c is a per-cipher image; build it with -DM4_ONE_CIPHER=<slug>"
#endif
#if (M4_BUILD_NARROW + M4_BUILD_AES + M4_BUILD_LIN) != 1
#error "exactly one cipher family must be selected"
#endif

/* -------------------------------------------------------------------------------- */

/* Set by M4_DEFS_<config> for flash-noart / sram-noart; product passes nothing. */
#ifndef M4_CONFIG
#define M4_CONFIG "product"
#endif

#define TRIALS 15
#define WARMUP 3

/* TIMED runs WARMUP discarded passes then TRIALS recorded ones over the same work,
 * leaving the per-trial cycle counts in samples[]. Interrupts are masked across each
 * measured region by cyc_begin/cyc_end (fw/m4/timing.h). Nothing inside a TIMED body
 * may touch the semihosting channel: every sh_* call traps to the host and would be
 * counted. Defined before use, unlike the body it wraps. */
#define TIMED(...)                                              \
    do {                                                       \
        for (int t_ = -WARMUP; t_ < TRIALS; t_++) {            \
            uint32_t c0_ = cyc_begin();                        \
            __VA_ARGS__;                                       \
            uint32_t d_ = cyc_end(c0_);                        \
            if (t_ >= 0) samples[t_] = d_;                     \
        }                                                      \
    } while (0)

/* 64 KiB, the working set bench/ctr_bench.c publishes and the video frame budget the
 * paper reasons about. A multiple of every backend's group: 512 B (bitslice-u64),
 * 256 B (bitslice-u32), 128 B (table-x16 and wide-x8), down to one block. */
#define CTR_WS_BYTES 65536u

/* Not zero, and chosen to carry across a 32-bit boundary partway through the buffer
 * (0xFFFFFF80 + the buffer's block count wraps the low word): a backend that keeps
 * its counter in 32 bits, or that ignores ctr0, computes a different keystream and
 * is caught by ctr_selfcheck() before it is ever timed. Matches the ctr0 the host
 * correctness gate (tests/test_ctr.c) uses. */
#define CTR0 0x00000000FFFFFF80ull

#if M4_ONE_BB == 8
#define CTR_BLOCK_BYTES 8u
#else
#define CTR_BLOCK_BYTES 16u
#endif

/* The workload buffer: SRAM (.bss), not CCM. CCM holds the context. In place. */
static uint8_t ctr_buf[CTR_WS_BYTES];

/* Small correctness scratch: one backend's output and the oracle's, compared. 512 B
 * is one bitslice-u64 group and a whole multiple of every other group. */
#define CTR_KAT_BYTES 512u
static uint8_t kat_a[CTR_KAT_BYTES];
static uint8_t kat_b[CTR_KAT_BYTES];

/* Written but never usefully read: keeps -O3 from deleting a timed pass whose only
 * effect is on ctr_buf. */
static volatile uint8_t ctr_sink;

static uint32_t samples[TRIALS];

/* The measured core clock, read once so every row divides by the same number. */
static uint32_t clk_hz;
static int clk_ok;

/* ---- the CTR backends --------------------------------------------------------
 *
 * Each is a complete counter-mode pass over buf[0..len): generate the counters,
 * encrypt, materialise the keystream, XOR in place. `st` is the prepared state --
 * a present_ctx_t for the 64-bit ciphers, an aes_key_t / lin_key_t for the 128-bit
 * pair. noinline so each is its own symbol and the tuning image times a real call,
 * not an inlined copy folded into the loop around it.
 */
typedef void (*ctr_fn)(const void *st, uint8_t *buf, size_t len, uint64_t ctr0);

#if M4_BUILD_NARROW

/* ctr-ref: the oracle. Counter serialised and keystream XORed byte at a time, the
 * form a reader checks against the specification -- and the form ctr_selfcheck()
 * clears every measured backend against. Its speed is irrelevant. */
__attribute__((noinline))
static void ctr_ref(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const present_ctx_t *ctx = st;
    for (size_t off = 0; off < len; off += 8) {
        uint64_t ks = present_encrypt_ref(ctx, ctr0 + off / 8);
        for (int b = 0; b < 8; b++)
            buf[off + b] ^= (uint8_t)(ks >> (56 - 8 * b));
    }
}

__attribute__((noinline))
static void ctr_table(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const present_ctx_t *ctx = st;
    for (size_t off = 0; off < len; off += 8)
        ctr_xor_be64(buf + off, present_encrypt_table(ctx, ctr0 + off / 8));
}

/* ctr-table-xN: N blocks per iteration through the batched table kernel. len is a
 * multiple of N*8 (CTR_WS_BYTES and CTR_KAT_BYTES both are), so there is no
 * partial-group path -- the same shape the host backend has. */
static inline void ctr_table_xN(
    const present_ctx_t *ctx, uint8_t *buf, size_t len, uint64_t ctr0,
    void (*enc)(const present_ctx_t *, const uint64_t *, uint64_t *), int n)
{
    uint64_t in[16], ks[16];
    for (size_t off = 0; off < len; off += (size_t)n * 8) {
        for (int i = 0; i < n; i++) in[i] = ctr0 + off / 8 + (uint64_t)i;
        enc(ctx, in, ks);
        for (int i = 0; i < n; i++) ctr_xor_be64(buf + off + 8 * i, ks[i]);
    }
}

#define DEFINE_TABLE_X(n) \
    __attribute__((noinline)) \
    static void ctr_table_x##n(const void *st, uint8_t *buf, size_t len, uint64_t ctr0) \
    { ctr_table_xN(st, buf, len, ctr0, present_encrypt_table_x##n, n); }
DEFINE_TABLE_X(2)
DEFINE_TABLE_X(4)
DEFINE_TABLE_X(8)
DEFINE_TABLE_X(16)
#undef DEFINE_TABLE_X

/* ctr-bitslice-u64: the honest bitsliced backend. present_ctr_counters64() produces
 * the 64 counters already in bitsliced form -- no input transpose -- the kernel
 * ping-pongs and returns the buffer holding the answer, present_transpose64() brings
 * it back to blocks, and the keystream is XORed in place. Every step is timed; the
 * transpose is the price a byte-oriented caller actually pays and it is charged here.
 * The scratch is automatic (~1.5 KiB), the only legal home per bench/ctr_backend.h. */
__attribute__((noinline))
static void ctr_bs_u64(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const present_ctx_t *ctx = st;
    uint64_t state[PRESENT_BLOCK_BITS], scratch[PRESENT_BLOCK_BITS];
    uint64_t ks[PRESENT_BITSLICE_BLOCKS];
    for (size_t off = 0; off < len; off += (size_t)PRESENT_BITSLICE_BLOCKS * 8) {
        present_ctr_counters64(state, ctr0 + off / 8);
        present_transpose64(present_encrypt_bitslice_bs(ctx, state, scratch), ks);
        for (int i = 0; i < PRESENT_BITSLICE_BLOCKS; i++)
            ctr_xor_be64(buf + off + 8 * i, ks[i]);
    }
}

/* ctr-bitslice-u32: the 32-block, 32-bit-word form. state/scratch are still
 * PRESENT_BLOCK_BITS words -- one per state bit, not per block -- because the kernel
 * writes 64 words for 32 blocks; sizing them by the block count writes half. */
__attribute__((noinline))
static void ctr_bs_u32(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const present_ctx_t *ctx = st;
    uint32_t state[PRESENT_BLOCK_BITS], scratch[PRESENT_BLOCK_BITS];
    uint64_t ks[PRESENT_BITSLICE32_BLOCKS];
    for (size_t off = 0; off < len; off += (size_t)PRESENT_BITSLICE32_BLOCKS * 8) {
        present_ctr_counters32(state, ctr0 + off / 8);
        present_bitslice32_unpack(present_encrypt_bitslice32_bs(ctx, state, scratch), ks);
        for (int i = 0; i < PRESENT_BITSLICE32_BLOCKS; i++)
            ctr_xor_be64(buf + off + 8 * i, ks[i]);
    }
}

#else /* the 128-bit pair: AES and AES-lin444 */

#define WBB 16

#if M4_BUILD_AES
/* Batches through aes_encrypt4 where n allows, scalar for the remainder -- one
 * encode serves n = 1, 4, 8. rounds is this image's one round count, a compile-time
 * constant from the generated cipher set, never a literal. */
static inline void wide_encode(const void *st, const uint8_t *in, uint8_t *out, int n)
{
    const aes_key_t *k = st;
    int i = 0;
    for (; i + 4 <= n; i += 4) aes_encrypt4(k, M4_ONE_ROUNDS, in + WBB * i, out + WBB * i);
    for (; i < n; i++)          aes_encrypt1(k, M4_ONE_ROUNDS, in + WBB * i, out + WBB * i);
}
#else /* M4_BUILD_LIN */
static inline void wide_encode(const void *st, const uint8_t *in, uint8_t *out, int n)
{
    const lin_key_t *k = st;
    for (int i = 0; i < n; i++)
        lin_encrypt_ref(k, M4_ONE_ROUNDS, in + WBB * i, out + WBB * i);
}
#endif

/* n counter blocks built (high 64 bits zero, low 64 bits the big-endian counter),
 * encoded together, keystream XORed in place. */
static inline void ctr_wide_n(const void *st, uint8_t *buf, size_t len, uint64_t ctr0, int n)
{
    uint8_t in[8 * WBB], ks[8 * WBB];
    for (size_t off = 0; off < len; off += (size_t)n * WBB) {
        for (int i = 0; i < n; i++) {
            uint64_t c = ctr0 + off / WBB + (uint64_t)i;
            uint8_t *blk = in + WBB * i;
            memset(blk, 0, 8);
            ctr_store_be64(blk + 8, c);
        }
        wide_encode(st, in, ks, n);
        ctr_xor_bytes(buf + off, ks, (size_t)n * WBB);
    }
}

/* ctr-ref: byte-at-a-time counter and XOR, the oracle. */
__attribute__((noinline))
static void ctr_ref(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    uint8_t in[WBB], ks[WBB];
    for (size_t off = 0; off < len; off += WBB) {
        uint64_t c = ctr0 + off / WBB;
        memset(in, 0, 8);
        for (int b = 0; b < 8; b++) in[8 + b] = (uint8_t)(c >> (56 - 8 * b));
        wide_encode(st, in, ks, 1);
        for (int b = 0; b < WBB; b++) buf[off + b] ^= ks[b];
    }
}

__attribute__((noinline))
static void ctr_table(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{ ctr_wide_n(st, buf, len, ctr0, 1); }

#if M4_BUILD_AES
__attribute__((noinline))
static void ctr_table_x4(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{ ctr_wide_n(st, buf, len, ctr0, 4); }
__attribute__((noinline))
static void ctr_table_x8(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{ ctr_wide_n(st, buf, len, ctr0, 8); }
#endif

#endif /* family */

/* The portfolio for this image's cipher. ctr-ref first: it is the oracle the rest
 * are cleared against, and it is a measured row too. */
typedef struct { const char *name; ctr_fn fn; } ctr_impl_t;
static const ctr_impl_t IMPLS[] = {
#if M4_BUILD_NARROW
    { "ctr-ref",          ctr_ref },
    { "ctr-table",        ctr_table },
    { "ctr-table-x2",     ctr_table_x2 },
    { "ctr-table-x4",     ctr_table_x4 },
    { "ctr-table-x8",     ctr_table_x8 },
    { "ctr-table-x16",    ctr_table_x16 },
    { "ctr-bitslice-u64", ctr_bs_u64 },
    { "ctr-bitslice-u32", ctr_bs_u32 },
#elif M4_BUILD_AES
    { "ctr-ref",          ctr_ref },
    { "ctr-table",        ctr_table },
    { "ctr-table-x4",     ctr_table_x4 },
    { "ctr-table-x8",     ctr_table_x8 },
#else /* M4_BUILD_LIN: lin_encrypt_ref is the only kernel; ref and table wrap it */
    { "ctr-ref",          ctr_ref },
    { "ctr-table",        ctr_table },
#endif
};
#define N_IMPLS ((int)(sizeof IMPLS / sizeof IMPLS[0]))

/* The published image's timed kernel: the frozen winner, pinned to 0x08010000. Its
 * body is one call so the winner's own code (in .text) is what runs; the .timed
 * symbol is the fixed anchor a layout sweep shifts against, per Task 2. */
#ifdef M4_CTR_WINNER
void M4_CTR_WINNER(const void *st, uint8_t *buf, size_t len, uint64_t ctr0);
/* noclone as well as noinline: main() calls this with CTR_WS_BYTES and CTR0 both
 * constant, so -O3 otherwise emits a constant-propagated ctr_timed_kernel.constprop.0
 * clone that lands first in .timed at 0x08010000 while the named symbol slips to a
 * higher address -- and the pinned-address contract, and tools/tests/test_m4_layout.py,
 * are about the named symbol. noclone keeps ctr_timed_kernel the one function at the
 * pin, which is also what makes the layout sweep move the code it means to. */
__attribute__((section(".timed"), aligned(16), noinline, noclone, used))
void ctr_timed_kernel(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    M4_CTR_WINNER(st, buf, len, ctr0);
}
#endif

/* ---- number formatting (same scales as fw/m4/bench_m4_main.c / results/speed.csv) */

static void app_u64(char *b, size_t n, uint64_t v)
{
    char tmp[24];
    int i = (int)sizeof tmp;
    tmp[--i] = 0;
    if (v == 0) tmp[--i] = '0';
    while (v) { tmp[--i] = (char)('0' + (int)(v % 10)); v /= 10; }
    sh_append(b, n, &tmp[i]);
}

/* v scaled by 10^dec, printed with dec digits after the point. */
static void app_fixed(char *b, size_t n, uint64_t v, unsigned dec)
{
    uint64_t scale = 1;
    char frac[12];
    for (unsigned i = 0; i < dec; i++) scale *= 10;
    app_u64(b, n, v / scale);
    sh_append(b, n, ".");
    uint64_t f = v % scale;
    frac[dec] = 0;
    for (int i = (int)dec - 1; i >= 0; i--) { frac[i] = (char)('0' + (int)(f % 10)); f /= 10; }
    sh_append(b, n, frac);
}

/* a * b / d with no 128-bit intermediate. (d-1)*b < 2^64 for every call here. */
static uint64_t muldiv(uint64_t a, uint64_t b, uint64_t d)
{
    return (a / d) * b + ((a % d) * b) / d;
}

static void sort_samples(void)
{
    for (int i = 1; i < TRIALS; i++) {
        uint32_t v = samples[i];
        int j = i - 1;
        while (j >= 0 && samples[j] > v) { samples[j + 1] = samples[j]; j--; }
        samples[j + 1] = v;
    }
}

/* ---- CSV emission ------------------------------------------------------------- */

static void emit_head(const char *impl, char *b, size_t n)
{
    b[0] = 0;
    sh_append(b, n, M4_ONE_NAME);
    sh_append(b, n, ",");
    app_u64(b, n, (uint64_t)M4_ONE_ROUNDS);
    sh_append(b, n, ",");
    sh_append(b, n, impl);
    sh_append(b, n, "," M4_CONFIG ",");
}

static void emit_fail(const char *impl)
{
    char b[192];
    emit_head(impl, b, sizeof b);
    sh_append(b, sizeof b, ",,,,KAT_FAIL\n");
    sh_write0(b);
}

/* One measured row. bytes is the workload byte count (CTR_WS_BYTES), ops the block
 * count, so cycles_per_byte and mb_per_sec describe the whole counter-mode pass and
 * ns_per_op is per block. Same arithmetic as bench_m4_main.c. */
static void emit_row(const char *impl, uint32_t ops, uint32_t bytes)
{
    char b[192];
    sort_samples();
    uint64_t med = samples[TRIALS / 2], min = samples[0];

    emit_head(impl, b, sizeof b);
    app_fixed(b, sizeof b, med * 10000ull / bytes, 4);
    sh_append(b, sizeof b, ",");
    app_fixed(b, sizeof b, min * 10000ull / bytes, 4);
    sh_append(b, sizeof b, ",");
    if (clk_ok) {
        /* MB/s = bytes * clk / cycles / 1e6 = bytes * clk / (cycles * 1e4). */
        app_fixed(b, sizeof b, (uint64_t)bytes * clk_hz / (med * 10000ull), 2);
        sh_append(b, sizeof b, ",");
        app_fixed(b, sizeof b, muldiv(med * 10000ull / ops, 1000000000ull, clk_hz), 4);
    } else {
        sh_append(b, sizeof b, ",");
    }
    sh_append(b, sizeof b, ",ok\n");
    sh_write0(b);
}

/* ---- correctness: the counter-mode wrapping, against ctr-ref ------------------
 *
 * kat_check_all() has already cleared the kernels against the host's ciphertext.
 * This clears what CTR adds on top -- counter generation (including the bitsliced
 * counters64/32 path and its transpose back), the big-endian serialisation, and the
 * in-place XOR -- by running each backend and ctr-ref over the same plaintext and
 * counter and demanding identical output. Two ctr0 values, one of them crossing a
 * 32-bit boundary within the buffer, so a backend that drops the counter's high half
 * is caught. ok[i] records the verdict per backend; a failing backend is emitted as
 * KAT_FAIL and never timed.
 */
static void fill_pattern(uint8_t *p, size_t n)
{
    uint32_t s = 0x2468ACE1u;
    for (size_t i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;   /* xorshift32 */
        p[i] = (uint8_t)s;
    }
}

static int ctr_selfcheck(const void *st, int *ok)
{
    static const uint64_t seeds[2] = { CTR0, 0xFFFFFFFFFFFFFFC0ull };
    int fails = 0;
    for (int i = 0; i < N_IMPLS; i++) ok[i] = 1;
    for (int s = 0; s < 2; s++) {
        fill_pattern(kat_b, CTR_KAT_BYTES);
        ctr_ref(st, kat_b, CTR_KAT_BYTES, seeds[s]);   /* the oracle ciphertext */
        for (int i = 0; i < N_IMPLS; i++) {
            fill_pattern(kat_a, CTR_KAT_BYTES);
            IMPLS[i].fn(st, kat_a, CTR_KAT_BYTES, seeds[s]);
            if (memcmp(kat_a, kat_b, CTR_KAT_BYTES) != 0 && ok[i]) {
                ok[i] = 0;
                fails++;
                char m[96];
                m[0] = 0;
                sh_append(m, sizeof m, "# ctr-kat FAIL: ");
                sh_append(m, sizeof m, IMPLS[i].name);
                sh_append(m, sizeof m, " != ctr-ref\n");
                sh_write0(m);
            }
        }
    }
    return fails;
}

/* ---- stack watermark (a coarse footprint line for the provenance header) ------ */

extern uint32_t _sbss, _ebss, _sccm, _eccm, _estack;

static void emit_u32(const char *prefix, uint32_t v, const char *suffix)
{
    char b[96];
    fmt_u32(b, sizeof b, prefix, v, suffix);
    sh_write0(b);
}

/* ------------------------------------------------------------------------------- */

int main(void)
{
    void *state;
    int ok[N_IMPLS];

#if M4_BUILD_NARROW
    present_ctx_t *ctx = kat_lend_ctx();
#endif
#if M4_BUILD_AES
    aes_init_tables();                 /* force the T-tables now, out of any timed region */
    static aes_key_t akey;
#endif
#if M4_BUILD_LIN
    static lin_key_t lkey;
#endif

    sh_write0("# m4-bench: on-device speed benchmark\n");
    sh_write0("# workload: counter mode, 64 KiB in place, one cipher per image\n");

    /* Gate 1: the kernels, against the host's vectors. */
    int kat_fail = kat_check_all();
    emit_u32("# kat: ", (uint32_t)kat_fail, " failing kernel pairs\n");

    /* Prepare this cipher's state. */
    uint8_t key[256];
    fill_pattern(key, sizeof key);
#if M4_BUILD_NARROW
    const present_variant_t *v = present_variant_by_name(M4_ONE_NAME);
    size_t kb = v ? present_variant_key_bytes(v) : 0;
    int prep_ok = (v != 0) && (present_init(ctx, v, key, kb) == 0);
    state = ctx;
#elif M4_BUILD_AES
    aes_key_schedule(&akey, key);
    akey.nr = M4_ONE_ROUNDS;
    int prep_ok = 1;
    state = &akey;
#else
    lin_key_schedule(&lkey, key);
    lkey.nr = M4_ONE_ROUNDS;
    int prep_ok = 1;
    state = &lkey;
#endif

    /* Gate 2: the counter-mode wrapping, against ctr-ref. */
    int ctr_fail = prep_ok ? ctr_selfcheck(state, ok) : N_IMPLS;
    if (!prep_ok)
        for (int i = 0; i < N_IMPLS; i++) ok[i] = 0;
    emit_u32("# ctr-kat: ", (uint32_t)ctr_fail, " backends disagree with ctr-ref\n");

    clk_hz = system_measure_sysclk_hz();       /* ~1 s; must precede any timing */
    clk_ok = (system_clock_meas_status() == SYSCLK_MEAS_OK);

    /* Provenance the host driver relays into the CSV header. */
    sh_write0("# config: " M4_CONFIG "\n");
    emit_u32("# workload_bytes: ", CTR_WS_BYTES, "\n");
    emit_u32("# block_bytes: ", CTR_BLOCK_BYTES, "\n");
    if (clk_ok) emit_u32("# observed sysclk_hz: ", clk_hz, "\n");
    else        sh_write0("# observed sysclk_hz: UNMEASURED\n");
    sh_write0("cipher,rounds,impl,config,cycles_per_byte,cycles_per_byte_min,"
              "mb_per_sec,ns_per_op,status\n");

    int gate = (kat_fail == 0);
    const uint32_t bytes = CTR_WS_BYTES;
    const uint32_t ops = CTR_WS_BYTES / CTR_BLOCK_BYTES;

#ifdef M4_CTR_WINNER
    /* Published image: time only the frozen winner, through ctr_timed_kernel. Its
     * per-backend verdict is the ok[] entry whose name matches the winner. */
    int widx = -1;
    for (int i = 0; i < N_IMPLS; i++)
        if (!strcmp(IMPLS[i].name, M4_CTR_WINNER_NAME)) widx = i;
    if (gate && widx >= 0 && ok[widx]) {
        TIMED(ctr_timed_kernel(state, ctr_buf, CTR_WS_BYTES, CTR0));
        ctr_sink ^= ctr_buf[0] ^ ctr_buf[CTR_WS_BYTES - 1];
        emit_row(M4_CTR_WINNER_NAME, ops, bytes);
    } else {
        emit_fail(M4_CTR_WINNER_NAME);
    }
#else
    /* Tuning image: time every applicable backend. */
    for (int i = 0; i < N_IMPLS; i++) {
        if (gate && ok[i]) {
            TIMED(IMPLS[i].fn(state, ctr_buf, CTR_WS_BYTES, CTR0));
            ctr_sink ^= ctr_buf[0] ^ ctr_buf[CTR_WS_BYTES - 1];
            emit_row(IMPLS[i].name, ops, bytes);
        } else {
            emit_fail(IMPLS[i].name);
        }
    }
#endif

    emit_u32("# ccm used: ", (uint32_t)((uintptr_t)&_eccm - (uintptr_t)&_sccm), " B of 65536\n");
    emit_u32("# bss used: ", (uint32_t)((uintptr_t)&_ebss - (uintptr_t)&_sbss), " B\n");
    /* A trailer line the host driver anchors the end of the stream on. */
    emit_u32("# stack peak: ", 0u, " B (not painted)\n");

    (void)ctr_sink;
    sh_exit();
    for (;;) { }
}
