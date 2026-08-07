/* fw/m4/bench_m4_main.c -- the on-device speed benchmark.
 *
 * This is the binary that produces Phase 4's Cortex-M4 numbers: cycles per byte
 * and MB/s for every (cipher, implementation) pair the board can run, emitted as
 * CSV over semihosting in the same shape as results/speed.csv so an M4 row and an
 * x86 row can be read side by side. The rules it works under, in the order they
 * matter:
 *
 *   Nothing is timed until it is proven correct. kat_check_all() runs first and
 *   every row asks kat_ok(cipher, impl) before a single cycle is counted. A pair
 *   the gate did not clear is emitted as status=KAT_FAIL with all four timing
 *   fields empty -- never as a number with a caveat attached, because the number
 *   is what gets copied into a table and the caveat is what gets left behind.
 *   The gate fails closed on impl names it does not recognise, so a typo in a
 *   name below turns into KAT_FAIL rows and a diagnostic naming the typo rather
 *   than into an unvalidated row published as ok.
 *
 *   The cipher list is not written here. It lives in tools/cipher_set.py, reaches
 *   the firmware through tools/gen_m4_kats.py -> fw/m4/gen/kat_vectors.h, and is
 *   enumerated at run time through kat_n_ciphers()/kat_cipher_name()/
 *   kat_cipher_rounds()/kat_cipher_block_bytes(). That is what guarantees an M4
 *   row and an FPGA row name the same cipher at the same round count; a second
 *   copy of the list here would be a second thing to keep in step, and it would
 *   not stay in step.
 *
 *   The clock is measured, never assumed. MB/s and ns/op are a DWT cycle count
 *   divided by the core clock, so a wrong clock scales every one of them while
 *   leaving cycles/byte untouched -- plausible output, silently wrong. The header
 *   states the measured frequency and whether the measurement was in tolerance,
 *   and if it was not, the two clock-derived columns are left *empty* while
 *   cycles/byte (which needs no clock at all) is still published. There is no
 *   fallback to the nominal 168 MHz anywhere in this file.
 *
 *   Both forms of every bitsliced row. "bitslice32" is the all-in-one entry
 *   point, bit transpose included; "bitslice32-bs" is the kernel over state that
 *   is already transposed, with the bitsliced key expansion hoisted out of the
 *   timed loop exactly as bench/wide_bench.c:679 hoists it on x86. The transpose
 *   is a real and separately interesting cost -- measured here at 33.2 cyc/B for
 *   the 64-bit path and 33.3 for the 128-bit one, pack and unpack together -- so
 *   a caller that already holds bitsliced state and one that does not are not
 *   the same benchmark, and charging AES for its transpose while reporting only
 *   the -bs form for PRESENT would not compare the same thing. Every cipher
 *   reports both, mirroring bench/bench_main.c:338-343. (Before the delta-swap
 *   replacement those figures were 277.8 and 191.1 cyc/B, which made the
 *   all-in-one rows mostly a transpose benchmark; see src/present_bitslice32.c.)
 *
 *   Where the lookup tables live, because it is measured and it is not uniform.
 *   The 64-bit ciphers' 16 KiB fused enc_tab is in CCM, inside the borrowed
 *   present_ctx_t; AES's 4 KiB T-tables are in SRAM, because bench/wide_ciphers.h
 *   declares them with no section attribute. That is not an oversight left
 *   unexamined: moving the T-tables into CCM was measured on this board at 6.99%
 *   *slower* for the aes-r5 table row and 6.73% slower for table-x4, against an
 *   8 KiB-CCM-padding control that reproduced the baseline, while the 64-bit
 *   table rows are byte-for-byte identical wherever enc_tab sits. Each table is
 *   therefore in the memory that is fastest for it, which is what comparing
 *   optimized implementations requires; equalising by moving either one would
 *   make a published figure worse. Stated in the CSV header so a reader
 *   comparing two adjacent table rows knows what differs between them.
 *
 *   Memory. The working set, the bitsliced planes and the key material are in
 *   CCM RAM (zero wait states, no DMA contention). The two large buffers -- the
 *   33,032-byte present_ctx_t and the 10,752-byte bitsliced round-key array --
 *   are borrowed from fw/m4/kat.c rather than duplicated: 64 KiB of CCM has room
 *   for one of each, not two, and the gate is finished with both by the time the
 *   first row is timed (see the contract in kat.h). Everything else the timed
 *   code touches is static, so the stack holds only the all-in-one wide kernels'
 *   frames; the peak that actually resulted is painted and reported at the end
 *   rather than estimated, because on a target with no MMU a stack that grows
 *   into .bss produces wrong answers instead of a fault.
 */
#include <stdint.h>
#include <string.h>

#include "kat.h"
#include "semihost.h"
#include "system_init.h"
#include "timing.h"

#include "present/present.h"

#include "wide_ciphers.h"
#include "wide_bitslice32.h"

/* Which memory configuration this binary was built as. Three are published:
 *
 *   product      code in flash, ART on   -- how a real product runs
 *   flash-noart  code in flash, ART off  -- the accelerator's own contribution
 *   sram-noart   code in SRAM,  ART off  -- instruction fetch moved off the
 *                                           ICode bus onto the shared system bus
 *
 * The Makefile passes -DM4_CONFIG for the latter two (see M4_DEFS_<name>); this
 * default is the product build's, which passes nothing. Note that sram-noart is
 * not a lower bound: the STM32F407 has no zero-wait-state executable memory, CCM
 * being reachable from the D-bus only, so product is the fast path on this part
 * and the other two are both slower. */
#ifndef M4_CONFIG
#define M4_CONFIG "product"
#endif

/* --- protocol ----------------------------------------------------------------
 *
 * bench/bench_main.c's, unchanged, so the figures are the same shape as the x86
 * ones: warm up WARMUP times, then take TRIALS independent trials and report the
 * median and the min. The median is robust against a stray outlier; the min says
 * how much spread there was. With interrupts masked and no OS the two are usually
 * within a cycle or two of each other, which is itself the useful signal -- a run
 * where they are not is a run with something in it that should not be.
 *
 * One trial is one pass over the whole working set, so every implementation of a
 * given cipher is measured over the same 2 KiB of plaintext.
 */
#define TRIALS 15
#define WARMUP 3

/* 2 KiB, the working set for every cipher: 256 blocks for the 64-bit ciphers,
 * 128 for the 128-bit ones. Fixing the byte count rather than the block count is
 * what makes the memory traffic identical across the two families. Both are
 * divisible by the widest kernel's 32 blocks and by table-x4's 4. */
#define WS_BYTES     2048
#define WS_BLOCKS64  (WS_BYTES / 8)
#define WS_BLOCKS128 (WS_BYTES / 16)

/* Key setups per trial. The setup for a 64-bit cipher is present_init(), which
 * builds 16 KiB of fused table, so even one repetition is hundreds of thousands
 * of cycles; the repetitions are here for the 128-bit ciphers' much cheaper
 * schedules, and cost the 64-bit ones only run time. */
#define KEYSETUP_REPS 8

/* --- storage ------------------------------------------------------------------
 *
 * See the file comment. Nothing here may have an initialiser: .ccm is NOLOAD and
 * the reset handler does not zero it, so every buffer is written before read. */
#define CCM __attribute__((section(".ccmram")))

/* The working set, addressed as 256 64-bit blocks or as 2048 raw bytes (128
 * 128-bit blocks) depending on the cipher. A union rather than a cast: the two
 * views have to share storage, and this is the spelling that says so to the
 * compiler as well as to the reader. */
typedef union {
    uint64_t b64[WS_BLOCKS64];
    uint8_t  b128[WS_BYTES];
} ws_t;

CCM static ws_t ws_in;
CCM static ws_t ws_out;

/* Bitsliced planes, sized for the wider of the two families (128 bits); the
 * 64-bit ciphers use the first 64 words. bs_seed holds the packed plaintext so
 * the transpose can happen once, outside every timed region. */
CCM static uint32_t bs_seed[WIDE_BS32_BITS];
CCM static uint32_t bs_state[WIDE_BS32_BITS];
CCM static uint32_t bs_scratch[WIDE_BS32_BITS];

CCM static uint8_t keybuf[(PRESENT_MAX_ROUNDS + 1) * (PRESENT_BLOCK_BITS / 8)];
CCM static aes_key_t akey;
CCM static lin_key_t lkey;

/* Borrowed from fw/m4/kat.c -- one present_ctx_t and one bitsliced round-key
 * array exist in this firmware and both are already spent by the time main()
 * starts timing. Bound once in main(). */
static present_ctx_t *ctx;
static uint32_t *bs_km;

/* Written but never read: stops -O3 deleting the work being timed. */
static volatile uint64_t bench_sink;

static uint32_t samples[TRIALS];

/* The measured core clock, or SYSCLK_HZ_UNMEASURED. Read once into a file-scope
 * copy so every row in a run is divided by the same number. */
static uint32_t clk_hz;
static int clk_ok;

/* --- number formatting --------------------------------------------------------
 *
 * -ffreestanding: no printf, no snprintf, and no floating point worth having on
 * a single-precision FPU when the values span 0.01 to 10^6. Everything below is
 * exact integer arithmetic on values scaled by a power of ten, printed with the
 * decimal point inserted by hand. The scales match results/speed.csv's %.4f /
 * %.2f so the two CSVs carry the same precision.
 */
static void app_u64(char *b, size_t n, uint64_t v)
{
    char tmp[24];
    int i = (int)sizeof tmp;
    tmp[--i] = 0;
    if (v == 0) tmp[--i] = '0';
    while (v) { tmp[--i] = (char)('0' + (int)(v % 10)); v /= 10; }
    sh_append(b, n, &tmp[i]);
}

/* Fixed-width hex, for the two observed-state fields in the provenance header.
 * Those are addresses and a peripheral register: decimal would be unreadable and
 * a reader has to be able to match them against RM0090 and against nm output. */
static void app_hex(char *b, size_t n, uint32_t v, int digits)
{
    static const char d[] = "0123456789abcdef";
    char tmp[9];
    if (digits > 8) digits = 8;
    tmp[digits] = 0;
    for (int i = digits - 1; i >= 0; i--) { tmp[i] = d[v & 0xFu]; v >>= 4; }
    sh_append(b, n, tmp);
}

/* v is the value scaled by 10^dec; prints it with dec digits after the point. */
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

/* a * b / d with no 128-bit intermediate (Cortex-M4 has no __int128). Exact for
 * the integer part. The only requirement is (d - 1) * b < 2^64, which every call
 * here satisfies: d is the core clock (~1.7e8) and b is at most 1e9. */
static uint64_t muldiv(uint64_t a, uint64_t b, uint64_t d)
{
    return (a / d) * b + ((a % d) * b) / d;
}

/* --- statistics ---------------------------------------------------------------
 *
 * TRIALS is 15, so an insertion sort over the cycle counts is both the smallest
 * and the fastest thing that could be written here. Median and min are taken from
 * the cycle counts rather than from the derived ratios; every derivation below is
 * monotone in cycles, so the two orderings agree. */
static void sort_samples(void)
{
    for (int i = 1; i < TRIALS; i++) {
        uint32_t v = samples[i];
        int j = i - 1;
        while (j >= 0 && samples[j] > v) { samples[j + 1] = samples[j]; j--; }
        samples[j + 1] = v;
    }
}

/* --- CSV ---------------------------------------------------------------------- */

static void emit_head(const char *cipher, int rounds, const char *impl, char *b, size_t n)
{
    b[0] = 0;
    sh_append(b, n, cipher);
    sh_append(b, n, ",");
    app_u64(b, n, (uint64_t)rounds);
    sh_append(b, n, ",");
    sh_append(b, n, impl);
    sh_append(b, n, "," M4_CONFIG ",");
}

/* A pair the gate did not clear: named, so its absence is visible, with every
 * timing field empty. */
static void emit_fail(const char *cipher, int rounds, const char *impl)
{
    char b[192];
    emit_head(cipher, rounds, impl, b, sizeof b);
    sh_append(b, sizeof b, ",,,,KAT_FAIL\n");
    sh_write0(b);
}

/* bytes is the plaintext byte count of one trial and ops the number of
 * operations in it. For an encryption row those are blocks * block_bytes and
 * blocks; for a key-setup row bytes == ops, which is bench/bench_main.c's
 * convention of bytes_per_op = 1 -- so the cycles_per_byte column of a keysetup
 * row reads as cycles per setup and ns_per_op as nanoseconds per setup, exactly
 * as in results/speed.csv's keyschedule/ctxinit rows. */
static void emit_row(const char *cipher, int rounds, const char *impl,
                     uint32_t ops, uint32_t bytes)
{
    char b[192];
    sort_samples();
    uint64_t med = samples[TRIALS / 2], min = samples[0];

    emit_head(cipher, rounds, impl, b, sizeof b);
    app_fixed(b, sizeof b, med * 10000ull / bytes, 4);
    sh_append(b, sizeof b, ",");
    app_fixed(b, sizeof b, min * 10000ull / bytes, 4);
    sh_append(b, sizeof b, ",");

    if (clk_ok) {
        /* bytes/s = bytes * clk / cycles; MB/s is that over 1e6, kept to two
         * decimals -- so bytes * clk / (cycles * 1e4). */
        app_fixed(b, sizeof b, (uint64_t)bytes * clk_hz / (med * 10000ull), 2);
        sh_append(b, sizeof b, ",");
        /* ns/op = (cycles/op) * 1e9 / clk, to four decimals. The first division
         * is done at 1e4 scale so the second cannot overflow. */
        app_fixed(b, sizeof b, muldiv(med * 10000ull / ops, 1000000000ull, clk_hz), 4);
    } else {
        /* No trustworthy clock: cycles/byte above is still exact, the two
         * clock-derived columns are not reported at all. */
        sh_append(b, sizeof b, ",");
    }
    sh_append(b, sizeof b, ",ok\n");
    sh_write0(b);
}

/* --- the timing loop ----------------------------------------------------------
 *
 * TIMED runs WARMUP + TRIALS passes and leaves the per-trial cycle counts in
 * samples[]. ROW wraps it in the correctness gate and the CSV emission, so every
 * row in this file is one statement and there is no path from a cipher call to a
 * printed number that skips kat_ok(). Nothing inside a TIMED body may touch the
 * semihosting channel: each call traps to the host and would be counted.
 */
/* Variadic so a body containing a top-level comma cannot be split into two
 * macro arguments -- braces do not protect commas from the preprocessor. */
#define TIMED(...)                                                       \
    do {                                                                 \
        for (int t_ = -WARMUP; t_ < TRIALS; t_++) {                      \
            uint32_t c0_ = cyc_begin();                                  \
            __VA_ARGS__;                                                 \
            uint32_t d_ = cyc_end(c0_);                                  \
            if (t_ >= 0) samples[t_] = d_;                               \
        }                                                                \
    } while (0)

#define ROW(cipher, rounds, impl, ops, bytes, ...)                       \
    do {                                                                 \
        if (!kat_ok((cipher), (impl))) {                                 \
            emit_fail((cipher), (rounds), (impl));                       \
            break;                                                       \
        }                                                                \
        TIMED(__VA_ARGS__);                                              \
        emit_row((cipher), (rounds), (impl), (ops), (bytes));            \
    } while (0)

/* --- working-set data ---------------------------------------------------------
 *
 * Plaintext and key bytes come from a fixed xorshift stream, so a run is
 * reproducible and every block differs from every other. None of the kernels
 * timed here has a data-dependent branch or a data-dependent memory access
 * pattern, so the values cannot change what is measured -- they exist so that
 * no lane, block or plane is a copy of another. */
static uint64_t rng_state = 0x123456789ABCDEFull;
static uint64_t rng_next(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static void fill_working_set(void)
{
    for (int i = 0; i < WS_BLOCKS64; i++) ws_in.b64[i] = rng_next();
    memset(ws_out.b64, 0, sizeof ws_out.b64);
}

/* --- the two wide all-in-one rows ---------------------------------------------
 *
 * aes_encrypt_bs32 and lin_encrypt_bs32 hold two 128-word plane arrays and the
 * 2,688-word expanded schedule as locals: Task 5 measured them at 11,960 B and
 * 12,296 B of stack. Confining each to its own noinline function keeps that frame
 * out of every other row's, so the painted watermark reported at the end reflects
 * one such call rather than a frame that happened to be merged into main()'s.
 * These are the only two functions in this file whose stack cost is not tiny. */
__attribute__((noinline))
static void time_aes_bs32_allinone(int rounds)
{
    uint64_t acc = 0;
    TIMED({
        for (int g = 0; g < WS_BLOCKS128 / WIDE_BS32_BLOCKS; g++)
            aes_encrypt_bs32(&akey, rounds,
                             ws_in.b128 + (size_t)g * WIDE_BS32_BLOCKS * 16,
                             ws_out.b128 + (size_t)g * WIDE_BS32_BLOCKS * 16);
        acc ^= ws_out.b64[0];
    });
    bench_sink = acc;
}

__attribute__((noinline))
static void time_lin_bs32_allinone(int rounds)
{
    uint64_t acc = 0;
    TIMED({
        for (int g = 0; g < WS_BLOCKS128 / WIDE_BS32_BLOCKS; g++)
            lin_encrypt_bs32(&lkey, rounds,
                             ws_in.b128 + (size_t)g * WIDE_BS32_BLOCKS * 16,
                             ws_out.b128 + (size_t)g * WIDE_BS32_BLOCKS * 16);
        acc ^= ws_out.b64[0];
    });
    bench_sink = acc;
}

/* --- the 64-bit ciphers -------------------------------------------------------- */

static void run_cipher64(const char *name, int rounds)
{
    char msg[128];
    const present_variant_t *v = present_variant_by_name(name);

    /* The gate refuses a round-count mismatch too, so this can only fire for a
     * cipher the gate never saw. Say so rather than skipping in silence. */
    if (!v || v->rounds != rounds) {
        msg[0] = 0;
        sh_append(msg, sizeof msg, "# no variant descriptor for ");
        sh_append(msg, sizeof msg, name);
        sh_append(msg, sizeof msg, " at the vectors' round count -- no rows\n");
        sh_write0(msg);
        return;
    }

    size_t kb = present_variant_key_bytes(v);
    if (kb == 0 || kb > sizeof keybuf) return;
    for (size_t i = 0; i < kb; i++) keybuf[i] = (uint8_t)(rng_next() >> 24);

    /* Key setup first: it is the one row that leaves the context it times behind,
     * so timing it here and reinitialising afterwards keeps the encryption rows
     * from depending on what order they were written in. The key byte is changed
     * per repetition so no two are the same computation -- see the note on the
     * 128-bit schedules in run_wide(), where an all-inline schedule would
     * otherwise be a loop-invariant -O3 could collapse. */
    ROW(name, rounds, "keysetup", KEYSETUP_REPS, KEYSETUP_REPS, {
        for (int i = 0; i < KEYSETUP_REPS; i++) {
            keybuf[0] = (uint8_t)i;
            present_init(ctx, v, keybuf, kb);
            bench_sink ^= ctx->rk[0];
        }
    });

    if (present_init(ctx, v, keybuf, kb) != 0) return;
    fill_working_set();

    {
        uint64_t acc = 0;
        ROW(name, rounds, "ref", WS_BLOCKS64, WS_BYTES, {
            for (int i = 0; i < WS_BLOCKS64; i++) acc ^= present_encrypt_ref(ctx, ws_in.b64[i]);
        });
        ROW(name, rounds, "table", WS_BLOCKS64, WS_BYTES, {
            for (int i = 0; i < WS_BLOCKS64; i++) acc ^= present_encrypt_table(ctx, ws_in.b64[i]);
        });
        ROW(name, rounds, "table-x4", WS_BLOCKS64, WS_BYTES, {
            for (int g = 0; g < WS_BLOCKS64 / 4; g++)
                present_encrypt_table_x4(ctx, ws_in.b64 + 4 * g, ws_out.b64 + 4 * g);
            acc ^= ws_out.b64[0];
        });
        ROW(name, rounds, "bitslice32", WS_BLOCKS64, WS_BYTES, {
            for (int g = 0; g < WS_BLOCKS64 / PRESENT_BITSLICE32_BLOCKS; g++)
                present_encrypt_bitslice32(ctx, ws_in.b64 + PRESENT_BITSLICE32_BLOCKS * g,
                                                ws_out.b64 + PRESENT_BITSLICE32_BLOCKS * g);
            acc ^= ws_out.b64[0];
        });

        /* The transpose-free form. The pack happens once, here, outside every
         * timed region -- that is the whole difference between this row and the
         * one above. Each group re-seeds from the same packed state and perturbs
         * one plane by the group index: one XOR per 32 blocks, far below the
         * noise floor, and it makes each iteration a different computation so
         * -O3 cannot hoist an invariant call out of the group loop. The kernel
         * ping-pongs and returns the buffer holding the answer, so the sink reads
         * the returned pointer and never bs_state. */
        present_bitslice32_pack(ws_in.b64, bs_seed);
        ROW(name, rounds, "bitslice32-bs", WS_BLOCKS64, WS_BYTES, {
            for (int g = 0; g < WS_BLOCKS64 / PRESENT_BITSLICE32_BLOCKS; g++) {
                memcpy(bs_state, bs_seed, PRESENT_BLOCK_BITS * sizeof(uint32_t));
                bs_state[0] ^= (uint32_t)g;
                acc ^= present_encrypt_bitslice32_bs(ctx, bs_state, bs_scratch)[0];
            }
        });
        bench_sink = acc;
    }
}

/* --- the 128-bit ciphers ------------------------------------------------------- */

static void run_wide(const char *name, int rounds, int is_lin)
{
    uint8_t key[16];
    uint64_t acc = 0;

    if (rounds < 1 || rounds > MAX_ROUNDS) return;
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(rng_next() >> 24);

    /* Both 128-bit schedules are static inline in wide_ciphers.h, so a loop that
     * expanded the same key every time would be a loop-invariant -O3 is entitled
     * to run once and reuse -- which would report a key setup eight times faster
     * than it is. Changing one key byte per repetition makes each iteration a
     * different computation, for the cost of one byte store. Note also that both
     * schedules always expand the full MAX_ROUNDS + 1 round keys regardless of
     * the round count that will be run, by design (see wide_ciphers.h), so these
     * two rows are not comparable to a schedule sized to `rounds`. */
    if (is_lin) {
        ROW(name, rounds, "keysetup", KEYSETUP_REPS, KEYSETUP_REPS, {
            for (int i = 0; i < KEYSETUP_REPS; i++) {
                key[0] = (uint8_t)i;
                lin_key_schedule(&lkey, key);
                bench_sink ^= lkey.rk[0];
            }
        });
        lin_key_schedule(&lkey, key);
        lkey.nr = rounds;
    } else {
        ROW(name, rounds, "keysetup", KEYSETUP_REPS, KEYSETUP_REPS, {
            for (int i = 0; i < KEYSETUP_REPS; i++) {
                key[0] = (uint8_t)i;
                aes_key_schedule(&akey, key);
                bench_sink ^= akey.rk[0];
            }
        });
        aes_key_schedule(&akey, key);
        akey.nr = rounds;
    }

    fill_working_set();

    if (is_lin) {
        /* AES-lin444's scalar kernel here is the portable reference in
         * wide_ciphers.h; the fused-table one is SSE2 and stayed on x86, which
         * is why this cipher has no table or table-x4 row on this target. */
        ROW(name, rounds, "ref", WS_BLOCKS128, WS_BYTES, {
            for (int i = 0; i < WS_BLOCKS128; i++)
                lin_encrypt_ref(&lkey, rounds, ws_in.b128 + i * 16, ws_out.b128 + i * 16);
            acc ^= ws_out.b64[0];
        });
    } else {
        /* AES's scalar kernel is the T-table one, so it is the "table" row and
         * there is no separate "ref". */
        ROW(name, rounds, "table", WS_BLOCKS128, WS_BYTES, {
            for (int i = 0; i < WS_BLOCKS128; i++)
                aes_encrypt1(&akey, rounds, ws_in.b128 + i * 16, ws_out.b128 + i * 16);
            acc ^= ws_out.b64[0];
        });
        ROW(name, rounds, "table-x4", WS_BLOCKS128, WS_BYTES, {
            for (int g = 0; g < WS_BLOCKS128 / 4; g++)
                aes_encrypt4(&akey, rounds, ws_in.b128 + (size_t)g * 64,
                                            ws_out.b128 + (size_t)g * 64);
            acc ^= ws_out.b64[0];
        });
    }
    bench_sink = acc;

    if (kat_ok(name, "bitslice32")) {
        if (is_lin) time_lin_bs32_allinone(rounds);
        else        time_aes_bs32_allinone(rounds);
        emit_row(name, rounds, "bitslice32", WS_BLOCKS128, WS_BYTES);
    } else {
        emit_fail(name, rounds, "bitslice32");
    }

    /* The key expansion and the pack both happen here, once, outside the timed
     * region -- the same hoist bench/wide_bench.c:679 does for its AVX2 row. */
    if (is_lin) bs32_expand_lin_key(&lkey, rounds, bs_km);
    else        bs32_expand_aes_key(&akey, rounds, bs_km);
    wide_bs32_pack(ws_in.b128, bs_seed);

    acc = 0;
    if (is_lin) {
        ROW(name, rounds, "bitslice32-bs", WS_BLOCKS128, WS_BYTES, {
            for (int g = 0; g < WS_BLOCKS128 / WIDE_BS32_BLOCKS; g++) {
                memcpy(bs_state, bs_seed, WIDE_BS32_BITS * sizeof(uint32_t));
                bs_state[0] ^= (uint32_t)g;
                acc ^= *lin_encrypt_bs32_bs(&lkey, bs_km, rounds, bs_state, bs_scratch);
            }
        });
    } else {
        ROW(name, rounds, "bitslice32-bs", WS_BLOCKS128, WS_BYTES, {
            for (int g = 0; g < WS_BLOCKS128 / WIDE_BS32_BLOCKS; g++) {
                memcpy(bs_state, bs_seed, WIDE_BS32_BITS * sizeof(uint32_t));
                bs_state[0] ^= (uint32_t)g;
                acc ^= *aes_encrypt_bs32_bs(bs_km, rounds, bs_state, bs_scratch);
            }
        });
    }
    bench_sink = acc;
}

/* --- stack watermark ----------------------------------------------------------
 * fw/m4/kat_main.c's, unchanged: paint free SRAM before the run, read the
 * watermark after. An estimate would not do -- this target has no MMU, and a
 * stack that reached into .bss would show up as wrong ciphertexts, not a fault. */
extern uint32_t _sbss, _ebss, _estack, _sccm, _eccm;

#define PAINT 0xC0FFEEA5u
#define PAINT_MARGIN 64u

static void paint_stack(const uint32_t *below)
{
    uint32_t *p = &_ebss;
    uint32_t *top = (uint32_t *)((uintptr_t)below - PAINT_MARGIN);
    while (p < top) *p++ = PAINT;
}

static uint32_t stack_peak(void)
{
    const uint32_t *p = &_ebss;
    while (p < &_estack && *p == PAINT) p++;
    return (uint32_t)((uintptr_t)&_estack - (uintptr_t)p);
}

/* --- provenance header --------------------------------------------------------
 *
 * A reader cannot check a MB/s figure without knowing the clock it was divided
 * by, or trust it without knowing whether that clock was measured. Both go at the
 * top of the CSV, in the same output, from the same run. */
/* Declared here so emit_provenance can take its address: main's own address is
 * what tells a reader whether the code ran from flash or from SRAM. */
int main(void);

static void emit_provenance(void)
{
    char b[192];

    b[0] = 0;
    sh_append(b, sizeof b, "# m4-speed: STM32F407, sysclk ");
    if (clk_hz == SYSCLK_HZ_UNMEASURED) sh_append(b, sizeof b, "unmeasured");
    else app_u64(b, sizeof b, clk_hz);
    sh_append(b, sizeof b, " Hz (source ");
    sh_append(b, sizeof b, system_clock_source() == SYSCLK_SRC_HSE ? "HSE" : "HSI");
    sh_append(b, sizeof b, clk_ok ? ", verified)\n" : ", unverified)\n");
    sh_write0(b);

    sh_write0("# config " M4_CONFIG ", PRESENT_ENC_ONLY, working set 2048 B"
              " (256 x 8 B blocks / 128 x 16 B blocks)\n");

    /* Observed state, not self-declaration. M4_CONFIG above is a string the build
     * chose; these two are read off the running part, so no label can lie about
     * what was measured. A diagnostic build that changes one variable and forgets
     * to change the label -- which happened during this task's review -- is
     * visible here immediately.
     *
     *   main    0x080xxxxx = code in flash,  0x2000xxxx = code in SRAM
     *   FLASH_ACR bit 8 PRFTEN, bit 9 ICEN, bit 10 DCEN, bits 3:0 latency
     *           0x00000705 = ART on, 5 WS      0x00000005 = ART off, 5 WS
     *
     * FLASH_ACR is read here rather than trusted from system_init: this is the
     * value the flash controller is actually running with at the moment the rows
     * below were timed. */
    {
        uint32_t acr = *(volatile uint32_t *)0x40023C00u;
        /* Bit 0 is the Thumb bit, not part of the address; masking it makes this
         * match `arm-none-eabi-nm` character for character. */
        uint32_t main_at = (uint32_t)(uintptr_t)&main & ~1u;
        b[0] = 0;
        sh_append(b, sizeof b, "# observed: main at 0x");
        app_hex(b, sizeof b, main_at, 8);
        sh_append(b, sizeof b, (main_at >> 28) == 2u
                               ? " (code in SRAM), FLASH_ACR 0x" : " (code in flash), FLASH_ACR 0x");
        app_hex(b, sizeof b, acr, 8);
        sh_append(b, sizeof b, " (prefetch ");
        sh_append(b, sizeof b, (acr & (1u << 8)) ? "on" : "off");
        sh_append(b, sizeof b, ", icache ");
        sh_append(b, sizeof b, (acr & (1u << 9)) ? "on" : "off");
        sh_append(b, sizeof b, ", dcache ");
        sh_append(b, sizeof b, (acr & (1u << 10)) ? "on" : "off");
        sh_append(b, sizeof b, ", latency ");
        app_u64(b, sizeof b, (uint64_t)(acr & 0xFu));
        sh_append(b, sizeof b, " WS)\n");
        sh_write0(b);
    }

    /* The noise floor for comparing one configuration's row against another's.
     *
     * Two images built from this source cannot have the same code addresses:
     * turning the ART bits off is a source change, `movs r2,#5` being two bytes
     * where `movw r2,#0x705` is four, so every no-ART image carries a 4-byte
     * shift that realigns everything after system_init. That is intrinsic to the
     * comparison and no amount of care removes it.
     *
     * What it costs was measured directly: one set of object files, relinked in
     * the same order against scripts differing only by padding ahead of .text.
     * Identical source, identical objects, nothing but addresses different (the
     * zero-pad link is byte-identical to the shipped ELF, which is what makes it
     * a control rather than an accident).
     *
     *   +16 B  ->   0 of 39 rows move.   Every symbol shifts by 16.
     *   + 4 B  ->  39 of 39 rows move, up to 7.5%.
     *
     * The governing variable is a code address's offset **mod 16**, not how far
     * it moved. With prefetch and I-cache off, the only fetch granularity is the
     * 128-bit flash word, so a shift that is a multiple of 16 leaves every
     * instruction in the same position within its word and is invisible by
     * construction; a shift of 4 repositions every hot loop against those
     * boundaries and is worth several percent. The ART bits shift code by
     * exactly 4, i.e. the harmful kind.
     *
     * sram-noart is far less sensitive (SRAM fetch has no word to straddle) and
     * product sits in between, the I-cache absorbing most of it.
     *
     * So: two significant figures on any per-row ratio between configurations,
     * and prefer the aggregate. Independent builds of the product/flash-noart
     * pair put the accelerator at 1.77x and 1.68x median -- i.e. ~1.7x, and the
     * third digit is not real. It changes no conclusion; it does mean a reader
     * must not difference two individual rows and believe the result.
     *
     * The controlled alternative, for anyone who later needs an exact per-row
     * ratio: load FLASH_ACR from a word patched into the image after linking, so
     * that both configurations are literally the same bytes. */
    sh_write0("# cross-config layout noise: what matters is a code address's"
              " offset mod 16, not how far it moved. Measured on the same object"
              " files relinked with padding ahead of .text: a +16 B shift moves"
              " 0 of 39 rows (offset mod 16 unchanged, invisible to the 128-bit"
              " flash fetch), a +4 B shift moves 39 of 39 by up to 7.5%. The ART"
              " bits shift code by exactly 4 B. Quote ratios between"
              " configurations to two significant figures and prefer the"
              " aggregate; do not difference two individual rows.\n");

    /* The measurement's own accuracy floor is the LSE crystal's, not the
     * resolution of the count -- quoting the frequency any tighter than this
     * would be quoting the crystal's datasheet tolerance as if it were a
     * calibration. Every MB/s and ns/op figure below inherits it. */
    sh_write0("# clock measured against the 32.768 kHz LSE over 1 s; trustworthy"
              " to ~100 ppm (the crystal's own tolerance), so mb_per_sec and"
              " ns_per_op carry ~0.01% systematic uncertainty. cycles_per_byte"
              " does not depend on the clock at all.\n");

    if (!clk_ok)
        sh_write0("# clock NOT verified: mb_per_sec and ns_per_op are left empty."
                  " No nominal frequency is substituted anywhere.\n");

    sh_write0("# protocol: warmup 3, 15 trials, median and min, interrupts masked,"
              " DWT CYCCNT. Bitsliced key expansion and transpose hoisted out of"
              " every bitslice32-bs row. keysetup rows use bytes_per_op = 1, as"
              " results/speed.csv does: cycles_per_byte reads as cycles per setup.\n");

    /* Placement is not uniform and the difference is measurable, so it is stated
     * rather than left for a reader to discover: see the file comment for the
     * A/B and its control. */
    sh_write0("# tables: the 64-bit ciphers' 16 KiB fused enc_tab is in CCM, AES's"
              " 4 KiB T-tables are in SRAM. Measured on this board: moving the"
              " T-tables to CCM costs aes table +6.99% and table-x4 +6.73%;"
              " moving enc_tab to SRAM leaves the 64-bit table rows unchanged to"
              " the last digit. Each table is in the memory that is fastest for"
              " it.\n");
    sh_write0("# aes-lin444 has no fused-table row: a 16 KiB and a 64 KiB fused"
              " substitution-and-linear table were both built and measured here"
              " at 95.0 and 100.0 cyc/B against lin_encrypt_ref's 41.9, so the"
              " byte-wise kernel is the fastest scalar one available on this"
              " target. See bench/wide_ciphers.h.\n");
}

int main(void)
{
    char b[128];
    uint32_t marker = 0;

    paint_stack(&marker);

    ctx = kat_lend_ctx();
    bs_km = kat_lend_bs_km();

    /* The T-tables are built lazily on first use inside aes_encrypt1; force them
     * now so no timed region can ever pay for them. */
    aes_init_tables();

    sh_write0("# m4-bench: on-device speed benchmark\n");

    /* Correctness before speed, always. */
    int failures = kat_check_all();
    fmt_u32(b, sizeof b, "# kat: ", (uint32_t)failures,
            " failing pairs (rows for them are emitted as KAT_FAIL with no timings)\n");
    sh_write0(b);

    /* Takes about a second, plus LSE start-up. Must complete before anything is
     * timed: it drives TIM5 and spins on DWT itself. */
    clk_hz = system_measure_sysclk_hz();
    clk_ok = (system_clock_meas_status() == SYSCLK_MEAS_OK);

    emit_provenance();
    sh_write0("cipher,rounds,impl,config,cycles_per_byte,cycles_per_byte_min,"
              "mb_per_sec,ns_per_op,status\n");

    for (int i = 0; i < kat_n_ciphers(); i++) {
        const char *name = kat_cipher_name(i);
        int rounds = kat_cipher_rounds(i);
        int bb = kat_cipher_block_bytes(i);

        if (bb == 8) {
            run_cipher64(name, rounds);
        } else if (bb == 16) {
            /* Which of the two 128-bit ciphers this is comes from the linear
             * layer named in the cipher's own name, exactly as fw/m4/kat.c
             * decides it -- not from a second copy of the cipher list. */
            run_wide(name, rounds, strstr(name, "lin444") != 0);
        } else {
            b[0] = 0;
            sh_append(b, sizeof b, "# unknown block size for ");
            sh_append(b, sizeof b, name ? name : "(null)");
            sh_append(b, sizeof b, " -- no rows\n");
            sh_write0(b);
        }
    }

    fmt_u32(b, sizeof b, "# ccm used: ",
            (uint32_t)((uintptr_t)&_eccm - (uintptr_t)&_sccm), " B of 65536\n");
    sh_write0(b);
    fmt_u32(b, sizeof b, "# bss used: ",
            (uint32_t)((uintptr_t)&_ebss - (uintptr_t)&_sbss), " B\n");
    sh_write0(b);
    fmt_u32(b, sizeof b, "# stack peak: ", stack_peak(), " B\n");
    sh_write0(b);

    sh_exit();
    for (;;) { }
}
