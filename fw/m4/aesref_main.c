/* fw/m4/aesref_main.c -- a diagnostic, not a published measurement.
 *
 * results/m4-speed.csv reports this project's AES variant at its research round
 * count of 5. The published Cortex-M4 AES figure to compare against -- Schwabe
 * and Stoffelen, SAC 2016, 634.7 cycles for a single block and 527.9 in CTR --
 * is standard AES-128 at 10 rounds. Dividing our 5-round figure by 5 and theirs
 * by 10 assumes cycles are linear in rounds, and they are not: the initial
 * AddRoundKey, the distinct final round, and the load/store of the block are all
 * fixed costs that a 5-round cipher pays over half as many rounds.
 *
 * So this binary times the same aes_encrypt1() at 5 and at 10 rounds on the same
 * board, in the same protocol as the benchmark, and prints both. Two points fix
 * the line, which turns a per-round comparison into a measured one.
 *
 * It deliberately does NOT touch results/m4-speed.csv or any of the three
 * published images. See the --gc-sections note in the Makefile: adding anything
 * to a firmware-linked translation unit republishes the benchmark. This is a
 * separate binary for exactly that reason.
 */
#include <stdint.h>
#include <string.h>

#include "semihost.h"
#include "system_init.h"
#include "timing.h"
#include "wide_ciphers.h"

#define TRIALS 15
#define WARMUP 3

/* Same 2 KiB working set as the benchmark, so the memory traffic per byte is
 * the one the published rows were measured under. 128 blocks of 16 bytes. */
#define WS_BYTES  2048
#define WS_BLOCKS (WS_BYTES / 16)

#define CCM __attribute__((section(".ccmram")))

CCM static uint8_t ws_in[WS_BYTES];
CCM static uint8_t ws_out[WS_BYTES];
CCM static aes_key_t akey;

static uint32_t samples[TRIALS];
static volatile uint64_t sink;

static uint64_t rng_state = 0x123456789ABCDEFull;
static uint64_t rng_next(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
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

/* One pass over the working set at the given round count, timed TRIALS times. */
static void run(int rounds)
{
    char b[128];

    for (int t = -WARMUP; t < TRIALS; t++) {
        uint32_t c0 = cyc_begin();
        for (int i = 0; i < WS_BLOCKS; i++)
            aes_encrypt1(&akey, rounds, ws_in + i * 16, ws_out + i * 16);
        uint32_t d = cyc_end(c0);
        if (t >= 0) samples[t] = d;
    }
    sink ^= ws_out[0];

    sort_samples();

    /* Cycles per 16-byte block, scaled by 10 so one decimal survives integer
     * arithmetic; TRIALS/2 is the median, [0] the min. */
    fmt_u32(b, sizeof b, "rounds=", (uint32_t)rounds, "");
    sh_write0(b);
    fmt_u32(b, sizeof b, "  median_cycles_per_pass=", samples[TRIALS / 2], "");
    sh_write0(b);
    fmt_u32(b, sizeof b, "  min_cycles_per_pass=", samples[0], "");
    sh_write0(b);
    fmt_u32(b, sizeof b, "  cycles_per_block_x10=",
            (uint32_t)((uint64_t)samples[TRIALS / 2] * 10u / WS_BLOCKS), "");
    sh_write0(b);
    fmt_u32(b, sizeof b, "  cycles_per_byte_x100=",
            (uint32_t)((uint64_t)samples[TRIALS / 2] * 100u / WS_BYTES), "\n");
    sh_write0(b);
}

int main(void)
{
    uint8_t key[16];

    for (int i = 0; i < WS_BYTES / 8; i++) {
        uint64_t v = rng_next();
        memcpy(ws_in + i * 8, &v, 8);
    }
    memset(ws_out, 0, sizeof ws_out);
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 7 + 1);

    aes_init_tables();
    aes_key_schedule(&akey, key);

    sh_write0("# aesref: T-table aes_encrypt1 at two round counts, same board,\n"
              "# same 2 KiB working set as results/m4-speed.csv. Diagnostic only:\n"
              "# this binary publishes nothing and is not one of the three images\n"
              "# stamped in that file.\n");

    /* The published round count first, so a reader can check this binary against
     * results/m4-speed.csv before reading the 10-round number it exists for. */
    run(5);
    run(10);

    sh_exit();
    for (;;) { }
}
