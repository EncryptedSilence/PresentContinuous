/* fw/m4/clock_check_main.c -- verify the core clock against the LSE crystal.
 *
 * This is the only thing in the system that can catch a wrong core clock. The
 * RCC's own status bits cannot: PLLRDY reports that the PLL loop closed, not
 * that it closed on a legal configuration, so an F407 with an out-of-range PLLN
 * asserts PLLRDY, switches SYSCLK to the PLL, and reports HSE + PLL OK while
 * running at a fraction of nominal. Since every MB/s figure this project
 * publishes is a cycle count divided by the core clock, that error scales all of
 * them and leaves cycles/byte untouched -- it is invisible in the output.
 *
 * The last line is the gate. `clock-check: PASS` is the only line that clears
 * Phase 4 to publish timings; anything else must stop it.
 */
#include "semihost.h"
#include "system_init.h"

#define REG32(a) (*(volatile uint32_t *)(a))

static const char *meas_status_text(int s)
{
    switch (s) {
    case SYSCLK_MEAS_OK:          return "ok";
    case SYSCLK_MEAS_OUT_OF_TOL:  return "measured but out of tolerance";
    case SYSCLK_MEAS_NO_LSE:      return "LSE did not start";
    case SYSCLK_MEAS_NO_DWT:      return "DWT CYCCNT is not counting";
    case SYSCLK_MEAS_NO_CAPTURE:  return "no TIM5 capture from the LSE";
    case SYSCLK_MEAS_OVERCAPTURE: return "captures were missed";
    default:                      return "not attempted";
    }
}

int main(void)
{
    char buf[96];

    /* The RCC state that produced the measurement, dumped in the same run.
     * The frequency says something is wrong; these say what. */
    fmt_hex32(buf, sizeof buf, "rcc_cr:      ", REG32(0x40023800u), "\n");
    sh_write0(buf);
    fmt_hex32(buf, sizeof buf, "rcc_pllcfgr: ", REG32(0x40023804u), "\n");
    sh_write0(buf);
    fmt_hex32(buf, sizeof buf, "rcc_cfgr:    ", REG32(0x40023808u), "\n");
    sh_write0(buf);

    sh_write0(system_clock_source() == SYSCLK_SRC_HSE
                  ? "clock: HSE\n"
                  : "clock: HSI (HSE failed)\n");
    if (system_pll_status() == SYSCLK_PLL_NO_LOCK) {
        sh_write0("pll: did not lock; SYSCLK is the raw HSI\n");
    } else if (system_pll_status() == SYSCLK_PLL_NO_SWITCH) {
        sh_write0("pll: locked but SYSCLK switch did not take\n");
    } else {
        sh_write0("pll: ok\n");
    }

    sh_write0("measuring against LSE (takes ~1 s, plus LSE start-up)...\n");
    uint32_t hz = system_measure_sysclk_hz();
    int st = system_clock_meas_status();

    fmt_u32(buf, sizeof buf, "meas_status: ", (uint32_t)st, " (");
    sh_write0(buf);
    sh_write0(meas_status_text(st));
    sh_write0(")\n");

    if (hz == SYSCLK_HZ_UNMEASURED) {
        sh_write0("sysclk: unverified\n");
        /* Deliberately loud. An unverified clock means every MB/s figure rests
         * on an assumption no instrument in this system has ever checked. */
        sh_write0("clock-check: FAIL (unverified -- do not publish timings)\n");
        sh_exit();
        for (;;) { }
    }

    fmt_u32(buf, sizeof buf, "sysclk measured: ", hz, " Hz\n");
    sh_write0(buf);
    fmt_u32(buf, sizeof buf, "nominal:         ", SYSCLK_NOMINAL_HZ, " Hz\n");
    sh_write0(buf);
    fmt_u32(buf, sizeof buf, "tim5 clock:      ", system_timclk_hz(),
            " Hz (expect sysclk/2)\n");
    sh_write0(buf);

    /* Deviation in parts per 10000, so a sub-1 % error is still legible without
     * floating point in the output path. */
    uint32_t dev = (hz > SYSCLK_NOMINAL_HZ) ? (hz - SYSCLK_NOMINAL_HZ)
                                            : (SYSCLK_NOMINAL_HZ - hz);
    fmt_u32(buf, sizeof buf, "deviation:       ",
            (uint32_t)(((uint64_t)dev * 10000u) / SYSCLK_NOMINAL_HZ),
            hz >= SYSCLK_NOMINAL_HZ ? " /10000 high\n" : " /10000 low\n");
    sh_write0(buf);

    sh_write0(st == SYSCLK_MEAS_OK
                  ? "clock-check: PASS (within 1% of nominal)\n"
                  : "clock-check: FAIL (outside 1% -- do not publish timings)\n");

    sh_exit();
    for (;;) { }
}
