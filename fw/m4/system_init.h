/* fw/m4/system_init.h -- clock tree bring-up for the STM32F407. */
#ifndef FW_M4_SYSTEM_INIT_H
#define FW_M4_SYSTEM_INIT_H

#include <stdint.h>

#define SYSCLK_SRC_HSE 0
#define SYSCLK_SRC_HSI 1

/* Outcome of the PLL bring-up. Anything other than SYSCLK_PLL_OK means SYSCLK is
 * still the raw HSI and every cycle-derived number is meaningless. */
#define SYSCLK_PLL_OK        0
#define SYSCLK_PLL_NO_LOCK   1   /* PLLRDY never asserted */
#define SYSCLK_PLL_NO_SWITCH 2   /* PLL locked, but SWS never reported PLL */

/* Enable the FPU, run SYSCLK from the PLL at 168 MHz, and start the DWT cycle
 * counter. Called from the reset handler before main(). */
void system_init(void);

/* SYSCLK_SRC_HSE if the external crystal was usable, SYSCLK_SRC_HSI otherwise.
 * Meaningful only after system_init(). */
int system_clock_source(void);

/* One of SYSCLK_PLL_*. Meaningful only after system_init(). Callers that report
 * timings must check this: a bounded spin means system_init() returns even when
 * the PLL never came up, so a wrong crystal is a printed diagnostic rather than
 * a mute hang. */
int system_pll_status(void);

/* --- measured core clock ----------------------------------------------------
 *
 * RCC_CR.PLLRDY means "the PLL loop closed", not "the PLL is configured
 * legally". With PLLN=1 -- 49x below RM0090's floor of 50 -- an F407 still
 * asserts PLLRDY, still switches SYSCLK to the PLL, and still reports
 * clock source HSE with PLL status OK, while the core actually runs at
 * ~25 MHz. Nothing in the RCC register set distinguishes that from a healthy
 * 168 MHz. Only an independent time reference can, which is what
 * system_measure_sysclk_hz() is.
 *
 * This matters because every MB/s figure the project publishes is a DWT cycle
 * count divided by the core clock. A wrong clock scales every one of them
 * while leaving cycles/byte correct -- plausible-looking output, silently
 * wrong. So no accessor here ever hands back a nominal number: an unmeasured
 * clock reads as SYSCLK_HZ_UNMEASURED and the caller has to deal with it. */

/* The design-intent clock. Deliberately a macro and not the return value of any
 * function, so a nominal figure can only enter a calculation where the source
 * literally spells out SYSCLK_NOMINAL_HZ. */
#define SYSCLK_NOMINAL_HZ 168000000u

/* Measured/nominal agreement required before cycle-derived timings may be
 * published: 1 %, the tolerance in the Task 7 brief. */
#define SYSCLK_TOLERANCE_NUM 1u
#define SYSCLK_TOLERANCE_DEN 100u

/* system_clock_hz() returns this when no successful measurement has been made.
 * It is 0 precisely so that a caller who forgets to check divides by zero or
 * produces a visibly absurd result, rather than quietly getting 168 MHz. */
#define SYSCLK_HZ_UNMEASURED 0u

/* Result of the last system_measure_sysclk_hz() call. */
#define SYSCLK_MEAS_UNMEASURED  0   /* never attempted */
#define SYSCLK_MEAS_OK          1   /* measured, and within tolerance */
#define SYSCLK_MEAS_OUT_OF_TOL  2   /* measured, but off nominal by >1 % */
#define SYSCLK_MEAS_NO_LSE      3   /* LSERDY never asserted; no time reference */
#define SYSCLK_MEAS_NO_DWT      4   /* CYCCNT not counting; nothing to measure with */
#define SYSCLK_MEAS_NO_CAPTURE  5   /* LSE ready but TIM5 saw no edges */
#define SYSCLK_MEAS_OVERCAPTURE 6   /* captures were missed; the period count is short */

/* Measure the core clock (HCLK, the rate DWT CYCCNT ticks at) against the
 * 32.768 kHz LSE crystal and return it in Hz, or 0 if it could not be measured.
 * Takes a little over one second, plus up to eight more for LSE start-up.
 *
 * A returned value is a measurement and nothing else: it is never substituted
 * from SYSCLK_NOMINAL_HZ, and a value outside tolerance is still returned (with
 * status SYSCLK_MEAS_OUT_OF_TOL) because the honest number is more useful than
 * a refusal. Callers that publish timings must gate on
 * system_clock_meas_status() == SYSCLK_MEAS_OK, not merely on a non-zero return.
 *
 * Repeat calls re-measure. Safe to call after system_init() only. */
uint32_t system_measure_sysclk_hz(void);

/* The last measured core clock in Hz, or SYSCLK_HZ_UNMEASURED if
 * system_measure_sysclk_hz() has not run or did not succeed. This never returns
 * a nominal or assumed value -- see the note above. */
uint32_t system_clock_hz(void);

/* One of SYSCLK_MEAS_*, describing the last measurement attempt. */
int system_clock_meas_status(void);

/* TIM5's counter rate in Hz as measured in the same pass, or 0. Expected to be
 * HCLK/2 with the APB1 prescaler this firmware sets, so it is an independent
 * check that the DWT figure is not an artefact of the DWT itself. */
uint32_t system_timclk_hz(void);

#endif /* FW_M4_SYSTEM_INIT_H */
