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

/* Nominal SYSCLK in Hz. Refined by Task 7's measurement. */
uint32_t system_clock_hz(void);

#endif /* FW_M4_SYSTEM_INIT_H */
