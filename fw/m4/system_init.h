/* fw/m4/system_init.h -- clock tree bring-up for the STM32F407. */
#ifndef FW_M4_SYSTEM_INIT_H
#define FW_M4_SYSTEM_INIT_H

#include <stdint.h>

#define SYSCLK_SRC_HSE 0
#define SYSCLK_SRC_HSI 1

/* Enable the FPU, run SYSCLK from the PLL at 168 MHz, and start the DWT cycle
 * counter. Called from the reset handler before main(). */
void system_init(void);

/* SYSCLK_SRC_HSE if the external crystal was usable, SYSCLK_SRC_HSI otherwise.
 * Meaningful only after system_init(). */
int system_clock_source(void);

/* Nominal SYSCLK in Hz. Refined by Task 7's measurement. */
uint32_t system_clock_hz(void);

#endif /* FW_M4_SYSTEM_INIT_H */
