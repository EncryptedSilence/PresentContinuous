/* fw/m4/hello_main.c -- smoke test: boot, clock, one line to the host. */
#include "semihost.h"
#include "system_init.h"

int main(void)
{
    sh_write0(system_clock_source() == SYSCLK_SRC_HSE
                  ? "clock: HSE\n"
                  : "clock: HSI (HSE failed)\n");

    /* Silent on the healthy path, so the expected output stays one line. */
    if (system_pll_status() == SYSCLK_PLL_NO_LOCK) {
        sh_write0("pll: did not lock; SYSCLK is the raw HSI\n");
    } else if (system_pll_status() == SYSCLK_PLL_NO_SWITCH) {
        sh_write0("pll: locked but SYSCLK switch did not take\n");
    }

    sh_exit();
    for (;;) { }
}
