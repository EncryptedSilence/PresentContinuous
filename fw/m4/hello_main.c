/* fw/m4/hello_main.c -- smoke test: boot, clock, one line to the host. */
#include "semihost.h"
#include "system_init.h"

int main(void)
{
    sh_write0(system_clock_source() == SYSCLK_SRC_HSE
                  ? "clock: HSE\n"
                  : "clock: HSI (HSE failed)\n");
    sh_exit();
    for (;;) { }
}
