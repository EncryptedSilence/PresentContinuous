/* fw/m4/semihost.c -- ARM semihosting. Never called inside a timed region. */
#include <stdint.h>

#include "semihost.h"

/* R1 carries either a pointer or an immediate depending on the operation, so it
 * is typed as uintptr_t rather than void *. */
static inline int sh_call(int op, uintptr_t arg)
{
    register int r0 __asm__("r0") = op;
    register uintptr_t r1 __asm__("r1") = arg;
    __asm__ volatile("bkpt #0xAB" : "+r"(r0) : "r"(r1) : "memory");
    return r0;
}

void sh_write0(const char *s) { sh_call(0x04, (uintptr_t)s); }   /* SYS_WRITE0 */

void sh_exit(void)
{
    /* On AArch32, SYS_EXIT takes the reason code *directly* in R1 -- it is not a
     * pointer. The {reason, subcode} block form is SYS_EXIT_EXTENDED (0x20),
     * which is a different operation number. Cross-checked against newlib's
     * librdimon _kill_shared. */
    sh_call(0x18, 0x20026u);   /* SYS_EXIT, ADP_Stopped_ApplicationExit */
}
