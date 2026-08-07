/* fw/m4/semihost.c -- ARM semihosting. Never called inside a timed region. */
#include <stdint.h>

#include "semihost.h"

static inline int sh_call(int op, void *arg)
{
    register int r0 __asm__("r0") = op;
    register void *r1 __asm__("r1") = arg;
    __asm__ volatile("bkpt #0xAB" : "+r"(r0) : "r"(r1) : "memory");
    return r0;
}

void sh_write0(const char *s) { sh_call(0x04, (void *)(uintptr_t)s); }  /* SYS_WRITE0 */

void sh_exit(void)
{
    uint32_t args[2] = {0x20026u, 0u};   /* ADP_Stopped_ApplicationExit */
    sh_call(0x18, args);                 /* SYS_EXIT */
}
