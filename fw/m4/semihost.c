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

/* --- tiny formatters -------------------------------------------------------
 * Everything below is bounds-checked against `len` rather than assuming the
 * caller sized the buffer: a formatter that can overrun would corrupt the very
 * measurement it is printing, and there is no MPU or stack guard here to catch
 * it. `put` is the single point where the bound is enforced. */

static size_t put(char *buf, size_t len, size_t at, const char *s)
{
    while (*s != '\0' && at + 1u < len) { buf[at++] = *s++; }
    return at;
}

void fmt_u32(char *buf, size_t len, const char *prefix, uint32_t v,
             const char *suffix)
{
    char dec[11];               /* 4294967295 is 10 digits */
    size_t n = 0;

    if (len == 0u) { return; }

    do { dec[n++] = (char)('0' + (v % 10u)); v /= 10u; } while (v != 0u);

    size_t at = put(buf, len, 0u, prefix);
    while (n != 0u && at + 1u < len) { buf[at++] = dec[--n]; }
    at = put(buf, len, at, suffix);
    buf[at] = '\0';
}

void fmt_hex32(char *buf, size_t len, const char *prefix, uint32_t v,
               const char *suffix)
{
    static const char digits[] = "0123456789abcdef";
    size_t at;

    if (len == 0u) { return; }

    at = put(buf, len, 0u, prefix);
    at = put(buf, len, at, "0x");
    for (int shift = 28; shift >= 0; shift -= 4) {
        if (at + 1u >= len) { break; }
        buf[at++] = digits[(v >> shift) & 0xFu];
    }
    at = put(buf, len, at, suffix);
    buf[at] = '\0';
}
