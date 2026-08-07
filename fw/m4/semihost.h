/* fw/m4/semihost.h -- host I/O over ARM semihosting. */
#ifndef FW_M4_SEMIHOST_H
#define FW_M4_SEMIHOST_H

#include <stddef.h>
#include <stdint.h>

/* Write a NUL-terminated string to the debugger's console. Each call traps to
 * the host, so this must never appear inside a timed region. */
void sh_write0(const char *s);

/* Compose prefix + decimal(v) + suffix into buf, always NUL-terminated and
 * never writing past buf[len-1]. The firmware is -ffreestanding: there is no
 * printf and no snprintf to borrow. Truncates silently if buf is too small;
 * callers here size buf generously (a u32 is at most 10 digits). */
void fmt_u32(char *buf, size_t len, const char *prefix, uint32_t v,
             const char *suffix);

/* Same, but v is written as 8 lowercase hex digits with a 0x prefix. Used to
 * dump RCC registers alongside a measurement, so a wrong frequency can be
 * traced to the field that caused it in the same run. */
void fmt_hex32(char *buf, size_t len, const char *prefix, uint32_t v,
               const char *suffix);

/* Tell the debugger the application finished normally. */
void sh_exit(void);

#endif /* FW_M4_SEMIHOST_H */
