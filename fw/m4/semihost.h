/* fw/m4/semihost.h -- host I/O over ARM semihosting. */
#ifndef FW_M4_SEMIHOST_H
#define FW_M4_SEMIHOST_H

/* Write a NUL-terminated string to the debugger's console. Each call traps to
 * the host, so this must never appear inside a timed region. */
void sh_write0(const char *s);

/* Tell the debugger the application finished normally. */
void sh_exit(void);

#endif /* FW_M4_SEMIHOST_H */
