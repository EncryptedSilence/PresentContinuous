/* fw/m4/libc_shim.c -- the freestanding subset of <string.h> GCC may emit calls
 * to on its own. -ffreestanding does not stop the compiler synthesising memset
 * and memcpy for aggregate initialisation and struct copies, and the cipher
 * headers linked from Task 9 onward trigger exactly that. Defining them here
 * keeps the firmware link independent of whichever newlib happens to be
 * installed.
 *
 * no-tree-loop-distribute-patterns is load-bearing: without it GCC recognises
 * each loop below as the very library call it is implementing and emits a
 * recursive call to it.
 */
#include <stddef.h>

__attribute__((optimize("no-tree-loop-distribute-patterns")))
void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    while (n--) { *d++ = (unsigned char)c; }
    return dst;
}

__attribute__((optimize("no-tree-loop-distribute-patterns")))
void *memcpy(void *restrict dst, const void *restrict src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) { *d++ = *s++; }
    return dst;
}
