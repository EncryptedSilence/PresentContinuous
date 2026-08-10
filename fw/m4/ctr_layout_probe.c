/* fw/m4/ctr_layout_probe.c -- the layout regression fixture, see the header.
 *
 * Pinned into `.timed` (fw/m4/link/product.ld) at a fixed flash address, the
 * same mechanism the CTR kernel will use once it exists on this target. The
 * body is real work -- a 64-round rotate/add/xor mix, not a stub -- so the
 * linked symbol has a real, nonzero size for `arm-none-eabi-nm` to report and
 * so `-O3` cannot see through it and fold the call to a constant: the return
 * value depends on `x`, which every caller supplies only at runtime.
 */
#include "ctr_layout_probe.h"

uint32_t ctr_timed_kernel(uint32_t x)
    __attribute__((section(".timed"), aligned(16), noinline, used));

uint32_t ctr_timed_kernel(uint32_t x)
{
    uint32_t acc = x;
    for (int i = 0; i < 64; i++) {
        acc = (acc << 3) | (acc >> 29);
        acc += 0x9E3779B9u ^ (uint32_t)i;
        acc ^= acc >> 7;
    }
    return acc;
}
