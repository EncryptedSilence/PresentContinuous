/* fw/m4/ctr_layout_probe.h -- layout regression fixture for the .timed section.
 *
 * ctr_timed_kernel is NOT the CTR kernel. It exists so that
 * tools/tests/test_m4_layout.py has a real, permanent symbol to check inside
 * fw/m4/link/product.ld's `.timed` output section, regardless of whether a
 * CTR-benchmark image happens to be built yet -- at the point this file was
 * added, it did not: the CTR kernel lands on this target in a later task, and
 * this file is the fixed point that lets the section/address contract be
 * proven and kept under regression before that happens.
 *
 * `ctr_timed_kernel` is the cross-task contract: later per-cipher CTR images
 * (a later task's `.timed`-tagged entry points) are additional occupants of
 * the same section at the same address, in their own images -- they do not
 * replace this symbol, and this file is not deleted when they land.
 */
#ifndef FW_M4_CTR_LAYOUT_PROBE_H
#define FW_M4_CTR_LAYOUT_PROBE_H

#include <stdint.h>

/* A small, deliberately non-foldable mixing function: `noinline` so it always
 * exists as its own symbol (never disappears into a caller), `used` so it is
 * kept even if a future caller is removed, and its result depends on the
 * argument at runtime so -O3 cannot reduce the body to a constant. */
uint32_t ctr_timed_kernel(uint32_t x);

#endif /* FW_M4_CTR_LAYOUT_PROBE_H */
