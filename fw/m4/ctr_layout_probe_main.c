/* fw/m4/ctr_layout_probe_main.c -- boots, calls ctr_timed_kernel once, reports
 * the result over semihosting so a run on real hardware is self-checking (the
 * value is deterministic: 0x12345678 in, always the same word out).
 *
 * This binary's only reason to exist is to put ctr_timed_kernel in a linked
 * image for tools/tests/test_m4_layout.py to inspect with
 * `arm-none-eabi-nm`; see fw/m4/ctr_layout_probe.h.
 */
#include "ctr_layout_probe.h"
#include "semihost.h"

int main(void)
{
    char buf[64];
    uint32_t r = ctr_timed_kernel(0x12345678u);
    fmt_hex32(buf, sizeof buf, "ctr_timed_kernel(0x12345678) = ", r, "\n");
    sh_write0(buf);
    sh_write0("ctr-layout-probe: ok\n");
    sh_exit();
    for (;;) { }
}
