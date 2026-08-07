/* fw/m4/kat_main.c -- run the correctness gate on the board and report.
 *
 * The last line is the gate: `kat-check: PASS` is the only outcome that clears
 * Phase 4 to time anything, and even then it is per pair -- the harness asks
 * kat_ok(cipher, impl) for each row it is about to measure. This binary exists
 * to run the same check standalone, so a failure can be read without a
 * benchmark's output around it.
 *
 * It also reports the two numbers that decide whether the firmware fits:
 * bytes of CCM in use against the linker script's 64 KiB ASSERT, and the peak
 * stack actually reached, measured by painting free SRAM before the run and
 * finding the watermark afterwards. Neither is guesswork on a target with no
 * MMU: a stack that grows into .bss produces wrong ciphertexts, which look
 * exactly like a KAT failure.
 */
#include <stdint.h>

#include "kat.h"
#include "semihost.h"
#include "system_init.h"

/* Placed by fw/m4/link/product.ld. */
extern uint32_t _sbss, _ebss, _estack, _sccm, _eccm;

#define PAINT 0xC0FFEEA5u

/* Bytes left unpainted below the caller's frame, so painting cannot overwrite
 * the frame doing the painting. */
#define PAINT_MARGIN 64u

static void paint_stack(const uint32_t *below)
{
    uint32_t *p = &_ebss;
    uint32_t *top = (uint32_t *)((uintptr_t)below - PAINT_MARGIN);
    while (p < top) *p++ = PAINT;
}

static uint32_t stack_peak(void)
{
    const uint32_t *p = &_ebss;
    while (p < &_estack && *p == PAINT) p++;
    return (uint32_t)((uintptr_t)&_estack - (uintptr_t)p);
}

int main(void)
{
    char buf[96];
    uint32_t marker = 0;

    paint_stack(&marker);

    sh_write0("m4-kat: known-answer gate\n");
    sh_write0(system_clock_source() == SYSCLK_SRC_HSE ? "clock: HSE\n"
                                                      : "clock: HSI (HSE failed)\n");

    fmt_u32(buf, sizeof buf, "ccm used:  ",
            (uint32_t)((uintptr_t)&_eccm - (uintptr_t)&_sccm), " B of 65536\n");
    sh_write0(buf);
    fmt_u32(buf, sizeof buf, "bss used:  ",
            (uint32_t)((uintptr_t)&_ebss - (uintptr_t)&_sbss), " B\n");
    sh_write0(buf);

    int failures = kat_check_all();
    kat_print_results();

    /* What the Phase 4 harness will do with the result, printed through the very
     * interface it consults. A row is only ever timed when kat_ok() answers 1;
     * everything else is status=KAT_FAIL with the timing fields left empty. The
     * "keysetup" name is here on purpose: it is a row the harness times but the
     * gate has no ciphertext for, so it exercises the documented fallback to the
     * cipher's own verdict -- a cipher whose kernel is broken must not get a key
     * setup figure published either. */
    static const char *const GATE_IMPLS[] = {
        "ref", "table", "table-x4", "bitslice32", "bitslice32-bs", "keysetup"
    };
    for (int i = 0; i < kat_n_ciphers(); i++) {
        for (unsigned k = 0; k < sizeof GATE_IMPLS / sizeof GATE_IMPLS[0]; k++) {
            const char *cipher = kat_cipher_name(i);
            const char *impl = GATE_IMPLS[k];
            buf[0] = 0;
            sh_append(buf, sizeof buf, "gate cipher=");
            sh_append(buf, sizeof buf, cipher);
            sh_append(buf, sizeof buf, " impl=");
            sh_append(buf, sizeof buf, impl);
            sh_append(buf, sizeof buf, kat_ok(cipher, impl)
                                        ? " status=ok\n"
                                        : " status=KAT_FAIL (no timing)\n");
            sh_write0(buf);
        }
    }

    fmt_u32(buf, sizeof buf, "stack peak: ", stack_peak(), " B\n");
    sh_write0(buf);

    if (failures == 0) {
        sh_write0("kat-check: PASS (0 failures)\n");
    } else {
        fmt_u32(buf, sizeof buf, "kat-check: FAIL (", (uint32_t)failures,
                " failing pairs -- do not publish timings for them)\n");
        sh_write0(buf);
    }

    sh_exit();
    for (;;) { }
}
