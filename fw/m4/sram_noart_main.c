/* fw/m4/sram_noart_main.c -- the m4-bench harness, sram-noart configuration.
 *
 * Identical code to build/m4/bench_m4.elf; the difference is entirely in how it
 * is linked and what the flash controller is told to do. The three published
 * configurations are:
 *
 *   product      code in flash, ART on   (prefetch + 1 KB I-cache + 1 KB D-cache)
 *   flash-noart  code in flash, ART off  -- the accelerator's own contribution
 *   sram-noart   code in SRAM,  ART off  -- instruction fetch moved to the
 *                                          shared system bus
 *
 * All three keep FLASH_ACR_LATENCY_5WS: five wait states are a property of the
 * flash at 168 MHz, not of the accelerator, and clearing them corrupts
 * instruction fetch even here, where .rodata, the vector table and the boot path
 * all still live in flash.
 *
 * This one is NOT "the cipher without the flash" and NOT a lower bound. Moving
 * the code to SRAM takes instruction fetch off the dedicated ICode bus and puts
 * it on the system bus, alongside every data access -- see fw/m4/link/sram_noart.ld.
 * The STM32F407 has no zero-wait-state executable memory (CCM is D-bus only), so
 * product is the fast path on this part.
 *
 * The Makefile's pattern rule derives a binary's main from its name
 * (fw/m4/NAME_main.c), so this file exists to give the sram-noart binary that
 * name. It includes the harness rather than duplicating it: there is exactly one
 * copy of the benchmark, and the configurations cannot drift apart.
 * -DM4_NO_ART and -DM4_CONFIG="sram-noart" come from M4_DEFS_sram_noart.
 */
#include "bench_m4_main.c"
