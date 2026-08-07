/* fw/m4/purecore_main.c -- the m4-bench harness, purecore configuration.
 *
 * Identical code to build/m4/bench_m4.elf; the difference is entirely in how it
 * is linked and what the flash controller is told to do:
 *
 *   product   code in flash, ART on  (prefetch + 1 KB I-cache + 1 KB D-cache)
 *   purecore  code in SRAM,  ART off (prefetch and both caches disabled)
 *
 * Both keep FLASH_ACR_LATENCY_5WS: five wait states are a property of the flash
 * at 168 MHz, not of the accelerator, and clearing them corrupts instruction
 * fetch even when nothing is executing from flash.
 *
 * The Makefile's pattern rule derives a binary's main from its name
 * (fw/m4/NAME_main.c), so this file exists to give the purecore binary that
 * name. It includes the harness rather than duplicating it: there is exactly one
 * copy of the benchmark, and the two configurations cannot drift apart.
 * -DM4_PURECORE and -DM4_CONFIG="purecore" come from M4_DEFS_purecore.
 */
#include "bench_m4_main.c"
