/* fw/m4/flash_noart_main.c -- the m4-bench harness, flash-noart configuration.
 *
 * Identical code and identical linker script (fw/m4/link/product.ld) to
 * build/m4/bench_m4.elf. The only difference is -DM4_NO_ART, which clears
 * FLASH_ACR's prefetch and both ART caches in system_init.c.
 *
 * That makes this the clean measurement of the accelerator's own contribution:
 * one variable changes, and nothing about where the code or the data sits does.
 * It is the configuration that answers "how much of each figure belongs to the
 * flash accelerator" -- 1.346x to 2.483x, median 1.773x, on this board.
 *
 * FLASH_ACR_LATENCY_5WS stays. Five wait states are a property of the flash
 * array at 168 MHz, not of the accelerator, and clearing them corrupts
 * instruction fetch.
 *
 * The Makefile's pattern rule derives a binary's main from its name
 * (fw/m4/NAME_main.c), so this file exists to give the flash-noart binary that
 * name. It includes the harness rather than duplicating it: there is exactly one
 * copy of the benchmark, and the configurations cannot drift apart.
 * -DM4_NO_ART and -DM4_CONFIG="flash-noart" come from M4_DEFS_flash_noart.
 */
#include "bench_m4_main.c"
