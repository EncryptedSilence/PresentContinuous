/* fw/m4/link/sram_noart.ld -- the sram-noart memory configuration.
 *
 * product.ld with one change: every object that can execute inside a timed
 * region has its .text placed in SRAM instead of flash. Paired with -DM4_NO_ART,
 * which turns the flash accelerator off in system_init.c.
 *
 * What this configuration measures, stated precisely because the obvious reading
 * is the wrong one: it moves instruction fetch off the dedicated ICode bus and
 * onto the system bus, which is the same AHB port that carries every stack, SRAM
 * and CCM data access the cipher makes. It is *not* "the cipher without the
 * flash" and it is not a lower bound on anything. Measured on this board it is
 * 1.19x-1.76x slower than product on every one of the 39 benchmark rows, and the
 * accelerator is not what makes the difference -- with the code already in SRAM,
 * switching the ART off costs a median of 1.000x. The accelerator's own
 * contribution is what fw/m4/link/product.ld plus -DM4_NO_ART (the flash-noart
 * configuration) measures instead.
 *
 * There is no faster placement available on this part: the STM32F407 has no
 * zero-wait-state executable memory. CCM is reachable from the D-bus only, so
 * code cannot be fetched from it at all. product -- flash behind the ART -- is
 * the fast path here, not a handicap.
 *
 * .rodata deliberately stays in flash. Moving it would need another ~40 KB of
 * the 128 KB SRAM, which the working set, .bss and the stack do not leave; and
 * the two big lookup tables that decide the table rows are not in .rodata at
 * all -- the 64-bit ciphers' fused enc_tab is built at run time into CCM and
 * AES's T-tables into SRAM. What is left in flash is small constant data
 * (S-boxes, round constants), read through the same 5 wait states in both
 * configurations, with the D-cache the only difference. That residue is not
 * negligible on every row: see the report's methods section.
 *
 * .ramtext is declared *before* .text on purpose. ld assigns each input section
 * to the first output section whose pattern matches it, so with .text's
 * unqualified *(.text*) first, .ramtext would match nothing at all and every
 * symbol would stay in flash while the link still succeeded. That is the one
 * failure this configuration cannot have: verify with
 *   arm-none-eabi-nm -n build/m4/sram_noart.elf | grep present_encrypt
 * and expect 0x2000xxxx, never 0x080xxxxx.
 */
ENTRY(Reset_Handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 1024K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 128K   /* SRAM1 + SRAM2, contiguous */
  CCM   (rw)  : ORIGIN = 0x10000000, LENGTH = 64K
}
_estack = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
  .isr_vector : { KEEP(*(.isr_vector)) } > FLASH

  /* Runs from SRAM; loaded from flash by the reset handler, which reads the
     load address from _sramtext_load rather than assuming it follows .text. */
  .ramtext : {
    . = ALIGN(4);
    _sramtext = .;
    /* The cipher library. */
    *present_core.o(.text*)
    *present_ref.o(.text*)
    *present_table.o(.text*)
    *present_table_x.o(.text*)
    *present_bitslice.o(.text*)
    *present_bitslice32.o(.text*)
    *present_avx2.o(.text*)
    *present_neon.o(.text*)
    *keyschedule_portable.o(.text*)
    *variant.o(.text*)
    *variants_gen.o(.text*)
    /* The harness: sram_noart_main.o carries bench_m4_main.c and, through it,
       the static AES and lin444 kernels from bench/wide_ciphers.h and
       bench/wide_bitslice32.h -- for the 128-bit ciphers those kernels *are* the
       implementation, so this object is as load-bearing as present_bitslice32.o.

       kat.o is deliberately absent. Its 16 KB of .text is kat_check_all() and
       the cross-checking helpers, all of which run to completion before the
       first cycle is counted; kat_ok() and kat_lend_ctx() are called by ROW
       outside the TIMED body, never inside it. Nothing in it executes in a timed
       region, and at 16 KB it is the difference between fitting in SRAM and
       not. */
    *sram_noart_main.o(.text*)
    /* memcpy/memset: reachable from inside a timed region, so they belong on the
       same side of the flash boundary as the code that calls them. */
    *libc_shim.o(.text*)
    . = ALIGN(4);
    _eramtext = .;
  } > SRAM AT> FLASH
  _sramtext_load = LOADADDR(.ramtext);

  /* Lower bound, and the more valuable of the two. The failure this
     configuration cannot have is the object-name patterns above matching
     nothing: the link still succeeds, the CSV still says sram-noart, and the
     code is still in flash. The relocated set is ~98 KB, so anything under 64 KB
     means the match broke -- a renamed source, a changed object path, or .text
     claiming the sections first because someone moved this block below it. */
  ASSERT(_eramtext - _sramtext >= 64K,
         "sram-noart: .ramtext is implausibly small -- did the object-name patterns match?")

  .text   : { *(.text*) *(.rodata*) . = ALIGN(4); _etext = .; } > FLASH
  .data   : AT (_etext) { _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > SRAM
  .bss    : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > SRAM
  /* Cipher context and block buffers: zero wait states, no DMA contention. */
  .ccm (NOLOAD) : { _sccm = .; *(.ccmram*) . = ALIGN(4); _eccm = .; } > CCM
  ASSERT(_eccm - _sccm <= 64K,
         "CCM overflow: context does not fit; is PRESENT_ENC_ONLY set?")

  /* Upper bound. SRAM is shared by .ramtext, .data, .bss and the descending
     stack, so the limit is a property of all four together. The 13,548 below is
     a stack reservation, and a 4 KB margin is added to it; an over-large
     .ramtext fails the link instead of quietly running the stack into the code
     it is executing.

     What the harness actually measures, and where the reservation stands
     against it -- stated here because the reservation is not derived afresh per
     build and a reader must be able to tell how much room is left:

       measured peak    13,532 B, identical in all three configurations
                        (results/m4-speed.csv, `stack peak`, at 52c1c634ba1c;
                        it was 13,524 B before the bitslice64 rows added an
                        8-byte frame). The peak is the wide all-in-one kernels'
                        ~12 KB frame, not the cipher rows.
       reservation      13,548 B, unchanged
       + margin          4,096 B
       total slack over the measured peak                     4,112 B

     The reservation is deliberately NOT tracked to the measured peak. A guard
     that moves with each build's measurement is not a guard: it would accept
     whatever the last build happened to need, and its 16 B lead over today's
     peak would be mistaken for the safety margin when the actual safety margin
     is the 4 KB. Raise the reservation only if a measured peak ever approaches
     13,548 + 4K, and say so in the commit that does it.

     This deliberately replaces an earlier `_eramtext - _sramtext <= 96K`. That
     bound was a round number rather than a derived one, it ignored .data and
     .bss, and it left 256 bytes of headroom -- so it fired on a 390-byte edit to
     the *harness* that had nothing to do with the relocation set, with a message
     blaming the relocated code. A guard that reports the wrong cause is worse
     than the coarser one it replaces. */
  ASSERT(_ebss - ORIGIN(SRAM) <= LENGTH(SRAM) - 13548 - 4K,
         "sram-noart: .ramtext + .data + .bss leave too little SRAM for the stack")

  /* Nothing below here is loaded; drop the toolchain's metadata sections so a
     stray one cannot silently land in a memory region. */
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) }
}
