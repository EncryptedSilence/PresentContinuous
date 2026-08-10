/* fw/m4/link/product.ld -- code in flash, tables and state in CCM. */
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

  /* The timed kernel at a fixed address, so a measurement cannot depend on
     which unrelated routine happened to precede it in the image. The repository
     measured up to 7.5% variation from position relative to the 128-bit flash
     fetch boundary; pinning the address is what removes it.

     Placed before .text on purpose, for the same reason sram_noart.ld places
     .ramtext first: ld assigns each input section to the first output section
     whose pattern matches, so with an unqualified *(.text*) first, .timed would
     match nothing and every symbol would stay where it was while the link still
     succeeded. tools/tests/test_m4_layout.py is the guard on that. */
  .timed 0x08010000 : ALIGN(16) { KEEP(*(.timed*)) . = ALIGN(16); } > FLASH

  .text   : { *(.text*) *(.rodata*) . = ALIGN(4); _etext = .; } > FLASH
  .data   : AT (_etext) { _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > SRAM
  .bss    : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > SRAM

  /* No code is relocated in this configuration -- this script is what both the
     product and flash-noart builds link against; they differ only in M4_NO_ART.
     The reset handler is shared with sram_noart.ld, so it always runs the
     .ramtext copy loop; an empty range makes that loop exit on its first
     comparison. Defined here rather than guarded in the assembler so all three
     configurations run the identical boot path. */
  _sramtext      = 0;
  _eramtext      = 0;
  _sramtext_load = 0;
  /* Cipher context and block buffers: zero wait states, no DMA contention. */
  .ccm (NOLOAD) : { _sccm = .; *(.ccmram*) . = ALIGN(4); _eccm = .; } > CCM
  ASSERT(_eccm - _sccm <= 64K,
         "CCM overflow: context does not fit; is PRESENT_ENC_ONLY set?")

  /* Nothing below here is loaded; drop the toolchain's metadata sections so a
     stray one cannot silently land in a memory region. */
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) }
}
