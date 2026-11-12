/* chacha_ascon/fw_m4/ca_m4.ld -- fw/m4/link/product.ld (code in flash, data in
   SRAM) plus the sections newlib-nano brings, all kept inside .text so the .data
   load image at _etext cannot overlap an orphan section. */
ENTRY(Reset_Handler)

MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 1024K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
  CCM   (rw)  : ORIGIN = 0x10000000, LENGTH = 64K
}
_estack = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS
{
  .isr_vector : { KEEP(*(.isr_vector)) } > FLASH
  .text : {
    *(.text*) *(.rodata*)
    . = ALIGN(4);
    __preinit_array_start = .; KEEP(*(.preinit_array*)) __preinit_array_end = .;
    __init_array_start = .;    KEEP(*(SORT(.init_array.*))) KEEP(*(.init_array*)) __init_array_end = .;
    __fini_array_start = .;    KEEP(*(SORT(.fini_array.*))) KEEP(*(.fini_array*)) __fini_array_end = .;
    KEEP(*(.init)) KEEP(*(.fini))
    . = ALIGN(4); _etext = .;
  } > FLASH
  .data : AT (_etext) { _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > SRAM
  .bss  : { _sbss = .; __bss_start__ = .; *(.bss*) *(COMMON) . = ALIGN(8); _ebss = .; __bss_end__ = .; end = .; } > SRAM
  _sramtext = 0; _eramtext = 0; _sramtext_load = 0;
  .ccm (NOLOAD) : { _sccm = .; *(.ccmram*) . = ALIGN(4); _eccm = .; } > CCM
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) }
}
