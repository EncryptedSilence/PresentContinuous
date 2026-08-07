/* fw/m4/startup_stm32f407.s -- reset vector and C runtime bring-up.
 *
 * Sole responsibility: get from the reset vector to main() with a valid stack,
 * an initialised .data and a zeroed .bss. Clock configuration lives in
 * system_init.c, which this file calls but does not know anything about.
 */
    .syntax unified
    .cpu    cortex-m4
    .fpu    fpv4-sp-d16
    .thumb

/* ---- vector table -------------------------------------------------------- */
/* Only the 16 Cortex-M system exceptions. This firmware enables no peripheral
 * interrupts, so the NVIC entries below SysTick are deliberately absent; any
 * fault lands in Default_Handler, which spins so a fault is visibly stuck under
 * the debugger rather than silently continuing. */
    .section .isr_vector, "a", %progbits
    .type   g_pfnVectors, %object
g_pfnVectors:
    .word   _estack             /*  0: initial stack pointer                  */
    .word   Reset_Handler       /*  1: reset                                  */
    .word   Default_Handler     /*  2: NMI                                    */
    .word   Default_Handler     /*  3: HardFault                              */
    .word   Default_Handler     /*  4: MemManage                              */
    .word   Default_Handler     /*  5: BusFault                               */
    .word   Default_Handler     /*  6: UsageFault                             */
    .word   0                   /*  7: reserved                               */
    .word   0                   /*  8: reserved                               */
    .word   0                   /*  9: reserved                               */
    .word   0                   /* 10: reserved                               */
    .word   Default_Handler     /* 11: SVCall                                 */
    .word   Default_Handler     /* 12: DebugMonitor                           */
    .word   0                   /* 13: reserved                               */
    .word   Default_Handler     /* 14: PendSV                                 */
    .word   Default_Handler     /* 15: SysTick                                */

/* ---- reset handler ------------------------------------------------------- */
    .section .text.Reset_Handler, "ax", %progbits
    .thumb_func
    .global Reset_Handler
    .type   Reset_Handler, %function
Reset_Handler:
    /* The core loads SP from vector[0] on a real reset, but a debugger that
     * sets PC directly after `load` does not. Set it explicitly. */
    ldr     r0, =_estack
    mov     sp, r0

    /* .data <- flash image at _etext */
    ldr     r0, =_sdata
    ldr     r1, =_edata
    ldr     r2, =_etext
1:  cmp     r0, r1
    bhs     2f
    ldr     r3, [r2], #4
    str     r3, [r0], #4
    b       1b

    /* .bss <- 0 */
2:  ldr     r0, =_sbss
    ldr     r1, =_ebss
    movs    r2, #0
3:  cmp     r0, r1
    bhs     4f
    str     r2, [r0], #4
    b       3b

    /* .ramtext <- its load image. The purecore configuration runs the cipher and
     * the harness from SRAM; product.ld defines the range empty, so this loop
     * exits immediately there and both configurations boot the same way. The
     * load address comes from the linker (_sramtext_load = LOADADDR(.ramtext))
     * rather than being assumed to follow .text.
     *
     * Order matters: this must finish before the first call to code that lives
     * in the copied range. system_init and main are both called below, and
     * neither this handler nor anything it reaches is itself relocated. */
4:  ldr     r0, =_sramtext
    ldr     r1, =_eramtext
    ldr     r2, =_sramtext_load
6:  cmp     r0, r1
    bhs     7f
    ldr     r3, [r2], #4
    str     r3, [r0], #4
    b       6b

    /* The copy wrote instructions through the data path. Flush the write buffer
     * and flush the pipeline before any of them is fetched, or the core may
     * execute what was at those addresses before the copy. */
7:  dsb
    isb

    bl      system_init
    bl      main
    /* main() must not return; if it does, stop here rather than run off. */
5:  b       5b
    .size   Reset_Handler, . - Reset_Handler

/* ---- catch-all handler --------------------------------------------------- */
    .section .text.Default_Handler, "ax", %progbits
    .thumb_func
    .global Default_Handler
    .type   Default_Handler, %function
Default_Handler:
    b       Default_Handler
    .size   Default_Handler, . - Default_Handler

    .end
