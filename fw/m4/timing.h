/* fw/m4/timing.h -- DWT cycle counting with interrupts masked.
 *
 * The whole of Phase 4's Cortex-M4 measurement rests on these two functions, so
 * they are deliberately tiny and deliberately explicit about four things:
 *
 *   The counter. DWT CYCCNT increments once per core clock (HCLK) tick. It is
 *   started in system_init() (DEMCR.TRCENA, then DWT_CTRL.CYCCNTENA) and never
 *   stopped or reset afterwards, so a caller here only ever reads it.
 *
 *   Wrap. CYCCNT is 32 bits and wraps every 2^32 cycles -- about 25.6 s at
 *   168 MHz. `end - start` in uint32_t arithmetic is exact across a single wrap,
 *   which is all a timed region shorter than 25.6 s can suffer. Nothing timed by
 *   this firmware comes close: the slowest single trial is the bit-by-bit
 *   reference kernel over 2 KiB, tens of milliseconds.
 *
 *   Interrupts. Masked for the whole measured region. This firmware enables no
 *   interrupt source -- SysTick is never started, and the TIM5 input capture the
 *   clock measurement uses is polled with its NVIC line left disabled -- so this
 *   is belt and braces rather than a fix for a known problem. It costs two
 *   instructions and removes an entire class of unexplainable outlier.
 *
 *   Reordering. `cpsid i` / `cpsie i` carry a "memory" clobber, but on their own
 *   they only stop code moving across the *instruction*, not across the CYCCNT
 *   read that follows or precedes it. So each function also places a bare
 *   compiler barrier on the timed side of its read: without the one in
 *   cyc_begin, -O3 may hoist the start of the timed work above the start
 *   timestamp; without the one in cyc_end, it may sink the end of it below the
 *   end timestamp. Either would report a region shorter than the one that ran.
 *   (These two barriers are the only addition to the primitive as specified in
 *   the task brief; they change no observable behaviour except that one.)
 */
#ifndef M4_TIMING_H
#define M4_TIMING_H

#include <stdint.h>

#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004)

static inline uint32_t cyc_begin(void)
{
    __asm__ volatile("cpsid i" ::: "memory");   /* no interrupt may land mid-measurement */
    uint32_t start = DWT_CYCCNT;
    __asm__ volatile("" ::: "memory");          /* nothing timed may float above `start` */
    return start;
}

static inline uint32_t cyc_end(uint32_t start)
{
    __asm__ volatile("" ::: "memory");          /* nothing timed may sink below `end` */
    uint32_t end = DWT_CYCCNT;
    __asm__ volatile("cpsie i" ::: "memory");
    return end - start;    /* unsigned arithmetic: a single wrap is still correct */
}

#endif /* M4_TIMING_H */
