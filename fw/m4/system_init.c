/* fw/m4/system_init.c -- FPU, 168 MHz PLL with HSE fallback, DWT cycle counter.
 *
 * Register addresses and bit positions are from RM0090 (STM32F405/407/415/417),
 * sections 6 (PWR), 7 (RCC) and 3.5 (FLASH_ACR).
 */
#include "system_init.h"

#define REG32(a) (*(volatile uint32_t *)(a))

#define RCC_BASE   0x40023800u
#define RCC_CR     REG32(RCC_BASE + 0x00u)
#define RCC_PLLCFGR REG32(RCC_BASE + 0x04u)
#define RCC_CFGR   REG32(RCC_BASE + 0x08u)
#define RCC_APB1ENR REG32(RCC_BASE + 0x40u)
#define RCC_BDCR   REG32(RCC_BASE + 0x70u)

#define RCC_APB1ENR_TIM5EN (1u << 3)
#define RCC_APB1ENR_PWREN  (1u << 28)

#define RCC_BDCR_LSEON  (1u << 0)
#define RCC_BDCR_LSERDY (1u << 1)
#define RCC_BDCR_LSEBYP (1u << 2)

#define PWR_CR     REG32(0x40007000u)
#define PWR_CR_DBP (1u << 8)

#define RCC_CR_HSEON  (1u << 16)
#define RCC_CR_HSERDY (1u << 17)
#define RCC_CR_PLLON  (1u << 24)
#define RCC_CR_PLLRDY (1u << 25)

#define RCC_PLLCFGR_PLLSRC_HSE (1u << 22)

/* AHB /1, APB1 /4 (42 MHz, the part's maximum), APB2 /2 (84 MHz, likewise). */
#define RCC_CFGR_HPRE_DIV1  (0u << 4)
#define RCC_CFGR_PPRE1_DIV4 (5u << 10)
#define RCC_CFGR_PPRE2_DIV2 (4u << 13)
#define RCC_CFGR_SW_PLL     (2u << 0)
#define RCC_CFGR_SWS_MASK   (3u << 2)
#define RCC_CFGR_SWS_PLL    (2u << 2)

#define FLASH_ACR             REG32(0x40023C00u)
#define FLASH_ACR_LATENCY_5WS (5u << 0)
#define FLASH_ACR_PRFTEN      (1u << 8)
#define FLASH_ACR_ICEN        (1u << 9)
#define FLASH_ACR_DCEN        (1u << 10)

#define SCB_CPACR REG32(0xE000ED88u)
#define SCB_DEMCR REG32(0xE000EDFCu)
#define DWT_CTRL  REG32(0xE0001000u)
#define DWT_CYCCNT REG32(0xE0001004u)

/* TIM5: 32-bit general-purpose timer on APB1. Chosen because it is the only
 * F407 timer whose TIM5_OR can route the LSE straight to an input capture
 * channel, so the reference never leaves the die and needs no pin. */
#define TIM5_BASE  0x40000C00u
#define TIM5_CR1   REG32(TIM5_BASE + 0x00u)
#define TIM5_SR    REG32(TIM5_BASE + 0x10u)
#define TIM5_EGR   REG32(TIM5_BASE + 0x14u)
#define TIM5_CCMR2 REG32(TIM5_BASE + 0x1Cu)
#define TIM5_CCER  REG32(TIM5_BASE + 0x20u)
#define TIM5_CNT   REG32(TIM5_BASE + 0x24u)
#define TIM5_PSC   REG32(TIM5_BASE + 0x28u)
#define TIM5_ARR   REG32(TIM5_BASE + 0x2Cu)
#define TIM5_CCR4  REG32(TIM5_BASE + 0x40u)
#define TIM5_OR    REG32(TIM5_BASE + 0x50u)

#define TIM5_CR1_CEN     (1u << 0)
#define TIM5_EGR_UG      (1u << 0)
#define TIM5_CCMR2_CC4S_TI4 (1u << 8)   /* CC4S = 01: IC4 mapped on TI4 */
#define TIM5_CCER_CC4E   (1u << 12)     /* CC4P = CC4NP = 0 -> rising edge */
#define TIM5_SR_CC4IF    (1u << 4)
#define TIM5_SR_CC4OF    (1u << 12)

/* RM0090 18.4.22, TIM5_OR bits 7:6 (TI4_RMP):
 *   00 = GPIO   01 = LSI   10 = LSE   11 = RTC wakeup
 * The Task 7 brief says 01 for the LSE; that value is the LSI, an untrimmed RC
 * oscillator specified over 17-47 kHz. Checked on the board rather than
 * assumed: with 01 the capture channel sees no edges at all and the measurement
 * returns SYSCLK_MEAS_NO_CAPTURE, because nothing here ever sets RCC_CSR.LSION.
 * So the brief's value could not have measured the LSE under any circumstances;
 * 10 is the LSE and gives 167998062 Hz against a host-timestamped 168.0 MHz. */
#ifndef TIM5_TI4_RMP
#define TIM5_TI4_RMP (2u << 6)          /* LSE */
#endif

#define HSE_TIMEOUT 0x5000u
/* PLL lock is ~200 us; at the 16 MHz HSI this spin runs far longer than that
 * before giving up, so it can only expire on a genuinely broken clock tree. */
#define PLL_TIMEOUT 0x40000u

static int clk_src = SYSCLK_SRC_HSI;
static int pll_status = SYSCLK_PLL_OK;

void system_init(void)
{
    /* CPACR: full access to CP10/CP11. Required before any FP instruction.
     * The architecture requires DSB then ISB after a context-altering system
     * register write, before any instruction affected by it -- here, any FP
     * instruction, which -mfloat-abi=hard makes the compiler free to emit. */
    SCB_CPACR |= (0xFu << 20);
    __asm__ volatile("dsb" ::: "memory");
    __asm__ volatile("isb" ::: "memory");

    RCC_CR |= RCC_CR_HSEON;
    uint32_t spin = 0;
    while (!(RCC_CR & RCC_CR_HSERDY) && ++spin < HSE_TIMEOUT) { }

    if (RCC_CR & RCC_CR_HSERDY) {
        clk_src = SYSCLK_SRC_HSE;
        /* 8 MHz / M=8 = 1 MHz, xN=336 -> 336 MHz VCO, /P=2 -> 168 MHz */
        RCC_PLLCFGR = 8u | (336u << 6) | (0u << 16)
                    | RCC_PLLCFGR_PLLSRC_HSE | (7u << 24);
    } else {
        clk_src = SYSCLK_SRC_HSI;
        /* 16 MHz / M=16 = 1 MHz, same VCO and dividers -> 168 MHz */
        RCC_PLLCFGR = 16u | (336u << 6) | (0u << 16) | (7u << 24);
    }

    /* ART on: the product configuration. Task 10 makes this conditional.
     * The latency must be raised *before* SYSCLK is switched to the PLL;
     * doing it afterwards hangs or faults the core. */
    FLASH_ACR = FLASH_ACR_LATENCY_5WS | FLASH_ACR_PRFTEN
              | FLASH_ACR_ICEN | FLASH_ACR_DCEN;

    /* This write also sets SW=00, i.e. SYSCLK stays on the HSI it booted from.
     * That is the state both failure paths below leave the part in. */
    RCC_CFGR = RCC_CFGR_HPRE_DIV1 | RCC_CFGR_PPRE1_DIV4 | RCC_CFGR_PPRE2_DIV2;
    RCC_CR |= RCC_CR_PLLON;

    /* Both spins below are bounded, for the same reason the HSE probe is: an
     * unbounded wait on a board whose clock tree is wrong hangs the core before
     * main() and prints nothing at all, which is indistinguishable from a failed
     * flash write or a dead probe. Falling through and reporting is worth more. */
    spin = 0;
    while (!(RCC_CR & RCC_CR_PLLRDY) && ++spin < PLL_TIMEOUT) { }
    if (!(RCC_CR & RCC_CR_PLLRDY)) {
        pll_status = SYSCLK_PLL_NO_LOCK;
    } else {
        RCC_CFGR |= RCC_CFGR_SW_PLL;
        spin = 0;
        while ((RCC_CFGR & RCC_CFGR_SWS_MASK) != RCC_CFGR_SWS_PLL
               && ++spin < PLL_TIMEOUT) { }
        if ((RCC_CFGR & RCC_CFGR_SWS_MASK) != RCC_CFGR_SWS_PLL) {
            pll_status = SYSCLK_PLL_NO_SWITCH;
        }
    }

    /* DWT cycle counter: the entire basis of every measurement in Phase 4. */
    SCB_DEMCR |= (1u << 24);   /* DEMCR.TRCENA */
    DWT_CTRL  |= 1u;           /* DWT_CTRL.CYCCNTENA */
}

int system_clock_source(void) { return clk_src; }
int system_pll_status(void) { return pll_status; }

/* --- LSE-referenced measurement of the core clock ---------------------------
 *
 * Method: route the 32.768 kHz LSE to TIM5's channel-4 input capture, then take
 * DWT CYCCNT at two rising edges exactly 32768 capture events apart. That
 * interval is one LSE second, so the CYCCNT delta is the DWT tick rate in Hz --
 * which is HCLK, and HCLK is precisely the clock every cycles/byte figure in
 * this project is counted in. No RCC register is read to derive it, so a
 * mis-set PLL field cannot cancel out of the answer.
 *
 * Accuracy: the LSE crystal is the only reference, at 20-100 ppm. The polling
 * loop adds jitter bounded by one iteration (single-digit cycles) at each end,
 * under 1e-7 of a one-second baseline. Neither is visible at the 1 % tolerance.
 *
 * Every wait is bounded in CYCCNT ticks rather than loop iterations, so the
 * timeouts stay roughly constant in wall time whatever the core is actually
 * running at -- including the wrong frequencies this function exists to catch.
 */

/* 8 s at nominal. A 32.768 kHz crystal's start-up is specified in seconds, not
 * milliseconds; a timeout in the tens of ms would report "no LSE" on a board
 * that has one. Comfortably under the 2^32 CYCCNT wrap either way. */
#define LSE_START_CYCLES 1344000000u

/* ~60 ms at nominal, against a 30.5 us expected edge interval: 2000x margin, so
 * this can only expire if the capture path has genuinely stopped. */
#define CAPTURE_CYCLES 10000000u

#define LSE_HZ 32768u

static uint32_t measured_hz;
static uint32_t measured_timclk_hz;
static int meas_status = SYSCLK_MEAS_UNMEASURED;

/* Wait for the next rising-edge capture. Records CYCCNT first and CCR4 second:
 * reading CCR4 is what clears CC4IF, so it must not happen until the timestamp
 * is in hand. Returns 0 on success, -1 on timeout. */
static int wait_capture(uint32_t *cyc, uint32_t *ccr)
{
    uint32_t t0 = DWT_CYCCNT;
    while (!(TIM5_SR & TIM5_SR_CC4IF)) {
        if ((uint32_t)(DWT_CYCCNT - t0) > CAPTURE_CYCLES) { return -1; }
    }
    *cyc = DWT_CYCCNT;
    *ccr = TIM5_CCR4;
    return 0;
}

static uint32_t meas_fail(int status)
{
    measured_hz = SYSCLK_HZ_UNMEASURED;
    measured_timclk_hz = 0u;
    meas_status = status;
    return SYSCLK_HZ_UNMEASURED;
}

uint32_t system_measure_sysclk_hz(void)
{
    measured_hz = SYSCLK_HZ_UNMEASURED;
    measured_timclk_hz = 0u;
    meas_status = SYSCLK_MEAS_UNMEASURED;

    /* system_init() starts the cycle counter, but this function is the one that
     * depends on it, so it re-arms and then proves it is counting. A stuck
     * CYCCNT would otherwise show up as a delta of 0, i.e. as "no LSE". */
    SCB_DEMCR |= (1u << 24);
    DWT_CTRL  |= 1u;
    {
        uint32_t a = DWT_CYCCNT;
        for (int i = 0; i < 8; i++) { __asm__ volatile("nop"); }
        if (DWT_CYCCNT == a) { return meas_fail(SYSCLK_MEAS_NO_DWT); }
    }

    /* RCC_BDCR lives in the backup domain and is write-protected until
     * PWR_CR.DBP is set, which in turn needs the PWR peripheral clocked. The
     * read-back after each enable is the documented way to let the APB write
     * retire before the peripheral is touched. */
    RCC_APB1ENR |= RCC_APB1ENR_PWREN;
    (void)RCC_APB1ENR;
    PWR_CR |= PWR_CR_DBP;
    (void)PWR_CR;

    /* Drive the crystal, never LSEBYP: bypass mode would clock the timer from
     * whatever is on OSC32_IN, which on a board with no oscillator fitted is a
     * fabricated reference that still produces a confident-looking number.
     * Clearing it first matters because BDCR is in the backup domain and
     * survives a system reset, so a previous image's setting persists. RM0090
     * only honours a write to LSEBYP while LSEON is 0, hence the order. */
    RCC_BDCR &= ~(RCC_BDCR_LSEON | RCC_BDCR_LSEBYP);

    /* Wait out the stale LSERDY before re-enabling. LSERDY lags LSEON by about
     * six LSE cycles in each direction, so re-enabling immediately and polling
     * would match on the *previous* run's ready flag and start capturing while
     * the crystal is still settling. Bounded, and a stuck flag is reported as
     * no-LSE rather than hung. */
    uint32_t t0 = DWT_CYCCNT;
    while (RCC_BDCR & RCC_BDCR_LSERDY) {
        if ((uint32_t)(DWT_CYCCNT - t0) > LSE_START_CYCLES) {
            return meas_fail(SYSCLK_MEAS_NO_LSE);
        }
    }

    RCC_BDCR |= RCC_BDCR_LSEON;

    t0 = DWT_CYCCNT;
    while (!(RCC_BDCR & RCC_BDCR_LSERDY)) {
        if ((uint32_t)(DWT_CYCCNT - t0) > LSE_START_CYCLES) {
            return meas_fail(SYSCLK_MEAS_NO_LSE);
        }
    }

    RCC_APB1ENR |= RCC_APB1ENR_TIM5EN;
    (void)RCC_APB1ENR;

    TIM5_CR1   = 0u;
    TIM5_PSC   = 0u;                     /* count the timer clock directly */
    TIM5_ARR   = 0xFFFFFFFFu;            /* TIM5 is 32-bit on the F407 */
    TIM5_OR    = TIM5_TI4_RMP;
    TIM5_CCMR2 = TIM5_CCMR2_CC4S_TI4;    /* no input filter, no IC prescaler */
    TIM5_CCER  = TIM5_CCER_CC4E;
    TIM5_EGR   = TIM5_EGR_UG;            /* load PSC/ARR */
    TIM5_CNT   = 0u;
    TIM5_SR    = 0u;                     /* drop UG's UIF and any stale CC4IF/CC4OF */
    TIM5_CR1   = TIM5_CR1_CEN;

    /* One throwaway capture: the first edge after CEN sits a fraction of an LSE
     * period from the start, and the remap has only just taken effect. */
    uint32_t c0 = 0u, r0 = 0u, c1 = 0u, r1 = 0u;
    if (wait_capture(&c0, &r0) != 0) {
        TIM5_CR1 = 0u;
        return meas_fail(SYSCLK_MEAS_NO_CAPTURE);
    }

    /* Clear CC4OF *before* the baseline edge, not after: clearing it afterwards
     * would mean writing SR while a real edge could be pending in CC4IF, and
     * writing SR discards that edge with no trace. From here to the final check
     * SR is only ever read, so CC4OF at the end means exactly one thing -- a
     * capture the polling loop missed. */
    TIM5_SR = 0u;
    if (wait_capture(&c0, &r0) != 0) {
        TIM5_CR1 = 0u;
        return meas_fail(SYSCLK_MEAS_NO_CAPTURE);
    }

    for (uint32_t i = 0; i < LSE_HZ; i++) {
        if (wait_capture(&c1, &r1) != 0) {
            TIM5_CR1 = 0u;
            return meas_fail(SYSCLK_MEAS_NO_CAPTURE);
        }
    }

    /* CC4OF is set whenever an edge arrived while CC4IF was still pending, i.e.
     * whenever the loop missed one. The interval would then be more than 32768
     * periods and the reported frequency correspondingly high -- a wrong answer
     * that looks like a right one, so it is a hard failure. */
    int overcapture = (TIM5_SR & TIM5_SR_CC4OF) != 0u;
    TIM5_CR1 = 0u;
    if (overcapture) { return meas_fail(SYSCLK_MEAS_OVERCAPTURE); }

    uint32_t hz = c1 - c0;               /* 32768 LSE periods == 1 s */
    if (hz == 0u) { return meas_fail(SYSCLK_MEAS_NO_CAPTURE); }

    measured_hz = hz;
    measured_timclk_hz = r1 - r0;

    uint32_t tol = SYSCLK_NOMINAL_HZ / SYSCLK_TOLERANCE_DEN * SYSCLK_TOLERANCE_NUM;
    uint32_t dev = (hz > SYSCLK_NOMINAL_HZ) ? (hz - SYSCLK_NOMINAL_HZ)
                                            : (SYSCLK_NOMINAL_HZ - hz);
    meas_status = (dev <= tol) ? SYSCLK_MEAS_OK : SYSCLK_MEAS_OUT_OF_TOL;
    return hz;
}

/* Deliberately no fallback to SYSCLK_NOMINAL_HZ. See system_init.h. */
uint32_t system_clock_hz(void) { return measured_hz; }
int system_clock_meas_status(void) { return meas_status; }
uint32_t system_timclk_hz(void) { return measured_timclk_hz; }
