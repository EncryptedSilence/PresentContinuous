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
uint32_t system_clock_hz(void) { return 168000000u; }   /* refined by Task 7 */
