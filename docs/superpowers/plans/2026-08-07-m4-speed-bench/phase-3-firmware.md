# Phase 3 — Firmware

Tasks 6–8. **This is the first phase that touches the board.** See [README.md](README.md) for global constraints.

Before starting, confirm the probe is visible:

```bash
st-info --probe
```
Expected: `Found 1 stlink programmers`, `chipid: 0x413`. If it reports zero, the device node is stale — replug the USB cable, or run `sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=usb --action=add`.

---

### Task 6: Firmware skeleton — boot, clock, semihosting

Ends with the board printing a line to the host. Everything after this task is incremental.

**Files:**
- Create: `fw/m4/startup_stm32f407.s`, `fw/m4/system_init.c`, `fw/m4/system_init.h`, `fw/m4/semihost.c`, `fw/m4/semihost.h`, `fw/m4/link/product.ld`, `fw/m4/hello_main.c`, `fw/m4/run.gdb`
- Modify: `Makefile`

**Interfaces:**
- Produces: `void system_init(void)`; `uint32_t system_clock_hz(void)`; `int system_clock_source(void)` returning `SYSCLK_SRC_HSE` (0) or `SYSCLK_SRC_HSI` (1); `void sh_write0(const char *s)`; `void sh_exit(void)`.

- [ ] **Step 1: Write the linker script**

```ld
/* fw/m4/link/product.ld -- code in flash, tables and state in CCM. */
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
  .text   : { *(.text*) *(.rodata*) . = ALIGN(4); _etext = .; } > FLASH
  .data   : AT (_etext) { _sdata = .; *(.data*) . = ALIGN(4); _edata = .; } > SRAM
  .bss    : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > SRAM
  /* Cipher context and block buffers: zero wait states, no DMA contention. */
  .ccm (NOLOAD) : { _sccm = .; *(.ccmram*) . = ALIGN(4); _eccm = .; } > CCM
  ASSERT(_eccm - _sccm <= 64K,
         "CCM overflow: context does not fit; is PRESENT_ENC_ONLY set?")
}
```

That `ASSERT` is the mechanical enforcement of the spec's memory budget: a full `present_ctx_t` is 66,056 B and will fail the link, an encryption-only one is 33,032 B and will pass.

> **Corrected during execution.** The spec's original 32,776 B was an arithmetic slip; the measured encryption-only size is 33,032 B. `PRESENT_ENC_ONLY` drops exactly `rk_mask_dec` + `pinv_tab` + `sinv_byte` = 33,024 B. Separately, the spec asserted `PRESENT_ENC_ONLY` as an existing feature — it did not exist in `src/` and was implemented in Task 8, inert when undefined (verified by byte-identical preprocessed headers and byte-identical host object files).

- [ ] **Step 2: Write startup**

`fw/m4/startup_stm32f407.s` provides the initial SP word (`_estack`), the reset handler, and a vector table with a default handler that spins (a fault must be visibly stuck, never silently continue). The reset handler copies `.data` from `_etext`, zeroes `.bss`, calls `system_init`, then `main`.

- [ ] **Step 3: Write clock init with HSE fallback**

The FPU must be enabled before any floating-point instruction, and the build uses `-mfloat-abi=hard`, so this comes first.

```c
/* fw/m4/system_init.c */
#define SYSCLK_SRC_HSE 0
#define SYSCLK_SRC_HSI 1
#define HSE_TIMEOUT    0x5000u

static int clk_src = SYSCLK_SRC_HSI;

void system_init(void)
{
    /* CPACR: full access to CP10/CP11. Required before any FP instruction. */
    *(volatile uint32_t *)0xE000ED88 |= (0xFu << 20);

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

    /* ART on: the product configuration. Task 10 makes this conditional. */
    FLASH_ACR = FLASH_ACR_LATENCY_5WS | FLASH_ACR_PRFTEN
              | FLASH_ACR_ICEN | FLASH_ACR_DCEN;

    RCC_CFGR = RCC_CFGR_HPRE_DIV1 | RCC_CFGR_PPRE1_DIV4 | RCC_CFGR_PPRE2_DIV2;
    RCC_CR |= RCC_CR_PLLON;
    while (!(RCC_CR & RCC_CR_PLLRDY)) { }
    RCC_CFGR |= RCC_CFGR_SW_PLL;
    while ((RCC_CFGR & RCC_CFGR_SWS_MASK) != RCC_CFGR_SWS_PLL) { }

    /* DWT cycle counter: the entire basis of every measurement in Phase 4. */
    *(volatile uint32_t *)0xE000EDFC |= (1u << 24);   /* DEMCR.TRCENA */
    *(volatile uint32_t *)0xE0001000 |= 1u;           /* DWT_CTRL.CYCCNTENA */
}

int system_clock_source(void) { return clk_src; }
uint32_t system_clock_hz(void) { return 168000000u; }   /* refined by Task 7 */
```

Setting the flash latency to 5 WS **before** raising the clock is mandatory; doing it after will hang or fault the core.

- [ ] **Step 4: Write semihosting**

```c
/* fw/m4/semihost.c -- ARM semihosting. Never called inside a timed region. */
static inline int sh_call(int op, void *arg)
{
    register int r0 __asm__("r0") = op;
    register void *r1 __asm__("r1") = arg;
    __asm__ volatile("bkpt #0xAB" : "+r"(r0) : "r"(r1) : "memory");
    return r0;
}

void sh_write0(const char *s) { sh_call(0x04, (void *)s); }   /* SYS_WRITE0 */

void sh_exit(void)
{
    uint32_t args[2] = {0x20026u, 0u};   /* ADP_Stopped_ApplicationExit */
    sh_call(0x18, args);                 /* SYS_EXIT */
}
```

A `bkpt` with no debugger attached halts the core. That is acceptable here — the firmware is only ever run under `st-util`.

- [ ] **Step 5: Write `hello_main.c` and the gdb script**

```c
/* fw/m4/hello_main.c */
#include "semihost.h"
#include "system_init.h"

int main(void)
{
    sh_write0(system_clock_source() == 0 ? "clock: HSE\n"
                                         : "clock: HSI (HSE failed)\n");
    sh_exit();
    for (;;) { }
}
```

```
# fw/m4/run.gdb
target extended-remote :4242
monitor semihosting enable
load
continue
quit
```

- [ ] **Step 6: Add the build target**

```make
M4_CC    := arm-none-eabi-gcc
M4_FLAGS := -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard \
            -O3 -std=gnu11 -Wall -Wextra -ffreestanding -DPRESENT_ENC_ONLY \
            -Iinclude -Isrc -Ifw/m4
M4_LD    := -Tfw/m4/link/product.ld -nostartfiles -Wl,--gc-sections

m4-hello:
	@mkdir -p $(BUILD)/m4
	$(M4_CC) $(M4_FLAGS) $(M4_LD) -o $(BUILD)/m4/hello.elf \
	    fw/m4/startup_stm32f407.s fw/m4/system_init.c fw/m4/semihost.c \
	    fw/m4/hello_main.c
	arm-none-eabi-objcopy -O binary $(BUILD)/m4/hello.elf $(BUILD)/m4/hello.bin
```

- [ ] **Step 7: Flash and run it on the board**

```bash
make m4-hello
st-flash --reset write build/m4/hello.bin 0x08000000
st-util & sleep 1
gdb-multiarch -batch -x fw/m4/run.gdb build/m4/hello.elf
kill %1
```
Expected: `clock: HSE` printed on the host.

If it prints `clock: HSI (HSE failed)`, the fitted crystal is not usable — record that fact and continue; Task 7 measures the real frequency either way. If nothing prints, check that `monitor semihosting enable` was accepted; without it the `bkpt` halts the core with no output.

- [ ] **Step 8: Commit**

```bash
git add fw/m4 Makefile
git commit -m "Add STM32F407 firmware skeleton: boot, 168MHz clock, semihosting"
```

---

### Task 7: On-device clock verification

Removes the risk that an undocumented crystal silently scales every MB/s figure while leaving cycles/byte correct.

> **Amended during execution — this task is a hard precondition for Phase 4, not a refinement.** Task 6's review established that `RCC_CR.PLLRDY` is a "loop closed" flag, not a validity check. With `PLLN=1` — 49× below its legal floor — the F407 still asserted `PLLRDY` and switched `SYSCLK` to the PLL (`RCC_CR=0x03037e83`, `RCC_CFGR=0x940a`), running at a measured 24.98 MHz while the firmware reported `clock: HSE`, `pll_status=OK`, and `system_clock_hz() == 168000000`. A silent 6.7× error that nothing else in the system can detect. So: `system_clock_hz()` must return the **measured** value and be self-describing when unmeasured, and a measurement outside tolerance is a hard failure that stops Phase 4 rather than a note in the CSV header. Task 6's independent host-timestamped measurement already puts the real clock at 168.017–168.079 MHz, so this task is expected to confirm that — but it must be able to fail.

**Files:**
- Modify: `fw/m4/system_init.c`, `fw/m4/system_init.h`
- Create: `fw/m4/clock_check_main.c`
- Modify: `Makefile`

**Interfaces:**
- Produces: `uint32_t system_measure_sysclk_hz(void)` — the measured SYSCLK in Hz, or `0` if the LSE never starts.

- [ ] **Step 1: Implement the measurement**

Enable LSE: set `PWR_CR.DBP` to unlock the backup domain, then `RCC_BDCR.LSEON`, and wait for `LSERDY` with a timeout. Route LSE to TIM5 channel 4 by setting `TIM5_OR.TI4_RMP = 0b10`, capture on the rising edge, and count DWT cycles between two captures 32768 LSE periods apart. At nominal LSE that interval is exactly one second, so the DWT delta *is* SYSCLK in Hz.

Return `0` on LSE timeout, so the caller reports `unverified` rather than a fabricated number.

> **Corrected during execution.** This step originally specified `TI4_RMP = 0b01`. That is the **LSI** — an RC oscillator with a 17–47 kHz spread — not the LSE. Established on hardware, not from the datasheet alone: with `LSION` set, `01` sees ~30,434 Hz drifting −283 ppm with die temperature and scattering 1600 ppm, while `10` sees 32,767.999 Hz, −0.04 ppm over a 40 s burn with 0.1 ppm spread — RC versus crystal. Clearing `RCC_CSR.LSION` makes `01` produce zero captures, which proves its source is gated by `LSION` and is therefore the LSI. Had `LSION` happened to be set, the original value would have referenced the RC oscillator and produced a plausible but wrong core frequency — the exact failure this task exists to catch.

- [ ] **Step 2: Print measured against nominal**

```c
/* fw/m4/clock_check_main.c */
#include "semihost.h"
#include "system_init.h"

int main(void)
{
    char buf[96];
    uint32_t hz = system_measure_sysclk_hz();
    if (hz == 0) {
        sh_write0("sysclk: unverified (LSE did not start)\n");
    } else {
        fmt_u32(buf, sizeof buf, "sysclk measured: ", hz, " Hz\n");
        sh_write0(buf);
    }
    sh_exit();
    for (;;) { }
}
```

`fmt_u32` is a small unsigned-to-decimal formatter in `semihost.c`; the firmware is `-ffreestanding` and has no `printf`.

- [ ] **Step 3: Run on the board and check the tolerance**

```bash
make m4-clock-check
st-flash --reset write build/m4/clock_check.bin 0x08000000
st-util & sleep 1
gdb-multiarch -batch -x fw/m4/run.gdb build/m4/clock_check.elf
kill %1
```

Expected: within 1% of `168000000`. Diagnose before proceeding — every number in Phase 4 depends on this being right:

| Measured | Meaning |
|---|---|
| ~168,000,000 | Correct |
| ~336,000,000 | PLL `P` divider wrong |
| ~84,000,000 | AHB prescaler not `/1`, or `P` wrong the other way |
| ~10,500,000 | Fell back to HSI with the HSE `M` divider still set |
| `unverified` | No LSE crystal fitted; MB/s stays nominal and the CSV must say so |

- [ ] **Step 4: Commit**

```bash
git add fw/m4/system_init.c fw/m4/system_init.h fw/m4/clock_check_main.c Makefile
git commit -m "Verify M4 core clock against the LSE crystal on-device"
```

---

### Task 8: KAT vectors and the on-device gate

Nothing is timed until it is proven correct on the board.

**Files:**
- Create: `tools/gen_m4_kats.py`, `fw/m4/kat.c`, `fw/m4/kat.h`
- Generated: `fw/m4/gen/kat_vectors.h`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `cipher_set.resolve()` (Task 1); the host `build/present-cli` and `build/wide_bench` as the trusted oracle.
- Produces: `int kat_check_all(void)` returning the number of failures; `int kat_ok(const char *cipher, const char *impl)` for the harness to consult per pair.

- [ ] **Step 1: Generate vectors from the trusted host build**

`tools/gen_m4_kats.py` runs the host implementations for each of the seven ciphers over a fixed key and four fixed plaintexts, emitting:

```c
/* AUTO-GENERATED by tools/gen_m4_kats.py. Do not edit. */
#ifndef M4_KAT_VECTORS_H
#define M4_KAT_VECTORS_H
typedef struct {
    const char *cipher;
    int rounds;
    uint8_t key[16];
    uint8_t pt[16];
    uint8_t ct[16];
    int block_bytes;    /* 8 for the src/ variants, 16 for the wide ciphers */
} kat_t;
static const kat_t KATS[] = {
    { "present-80-r16", 16, {...}, {...}, {...}, 8 },
    /* ...one row per (cipher, plaintext)... */
};
#define N_KATS (sizeof KATS / sizeof KATS[0])
#endif
```

Fixed plaintexts, matching the style of `PRESENT_KATS` at `tools/gen_fpga.py:37`: all-zero, all-ones, `0x0123456789ABCDEF`, `0xFEDCBA9876543210` (left-padded for the 128-bit ciphers).

- [ ] **Step 2: Implement the gate**

`kat_check_all()` runs every (cipher, implementation) pair against its vectors and records which pairs failed. The Phase 4 harness calls it once at startup and skips timing for any failing pair, emitting `status=KAT_FAIL` with no timing figures.

- [ ] **Step 3: Verify the gate actually catches a fault**

A gate that has never failed is not known to work.

```bash
# Corrupt one gate in a generated u32 circuit.
sed -i '0,/\^/{s/\^/\&/}' src/gen/sbox_circuits.h   # first XOR becomes AND
make m4-bench-fw && <flash and run>
```
Expected: KAT failures reported for every cipher using that circuit, and **no timing rows** for them.

Then restore and confirm a clean pass:

```bash
make generate            # regenerates sbox_circuits.h from source
git diff --stat src/gen/ # expect: no changes
```
Expected: all KATs pass.

- [ ] **Step 4: Commit**

```bash
git add tools/gen_m4_kats.py fw/m4/kat.c fw/m4/kat.h Makefile
git commit -m "Add on-device known-answer gate for the M4 benchmark"
```
