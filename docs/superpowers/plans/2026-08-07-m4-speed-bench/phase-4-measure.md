# Phase 4 — Measurement and results

Tasks 9–12. Runs on the board. See [README.md](README.md) for global constraints.

---

### Task 9: The benchmark harness

**Files:**
- Create: `fw/m4/bench_m4.c`, `fw/m4/timing.h`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `present_encrypt_bitslice32` and friends (Task 3), `aes_encrypt_bs32` / `lin_encrypt_bs32` (Task 5), `system_clock_source` / `system_measure_sysclk_hz` (Tasks 6–7), `kat_ok` (Task 8).
- Produces: CSV rows on the semihosting channel.

- [ ] **Step 1: Implement the timing primitive**

```c
/* fw/m4/timing.h -- DWT cycle counting with interrupts masked. */
#ifndef M4_TIMING_H
#define M4_TIMING_H

#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004)

static inline uint32_t cyc_begin(void)
{
    __asm__ volatile("cpsid i" ::: "memory");   /* no interrupt may land mid-measurement */
    return DWT_CYCCNT;
}

static inline uint32_t cyc_end(uint32_t start)
{
    uint32_t end = DWT_CYCCNT;
    __asm__ volatile("cpsie i" ::: "memory");
    return end - start;    /* unsigned arithmetic: a single wrap is still correct */
}

#endif
```

- [ ] **Step 2: Implement the measurement loop**

Same protocol as `bench/bench_main.c` so the figures are the same shape as the x86 ones: `WARMUP 3`, `TRIALS 15`, report **median** and **min**. Specifics for this target:

- Working set 256 blocks (2 KiB), declared `__attribute__((section(".ccmram")))`.
- The `present_ctx_t` also lives in `.ccmram`, built one cipher at a time into the same buffer.
- A `volatile` sink consumes each result so `-O3` cannot delete the timed work.
- SysTick stays disabled for the entire run; nothing may generate an interrupt.
- Key setup is timed separately from encryption, as `impl=keysetup`.

**Amended during execution (Task 5).** Every bitsliced cipher reports **two** rows, following `bench/bench_main.c:338-343`: `bitslice32` (bit transpose included) and `bitslice32-bs` (state already transposed). On this target the transpose was measured at 77% of `aes_encrypt_bs32(rounds=5)`, so a single row would be reporting a transpose benchmark, and reporting only the `-bs` form for PRESENT while charging AES for its transpose would not be comparing the same thing. All seven ciphers report both. The bitsliced key expansion is hoisted out of the timed loop for every cipher, matching `bench/wide_bench.c:679`.

- [ ] **Step 3: Emit CSV with a provenance header**

```
# m4-speed: STM32F407, sysclk <measured> Hz (source HSE|HSI, <verified|unverified>)
# config <product|flash-noart|sram-noart>, PRESENT_ENC_ONLY, working set 256 blocks (2 KiB)
cipher,rounds,impl,config,cycles_per_byte,cycles_per_byte_min,mb_per_sec,ns_per_op,status
present-80-r16,16,bitslice32,product,1.234,1.201,1234.5,12.3,ok
```

`status` is `ok` or `KAT_FAIL`; a `KAT_FAIL` row carries empty timing fields. The header must state the measured clock and whether it was verified — a reader cannot check MB/s without it.

- [ ] **Step 4: Run and sanity-check the sign of the results**

Expected from the repo's existing measurements, which the M4 should agree with in direction even where it differs in magnitude:

- PRESENT's bitslice path beats its table path. `src/present_bitslice.c:22` records 8.4x on x86.
- The cipher-D family's **table** path beats its bitslice path — the same comment records the table path winning by 6.5x scalar, because an 8-bit S-box costs 1107 gates against PRESENT's 15.

If bitslice32 wins for cipher-D, something is wrong. Investigate before recording results; a plausible-looking inverted result is exactly the failure this benchmark exists to avoid.

- [ ] **Step 5: Commit**

```bash
git add fw/m4/bench_m4.c fw/m4/timing.h Makefile
git commit -m "Add M4 benchmark harness with DWT cycle counting"
```

---

### Task 10: The second and third memory configurations

> **Amended during execution.** This task was specified as one extra configuration, `purecore` (code in SRAM, ART off), intended to show how much of each figure belongs to the flash and its accelerator. On measurement that intent is **not** what `purecore` answers. A 2×2 control — {flash, SRAM} × {ART on, ART off}, all four cells built and run on the board twice by different agents — shows that with code in SRAM the ART contributes a **median 1.000×**, while moving code flash→SRAM with the ART held on costs 1.189–1.757×. The gap is instruction supply, not the accelerator: flash code is fetched over the dedicated ICode port, SRAM code over the system bus it shares with all data traffic. Cache capacity is not the explanation either — cipher-D's 5,468 B bitsliced S-box, 5.3× the 1 KB I-cache, has the *worst* ratio.
>
> So the published set becomes three configurations, with these exact `config` values:
>
> | `config` | What it is | What it answers |
> |---|---|---|
> | `product` | code in flash, ART on | how the cipher actually runs; the lower bound available on this part |
> | `flash-noart` | code in flash, ART off | **the accelerator's contribution** — measured at 1.3×–2.4×, median ~1.6× over the 49 published pairs (the 1.346×–2.483×/1.773× quoted while this plan was written was a 39-pair set, superseded by Task 12a and by the 7.5% precision floor) |
> | `sram-noart` | code in SRAM, ART off (was `purecore`) | instruction fetch moved to the shared system bus |
>
> `sram-noart` must never be described as "the cipher without the flash" — it is a worse instruction path, not a lower bound. This part has no zero-wait-state executable memory; CCM is D-bus only. The full 2×2 belongs in the write-up's methods.

**Files:**
- Create: `fw/m4/link/purecore.ld`
- Modify: `fw/m4/startup_stm32f407.s`, `fw/m4/system_init.c`, `Makefile`

- [ ] **Step 1: Write the second linker script**

Identical to `product.ld` except that the cipher and harness code is placed in a `.ramtext` section, loaded to SRAM at boot:

```ld
  .ramtext : AT (_etext) {
    _sramtext = .;
    *present_bitslice32.o(.text*)
    *present_table.o(.text*)
    *present_ref.o(.text*)
    *bench_m4.o(.text*)
    . = ALIGN(4);
    _eramtext = .;
  } > SRAM
  ASSERT(_eramtext - _sramtext <= 96K,
         "purecore: relocated code exceeds the SRAM budget")
```

- [ ] **Step 2: Copy `.ramtext` at boot**

Extend the reset handler to copy `_sramtext.._eramtext` from its load address, alongside the existing `.data` copy, before calling `system_init`.

- [ ] **Step 3: Bypass the ART in this configuration**

Guard the accelerator bits in `system_init.c`:

```c
#ifdef M4_PURECORE
    FLASH_ACR = FLASH_ACR_LATENCY_5WS;                 /* no prefetch, no caches */
#else
    FLASH_ACR = FLASH_ACR_LATENCY_5WS | FLASH_ACR_PRFTEN
              | FLASH_ACR_ICEN | FLASH_ACR_DCEN;
#endif
```

The 5 wait states stay in both: they are a property of the flash at 168 MHz, not of the accelerator, and dropping them corrupts instruction fetch.

- [ ] **Step 4: Verify the code really moved**

```bash
arm-none-eabi-nm -n build/m4/purecore.elf | grep -i "present_encrypt_bitslice32"
```
Expected: the symbol's address is `0x2000xxxx` (SRAM), **not** `0x080xxxxx` (flash).

If it is still in flash the section match failed silently and the whole configuration is meaningless — the two columns would differ only by the ART bits. Check the object-file names in the `.ramtext` match against the actual paths the build produces.

- [ ] **Step 5: Commit**

```bash
git add fw/m4/link/purecore.ld fw/m4/startup_stm32f407.s fw/m4/system_init.c Makefile
git commit -m "Add purecore memory configuration with SRAM-resident cipher code"
```

---

### Task 11: Host driver and make target

**Files:**
- Create: `tools/run_m4_bench.py`
- Modify: `Makefile`

- [ ] **Step 1: Implement the driver**

For each of the three configurations: build, `st-flash --reset write`, start `st-util`, run `gdb-multiarch -batch -x fw/m4/run.gdb`, capture the semihosted output, and append rows to `results/m4-speed.csv`.

Two things that will otherwise waste an afternoon:

- Always terminate `st-util` in a `finally` block. A stray server holds the USB device, and the next run fails with a misleading "cannot open" error.
- Check `st-info --probe` first and fail loudly with its output if it reports zero programmers, rather than letting `st-flash` fail obscurely.

- [ ] **Step 2: Add the target**

```make
m4-bench: $(GENERATED)
	@mkdir -p results
	$(PYTHON) tools/run_m4_bench.py --out results/m4-speed.csv
```

- [ ] **Step 3: Run the whole thing end to end**

```bash
make m4-bench && column -s, -t results/m4-speed.csv
```
Expected: seven ciphers × implementations × **three** configs (`product`, `flash-noart`, `sram-noart`), every row `status=ok`, and a provenance header naming the measured clock.

- [ ] **Step 4: Commit**

```bash
git add tools/run_m4_bench.py Makefile results/m4-speed.csv
git commit -m "Add one-command M4 benchmark run"
```

---

### Task 12: Results write-up

**Files:**
- Create: `docs/m4-optimizations.md`
- Modify: `README.md`

- [ ] **Step 1: Write the document**

Follow `docs/fpga-optimizations.md` and `docs/gpu-optimizations.md`: what was tried, what it bought, in measured numbers. Cover at minimum:

- **64-bit versus 32-bit bitslice on a 32-bit core** — the headline optimization. Quantify it by building the `u64` bitslice path for the M4 as well and reporting both, so the claim rests on a measurement rather than on the instruction-count argument.
- **`product` versus `flash-noart` versus `sram-noart`** — `flash-noart` is what isolates the accelerator (median ~1.6× over the 49 published pairs; earlier text in this plan says 1.773×, a superseded 39-pair figure quoted to a third significant figure the layout floor does not support). Do **not** present `sram-noart` as "the cipher without the flash"; it is a worse instruction path, because SRAM code is fetched over the system bus while flash code uses the dedicated ICode port. Include the 2×2 that establishes this in the methods.
- **Where the 8-bit-S-box ciphers land**, and why bitslicing loses for them (1107 gates against PRESENT's 15).
- **The measured core clock and clock source**, stated plainly, including whether LSE verification succeeded.
- **The stated limits:** encryption only, 2 KiB working set, 32 blocks in flight rather than 64.

- [ ] **Step 2: Cross-check against the other targets**

Confirm the M4 ranking of the seven ciphers is consistent with the FPGA and x86 rankings. Where it is not, say why in the document. An unexplained inversion is either a finding or a bug, and both belong in the text.

- [ ] **Step 3: Link it from the README**

Add `docs/m4-optimizations.md` beside the existing GPU and FPGA write-ups.

- [ ] **Step 4: Commit**

```bash
git add docs/m4-optimizations.md README.md
git commit -m "Document Cortex-M4 speed results"
```
