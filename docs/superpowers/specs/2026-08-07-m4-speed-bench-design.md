# Cortex-M4 speed benchmark (STM32F407) — Design

Date: 2026-08-07

## Purpose

Measure encryption speed for the project's seven headline ciphers on a real
Cortex-M4, so the repo's speed story covers three hardware classes rather than
two: x86 (`results/speed.csv`), GPU (`results/gpu-speed*.csv`), FPGA
(`results/fpga-*`), and now an embedded microcontroller — the class these
lightweight ciphers were actually designed for.

The deliverable is `results/m4-speed.csv`: for each cipher, each implementation,
and each of two memory configurations, the cycles/byte and throughput achieved on
an STM32F407 at 168 MHz.

## Non-goals

- Constant-time or side-channel-hardened implementations. This is a speed harness,
  the same as the x86 and GPU benches.
- Decryption speed. The firmware is built encryption-only (see *Memory budget*).
- Energy or power measurement. Interesting for this device class, but it needs
  instrumentation we do not have.
- Covering all 25 registered variants. Scope is the seven ciphers below, matching
  the FPGA experiment set.

## Target hardware

Verified present and accessible on 2026-08-07:

```
board    STM32F407ZGT6 development board
chipid   0x413  (STM32F4x5_F4x7)
flash    1048576 B (1 MB), 16 KiB pages
sram     196608 B (192 KB) = 112 KB SRAM1 + 16 KB SRAM2 + 64 KB CCM
probe    ST-LINK/V2, firmware V2J39S7, serial 56FF6C065067485508262287
```

Two hardware notes recorded during the probe:

- `NRST is not connected` — the hardware reset line is not wired to the ST-LINK.
  All resets are software resets. This is normal for these boards and does not
  affect flashing.
- The board arrived with unrelated firmware already in flash (vector table at
  `0x08000000` gives `SP = 0x20000588`, reset vector `0x080035B1`). A full 1 MB
  backup is taken before the first write.

The core is clocked from **HSI** (16 MHz internal RC) through the PLL to 168 MHz,
not from the HSE crystal. This makes the firmware work on any F407 board
regardless of which crystal is fitted. Cycle counts are unaffected — DWT `CYCCNT`
counts core cycles — so only derived MB/s inherits the HSI's ±1% tolerance. If the
crystal value is confirmed later, switching to HSE makes MB/s exact too.

## Scope: seven ciphers

The set, and the round counts, are exactly those already used by the FPGA flow in
`tools/gen_fpga.py`, so an M4 number and an FPGA number always name the same
cipher.

| Reported name | Variant file | Rounds | Block | S-box |
|---|---|---|---|---|
| PRESENT | `variants/present-80-r16.json` | 16 | 64 | 4-bit |
| PRESENT-lin444 | `variants/present-80-lin444-297-r7.json` | 7 | 64 | 4-bit |
| DONATION | `variants/cipher-D.json` | 8 | 64 | 8-bit |
| DONATION-l444 | `variants/cipher-D-lin444-297-r5.json` | 5 | 64 | 8-bit |
| DONATION-l444-AES_Sbox | `variants/cipher-D-lin444-297-aes-r5.json` | 5 | 64 | 8-bit (AES) |
| AES | `variants/wide/aes.json` | **5** (override) | 128 | 8-bit (AES) |
| AES-lin444 | `variants/wide/aes-lin444-0-8-15.json` | 4 | 128 | 8-bit (AES) |

The two 128-bit ciphers declare `rounds: 4` in JSON and are overridden to 5 and 4
respectively by `FPGA_VARIANT_OVERRIDES`. The first five are driven through
`src/`; the last two are self-contained in `bench/wide_bench.c`, which already
supports reduced-round runs and reports `rounds` in its CSV.

### Shared cipher set

`DEFAULT_VARIANTS` and `FPGA_VARIANT_OVERRIDES` move out of `tools/gen_fpga.py`
into a new `tools/cipher_set.py`, imported by both `gen_fpga.py` and the M4 tool.
One definition, so the FPGA and M4 result sets cannot drift apart. `gen_fpga.py`
keeps its current behaviour exactly; this is a move, not a change.

## Decision 1: what "optimized for M4" means

Every implementation in `src/` is `uint64_t`-based and tuned for x86. On a 32-bit
Cortex-M4 each 64-bit word is a register pair, so every AND/XOR/shift in a
bitsliced S-box circuit costs two instructions. Cross-compiling as-is would measure
a handicapped implementation and understate the device by roughly 2x.

The chosen approach is a **32-bit implementation path emitted by the generator**,
not hand-written per cipher:

- `tools/gen_c.py` gains 32-bit emission. The bitslice state becomes 64 ×
  `uint32_t` — 32 blocks in flight instead of 64, 256 B of state, one instruction
  per gate.
- Because the change lives in the generator, it applies **uniformly to all seven
  ciphers**. This is what keeps the comparison fair, and is the lesson recorded in
  the README's *Making the comparison fair*: an earlier version of this project
  reached a reversed conclusion because the modification had been specialised and
  the baseline had not.

Hand-written Thumb-2 assembly was considered and rejected: it cannot be generated
per-variant, so it would optimize some ciphers harder than others and reintroduce
exactly that unfairness.

The M4 features this path targets are the free barrel shifter on data-processing
instructions and the 16 general-purpose registers. NEON is **not** available on
Cortex-M4 (it is an ARMv7-A/v8-A feature), so `src/present_neon.c` is excluded from
this build alongside `src/present_avx2.c`.

## Decision 2: two memory configurations

At 168 MHz the F407's flash needs 5 wait states, and the table implementations use
a 16 KB `enc_tab` that cannot fit the ART accelerator's 1 KB data cache. Left
alone, the memory system rather than the cipher would dominate the result. So every
measurement runs in two configurations:

| Config | Code | Flash accelerator | Tables + state |
|---|---|---|---|
| `product` | flash @ `0x08000000`, 5 WS | ART on (prefetch + I-cache + D-cache) | CCM RAM |
| `purecore` | copied to SRAM @ `0x20000000` at boot | bypassed | CCM RAM |

`product` is the realistic, directly quotable figure. `purecore` isolates the cost
of the cipher itself. The divergence between the two columns is a reportable result
in its own right: it is the share of the number that belongs to the memory system.

Implemented as two linker scripts over one firmware source, run back to back.

## Decision 3: result channel

Semihosting. The firmware issues `BKPT 0xAB` / `SYS_WRITE`; `st-util` provides the
GDB server and `gdb-multiarch` (installed 2026-08-07) relays CSV rows straight to a
file on the host.

Chosen over the alternatives because it needs no flash-programming driver in the
firmware, gives live progress during a multi-minute run, and scripts cleanly. The
board's ST-LINK/V2 exposes no virtual COM port, and `/dev/ttyACM0` on this host
belongs to an unrelated Armbian SBC in USB-gadget mode, so there is no serial route
without extra hardware.

Semihosting I/O is slow, but it happens strictly outside the timed regions, so it
cannot affect a measurement.

## Memory budget

`present_ctx_t` as currently declared is 66,048 B:

```
var           pointer (32-bit)      =      4  (+4 padding for 8-byte alignment)
rk            32 × 8                =    256
rk_mask_enc   32 × 64 × 8           = 16,384
rk_mask_dec   32 × 64 × 8           = 16,384
enc_tab        8 × 256 × 8          = 16,384
pinv_tab       8 × 256 × 8          = 16,384
sinv_byte                           =    256
                                      ------
                                      66,056 B
```

CCM is 65,536 B, so a full context overflows it by 520 B — and CCM is where the
tables must live, since it is zero-wait-state with no DMA contention.

The firmware is therefore built with **`PRESENT_ENC_ONLY`**, which drops
`pinv_tab`, `rk_mask_dec` and `sinv_byte`, leaving 32,776 B. This is a legitimate configuration
rather than a workaround: an encryption-speed benchmark never decrypts, and a real
M4 product running CTR mode never materializes decryption tables. The results
record that the firmware is encryption-only so the figures are not compared against
something they are not.

Contexts are built one cipher at a time into the same CCM buffer, so the budget is
per-cipher, not cumulative.

## Measurement protocol

Deliberately the same shape as `bench/bench_main.c`, so figures are comparable:

- Warm-up 3 runs, then 15 trials; report **median** and **min**.
- Timing from DWT `CYCCNT` (exact core cycles; wraps at 2^32 ≈ 25.6 s at 168 MHz,
  far above any single trial).
- Interrupts and SysTick disabled inside the timed region.
- A `volatile` sink consumes the output so the optimizer cannot delete the work.
- Working set is 256 blocks (2 KiB) rather than x86's 64 KiB. All F407 RAM is
  single-cycle, so there is no cache hierarchy to keep the working set inside, and
  64 KiB would not fit beside the context. This difference is recorded in the
  results.

Reported per row: `cycles_per_byte`, `cycles_per_byte_min`, `mb_per_sec`, `ns_per_op`,
and key setup cost measured separately.

### Implementations timed

| Ciphers | Implementations |
|---|---|
| Five 64-bit variants | `ref`, `table`, `table_x2`, `table_x4`, `bitslice32` |
| Two 128-bit variants | the scalar implementations `wide_bench.c` already defines (`enc1`, `enc4`, and `ref` where present), plus `bitslice32` |

`table_x8` and `table_x16` are dropped: with 16 GP registers they spill, and
measuring spill traffic is not informative. The wide `bitslice32` path reuses the
same generated 132-gate AES S-box circuit that `wide_bench.c` already shares with
`src/`, re-parameterized to `uint32_t` — the same circuit, not a second copy.

## Correctness gate

No implementation is timed until it is proven correct on-device.

The host build emits known-answer vectors for every (cipher, implementation) pair.
The firmware verifies each on the board before timing it, and any pair that
mismatches is reported as `FAIL` in the CSV with no timing figure.

This is not ceremony. Re-parameterizing a bitsliced circuit from 64-bit to 32-bit
words is precisely the kind of change that produces fast, plausible, wrong code,
and a benchmark that reports the throughput of wrong code is worse than no
benchmark.

## Components

```
fw/m4/startup_stm32f407.s     vector table, reset handler, .data/.bss init,
                              SRAM code copy for the purecore config
fw/m4/system_init.c           HSI→PLL 168 MHz, 5 wait states, ART enable/bypass,
                              DWT CYCCNT enable
fw/m4/link/product.ld         code in flash
fw/m4/link/purecore.ld        hot code relocated to SRAM
fw/m4/semihost.c              SYS_WRITE / SYS_WRITE0 via BKPT 0xAB
fw/m4/bench_m4.c              harness: KAT gate, timing loops, CSV emission
fw/m4/kat_vectors.h           generated known-answer vectors (build artifact)

src/present_bitslice32.c      32-bit bitslice over generated circuit bodies
tools/gen_c.py                + 32-bit emission
tools/cipher_set.py           shared seven-cipher list + round overrides
tools/run_m4_bench.py         build → backup → flash → run → collect CSV

Makefile                      m4-build, m4-flash, m4-bench (following fpga-* naming)
results/m4-speed.csv          deliverable
docs/m4-optimizations.md      write-up, mirroring docs/{gpu,fpga}-optimizations.md
```

Each unit has one job and a defined interface: `semihost.c` knows nothing about
ciphers, `bench_m4.c` knows nothing about how bytes reach the host, and the
generator changes are invisible to both.

## Host flow

```
tools/run_m4_bench.py
  1. build both configs           arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb
                                  -mfpu=fpv4-sp-d16 -mfloat-abi=hard -O3
  2. back up existing flash       st-flash read fw/m4/backup-<date>.bin 0x08000000 0x100000
                                  (once; refuses to overwrite an existing backup)
  3. flash                        st-flash --reset write build/m4/<config>.bin 0x08000000
  4. run                          st-util & ; gdb-multiarch -x run.gdb
  5. collect                      semihosted CSV → results/m4-speed.csv
  6. repeat 3–5 for the second config
```

## Risks

| Risk | Mitigation |
|---|---|
| 64→32-bit bitslice re-parameterization produces wrong ciphertext | On-device KAT gate; nothing wrong gets timed |
| Existing firmware on the board is destroyed | Full 1 MB backup before first write |
| `purecore` hot-code working set exceeds 112 KB SRAM | Only the round functions and harness are relocated, not the whole image; measured at link time and it fails the build if it does not fit |
| Semihosting overhead contaminates timing | All I/O is outside the timed region, by construction |
| 8-bit S-box ciphers are very slow in bitslice (1107 gates vs PRESENT's 15) | Expected result, not a fault; recorded as-is |

## Deliverables

1. `results/m4-speed.csv` — the seven ciphers × implementations × two configs.
2. `docs/m4-optimizations.md` — what was done to reach these numbers and what each
   step bought, in the style of the existing GPU and FPGA optimization write-ups.
3. `make m4-bench` — a repeatable one-command run.
