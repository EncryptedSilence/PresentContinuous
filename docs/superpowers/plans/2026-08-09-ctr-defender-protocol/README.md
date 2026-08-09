# Complete-CTR Measurement Protocol — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the round-function defender benchmark with a complete counter-mode pass over a byte buffer, measured identically on x86-64, Cortex-A7 and Cortex-M4, produced by one reproducible command per target, with tuning separated from measurement.

**Architecture:** A backend registry (`bench/ctr_backend.h`) describes one complete CTR implementation as a `prepare` (untimed) plus a `run` (timed). `bench/ctr_bench.c` is the only harness; every backend lives in its own ISA-specific file so the backend tasks never touch the same source. A Python driver (`tools/campaign.py`) captures provenance and runs tuning and measurement as separate phases; `tools/summarize.py` turns raw runs into medians, bootstrap intervals and paired ratios, which `tools/make_tables.py` renders as TeX.

**Tech Stack:** C11 (gcc 13 host, gcc 14 armhf, `arm-none-eabi-gcc` for the M4), CUDA, Python 3.12 standard library only, GNU make.

**Design spec:** [`docs/superpowers/specs/2026-08-09-ctr-defender-protocol-design.md`](../../specs/2026-08-09-ctr-defender-protocol-design.md). Every decision there is binding.

## Global Constraints

Every task's requirements implicitly include this section.

- Published workload: **64 KiB**, processed **in place**. 4 KiB and 16 KiB are also measured; only 64 KiB is published.
- 64- and 128-bit ciphers process the **same number of bytes**, never the same number of blocks.
- Key expansion happens **once, before** the timed region, and is measured separately.
- **Counter definition**, established by `ctr-ref` and reproduced byte for byte by every other backend: block *i* is the integer `ctr0 + i`, and its keystream bytes are that block serialised **big-endian**. For the 128-bit ciphers the counter occupies the low 64 bits of the 16-byte block and the high 64 bits are zero.
- The transpose is **inside** the timed region for every bitslice backend. No backend may assume a non-byte representation of input or output. A backend that does is a kernel ceiling and belongs in `bench/bench_main.c`, which this plan does not modify.
- Existing result CSVs are never overwritten. New output goes under `results/v2/`; old files gain a `SUPERSEDED by ...` header (Task 8).
- No number reaches a paper table by hand. TeX comes from `tools/make_tables.py`.
- Python: **standard library only**. The repo has no third-party Python dependency and must not gain one.
- The seven ciphers and their round counts come from `tools/cipher_set.py`. Never restate the list anywhere else.
- Every new C file compiles clean under the repo's existing `-Wall -Wextra -Wpedantic`.
- `make test` passes before and after every task.
- Firmware keeps `-DPRESENT_ENC_ONLY`; the host build never defines it.

## File Structure

**Created:**

| file | responsibility | task |
|---|---|---|
| `bench/ctr_backend.h` | backend interface and registry declaration — **frozen by Task 1** | 1 |
| `bench/ctr_registry.c` | list of backend groups; each backend task appends exactly one line | 1 |
| `bench/ctr_bench.c` | harness: workload, correctness gate, timing, CSV | 1 |
| `bench/ctr_narrow.c` | `ctr-ref`, `ctr-table`, `ctr-table-xN` for the five 64-bit ciphers | 1 |
| `bench/ctr_wide.c` | `ctr-ref`, `ctr-table` for AES and AES-lin444 | 1 |
| `tests/test_ctr.c` | the correctness gate as a unit test | 1 |
| `src/present_ctr.h` | `present_ctr_counters64` / `_counters32` declarations | 2 |
| `src/present_ctr_bitslice.c` | `ctr-bitslice-u64`, `ctr-bitslice-u32` | 2 |
| `src/present_ctr_avx2.c` | `ctr-bitslice-avx2` | 2 |
| `src/present_ctr_neon.c` | `ctr-bitslice-neon` for the 64-bit set | 2′ |
| `bench/wide_bitslice_neon.h` | NEON bitsliced AES / AES-lin444 round function | 3 |
| `bench/ctr_wide_neon.c` | `ctr-bitslice-neon` for the 128-bit pair | 3 |
| `tests/test_wide_bitslice_neon.c` | NEON wide bitslice against the reference | 3 |
| `tools/summarize.py` | medians, bootstrap CIs, paired ratios, top-group, ranking-stability assert | 4a |
| `tools/make_tables.py` | `summary.csv` → `paper/tables/*.tex` | 4a |
| `tools/tests/test_summarize.py` | statistics unit tests with known inputs | 4a |
| `tools/campaign.py` | provenance capture, tuning phase, measurement phase, per-target drivers | 4b |
| `tools/tests/test_campaign.py` | the guards, with no hardware in the loop | 4b |
| `tools/tests/test_m4_layout.py` | every image's timed symbol at the expected address | 6a |
| `fw/m4/ctr_m4_main.c` | M4 CTR firmware, one cipher per image | 6b |

**Modified:** `Makefile`, `fw/m4/link/product.ld`, `bench/gpu_bench.cu`, `artifact-manifest.json`, and a `SUPERSEDED` header line in each existing result CSV.

Splitting the backends by ISA is a deliberate design choice, not housekeeping: it is what lets Tasks 2, 2′ and 3 run in three parallel sessions whose only shared edit is one line each in `bench/ctr_registry.c`.

## Phases

| phase | tasks | deliverable |
|---|---|---|
| [wave-1-foundation.md](wave-1-foundation.md) | 1, 6a, 7 | the frozen backend interface with ref/table backends passing the gate; the M4 fixed-address section; the CUDA attacker split |
| [wave-2-bitslice.md](wave-2-bitslice.md) | 2, 2′, 3 | bitsliced CTR backends whose counters are generated bitsliced and whose transpose is timed |
| [wave-3-campaigns.md](wave-3-campaigns.md) | 4a, 4b, 5, 6b | statistics, TeX generation, and the x86 / A7 / M4 campaigns |
| [wave-4-supersede.md](wave-4-supersede.md) | 8 | old results marked superseded, manifest and tables regenerated |

## Execution order

```
Wave 1   Task 1  ∥  Task 7  ∥  Task 6a
Wave 2   Task 2  ∥  Task 2′ ∥  Task 3
Wave 3   Task 4a ∥  Task 5 driver ∥ Task 6b firmware
Wave 4   MEASUREMENT — no parallelism
           Task 5 campaign  ∥  Task 6b campaign     (separate boards, host idle)
           ──── quiet machine, nothing else running ────
           Task 4b x86 campaign
           Task 7 CUDA campaign
Wave 5   Task 8
```

Development parallelises; measurement does not. The constraint is not core count — the development machine has 32 threads — but that this one machine is simultaneously the x86 target, the CUDA target, the build machine and a desktop.

The x86 campaign is exclusive against everything local: a concurrent build in another session invalidates it directly. The CUDA campaign loads the CPU as well as the GPU, and the GPU already carries desktop load, so it is serial with the x86 campaign. The A7 board and the STM32 are separate hardware with the host merely waiting on them, so those two campaigns overlap freely and may overlap with local development.

## Out of scope

Everything Vivado: no XCV80 place-and-route, no replication sweep, no attack-loop periphery. The spec's §9 records the one FPGA item this plan deliberately does not execute — synthesising a **pre-expanded-key** PRESENT so all seven cores perform the same operation, while keeping the existing master-key PRESENT as a second, separately-labelled core. That gets its own spec and its own plan.

`bench/bench_main.c` is not modified. It keeps measuring the round function, which is a legitimate number under its own name; Task 8 republishes its output as the kernel-ceiling artifact.

## Open assumption

The spec's §6 records an **assumption to be confirmed**: the x86 campaign runs with `governor=performance`, pinned to **CPU 8** with **CPU 9 kept idle**, in a quiet session with the desktop browser and editor closed. `isolcpus=8,9 nohz_full=8,9` on the kernel command line is optional and needs a reboot. If a quiet session on this machine is unacceptable, x86 moves to a dedicated machine and the provenance record gains one more platform. Task 4b works either way; only the numbers change.
