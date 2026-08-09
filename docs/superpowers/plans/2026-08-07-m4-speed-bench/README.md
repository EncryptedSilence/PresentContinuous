# Cortex-M4 (STM32F407) Speed Benchmark — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure encryption speed for the project's seven headline ciphers on a real STM32F407 at 168 MHz, in two memory configurations, producing `results/m4-speed.csv`.

**Architecture:** A new 32-bit implementation path is emitted by the existing code generator (so all seven ciphers are optimized identically), compiled into bare-metal firmware that self-verifies its clock and its ciphertexts before timing anything, and reports CSV rows to the host over ARM semihosting.

**Tech Stack:** `arm-none-eabi-gcc` 13.2.1, `stlink-tools` 1.8.0 (`st-flash`, `st-util`), `gdb-multiarch`, Python 3, GNU make.

## Global Constraints

Every task's requirements implicitly include this section.

- Design spec: `docs/superpowers/specs/2026-08-07-m4-speed-bench-design.md`. Every decision there is binding.
- Target: STM32F407ZGT6, chipid `0x413`, 1 MB flash @ `0x08000000`, 112 KB SRAM1 @ `0x20000000`, 16 KB SRAM2 @ `0x2001C000`, 64 KB CCM @ `0x10000000`.
- Compiler flags for all firmware: `-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -O3 -std=gnu11 -Wall -Wextra -ffreestanding`.
- The seven ciphers and their round counts come from `tools/cipher_set.py` (Task 1). Never hardcode them anywhere else.
- Firmware is built with `-DPRESENT_ENC_ONLY`. Decryption is out of scope.
- `NRST` is not wired on this board: always use software reset (`st-flash --reset`), never `--connect-under-reset` for writes.
- The board's existing firmware is disposable. No backup step.
- Existing host behaviour must not regress: `make test` passes before and after every task.
- Never edit `src/gen/*` by hand — those are generated. Change the generator and regenerate.
- **The firmware links `src/keyschedule_portable.c`, never `src/keyschedule.c`.** The latter uses `__int128` unguarded at `src/keyschedule.c:15`, which does not exist on Cortex-M4; the portable file is the guarded drop-in added in commit `6fd7341` for exactly this reason. The host build is unaffected and keeps using `keyschedule.c`.
- `src/present_neon.c` and `src/present_avx2.c` both compile to stubs on this target (`__ARM_NEON` and `__AVX2__` are undefined for Cortex-M4), so they cost nothing and need no exclusion.
- New per-variant cross-checks extend `tests/test_impls.c` following the pattern at `tests/test_impls.c:116-124` — a `present_have_*()` predicate guarding a block that compares against the reference oracle. Do not add standalone per-implementation test files.

## Phases

| Phase | Tasks | Deliverable |
|---|---|---|
| [Phase 1 — generator and 32-bit path](phase-1-generator.md) | 1–3 | `u32` circuits and `bitslice32`, verified on the host against the existing table path |
| [Phase 2 — wide ciphers](phase-2-wide.md) | 4–5 | AES and AES-lin444 usable outside the x86 harness, with a 32-bit bitslice path |
| [Phase 3 — firmware](phase-3-firmware.md) | 6–8 | Board boots at a *verified* 168 MHz, talks to the host, and gates on known-answer tests |
| [Phase 4 — measurement](phase-4-measure.md) | 9–12 | `results/m4-speed.csv` and `docs/m4-optimizations.md` |

Phases 1 and 2 are host-only and need no hardware. Phase 3 is the first task that touches the board.

## Why this order

Phases 1 and 2 are fully testable on the host against implementations already known to be correct, so the risky part of the work — re-parameterizing bitsliced circuits from 64-bit to 32-bit words — is settled before any bare-metal debugging starts. Debugging a wrong cipher through a semihosting link is far more expensive than debugging it under `make test`.

## Self-review notes

**Spec coverage.** Every spec section maps to a task: scope and shared cipher set → Task 1; the 32-bit path → Tasks 2, 3, 5; wide ciphers → Tasks 4, 5; clock configuration and verification → Tasks 6, 7; memory budget and `PRESENT_ENC_ONLY` → the `ASSERT` in Task 6's linker script; two memory configurations → Tasks 6, 10; result channel → Tasks 6, 11; correctness gate → Task 8; measurement protocol → Task 9; deliverables → Tasks 11, 12.

**Amended after commit `6fd7341`.** That commit added a NEON backend derived by *mechanically retyping* the u64 circuits (`tools/gen_neon_circuits.py`) rather than by re-synthesising them. Task 2 originally added a `BE_U32` synthesis backend to `tools/sbox_synth.c`; it now generalizes the retype tool instead, which gives the same-program guarantee structurally rather than by assertion and keeps one pattern in the tree. Task 3's cross-check likewise moved into `tests/test_impls.c` to match the NEON block already there, and the `keyschedule_portable.c` constraint above closes a gap the original plan missed.

**Known open detail.** Task 2's retype depends on the textual layout of the generated `src/gen/sbox_circuits.h` — specifically that the u64 circuit span ends at the `#if defined(__AVX2__)` line. That dependency already exists for the NEON header and is not new, but it means a change to `gen_c.py`'s emission order breaks both derived backends at once. The byte-identical NEON check in Task 2 Step 4 is what detects it.

**Type consistency.** `present_ctx_t`, `present_variant_t`, `aes_key_t` and `lin_key_t` are existing types used unchanged. New symbols introduced by one task and consumed by another: the retyped `present_circuit*_u32_c<N>` functions in `src/gen/sbox_circuits_u32.h` (Task 2 → Tasks 3, 5); `present_encrypt_bitslice32` and `PRESENT_BITSLICE32_BLOCKS` (Task 3 → Tasks 8, 9); `aes_encrypt_bs32` / `lin_encrypt_bs32` / `WIDE_BS32_BLOCKS` (Task 5 → Tasks 8, 9); `system_clock_source` / `system_measure_sysclk_hz` (Tasks 6, 7 → Task 9); `kat_check_all` (Task 8 → Task 9).
