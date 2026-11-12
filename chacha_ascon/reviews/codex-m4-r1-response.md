# Response to Codex M4 review, round 1

Review: `codex-m4-r1.md`. Every finding was accepted. The table gives what changed and where.

| # | Finding | Action |
|---|---------|--------|
| 1 | Stores mispriced; load-address dependency ignored | `m4_cost` now follows the TRM: `STR Rx,[Ry,#imm]` costs 1, and other STRs cost 2, or 1 after a single LDR. An LDR pipelines after an LDR only when its address registers are not that LDR's destination. Branch refill is a named constant `M4_P`. The ALU→address stall Codex mentioned is now a switch, `--m4-agu-stall`, and was tested against the measured PRESENT kernels. It moves table, table-x4, bitslice32 and ref by less than 0.1% and bitslice64 by +2.4%, so it does not explain the residuals and stays off. The docstring says so. |
| 2 | Flash model is fetch-only | Accepted as stated, and now labelled everywhere (class docstring, Makefile comment, report) as an *instruction-fetch-only sensitivity model*. A held-out check confirms the limit: the same model with the ART off (`--flash-lines 1`) misses the board's measured `flash-noart` rows by −11…−33%. "46.0 → 46.0" is no longer read as "no flash overhead". |
| 3 | Calibration does not justify a +0…+10% band | Withdrawn. The residuals are reported as observations, not as an interval. The provenance is also corrected: the measured rows are `config=product` (code in flash, ART on) with a 2048 B working set. Under the corrected model, the zero-wait and flash variants compare with `product` as below. Both are optimistic on every kernel. |
| 4 | No KAT gate before `cycles` | `cycles` now depends on `$(B)/.kat-passed`, which is touched only after the qemu KAT run of the *same build* exits 0. QEMU's PID is waited explicitly and its status checked. The CSV is written to `.tmp` and renamed only when both statuses are 0. |
| 5 | Condition-failed instructions are traced | Documented in the model docstring. Both cores issue condition-failed instructions, so each is charged, but at its opcode's price, which overstates a failed load or store by about one cycle. No measured loop has a conditional memory access or branch. Not modelled further. |
| 6 | IT folding, TBB/TBH, LDR PC | TBB/TBH now cost 2+P, LDR PC 3+P (5 with P=2), and LDM/POP with PC 1+N+P. IT folding is marked approximate in the docstring. No measured region contains TBB/TBH or LDR PC. |
| 7 | Silent acceptance of unknown PCs and labels | A PC with no disassembly entry, or a data directive (`.word`), inside a *measured* interval is now a hard error; in harness gaps it is only a warning. The interval count must equal exactly 2·regions−1, and REGION labels must be numbered 0..n−1. |
| 8 | Cold flash in the marker baseline | The baseline subtracted from each region is now region 0's *core* price, not its flash-model price. Results are described as the full harness call interval: call, argument setup, wrapper and tail included. |
| 9 | Stale objects after flag changes | A `$(B)/.flags` stamp holds the compiler, CFLAGS, OPT and Thumb list. It is rewritten only when they change, and every object depends on it. |

## Calibration after the fixes (M4, PRESENT-80 CTR kernels, cycles per byte)

| kernel | measured `product` | zero-wait model | flash+ART model (fetch only) |
|---|---:|---:|---:|
| table | 150.8 | 143.4 (−4.9%) | 143.4 (−4.9%) |
| table-x4 | 197.4 | 173.3 (−12.2%) | 174.5 (−11.6%) |
| bitslice32 | 107.2 | 95.8 (−10.6%) | 101.9 (−4.9%) |
| ref | 3296 | 3185 (−3.4%) | 3185 (−3.4%) |
| bitslice64 | 148.7 | 118.0 (−20.6%) | 122.3 (−17.8%) |

Held out, ART off (`flash-noart`), against the model with `--flash-lines 1`: table 268.0 vs 216.6, table-x4 291.5 vs 194.5, bitslice32 180.1 vs 159.5, ref 6683 vs 4900, bitslice64 215.4 vs 154.8.

The report therefore treats the M4 figures as *lower bounds on cycles*. Real hardware was 3–21% slower on every calibration kernel, and the largest gaps were on the LDRD/STRD-dense kernels.

## Re-run

`make TARGET=m4 cycles` and `make TARGET=m4 cycles-flash` were re-run through the new gate (16/16 KATs passed under qemu `-cpu cortex-m4`). At 4096 B, ChaCha20 m4-asm costs 15.06 c/B with zero-wait memory and 16.57 with flash+ART. The best Ascon is ascon-c/bi32_armv7m at 41.2 c/B with zero-wait memory; with flash+ART it is ascon-c/armv7m_small at 45.6 c/B.
