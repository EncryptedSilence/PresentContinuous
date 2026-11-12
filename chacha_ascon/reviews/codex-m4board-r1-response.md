# Response to Codex review of the on-board M4 measurement, round 1

Review: `codex-m4board-r1.md`. Codex found no bug in what is timed: the ELF hash matches the CSV, and the timed APIs, lengths, payload accounting and inputs match the model harness. All six points were accepted.

| # | Finding | Action |
|---|---------|--------|
| 1 | The comparison sign was reversed, and "25–33% slower" described throughput, not cycles | The report now states *cycles* as board/model − 1. Against flash+ART: −1.5…+16.8%. Against zero-wait, unrolled variants: +30…+48% (armv7m +48%, bi32_armv7m +39%). |
| 2 | Not a controlled model validation: the model build differs (soft-float, alignment) and function addresses differ | Stated in report §3.4. Agreement confirms the order of magnitude, not the accuracy of the ART model, and excess cycles are not attributed to flash alone. |
| 3 | Firmware prerequisites missing | `timing.h`, `system_init.[ch]`, `semihost.[ch]` and the startup file are now prerequisites of `ca_fw.elf`. |
| 4 | The parser accepts incomplete output | `m4_board.py` now requires each marker exactly once and in order, a full regex match on the clock line with `meas_status=1`, the exact header, numeric and positive fields, and exactly one row per KAT-passed implementation × {64, 1536, 4096}. Offline checks with the real log: dropped row, `meas_status=10`, `KAT_END status=1` and a garbage header are all rejected. The docstring now says that a failed run leaves the previous CSV untouched; that CSV carries its own date and hash. |
| 5 | The "complete KAT" claim is false on the board | Firmware comment and report corrected. On the board, 8 long records per implementation (8–64 KiB) are skipped and reported as skipped. They run under qemu on the same sources. |
| 6 | The 1-cycle overhead does not isolate the function | Stated in report §3.4: the measurement is a call-level boundary, not instruction-identical with the model, and this matters most at 64 B. |

Re-run after the fixes: same 48 rows byte for byte. The new firmware hash is in `results/arm/m4-board.csv`.
