# Cortex-M4 encryption optimizations

**This document is a measurement.** Every number in it is quoted from
[results/m4-speed.csv](../results/m4-speed.csv), which is the single authoritative
M4 artifact for this project: 147 rows, all `status=ok`, 49 (cipher, implementation)
pairs across three memory configurations, produced by one `make m4-bench` run on one
board at commit `52c1c634ba1c`. That file supersedes every per-task CSV quoted during
development; those were built at different commits and their columns are not
comparable with each other.

Where this document states a *mechanism* rather than a result — an instruction count,
a control experiment, a code size — the number comes from a named diagnostic that is
not part of the published CSV, and it is labelled as such at the point of use. The
distinction matters: the CSV's rows are reproducible from the recorded commit and the
diagnostics are not.

**One conclusion here does rest on non-CSV evidence, and it is named up front rather
than left to be discovered.** The finding that the `product`-to-`sram-noart` gap is
bought by instruction *supply* rather than by the ART accelerator — and the disposal of
cache capacity as an alternative explanation — both depend on the `SRAM + ART on` cell
of a 2×2 control, which is a diagnostic build and not one of the three published
configurations. That cell was built by overriding the make variables, run on the same
board in the same session, and is described in full in the Task 10 investigation; no
committed file describes it. Every other conclusion *about the M4* is derivable from
`results/m4-speed.csv` alone — the cross-target section additionally uses the other
targets' own published artifacts — and the diagnostics elsewhere corroborate results
rather than carry them.

It is the microcontroller counterpart to the x86 numbers in
[lin444-experiment.md](lin444-experiment.md), the Cortex-A7 measurement in
[arm-optimizations.md](arm-optimizations.md), the GPU sweep in
[gpu-optimizations.md](gpu-optimizations.md) and the hardware estimate in
[fpga-optimizations.md](fpga-optimizations.md).

## Platform

| | |
|---|---|
| part | STM32F407, ARM Cortex-M4, 32-bit, single core (no floating point is used) |
| core clock | **167,998,819 Hz** (`product`), 167,998,801 Hz (`flash-noart`), 167,998,826 Hz (`sram-noart`) — source **HSE**, verified |
| clock measurement | on-device against the 32.768 kHz LSE crystal over 1 s, reported by the firmware per configuration |
| counter | DWT `CYCCNT`, interrupts masked, SysTick off |
| protocol | 3 warm-up iterations, 15 timed trials, median and min reported |
| working set | 2,048 B (256 × 8 B blocks, or 128 × 16 B blocks), in CCM |
| memory in use | CCM 56,952 B of 65,536; `.bss` 8,760 B; measured stack peak 13,532 B |
| toolchain | arm-none-eabi-gcc 13.2.1 (15:13.2.rel1-2), st-flash/st-util 1.8.0, gdb 15.1 |

The clock is **measured, not assumed**, and no nominal figure appears anywhere in this
document. Each configuration's firmware counts core cycles
against the LSE crystal for one second and prints the result, so the figure above is a
property of the board that ran the rows and not of the PLL configuration someone
intended. It is trustworthy to about 100 ppm — the crystal's own tolerance — which
means `mb_per_sec` and `ns_per_op` carry roughly 0.01% systematic uncertainty.
`cycles_per_byte`, the column every conclusion below rests on, does not depend on the
clock at all.

The firmware also reports what it *observes* rather than what it was built as: `main`'s
linked address and `FLASH_ACR` read back from the peripheral. A build label cannot
therefore misdescribe the configuration that was measured.

### Stated limits

- **Encryption only.** The firmware is built `PRESENT_ENC_ONLY`; no decryption path is
  compiled, linked or timed.
- **A 2 KiB working set.** Every row encrypts 2,048 B per operation. This is a
  cache-and-CCM-resident measurement, not a streaming one.
- **32 blocks in flight for the 32-bit bitslice path**, against 64 for the 64-bit one.
  `cycles_per_byte` normalises the block count, so the two are directly comparable, but
  the 32-bit path never holds more than 32 blocks of state.
- Every (cipher, implementation) pair passes an on-device known-answer test before it
  is timed. A pair that fails is emitted as `status=KAT_FAIL` with empty timing fields
  rather than dropped, because a missing row and a failing row mean different things.
  This run: 0 failing pairs.

## The three configurations

| `config` | code | ART | what it isolates |
|---|---|---|---|
| `product` | flash | on | how the cipher actually runs, and the fastest placement this part offers |
| `flash-noart` | flash | off | the ART accelerator's own contribution |
| `sram-noart` | SRAM | off | instruction fetch moved off the dedicated ICode bus onto the system bus |

`sram-noart` is **not** "the cipher without the flash" and not a lower bound. It is a
*worse* instruction path: SRAM code is fetched over the system bus that also carries
every data access, while flash code uses the dedicated ICode port. This part has no
zero-wait-state executable memory — CCM is D-bus only — so there is no configuration
here in which instruction supply is free.

All three images come from one build with `build/m4` removed first, and the build
refuses to link `sram-noart` unless an `nm` audit finds every `.text` symbol of every
relocated object inside `.ramtext` (this run: 79 symbols in `[20000000,200182f0)`,
floor 70, 12 removed by `--gc-sections`). A run whose timed code silently stayed in
flash cannot be published.

### Resolution: what a cross-configuration ratio is worth

A per-row figure moves by up to **7.5%** from code placement alone. The governing
variable is a code address's offset mod 16: with the ART off the only
instruction-fetch granularity is the 128-bit flash word, so a +16 B shift of the image
is invisible (0 of 39 rows move) while a +4 B shift is close to worst case (39 of 39
move, up to 7.5%). Turning the ART bits off is *itself* a 4-byte shift — `movs r2,#5`
is two bytes where `movw r2,#0x705` is four — so the harmful case is exactly the one
this file's own comparison sits on, and no amount of care removes it.

One qualification, because the same supersession that retracted the ART figure applies
here: the relink experiment was run on a **39-row image**, before the ten `bitslice64`
rows existed, and has not been re-measured on the image that produced this file. By the
CSV's own argument — a firmware change recompiles the objects, so this figure does not
bound the difference across one — carrying 7.5% forward is an assumption rather than a
measurement. The mechanism is a property of the part and not of the row set, so the
figure is very likely still about right; it is used below as the working floor, and
anything that would turn on a third significant figure should re-run the relink on the
current objects first.

Consequently: cross-configuration ratios are quoted here to **two significant
figures**, always as an aggregate, and two individual rows are never differenced across
configurations. At a 7.5% floor a 1.05x per-row difference is not a measurement.

Within a single configuration the board is deterministic and the counter repeats to the
last digit, so within-configuration ratios (every bitslice comparison below) do not
carry this floor.

## Reading the rows

Three properties of the data look like defects and are not.

**`cycles_per_byte` equals `cycles_per_byte_min` in all 147 rows.** These are not one
number printed twice: the firmware sorts the trial array and reads `samples[TRIALS/2]`
and `samples[0]` from it, two different elements computed separately. They coincide
because every trial returns the identical cycle count — interrupts masked, SysTick off,
working set in CCM, each table in the memory chosen for it. Read it as: on this part,
under this protocol, the measurement has no run-to-run spread to report. The min column
is confirmation, not information, and the trial count should not be read as implying a
variance that does not exist. This says nothing about spread *between* configurations,
which is real and is the subject of the section above.

**The two cipher-D variants have bit-identical `table` and `table-x4` rows** — six row
pairs across the three configurations. `cipher-D-lin444-297-r5` and
`cipher-D-lin444-297-aes-r5` differ in exactly one field that affects computation, the
8-bit S-box; `key_bits`, `key_schedule`, `linear`, `rounds` and `sbox_bits` are all
equal in their two variant files. A table implementation does the same number of
lookups into a table of the same size with the same access pattern whatever the S-box
holds, so its cycle count cannot tell the two apart. That they *are* different ciphers
is visible in any row whose implementation depends on S-box structure rather than
size — see "Where the 8-bit-S-box ciphers land" below.

**`mb_per_sec` is not a throughput for the `keysetup` rows.** Those rows use
`bytes_per_op = 1`, as `results/speed.csv` does, so their `cycles_per_byte` reads as
cycles per key setup and the derived MB/s is really "key setups per microsecond". Of
the 21 `keysetup` rows, 15 print `0.00` and 6 do not: the five 64-bit ciphers take
177,000–189,000 cycles per key setup, which lands at about 0.001 and truncates to zero
at two decimals, while `aes-r5` and `aes-lin444-0-8-15-r4` take only 2,260–2,510 and so
survive the truncation as 0.03 to 0.07. The ~75x gap is not a property of the ciphers'
key schedules: the 64-bit rows time `present_init`, which expands the round keys *and*
builds the implementation tables and the 64-word-per-round bitslice key masks
(`src/present_core.c:125`), while the 128-bit rows time `aes_key_schedule` /
`lin_key_schedule` alone. They are not comparable to each other. Neither the
zeros nor the non-zeros should be read as a byte rate: the column is meaningless for
all 21 `keysetup` rows and meaningful for the other 126.

## Results

`cycles_per_byte` in the `product` configuration. `-bs` rows run the round function
with the state already transposed and the key already expanded, so they are the
counter-mode ceiling; the all-in-one rows are what a caller holding ordinary blocks
pays. `keysetup` is cycles per key setup.

| cipher | rounds | keysetup | ref | table | table-x4 | bitslice32 | bitslice32-bs | bitslice64 | bitslice64-bs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| present-80-r16 | 16 | 181,071 | 3,295.86 | 150.75 | 197.42 | 107.16 | 67.01 | 148.70 | **58.92** |
| present-80-lin444-297-r7 | 7 | 186,652 | 1,447.90 | 69.75 | 89.14 | 94.16 | **55.41** | 140.08 | 58.52 |
| cipher-D | 8 | 177,077 | 1,475.55 | **78.75** | 101.17 | 730.15 | 699.20 | 842.57 | 761.74 |
| cipher-D-lin444-297-r5 | 5 | 188,552 | 927.35 | **51.75** | 65.08 | 489.03 | 456.88 | 581.71 | 501.66 |
| cipher-D-lin444-297-aes-r5 | 5 | 188,593 | 926.07 | **51.75** | 65.08 | 114.24 | 77.50 | 170.98 | 92.60 |
| aes-r5 | 5 | 2,507 | — | **38.06** | 57.03 | 131.90 | 89.58 | — | — |
| aes-lin444-0-8-15-r4 | 4 | 2,261 | **44.68** | — | — | 127.69 | 78.26 | — | — |

Not every cipher has every implementation, and the gaps are deliberate: `aes-r5` has no
`ref` row, `aes-lin444-0-8-15-r4` has no fused-table row (see "Candidates that did not
win"), and the two 128-bit ciphers have no `bitslice64` row because
`bench/wide_bitslice32.h` is a 32-bit-word bitslice with no 64-bit-word counterpart —
there is nothing to time. That absence is recorded by the KAT gate as not-applicable
rather than left for a reader to notice.

The `ref` rows are the definition compiled straight, and on the 64-bit ciphers they are
17.9x–21.9x slower than the table path under `product` (17.9x–24.9x across all three
configurations). They are a correctness anchor, not a candidate.

## Most effective optimizations

### 64-bit bitslice versus 32-bit bitslice on a 32-bit core

This was the project's headline argument for the M4, and it is now a measurement rather
than an argument. `bitslice64` and `bitslice64-bs` rows exist for the five 64-bit-block
ciphers: the same circuits, the same linear-layer bodies and the same
`ctx->rk_mask_enc` round keys, compiled at two word widths, 32 blocks per call against
64. Both consume the same 2,048 B working set, both re-seed 2,048 B of plane state per
trial in the `-bs` form, and both hoist the same key expansion and the same transpose.

**Result: the 32-bit bitslice beats the 64-bit one by a median 1.2x, in 15 of 15
pairs, with no exceptions** (`bitslice32` against `bitslice64`, min 1.1, max 1.5, over
5 ciphers × 3 configurations). That is the all-in-one form — the one a caller who does
not already hold bitsliced state pays — it is unanimous, and it survives being stated
without qualification.

The transpose-free form is weaker and is stated as such: a median 1.1x with three of
fifteen pairs inverted. It is not the number to lead with.

**The measurement did not confirm the argument's mechanism, and that is the more
interesting finding.** The plan attributed the margin to the round function: a 32-bit
machine synthesizes each 64-bit gate from two instructions, so the u64 round is slower.
For PRESENT-80 that is false in the strongest available sense. With the state already
transposed, the u64 kernel is the **faster** of the two in all three configurations:

| present-80-r16 | `bitslice32-bs` | `bitslice64-bs` | u64/u32 |
|---|---:|---:|---:|
| product | 67.01 | 58.92 | 0.879 |
| flash-noart | 124.62 | 97.85 | 0.785 |
| sram-noart | 95.13 | 73.91 | 0.777 |

The u64 round function wins by 1.14x to 1.29x. The reason is that a pbox round over a
15-gate S-box (`src/gen/sbox_circuits.h:7514`) is dominated by *moving* state rather
than computing it: per round for 64 blocks the kernel does 16 S-box circuits — 240
gates — against 64 key XORs and 64 permuted stores, where the permutation *is* the
store index and costs nothing but the store. Doubling the word width halves the memory
operations and loop iterations for the same number of blocks and lets the compiler pair
them into `LDRD`/`STRD`, which move 8 bytes in 3 cycles where two singles take 4. The
"two instructions per 64-bit gate" penalty applies only to the 240 gates, and it is not
enough. *(Instruction counts recovered from the disassembly of this firmware's own
objects give 1,236 dynamic instructions per round per 64 blocks for the u64 kernel
against the u32 path's 1,492, a ratio of 0.83 against the measured 0.78–0.88; both
halves of the round favour the wider word. This is a diagnostic, not a CSV row.)*

**The margin the headline rests on is the transpose.** Within one configuration the
all-in-one row minus the `-bs` row isolates the two transposes, and
`present_transpose64` twice costs **1.7x to 2.6x** what `present_bitslice32_pack` plus
`present_bitslice32_unpack` cost, in all 15 cases. A 64-word delta-swap runs six stages
of two-instruction 64-bit operations against five stages of one-instruction 32-bit
ones. That is the whole of the all-in-one margin and then some.

So the honest claim is narrower than the plan's and better founded: **at 32 bits the
bitslice path wins on this core because transposing into and out of bitsliced form is
cheaper at the machine's native word width, not because the cipher rounds are.** The
price of a 64-bit bitslice on a 32-bit core is paid at the boundary, and it is paid
whether or not the round function happens to like the wider word.

Where the gate-synthesis mechanism *does* hold is the four ciphers whose rounds are not
dominated by state movement, on the evidence of their twelve `-bs` rows
(`bitslice64-bs` over `bitslice32-bs`, range across the three configurations). The
`gates/round` column is a *diagnostic* — gates per round per block, counted from the
circuits the M4 links during the Task 12a investigation, not a CSV column — and it
orders the ratios rather than predicting them:

| cipher | round function | gates/round | u64/u32, `-bs` |
|---|---|---:|---|
| present-80-r16 | pbox, 4-bit S-box | 240 | **0.78–0.88** (u64 faster) |
| present-80-lin444-297-r7 | lin444, 4-bit S-box | 240 + linear | 1.06–1.09 |
| cipher-D | pbox8, 8-bit S-box | 8,856 | 1.07–1.12 |
| cipher-D-lin444-297-r5 | lin4448, 8-bit S-box | 8,856 + linear | 1.10–1.13 |
| cipher-D-lin444-297-aes-r5 | lin4448, AES S-box | 1,056 + linear | 1.15–1.25 |

The cleanest evidence that the inversion is a gate-density effect rather than an
artifact is inside PRESENT-80 itself: adding a linear layer to an otherwise identical
round flips the sign, 0.879 → 1.056, with the S-box, the key schedule and the block
count all held fixed.

The sentence that survives all of this: **the 32-bit path wins, and the one cipher
whose 64-bit round function is genuinely cheaper still loses 1.39x end-to-end once the
transpose is counted** (present-80-r16, `product`: 107.16 against 148.70).

One consequence worth stating plainly, because it cuts the other way: for a
counter-mode caller that keeps its state bitsliced, `bitslice64-bs` at 58.92 cyc/B is
PRESENT-80-r16's fastest row on this part, faster than `bitslice32-bs` at 67.01. The
u64 path is not useless here — it is useless *at the boundary*.

### `product` versus `flash-noart` versus `sram-noart`

Aggregated over the 49 pairs, as `cycles_per_byte` of the named configuration over
`product`:

| configuration | min | **median** | max | slower than `product` |
|---|---:|---:|---:|---:|
| `flash-noart` | 1.3 | **1.6** | 2.4 | 49 of 49 |
| `sram-noart` | 1.3 | **1.6** | 1.8 | 49 of 49 |

The median is the figure to quote — an aggregate is what survives the 7.5% floor. The
min and max are single rows and each carries that floor in full; read them as spread,
not as measurements of a best and worst case. The unanimity is a sign test and needs no
error bar at all.

**The ART accelerator is worth about 1.6x**, two significant figures. A third
significant figure is not meaningful at a 7.5% per-row layout floor, and no *conclusion*
in this document rests on one. Three digits do appear below — in the retraction
immediately following, in the `SRAM + ART on` 2×2, and in the T-table A/B — and they are
there because the underlying diagnostic printed them and rounding a quoted diagnostic
would misrepresent it. Read every one of them as showing which side of a comparison won,
not as a value good to that precision; the same goes for the handful of per-row
cross-configuration percentages, which the rule stated above otherwise forbids and which
are quoted only to show that a residue is *not* uniformly small. *(Earlier development
text quoted 1.773x, and briefing text 1.7x;
both are the median of a 39-pair set measured before the ten `bitslice64` pairs
existed. Restricted to those same 39 pairs the published CSV gives 1.69. The 1.6 above
is the median over all 49 pairs, which is what the published artifact reports and what
this document quotes.)*

**What `sram-noart` shows is instruction supply, not the accelerator.** The 2×2
control that establishes this was run on the same board in the same session as a
diagnostic — the two missing cells, `{flash, SRAM} × {ART on, ART off}` — and is not
part of the published CSV:

| comparison | what moves | median |
|---|---|---:|
| code flash → SRAM, ART stays on | instruction supply | 1.51x |
| ART off, code already in SRAM | the accelerator alone | **1.000x** |

With the code already in SRAM, switching the ART off costs nothing at all: a median of
exactly 1.000x, with 28 of 39 rows agreeing to within 0.3%. The rows that do move are
the ones with real flash *data* traffic left, because `.rodata` is still read through 5
wait states with the D-cache off, and that residue is not uniformly small
(`aes-lin444-0-8-15-r4/ref` is +16.1%, the five 64-bit `keysetup` rows +8.3% to
+10.2%). The qualitative conclusion survives: essentially the whole
`product`-to-`sram-noart` gap is bought by moving the *instructions*.

**Both statements above rest on the `SRAM + ART on` cell, which is a diagnostic and not
a published configuration.** It is the one conclusion in this document that
`results/m4-speed.csv` cannot settle on its own, and the flag in the introduction points
here. The evidence is the two extra cells of the 2×2, built by overriding the make
variables, run on the same board in the same session as the published images, and
reported in the Task 10 investigation. It is not reproducible from the recorded commit
the way the 147 rows are.

**Cache capacity is not the explanation either.** The `SRAM + ART on` cell has the full
1 KB ART I-cache available and still loses to `product` on every row — including rows
whose kernel is five times the cache size. `present_circuit8_u32_c0`, cipher-D's
bitsliced inner loop, is **5,466 B** (`0x155a`) — *diagnostic: a code size read from the
built object during the Task 10 investigation, not a CSV column* — which is 5.3x a 1 KB
I-cache. It cannot possibly be resident, and it has the *worst* ratio in the table
rather than the best. A capacity argument predicts the opposite sign.

### Tables in the memory that is fastest for them

The 64-bit ciphers' 16 KiB fused `enc_tab` is in CCM; AES's 4 KiB T-tables are in SRAM.
This is not a default, it was measured on this board: moving the T-tables to CCM costs
`aes` `table` +6.99% and `table-x4` +6.73%, while moving `enc_tab` to SRAM leaves the
64-bit table rows unchanged to the last digit. Each table is in the memory that is
fastest for it, and the asymmetry is recorded rather than assumed. Those two
percentages are single-row differences between separate builds — the comparison the
resolution rule above forbids, and worse than a relink, since moving a table
recompiles. Both are quoted for their **sign**, which is the whole of the conclusion;
the magnitudes sit inside the layout floor and should not be read as measurements.

### Where the 8-bit-S-box ciphers land, and why bitslicing loses for them

Bitslicing is worth having when the S-box is a small Boolean circuit and worth nothing
when it is not, and this target makes the point unusually sharply because
`cipher-D-lin444-297-r5` and `cipher-D-lin444-297-aes-r5` are a controlled pair: only
the 8-bit S-box differs between them. Under `product`:

| | `bitslice32-bs` | `table` |
|---|---:|---:|
| cipher-D-lin444-297-aes-r5 (132-gate AES S-box) | 77.50 | 51.75 |
| cipher-D-lin444-297-r5 (1107-gate S-box) | 456.88 | 51.75 |
| ratio | **5.9x** | 1.00 |

The table rows are bit-identical, as they must be. The bitsliced rows differ by 5.9x,
and that difference is the entire evidence that these are two ciphers rather than one.

Bitsliced, cipher-D's S-box costs **1107 gates** where the AES S-box costs 132 and
PRESENT's 4-bit S-box costs 15 (`src/gen/sbox_circuits.h:7514`, confirmed; the M4 links
the u32 retype of the same circuits). **1107/132 is 8.4x in gates against a measured
5.9x in cycles, so the gate count bounds the difference rather than explaining all of
it** — and that is what should happen, because only the S-box layer differs: the linear
layer, the round-key addition and the bitslice transpose are identical work in both and
dilute the ratio. The gate counts set the direction and the order of magnitude of the
gap; they do not account for the whole of it on their own. Both figures come from the
same image in the same run, so the 7.5% layout floor does not apply.

Against PRESENT's 15 gates the factor is 74x, and the outcome is what the table shows:
for the two ciphers with a raw 8-bit S-box, the fused byte table beats the transpose-free
bitslice by **8.8x–8.9x under `product`** (7.1x–10.6x across all three configurations),
and no amount of word-width tuning changes that.

## Candidates that did not win

- **A fused substitution-and-linear table for `aes-lin444-0-8-15-r4`.** Both a 16 KiB
  and a 64 KiB form were built and measured on this board, verified bit-identical to
  `lin_encrypt_ref` before timing, at **95.0** and **100.0 cyc/B** against
  `lin_encrypt_ref`'s **41.9**. Both lose, and the unreduced 64 KiB form loses hardest,
  so it is not an artefact of shrinking the table. The reason is structural and is
  arithmetic rather than measurement: AES's T-table works because ShiftRows and
  MixColumns keep one input byte's influence inside one 32-bit column, so a fused entry
  is 32 bits — one load and one XOR per byte. lin444 mixes every input byte into all
  four state words, so a fused entry is 128 bits: one load and one XOR per byte on
  SSE2, but **four loads and four XORs per byte on 32-bit registers, 64 loads per round
  against AES's 16**. The fused table is an x86 optimisation that does not survive the
  register width. That is why `aes-lin444-0-8-15-r4` has no fused-table row in the CSV,
  and why its `ref` row is the fastest scalar kernel available for it on this target.
  *(The 41.9/95.0/100.0 triple was measured in a separate diagnostic build; the
  published `ref` row for this cipher under `product` is 44.68 cyc/B. The 6.6% between
  them is layout, well inside the floor above, and nothing turns on which is quoted —
  both fused forms lose by more than 2x.)*
- **`table-x4`, four-way interleaved table lookups.** Slower than plain `table` in 18
  of 18 cipher/configuration cases, by 1.05x to 1.63x. That is the measurement; the
  explanation offered for it, not established here, is that the M4 is in-order with a
  three-stage pipeline, so there is little load latency for a second stream to hide
  while the interleaving costs register pressure on 14 usable registers. On x86 an
  interleaved table (`table-x8`) is the fastest table kernel for all five 64-bit
  ciphers, and the fastest kernel of any kind for the two with a raw 8-bit S-box.
  Interleaving is a target property, not a cipher property.
- **Bitslicing the raw 8-bit S-box ciphers.** `cipher-D` and `cipher-D-lin444-297-r5`
  are 8.9x and 8.8x slower bitsliced than tabulated even in the transpose-free form.
  The rows are kept because they are the control that makes the 5.9x above meaningful.
- **The 64-bit bitslice as a general replacement.** Loses 15 of 15 all-in-one, for the
  reason given above. Kept because it wins the counter-mode row for PRESENT-80-r16 and
  because the reason it loses is not the reason that was predicted.

## Cross-check against the other targets

`results/speed.csv` is x86-64 (AVX2, no AES-NI/GFNI), `results/speed-arm.csv` is a
32-bit ARMv7-A Cortex-A7 with NEON (see [arm-optimizations.md](arm-optimizations.md)),
and the FPGA estimates are in [fpga-optimizations.md](fpga-optimizations.md). Only the
five 64-bit-block ciphers appear on all of x86, ARMv7 and the M4; the two 128-bit
ciphers are M4-and-FPGA only.

**Restricted to each target's scalar table kernels, the ranking of the five shared
ciphers is identical on all three CPUs**, fastest first:

| rank | M4 (`product`, cyc/B) | Cortex-A7 (cyc/B) | x86-64 (cyc/B) |
|---:|---|---|---|
| 1 | cipher-D-lin444-297-aes-r5 51.75 | cipher-D-lin444-297-aes-r5 31.62 | cipher-D-lin444-297-aes-r5 1.433 |
| 2 | cipher-D-lin444-297-r5 51.75 | cipher-D-lin444-297-r5 31.64 | cipher-D-lin444-297-r5 1.531 |
| 3 | present-80-lin444-297-r7 69.75 | present-80-lin444-297-r7 42.61 | present-80-lin444-297-r7 1.984 |
| 4 | cipher-D 78.75 | cipher-D 48.10 | cipher-D 2.415 |
| 5 | present-80-r16 150.75 | present-80-r16 91.42 | present-80-r16 4.267 |

Every cell is that target's `table`-family row, so the table can be checked against the
three CSVs directly.

(The M4's rank-1 and rank-2 rows are bit-identical for the reason given above; on the
other two targets the same pair differs by 0.06% and 6.8%. The A7 column is derived
from wall-clock MB/s at a pinned 1296 MHz and carries ~15% jitter, so it is quoted for
its *order*, which is stable, not for its absolute values.) The M4's *overall*
all-in-one ranking is the same list, because `table` is its fastest all-in-one kernel
for four of the five; the exception is `present-80-r16`, where `bitslice32` at 107.16
beats `table` at 150.75 — which changes that cipher's fastest kernel but not its rank,
since it is last either way.

**Two inversions exist, both against targets with a wide vector unit, and both have the
same cause.** On x86 the fastest kernels are `avx2`/`avx2-bs` and the two PRESENT
variants move to ranks 1 and 2; on the Cortex-A7 the fastest counter-mode kernels are
`neon-bs` and `present-80-lin444-297-r7` moves to rank 1. Bitslicing rewards a small
S-box circuit in proportion to how many blocks fit in a register, and the M4's widest
word is 32 bits. AVX2 gives 256 blocks in flight and NEON 128, against the M4's 32 with
14 usable general-purpose registers. So on the M4 bitslicing still wins where it should
— `present-80-r16` all-in-one, and both PRESENT variants in the transpose-free form —
but it does not win by enough to lift the bit-oriented ciphers past the byte-oriented
ones. A second-order version of the same effect: on the A7 `neon-bs` beats `table` for
`cipher-D-lin444-297-aes-r5`, and on the M4 `bitslice32-bs` at 77.50 loses to `table`
at 51.75. That is the ranking behaving consistently with word width, not a
contradiction.

**The inversion against the FPGA is real and is a property of the target, not an
error.** By projected candidate rate the FPGA speed cores rank
`PRESENT-80-lin444-297-r7` first (3.17e11 tests/s) and `PRESENT-80-r16` second
(2.29e11), with `cipher-D-r8` last; the same two also lead by logic cost per lane
(1,920 and 2,161 LUT+ALU against cipher-D's 8,694). On the M4 the two PRESENT variants
are ranks 3 and 5 of the five, and `present-80-r16` is the slowest cipher in the whole
table. The cause is PRESENT's bit permutation: in hardware it is wiring and costs
literally nothing, and a 4-bit S-box is ~15 gates, so PRESENT is both the cheapest lane
and the fastest one. In software the same permutation has to be *emulated* — either as
a table that destroys the bit structure, or by bitslicing, which recovers it but only
at the register width the machine offers. The FPGA and the M4 are measuring the same
property of the cipher and disagreeing about its sign because one of them can route
wires.

**A fourth inversion is mostly an artefact of the two targets' units, and the part that
is not is stated as unresolved.** The two 128-bit ciphers are the M4's *fastest* two
rows — `aes-r5` at 38.06 and `aes-lin444-0-8-15-r4` at 44.68 cyc/B — and the FPGA's
fifth and sixth by candidate rate. But `cycles_per_byte` credits a 128-bit block for
encrypting sixteen bytes, whereas one FPGA candidate is one block encryption whatever
the block width. Re-expressed in the FPGA's own unit — `cycles_per_byte` × block
bytes, `product`, all-in-one — the M4 ranking becomes:

| cipher | cyc/block | M4 rank by cyc/B | M4 rank by cyc/block | FPGA rank |
|---|---:|---:|---:|---:|
| cipher-D-lin444-297-r5 | 414 | 3= | 1= | 4 |
| cipher-D-lin444-297-aes-r5 | 414 | 3= | 1= | 3 |
| present-80-lin444-297-r7 | 558 | 5 | 3 | 1 |
| **aes-r5** | **609** | **1** | **4** | **5** |
| cipher-D | 630 | 6 | 5 | 7 |
| **aes-lin444-0-8-15-r4** | **715** | **2** | **6** | **6** |
| present-80-r16 | 857 | 7 | 7 | 2 |

The `=` marks a tie, and it matters here: the two `cipher-D-lin444-297` variants are
not ranked 1 and 2, they are **exactly equal** — 51.7534 cyc/B each, 414.03 cyc/block
each, the bit-identical `table` rows explained under "Reading the rows" above. The M4
cannot order them at all. Ordering them arbitrarily and then reading off the FPGA's 4
and 3 would manufacture an inversion out of a tie-break; there is no M4 disagreement to
explain in that pair.

Changing the unit moves `aes-r5` from rank 1 to rank 4 against the FPGA's 5, and
`aes-lin444-0-8-15-r4` from rank 2 to exactly the FPGA's rank 6. So most of this
inversion is the metric and not the ciphers, and the remaining PRESENT disagreement is
the one already explained above.

What the FPGA table then costs the 128-bit lanes is **S-box instances per lane**, and
that much is established rather than guessed. `fpga/generated/cores.csv` gives
`rounds × sboxes_per_block` for each speed core, and the three cores that share the
Boyar-Peralta AES S-box scale almost exactly with it:

| speed core | S-box instances | LUT+ALU | per instance |
|---|---:|---:|---:|
| cipher-D-lin444-297-AES-r5 | 40 | 4,056 | 101.4 |
| AES-lin444-(0,8,15)-r4 | 64 | 6,369 | 99.5 |
| AES-r5 | 80 | 7,411 | 92.6 |

Doubling the block width doubles the S-boxes at equal round count, the logic per lane
follows to within 9%, and `cores` at 80% of the V80 is `min` over resource classes and
so falls with it. A 128-bit block costs area on the FPGA and costs only more loads on a
32-bit core.

The residual — `aes-r5` sitting one place ahead on the M4 even in cycles per block,
swapping with `cipher-D` — is one rank on two adjacent numbers (609 against 630) and
**this document does not claim a cause for it.** A cross-target rank difference that
small is not something the measurements here can resolve.

**One inversion is internal to the M4 and is stated in "Candidates that did not win"
above**: `aes-lin444-0-8-15-r4`'s fused table loses to its byte-wise reference kernel,
which is the reverse of the x86 result, for the register-width reason given there.

Nothing in the FPGA or GPU rankings contradicts the M4 result for the 8-bit-S-box
ciphers: bitslicing loses for a 1107-gate S-box on every target measured. The GPU sweep
reports the same thing for cipher-D-r8 — "its S-box is 8-bit and unstructured, which
rules out bitslicing" — and the A7 measurement reports it independently.

## Interpretation limits

- **One part, one board, one run.** All 147 rows come from the run described in the CSV
  header. Repeat runs at commits differing only in the driver's comment text reproduced
  all three image hashes and columns 1–7 of all 147 rows byte-identically; `ns_per_op`
  is the only column that moved, in its low-order digits, tracking the LSE-referenced
  clock measurement.
- **Rows from an older copy of this CSV are not comparable with these.** The revision
  that added the `bitslice64` rows is a firmware change, and a firmware change moves
  code addresses. The 7.5% layout floor does not bound a cross-commit difference either:
  it was measured by relinking one set of object files, and a firmware change recompiles
  them.
- **This is a throughput measurement at a 2 KiB working set**, with key expansion and
  the bitslice transpose hoisted out of the `-bs` rows on identical terms for the 32-bit
  and 64-bit paths. It is not a latency measurement, not a streaming measurement, and
  the `keysetup` column is the only statement here about key agility.
- **Encryption only.** No decryption path was built or timed.
- The 8-bit S-box circuits are the BDD-heuristic ones, not minimal, so cipher-D's
  bitsliced rows reflect that heuristic as much as they reflect the target.

## Reproduction

```sh
git checkout 52c1c634ba1c && make m4-bench
```

`results/m4-speed.csv` is committed on top of that commit, so it is not in the tree the
command checks out. One command, one session, all three configurations built from a
removed `build/m4` and measured one after another on the same board without rebuilding
in between — which is a requirement rather than a convenience, given the layout floor.

The driver refuses to run with any of `Makefile`, `fw/`, `src/`, `include/`, `bench/`,
`variants/`, `tools/cipher_set.py`, `tools/gen_m4_kats.py`, `tools/gen_c.py`,
`tools/gen_retyped_circuits.py`, `tools/m4_kat_oracle.c`, `tools/sbox_synth.c` or
`tools/run_m4_bench.py` modified, because those are the inputs that can change a
firmware byte. The three image sha256 are recorded in the CSV header so a rebuild can
be checked against them rather than trusted.

Each configuration is flashed twice before it runs: `st-flash --reset write` puts the
image on the part and software-resets it (NRST is not wired on this board), and gdb's
`load` over the `st-util` session writes the same image again before running it. The
second write is what executes. Both write the same bytes from the same build, so this
affects nothing in the rows — it is recorded because the procedure should be checkable
against the artifact rather than reconstructed from the script.
