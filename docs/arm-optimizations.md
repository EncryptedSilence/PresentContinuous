# Optimising the ciphers for 32-bit ARM (Cortex-A7), and what it bought

**This document is a measurement.** Every number here was produced on the hardware
named below, cross-checked against the reference implementation on the same board,
and the raw rows are in [results/speed-arm.csv](../results/speed-arm.csv). It is the
ARM counterpart to the x86 numbers in
[lin444-experiment.md](lin444-experiment.md) and to the predictions in
[platform-estimate.md](platform-estimate.md) — one row of which, "ARM NEON
bitsliced", this document turns from an estimate into a measurement.

## Platform

| | |
|---|---|
| board | OrangePi R1 (Allwinner H2+) |
| CPU | 4× ARM Cortex-A7, ARMv7-A, **32-bit**, up to 1296 MHz |
| SIMD | NEON (VFPv4), 128-bit registers, 64-bit datapath |
| RAM | 484 MiB |
| OS / compiler | Linux 6.18 (armhf), gcc 14.2.0 |
| clock during measurement | governor `performance`, pinned at 1296 MHz, one core (`taskset -c 3`) |

This is a *32-bit* ARMv7 core: there is no AVX2, and no AArch64 either, so the
SHA3 `EOR3`/`BCAX` three-input gates that a 64-bit ARM core would use do not exist
here. NEON is the only vector unit, and its integer datapath is 64 bits wide —
a 128-bit op issues over two cycles — so the win from NEON is not raw 2× arithmetic
but wider parallelism (128 blocks vs 64) and, above all, a register file big enough
to hold a bitsliced state that spills badly on the 14 usable 32-bit GP registers.

`cycles/byte` below is derived from wall-clock MB/s at the fixed 1296 MHz
(`cyc/B = 1296 / MB·s⁻¹`); the harness's raw cycle column uses `rdtsc`, which is
x86-only, so on ARM it is meaningless and is ignored.

## The three optimisations applied

### 1. A portable 128-bit key schedule (enabling change, not a speed change)

`src/keyschedule.c` expresses PRESENT's 80- and 128-bit key registers as
`unsigned __int128`. That type does not exist on a 32-bit target, so the stock code
does not compile for ARMv7 at all. `src/keyschedule_portable.c` is a drop-in
replacement: on targets with `__int128` (x86-64) it is bit-for-bit the original; on
ARMv7 it emulates the 128-bit register with a two-word `{hi, lo}` struct and the
handful of shift/mask/xor operations the schedules actually use. It is off the hot
path (once per key setup), so it costs nothing in throughput; it is what makes the
rest possible. Correctness is pinned by the published PRESENT-80 and PRESENT-128
KATs and the round-31 key-schedule vector (`test_vectors`, 30/30).

### 2. Platform build flags

`-mcpu=native -mfpu=neon-vfpv4 -mfloat-abi=hard`, `-O3` on the hot code. The two
translation units that inline the 1107-gate 8-bit S-box circuits
(`present_bitslice.c`, `present_neon.c`) and the variant tables (`variants_gen.c`)
are built at `-O2` — at `-O3` they exhaust the 484 MiB board and it OOM-freezes.
Both bitsliced backends being at the same `-O2` keeps the NEON-vs-scalar comparison
fair.

### 3. A NEON-native bitsliced backend — the actual speed optimisation

`src/present_neon.c` is the scalar bitslicer (`src/present_bitslice.c`) one lane
wider: bit *i* of **128** blocks lives in one 128-bit NEON register (`u64x2`, a
GCC/Clang `vector_size(16)` type of two 64-bit lanes) instead of bit *i* of 64
blocks in a `uint64_t`. A round is the same S-box circuits, the same linear layer
and the same key XOR over a type twice as wide.

Three things make this essentially free to build and impossible to get subtly wrong:

- **The S-box circuits are *derived*, not rewritten.** A synthesised bitslice
  circuit is a straight-line program over `& | ^ ~` — exactly the operators a GCC
  vector type supports. So the NEON circuit for an S-box is the scalar `u64`
  circuit with its element type widened to `u64x2`; every gate still maps to one
  NEON instruction (`vand`/`vorr`/`veor`/`vmvn`/`vbic`/`vorn`). `tools/gen_retyped_circuits.py`
  performs that retype mechanically to produce `src/gen/sbox_circuits_neon.h`, and
  `make generate` regenerates it. Because it is a retype of the *same* minimal
  circuits the rest of the harness verifies, the NEON path is bit-for-bit identical
  to the scalar one — nothing can drift, and no second synthesis is needed.
- **The linear layers are shared verbatim.** `lin444_body.h` is already generic
  over `(type, XOR)`; the NEON backend instantiates it over `u64x2` exactly as the
  AVX2 backend does over `__m256i`. A bit-permutation costs nothing here too — it is
  which register index the S-box output is stored to.
- **The round key broadcasts.** A single key means round-key bit *i* is the same for
  all 128 blocks, so the scalar 0/~0 mask word broadcasts to both lanes
  (`(u64x2){km[i], km[i]}`) — the vector analogue of AVX2's `_mm256_set1_epi64x`.

The backend is guarded by `#if defined(__ARM_NEON)`; on any other target it compiles
to no-op stubs and `present_have_neon()` returns 0, so the x86 build and its results
are untouched. It exposes the same shape as the AVX2 path: an all-in-one
`present_encrypt_neon` / `present_decrypt_neon`, and the transpose-skipping
`present_encrypt_neon_bs` / `present_decrypt_neon_bs` for a counter-mode caller that
keeps its state bitsliced.

## Correctness

Validated **on the board**, not just by construction:

- `test_vectors` — PRESENT-80/128 KATs + key-schedule vector: **30/30**.
- `test_impls` — every backend vs the reference oracle on random inputs, for every
  registered variant, now including a NEON block (encrypt vs `ref` over 128 blocks,
  decrypt round-trip, and `pack`/`neon_bs`/`unpack` reproducing the all-in-one):
  **10501/10501**.

## Measured effect

Speedup of the NEON bitsliced round function over the scalar one (`neon-bs` vs
`bitslice-bs`, the counter-mode throughput path, same board, back-to-back):

**Median 1.70×, range 1.40×–2.34×.** Stable across runs (per-run medians 1.699× and
1.703×), even though absolute MB/s carries ~15% run-to-run jitter under sustained
thermal load — the speedup is a within-run ratio, so the jitter cancels.

Selected variants (full set in `results/speed-arm.csv`); MB/s and derived cyc/byte:

| variant | scalar `bs-bs` MB/s | **`neon-bs` MB/s** | speedup | cyc/byte |
|---|--:|--:|--:|--:|
| present-80 (baseline) | 16.0 | **23.2** | 1.45× | 55.8 |
| present-128 | 16.0 | **23.2** | 1.45× | 55.8 |
| present-80-r16 | 30.2 | **44.1** | 1.46× | 29.4 |
| present-80-lin444-297 | 7.1 | **12.1** | 1.70× | 106.9 |
| present-80-lin444-297-r6 | 35.4 | **60.1** | 1.70× | 21.6 |
| present-80-lin444-297-r7 | 30.4 | **51.9** | 1.71× | 25.0 |
| present-80-sbox-opt2 | 16.4 | **26.4** | 1.61× | 49.0 |
| cipher-D-lin444-297-aes | 20.7 | **28.9** | 1.40× | 44.8 |
| cipher-D-lin444-297-aes-r5 | 32.5 | **45.8** | 1.41× | 28.3 |
| cipher-D (8-bit S-box) | 2.3 | **5.5** | 2.34× | 237.8 |

The fastest cipher on this platform is **present-80-lin444-297-r6 at 60.1 MB/s
(21.6 cyc/byte)**; the PRESENT-80 baseline goes from 16.0 to **23.2 MB/s** (81.0 →
55.8 cyc/byte).

### Why the speedup is not uniform

The pattern is the whole story of what NEON is doing here:

- **Bit-permutation PRESENT variants (~1.45×).** `present-80`, `-128`, `randperm-p`,
  `rotate-p`, `identity-p`, `-r16`: PRESENT's S-box is only ~15 gates, so a round is
  dominated by the 64 key-XOR-and-store operations. That work is store-bound, and
  doubling the lane width halves the store *count* but not the store *traffic*, so
  the gain is the modest 1.45×.
- **lin444 variants (~1.70×).** The general linear layer adds ~160 XORs of real
  vector work per round on top of the S-box. That work vectorises cleanly with no
  extra memory traffic, so it lifts the average ratio to 1.70×.
- **cipher-D, 8-bit S-box (~2.3×).** Its 1107-gate circuit needs far more live
  temporaries than 14 GP registers hold, so the scalar path spills constantly;
  NEON's 16×128-bit register file absorbs much of that, and the ratio exceeds the 2×
  lane width. But 2.3× of a very small number is still small: cipher-D's bitsliced
  path is 5.5 MB/s against its **table** path's 20.8, so — as on x86 — an 8-bit
  S-box is the case where bitslicing loses and the table wins regardless of backend.

### What now wins on this platform

With NEON in, `neon-bs` is the fastest implementation for **every** PRESENT-family
and lin444 variant — it overtakes both the scalar bitslicer and the table path,
which on this small in-order core is slow (8 dependent 64-bit lookups per round;
PRESENT-80 `table` is only 5.8 MB/s). The sole exceptions are the variants with a
raw 8-bit S-box — full cipher-D and `cipher-D-lin444-297-r5` — where the table path
still wins; the AES-S-box cipher-D variants (132-gate circuit) go back to NEON.

This overturns the x86-derived guess in
[platform-estimate.md](platform-estimate.md) that "any table-driven path" is the one
to beat on small cores: on a register-starved 32-bit core the bitsliced NEON path is
faster than the table for everything except a genuine 8-bit S-box.

## The 128-bit ciphers: AES against AES-lin444 on this board

Everything above is the 64-bit-block library. The two 128-bit ciphers — real AES and
AES-lin444 — live in `bench/wide_bench.c` and were previously measured only on x86 and
on the Cortex-M4. Raw rows for this board are in
[results/wide-speed-arm.csv](../results/wide-speed-arm.csv), the ten per-run CSVs
behind it (five runs × two round counts) in
[results/wide-speed-arm-runs/](../results/wide-speed-arm-runs/).

**Answer first: AES is faster, at equal proven differential margin and at equal round
count.** This *reverses* the x86 result.

At each cipher's equal-margin round count X from
[speed-at-equal-security.md](speed-at-equal-security.md) — AES at 5 rounds, AES-lin444
(0,8,15) at 4 — best kernel on each side:

| cipher | X | best kernel | MB/s | cyc/B |
|---|---:|---|--:|--:|
| **AES** | 5 | `table` | **42.13** | **30.76** |
| AES-lin444 (0,8,15) | 4 | `ref` | 40.19 | 32.25 |

AES wins by 1.05× — narrow. At equal round count the gap is wider: 1.24× at r = 4 and
1.27× at r = 5.

Having both round counts for both ciphers separates each kernel's per-round cost from its
fixed per-block cost (load, the final key XOR, store), and that is where the 1.05× comes
from:

| cipher | marginal cost of one round | fixed per-block cost |
|---|--:|--:|
| AES | 4.78 cyc/B | 6.86 cyc/B |
| AES-lin444 | 6.77 cyc/B | 5.18 cyc/B |

**AES-lin444's round is 1.42× dearer**, and dropping from 5 rounds to 4 buys back only
1.25× — so on round work alone it loses by more than the headline figure. What pulls it
back to 1.05× is the *other* column: its byte-wise kernel has 1.7 cyc/B less fixed
overhead than AES's T-table kernel, which at these very short round counts is a large
fraction of the total. Almost all of the apparent closeness is that fixed-cost gap, not
the round function.

That the two per-round figures differ between round counts (6.50 vs 6.15 cyc/B/round for
AES at r = 4 and r = 5) is this same fixed cost being amortised over more rounds; dividing
a total by X is therefore the wrong way to compare the two round functions, and the
marginal column above is the right one.

### Why this reverses the x86 answer

On x86, at equal margin, AES-lin444 wins: 1.185 against 1.269 cyc/B. Both of those
figures are `avx2-bs` rows. The AVX2 bitslice is the fastest kernel for both ciphers
there, and it favours AES-lin444, whose linear layer is XORs that bitslice for free while
its *table* form is expensive. Take the bitslice away and x86 agrees with this board: on
table kernels alone, AES at r = 5 is 1.69 cyc/B against AES-lin444 at r = 4's 1.92.

**There is no NEON bitslice for the 128-bit ciphers.** `wide_bench.c`'s bitslice is
AVX2-only, and unlike the 64-bit library — where `src/present_neon.c` was written for
exactly this reason — no NEON counterpart exists. So this comparison is between table-family
kernels on both sides, and it is the kernel family that decides the winner. See the caveat
below.

### Every kernel, not just the winner

cyc/B, derived from MB/s at 1296 MHz; **bold** = the row quoted above.

| cipher | r | ref | table | table-x4 | table-x8 | table-x16 |
|---|---:|--:|--:|--:|--:|--:|
| aes | 4 | — | **25.98** | 34.25 | 34.18 | — |
| aes | 5 | — | **30.76** | 42.52 | 42.49 | — |
| aes-lin444 | 4 | **32.25** | 71.52 | 68.90 | 72.81 | 72.52 |
| aes-lin444 | 5 | **39.01** | 88.52 | 85.54 | 90.38 | 90.19 |

Two results in that table are not what the x86 numbers predict, and both are the same
story — this core has 14 usable 32-bit GP registers and is in-order.

- **Block interleaving *hurts* AES here.** On x86 `table-x4` is AES's big win (2.36 → 1.69
  cyc/B at r = 5), because a single block is latency-bound and four independent ones hide
  it. On the A7 it is a *loss* — 1.32× at r = 4, 1.38× at r = 5: four AES states are 16 live
  32-bit words plus round
  keys plus four T-table pointers, which does not fit, so the interleaved kernel spills
  every round. Plain single-block `table` is AES's best kernel on this board.
- **The fused table loses to the byte-wise reference for AES-lin444, by 2.1–2.2×** — that is
  against the fused family's *best* interleave, not its worst. This
  reproduces on the A7 exactly what `bench/wide_ciphers.h` records for the Cortex-M4, and
  it survives being given NEON. Porting the SSE2 fused kernel to NEON (`uint32x4_t`, same
  gate-for-gate body — see `LV_*` in `wide_bench.c`) does give lin444 a genuine 128-bit
  vector register for the 16-way XOR accumulation, so the M4's stated reason (*"four loads
  and four XORs per byte on a machine with 32-bit registers"*) does not apply. It loses
  anyway, and the reason is ARMv7-specific: each round needs all four state words back in
  GP registers to index the table, and on ARMv7 a NEON-to-ARM lane read is a transfer
  across a pipeline boundary rather than a register move. Sixteen of those per round is
  the only candidate large enough to account for the gap, and the byte-wise `ref` kernel,
  which never leaves the GP register file, wins. That attribution is inference from the
  measured totals plus the known pipeline behaviour of this core — the transfer penalty
  itself was not isolated here, which would want a microbenchmark or a cycle counter this
  harness does not have on ARM.

Both of those are why `ref` is measured on every target now rather than only quoted on
the M4, and why the NEON port was worth doing even though it lost: without it, AES-lin444
would have been represented by a kernel nobody had tried to make fast, and the comparison
would have measured effort rather than ciphers.

## Caveats

- **`neon-bs` is the counter-mode ceiling.** It runs the round function with the
  state already transposed, so it is the right number for a keystream/CTR caller but
  excludes the pack/unpack transpose. For arbitrary-block I/O the all-in-one `neon`
  row applies (PRESENT-80: 12.4 MB/s), and it is still ~1.2× the full scalar
  `bitslice` row. Both are reported in the CSV.
- **Absolute MB/s carries ~15% thermal jitter** at sustained load (board reached
  74 °C, clock held at 1296 MHz); the 1.70× *ratio* does not, being a within-run
  comparison. Treat the absolute cyc/byte as ±15%, the speedup as tight.
- **This is compiler-vectorised, not hand-written assembly.** The gates are NEON
  intrinsics-equivalent (GCC vector ops) but instruction scheduling and register
  allocation are gcc's. A hand-scheduled NEON kernel, or interleaving two
  independent bitslice states to hide the A7's 2-cycle 128-bit latency, could go
  further; that is left as future work.
- The 8-bit circuits are the BDD-heuristic ones, not minimal, so cipher-D's numbers
  reflect that heuristic as much as the backend.
- **The AES-vs-AES-lin444 result is conditional on there being no NEON bitslice for the
  128-bit ciphers, and that is the one kernel most likely to change it.** On x86 the
  bitslice is what makes AES-lin444 win; removing it flips x86 to agree with this board.
  The 64-bit half of this document is direct evidence that the missing kernel would be
  fast here — `neon-bs` is the winner for *every* AES-S-box variant on this board,
  including `cipher-D-lin444-297-aes`, which is the same S-box and the same linear layer
  as AES-lin444 at 64 bits. So a NEON wide bitslice would plausibly beat both table paths
  and plausibly favour AES-lin444, as AVX2 does. It is unbuilt and therefore unmeasured;
  the honest statement is *AES is faster with the best kernel either cipher currently has
  on ARMv7*, not that AES's round function is faster on this core in principle. The
  per-round figures (6.15 against 8.06 cyc/B/round) are the table-family ones and would
  not carry over to a bitsliced kernel.
- The `--c0 1 10 15` rotation set was not run on this board. On x86 the two sets are
  within 2% on every table kernel and differ only in security, and rotation amounts are
  baked into `Tl` at setup so they cannot reach the table kernels at all — but the
  byte-wise `ref` kernel, which is the one that wins here, does read `k->c` at runtime,
  so that 2% is inherited rather than measured.

## Reproducing

On an ARMv7 + NEON target with gcc:

```bash
# generated NEON circuits come with the tree; regenerate with:  make generate
gcc -O2 -mcpu=native -mfpu=neon-vfpv4 -mfloat-abi=hard -Iinclude -Isrc \
    -c src/present_neon.c -o present_neon.o           # -O2: fits small-RAM boards
# build the rest at -O3, using src/keyschedule_portable.c in place of keyschedule.c,
# then link bench and tests as usual.
taskset -c 3 ./bench --csv results/speed-arm.csv       # governor=performance
./test_vectors && ./test_impls                          # KAT + NEON-vs-ref cross-check
```

The 128-bit ciphers are a single self-contained translation unit — no `src/`, no library
objects, so none of the above applies to them:

```bash
gcc -O3 -mcpu=native -mfpu=neon-vfpv4 -mfloat-abi=hard -std=gnu11 -Wall -Wextra \
    -Iinclude -Isrc -Ibench -o build/wide_bench bench/wide_bench.c
# five runs per round count; results/wide-speed-arm.csv holds the median of them
for r in 4 5; do for i in 1 2 3 4 5; do
  taskset -c 3 ./build/wide_bench --rounds $r --c0 0 8 15 \
      --csv results/wide-speed-arm-runs/r$r-run$i.csv
done; done
```

`wide_bench` selects its AES-lin444 fused-table kernel from the target's vector unit —
`__m128i` on x86, `uint32x4_t` on `__ARM_NEON`, nothing on a target with neither — and
refuses to time anything until AES matches FIPS-197 C.1 and every fused kernel matches
the byte-wise reference at all round counts it will time. Both gates passed on the board
(`ok AES-lin444: neon x1/x4/x8/x16 == scalar reference for 2..20 rounds`).

The x86 build is unaffected: `make && make test` builds the NEON file as stubs and
every existing result stands.
