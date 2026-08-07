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
  NEON instruction (`vand`/`vorr`/`veor`/`vmvn`/`vbic`/`vorn`). `tools/gen_neon_circuits.py`
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

The x86 build is unaffected: `make && make test` builds the NEON file as stubs and
every existing result stands.
