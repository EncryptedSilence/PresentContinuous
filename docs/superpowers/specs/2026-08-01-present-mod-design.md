# PRESENT_mod — Design

Date: 2026-08-01

## Purpose

A research harness for the PRESENT block cipher that lets you define **variants**
(modified S-box, permutation layer, round count, key size) and measure two things
for each variant:

1. **Speed** — cycles/byte and throughput, across several implementation styles.
2. **Strength** — SAT-based differential cryptanalysis: minimum number of active
   S-boxes and minimum differential trail weight over *r* rounds, hence the number
   of rounds needed to reach a given security level.

The deliverable is a table: *variant × (speed, security margin)*.

## Non-goals

- Production/constant-time crypto. This is an analysis harness.
- Linear cryptanalysis, key-recovery attacks, related-key models. (The CNF layer is
  structured so linear trails could be added later, but they are not in scope.)
- Model counting / exact differential probability. Trail clustering is provided as an
  optional enumeration, not an exact count.

## Single source of truth: the variant

Everything hangs off one JSON file per variant in `variants/`:

```json
{
  "name": "present-80",
  "sbox": [12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2],
  "pbox": [0,16,32,48,1,17,...],
  "rounds": 31,
  "key_bits": 80,
  "key_schedule": "present80"
}
```

- `sbox[x]` — 4-bit S-box, must be a permutation of 0..15.
- `pbox[i]` — bit at position *i* moves to position `pbox[i]`; must be a permutation
  of 0..63. Bit 0 is the LSB of the 64-bit state.
- `key_schedule` — `present80` or `present128`; the schedule reuses the variant's S-box.

`tools/gen_variants.py` reads these and emits `src/gen/variants_gen.c` +
`include/present/variants_gen.h`. The Python analysis package reads the same JSON.
A variant can therefore never drift between the speed pipeline and the SAT pipeline.

Inverse S-box and inverse permutation are **computed**, never hand-written.

### Shipped variants

| name | change vs. PRESENT-80 | why |
|---|---|---|
| `present-80` | — (reference) | baseline, official test vectors |
| `present-128` | 128-bit key schedule | baseline, official test vectors |
| `present-80-r16` | 16 rounds | reduced-round target, attack feasibility |
| `present-80-identity-p` | pLayer = identity | deliberately broken diffusion — sanity check that the SAT layer *detects* weakness |
| `present-80-rotate-p` | pLayer = 16 independent nibble-local rotations | weak but not trivially broken diffusion |
| `present-80-sbox-<c>` | alternative optimal 4-bit S-box | S-box axis; several representatives |

Alternative S-boxes are **searched for**, not hardcoded: `tools/find_sboxes.py` enumerates
4-bit permutations with differential uniformity 4 and linearity 8 (the Leander–Poschmann
"optimal" criteria) and picks deterministic representatives. Restricting to
differential uniformity 4 keeps every DDT entry in {0,2,4,16}, so trail weights stay
integral ({2,3} bits per active S-box) and the SAT cardinality encoding stays small.
Non-integral weights are still supported via a scaled-integer weight unit, but no
shipped variant needs it.

## Component 1 — C cipher core

```
include/present/present.h    public API
include/present/variant.h    variant descriptor struct
src/variant.c                registry, table derivation, self-consistency checks
src/present_ref.c            reference: bit-by-bit pLayer, nibble S-box
src/present_table.c          8 × 256 × u64 fused sBox+pLayer tables, built at init
src/present_bitslice.c       64 blocks in parallel, 1 register per state bit
src/keyschedule.c            present80 / present128, using the variant's S-box
src/gen/variants_gen.c       generated from variants/*.json
src/gen/sbox_circuits.h      generated bitslice circuits (optional, see below)
```

Three implementations, all covering **any** variant:

- **ref** — straightforward, obviously correct, slow. The oracle for the others.
- **table** — fuses sBoxLayer and pLayer into 8 lookup tables of 256 × `uint64_t`
  (16 KiB), derived at runtime from `sbox` and `pbox`. One round = 8 loads + 8 XORs.
  This is the "generic and fast" implementation and works for every variant with no
  per-variant code.
- **bitslice** — 64 state bits in 64 registers, 64 blocks encrypted in parallel.
  pLayer becomes register renaming (free). The S-box is evaluated as a boolean
  circuit. Circuits come from `tools/sbox_synth`, an exhaustive minimum-gate-count
  BFS over 4-input truth tables (each of the 4 output bits gets a minimum-cost
  circuit; common subexpressions are shared). If no synthesized circuit is present
  for a variant, a generic Shannon-expansion MUX evaluation is used instead.
  Transposition to/from bitsliced form is a standard 64×64 bit transpose.

Every implementation is checked against `ref` on random inputs, and `ref` is checked
against the official PRESENT-80 and PRESENT-128 test vectors.

## Component 2 — speed tests

`bench/bench_main.c`:

- **latency** — single-block encryption, serialized.
- **throughput** — long buffer, ECB-style loop, per implementation.
- **key schedule** — cost of expanding one key.

Timing uses `__rdtsc` for cycles and `clock_gettime(CLOCK_MONOTONIC)` for wall time.
Protocol: warmup, then N repetitions; report **median**, min, and relative deviation
(median is robust against scheduler noise; min is the "clean run" estimate). TSC
frequency is calibrated once against `CLOCK_MONOTONIC` so cycles/byte is meaningful
even with frequency scaling caveats noted in the output.

Output: `results/speed.csv` (one row per variant × implementation × mode) plus a
Markdown table.

## Component 3 — SAT differential cryptanalysis

Pure-stdlib Python package `analysis/present_sat/`. No third-party dependencies —
the environment cannot bootstrap pip.

### The model

The difference propagation through PRESENT is the clean case: key addition is
transparent to differences, and the pLayer is a bit permutation, i.e. pure wiring
with **no clauses at all** — it is variable aliasing. So the CNF is *only* S-box
constraints plus the objective.

Variables: `d[r][0..63]` = state difference before round *r*'s S-box layer,
`r = 0..R`. For round *r*, the 16 S-boxes constrain nibbles of `d[r]` to nibbles of an
intermediate `y[r]`, and `d[r+1][pbox[i]] = y[r][i]` is realized by using the same
variable, not by adding clauses.

Constraints:
- `d[0] != 0` (one clause).
- Per S-box, a CNF over 4 input-difference bits, 4 output-difference bits and 3 unary
  weight bits `u1 >= u2 >= u3` (weight = `u1+u2+u3` ∈ {0,2,3}).
- Objective `Σ weight <= W`, encoded with a Sinz sequential counter.

Two search modes:
- **active S-boxes** — replace weight bits by a single activity bit per S-box
  (`a = 1` iff the input difference nibble is nonzero) and bound `Σ a <= k`. Cheap;
  gives the classic "≥10 active S-boxes in 5 rounds" style bound.
- **trail weight** — the full weighted model; the minimum W is the best (highest
  probability) differential characteristic over *r* rounds.

Search: linear scan upward from a lower bound (`2 × minActive` is valid because the
minimum non-zero weight per active S-box is 2) until the first SAT, with a per-call
timeout. The first SAT is the optimum, and its model decodes into a printable trail.

### S-box CNF generation

For each S-box the valid `(Δin, Δout, weight)` triples are computed from the DDT. The
complement (invalid assignments) is covered by greedily expanding each invalid
assignment into a maximal cube contained in the off-set, then greedily removing
redundant cubes. Each cube becomes one clause. The result is **verified by brute force**
over all 2^11 assignments before use — a wrong S-box encoding would silently produce
wrong cryptanalysis, so this check is not optional.

### Solver interface

`analysis/present_sat/solver.py` writes DIMACS and shells out to a solver binary,
auto-detecting `cadical`, `kissat`, `cryptominisat5`, `minisat` on `PATH` or in
`third_party/`. `tools/get_solver.sh` builds CaDiCaL from source. Parsing accepts the
standard `s SATISFIABLE` / `v ...` output, so any DIMACS-compatible solver works.

## Component 4 — reports

`analysis/cli.py` drives the whole thing:

- `analyze` — for a variant, minimum active S-boxes and minimum trail weight for
  `r = 1..R_max`, with timeouts; writes `results/<variant>-differential.csv`.
- `report` — joins speed results with differential results into `results/report.md`:
  cycles/byte, best trail weight per round, the round count at which trail weight
  exceeds the block/key security level, and the resulting security margin against the
  variant's full round count.

The headline strength metric is **`rounds_to_64_bits`**: the smallest *r* whose best
single-trail weight is ≥ 64. Security margin = `rounds / rounds_to_64_bits`. This is a
single-trail bound, not a proof of resistance, and the report says so.

## Testing

- `tests/test_vectors.c` — official PRESENT-80/128 vectors against `ref`.
- `tests/test_impls.c` — table and bitslice agree with `ref` on random inputs, for
  every registered variant; decryption inverts encryption.
- `tests/test_variants.c` — every registered variant's sbox/pbox is a permutation and
  the generated inverses are correct.
- `analysis/tests/` — S-box CNF verified exhaustively; cardinality encoding verified
  against brute force on small instances; the known PRESENT bound (10 active S-boxes
  over 5 rounds) is asserted as an end-to-end regression test.

## Risks

- **Solver availability.** If CaDiCaL cannot be built, the analysis cannot run.
  Mitigated by supporting any DIMACS solver and by keeping the CNF writer independent
  of the solver.
- **Search cost.** Optimal-trail search past ~10 rounds is expensive. Mitigated by
  per-call timeouts and by recording partial results ("≥ X, timed out") rather than
  failing.
- **Weight granularity.** Only S-boxes with DDT entries that are powers of two give
  integral weights. Shipped variants respect this; others fall back to a scaled weight
  unit with a documented rounding error.
