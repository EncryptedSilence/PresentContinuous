# PRESENT_mod

A harness for modifying the [PRESENT](https://en.wikipedia.org/wiki/PRESENT) block
cipher and measuring what the modification costs you — in **speed** and in
**differential strength**.

Define a variant once, in JSON. The same definition drives three C implementations
(so you can benchmark it) and a SAT-based differential trail search (so you can bound
its security). Nothing can drift between the two.

```
variants/present-80.json ─┬─→ tools/gen_c.py ─→ C: ref / table / bitslice ─→ speed
                          └─→ analysis/present_sat  ─→ CNF ─→ SAT solver ──→ strength
```

## Quick start

```bash
make                       # generate code, build library, tests, bench, CLI
make test                  # C test vectors + implementation equivalence + Python tests
tools/get_solver.sh        # build CaDiCaL into third_party/ (needs network, once)

make bench                 # speed tests  -> results/speed.csv
python3 analysis/cli.py analyze --all --max-rounds 8   # -> results/*-differential.csv
make report                # join both    -> results/report.md
```

Results live in [results/report.md](results/report.md).

## Defining a variant

One JSON file per variant in `variants/`:

```json
{
  "name": "present-80",
  "description": "Original PRESENT-80.",
  "sbox": [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2],
  "pbox": [0, 16, 32, 48, 1, 17, "..."],
  "rounds": 31,
  "key_bits": 80,
  "key_schedule": "present80"
}
```

- `sbox[x]` — the 4-bit S-box; must be a permutation of 0..15.
- `pbox[i]` — bit `i` of the state moves to position `pbox[i]`; must be a permutation
  of 0..63. Bit 0 is the least significant bit.
- `key_schedule` — `present80` or `present128`. The schedule reuses the variant's
  own S-box, so changing the S-box changes the key schedule too.

Inverse tables are always **computed**, never written by hand. After adding or
editing a file, `make` regenerates `src/gen/`. `make variants` regenerates the whole
`variants/` directory from `tools/make_variants.py`, which is also where the search
for alternative S-boxes lives.

### What ships

| variant | change | why |
|---|---|---|
| `present-80`, `present-128` | — | reference, pinned to the official test vectors |
| `present-80-r16` | 16 rounds | round-count axis |
| `present-80-identity-p` | pLayer = identity | no diffusion at all; confirms the analysis detects weakness |
| `present-80-rotate-p` | pLayer = rotate by 1 | diffusion stays local |
| `present-80-randperm-p` | pseudorandom pLayer | is PRESENT's designed pLayer better than an arbitrary one? |
| `present-80-sbox-opt1/2` | alternative optimal S-box | differential uniformity 4, linearity 8, same as PRESENT's |
| `present-80-sbox-weak1/2` | differential uniformity 8 | one active S-box can now cost as little as one bit |

The alternative S-boxes are found by seeded search in `tools/make_variants.py`, not
copied from anywhere, so you can audit or re-run the selection.

## The three implementations

| | what it does | when to use it |
|---|---|---|
| `ref` | one bit at a time, straight from the spec | the oracle; the other two are tested against it |
| `table` | sBoxLayer and pLayer fused into 8 × 256 × `uint64_t` (16 KiB), built at init | generic and fast; works for any variant with no per-variant code |
| `bitslice` | 64 blocks in parallel, one register per state bit | fastest; the pLayer becomes register renaming |

The bitsliced S-box is a boolean circuit, and the circuits are **synthesised**, not
hand-written: `tools/sbox_synth.c` does a breadth-first search over all 65536
four-variable truth tables to find a minimum-cost circuit for each output bit, then
shares common subexpressions. That is what makes the bitsliced path work for a new
S-box you invent, rather than only for PRESENT's. For the original S-box it finds a
20-gate circuit.

Decryption in the table implementation costs about twice what encryption does. This
is not an oversight: after the inverse pLayer, a nibble is made of bits that came
from different input bytes, so the inverse S-box cannot be folded into the
permutation tables the way the forward one can.

## Differential cryptanalysis with SAT

Difference propagation through PRESENT is unusually clean to encode:

- round keys are XORed in, so they cancel in a difference and never appear;
- the pLayer is a bit permutation — **pure wiring, zero clauses**, just variable
  aliasing;
- so the formula is nothing but S-box constraints plus the objective.

Each S-box contributes a small CNF over 4 input-difference bits, 4 output-difference
bits, and the weight of the transition in unary (`weight = -log2 P`, so weight 2
means probability 2^-2). The clauses come from covering the invalid assignments with
maximal cubes; the result is **verified exhaustively** against the DDT every time it
is built, because a wrong S-box encoding would produce confident, wrong
cryptanalysis rather than an error.

Two objectives, both bounded with a Sinz sequential counter and minimised by scanning
upward until the first satisfiable call:

- **minimum active S-boxes** over *r* rounds — cheap, and the classic design metric;
- **minimum trail weight** over *r* rounds — the best differential characteristic.

The searches reproduce the published PRESENT figures: 1, 2, 4, 6, **10** active
S-boxes over 1–5 rounds, and a best 5-round characteristic of probability 2^-20.
These are asserted as regression tests in `analysis/tests/test_model.py`, so a change
that breaks the model breaks the build.

### From a few rounds to a real bound

Searching 31 rounds directly is out of reach. It is not necessary: a characteristic
over `m × r` rounds restricts to a valid characteristic on each of its `m` disjoint
`r`-round windows, so its weight is at least `m × W(r)`. A search you *can* run —
six, eight, ten rounds — therefore **proves** a bound on the full cipher rather than
extrapolating one. `results/report.md` reports the best such bound and the round
count at which it clears 2^-64.

### Usage

```bash
python3 analysis/cli.py sboxes                                   # S-box properties
python3 analysis/cli.py trail   --variant present-80 --rounds 5  # print the best trail
python3 analysis/cli.py analyze --all --max-rounds 8 --timeout 300
python3 analysis/cli.py cluster --variant present-80 --rounds 5  # trail clustering
python3 analysis/cli.py report
```

Any DIMACS solver works (`--solver PATH`); CaDiCaL, Kissat, CryptoMiniSat and MiniSat
are auto-detected. Searches that run out of time are reported as `≥ x (timed out)`,
never silently dropped.

## What the shipped variants show

Full numbers in [results/report.md](results/report.md); the short version, from a
12-round search on every variant:

**The harness reproduces the published PRESENT figures.** Minimum active S-boxes over
1–12 rounds come out as 1, 2, 4, 6, **10**, 12, 14, 16, 18, 20, 22, 24, and optimal
trail weights as 2, 4, 8, 12, **20**, 24, 28, 32, 36, 41, 46, 52 — including the
design paper's "at least 10 active S-boxes in any 5 consecutive rounds". Those are
asserted as tests, so the model cannot quietly drift.

**Branch number, not differential uniformity, is what makes PRESENT's S-box work.**
Both alternative S-boxes found by searching for the standard optimality criteria
(differential uniformity 4, linearity 8) are "optimal" by those criteria, yet
`present-80-sbox-opt2` collapses to 2.0 weight per round against PRESENT's 4.33 — as
weak as deleting the permutation layer entirely. The difference is the differential
branch number: PRESENT's S-box has 3, both replacements have 2. Branch number 2 means
a one-bit input difference can produce a one-bit output difference, and since the
pLayer maps single bits to single bits, such a trail survives forever at one active
S-box per round. Picking an S-box for this cipher on uniformity alone would have
silently cost roughly half the security margin.

**PRESENT's designed permutation beats a random one.** `present-80-randperm-p` reaches
3.75 weight per round against 4.33 — interestingly with *fewer* active S-boxes (17 vs
24 at 12 rounds) but more expensive ones, netting out worse.

**The S-box only affects speed in the bitsliced implementation**, and roughly linearly
in synthesised gate count (12 gates → 7.08 cyc/B, 22 gates → 7.74). The table
implementation is within noise across every variant, because a lookup table does not
care what is in it. So on the table path, a stronger S-box is free; on the bitsliced
path it costs about 3% per extra gate. The permutation choice costs nothing on either
path.

Putting those together, the weak variants bought nothing: `present-80-sbox-weak2` is
the fastest bitsliced variant (7.08 vs 7.58 cyc/B, ~7%) and gives up 56% of the
security margin (0.89x vs 1.94x).

## Reading the speed numbers

- **cyc/B** is *nominal* TSC ticks per plaintext byte. On modern x86 the TSC runs at
  a fixed rate rather than the core clock, so treat it as a stable relative measure,
  not as true core cycles. **MB/s** is measured against `CLOCK_MONOTONIC` and has no
  such caveat.
- Each figure is the median of 15 trials of 8192 blocks, after 3 warmup trials. The
  `min` column shows the cleanest trial, so the gap between the two tells you how
  noisy the machine was.
- For the `keyschedule` and `ctxinit` rows the unit is per *operation*, not per byte;
  the MB/s column is meaningless there. `ctxinit` includes building the 16 KiB of
  lookup tables, which is why the table implementation has expensive key setup — it
  is a throughput design, not a key-agility one.
- Pin the process for tighter numbers: `taskset -c 2 ./build/bench`.

## Layout

```
variants/            variant definitions (the single source of truth)
include/present/     public API
src/                 cipher implementations; src/gen/ is generated, do not edit
bench/               speed tests
tests/               C tests: official vectors, implementation equivalence
analysis/present_sat/ CNF construction, differential model, search, reporting
analysis/tests/      Python tests: encodings checked against brute force
tools/               variant generation, C generation, S-box circuit synthesis
third_party/         SAT solver, built by tools/get_solver.sh
results/             benchmark and analysis output
docs/superpowers/specs/  design document
```

## Limits

- Bounds here are on **single characteristics**. A differential can cluster many
  characteristics with the same input and output difference, and their probabilities
  add; `analysis/cli.py cluster` measures that for a given difference pair.
- Nothing here addresses linear, algebraic, integral or related-key attacks, and a
  bound on characteristic probability is not by itself a proof of resistance to
  differential cryptanalysis.
- S-boxes whose DDT entries are not powers of two get weights rounded *down*, which
  keeps the bound valid (the real trail can only be less probable) but no longer
  tight. `analysis/cli.py sboxes` shows which variants are exact.
- This is analysis code. It is not constant-time and is not meant for protecting
  anything.
