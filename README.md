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

A worked example of the whole loop, from choosing rotation constants to a differential
bound: [docs/lin444-experiment.md](docs/lin444-experiment.md) — replacing PRESENT's
pLayer with a general GF(2)-linear layer costs 1.82x on the fastest implementation and
nothing at all on the table paths, and buys a differential bound of 2^-290 against
PRESENT's own 2^-123. Spent as a round reduction at equal proven margin instead, it is
a 1.8x *gain* on the table paths and a 9–16% loss on AVX2.

That comparison is only worth reading because the baseline was optimised too. It was
not, at first: the modification's constants had been specialised and PRESENT's had not,
which was worth 20 percentage points and reversed the conclusion. See
[Making the comparison fair](#making-the-comparison-fair).

The harness is not limited to PRESENT-shaped variants. A second worked example takes
an externally supplied design with an **8-bit** S-box and 8 rounds through the same
pipeline: [docs/cipher-D.md](docs/cipher-D.md) — its differential bound holds at
2^-77, but its fastest implementation is 2.4x slower than PRESENT's despite running a
quarter of the rounds, because an 8-bit S-box needs 1107 gates to bitslice against
PRESENT's 15.

## Quick start

```bash
make                       # generate code, build library, tests, bench, CLI
make test                  # C test vectors + implementation equivalence + Python tests
tools/get_solver.sh        # build CaDiCaL into third_party/ (needs network, once)

make bench                 # speed tests  -> results/speed.csv
tools/compare.sh avx2      # variant-vs-baseline ratios, one pinned process per rep
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

- `sbox[x]` — the S-box; must be a permutation of 0..2^`sbox_bits`-1.
- `sbox_bits` — 4 (default) or 8. At 8 the state is eight bytes rather than sixteen
  nibbles, and the bitsliced circuit comes from a different synthesiser; see
  [Wider S-boxes](#wider-s-boxes).
- `pbox[i]` — bit `i` of the state moves to position `pbox[i]`; must be a permutation
  of 0..63. Bit 0 is the least significant bit.
- `key_schedule` — `present80`, `present128`, or `independent`. The two PRESENT
  schedules reuse the variant's own S-box, so changing the S-box changes the key
  schedule too. `independent` takes `(rounds + 1) * 64` bits of key material and uses
  them directly, one 64-bit round key each — the assumption the differential model
  makes anyway, here made explicit.

The linear layer does not have to be a permutation. Replace `pbox` with `linear`
to get a general GF(2)-linear map — exactly one of the two must be present:

```json
{ "linear": { "type": "lin444", "word_bits": 16, "c0": [0, 1, 3] } }
```

`lin444` is the XOR-and-rotate layer from ShiftGen2's `lin444_r1`: the state is read
as four 16-bit words and each word absorbs three rotations of the others, chained so
that later words see the already-updated earlier ones. It is unitriangular over
GF(2), so it is invertible for **every** `c0` and its inverse is the same four lines
run bottom-up at identical cost. Rotation constants come from
`tools/shiftgen_present.c` (see below).

Internally both kinds are flattened to the same 64-column matrix — `lin_col[i]` is
what input bit `i` contributes to the output — so the reference and table
implementations need one code path for both. A bit permutation is just the case
where every column has a single bit set.

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
| `present-80-lin444-297`, `present-80-lin444-013` | pLayer replaced by `lin444`, 192 XORs/round | what does a non-permutation linear layer cost? |
| `present-80-lin444-1-15-13` | `lin444` with constants in arithmetic progression, 160 XORs/round | does a cheaper-to-evaluate triple pay for itself? |
| `present-80-lin444-213` | `lin444` with `c2 = c0+c1`, 144 XORs/round encrypting | the cheapest tier there is — is fewer XORs less work? |
| `present-80-lin444-013-r16`, `present-80-lin444-297-r18` | the above, cut to the round count that matches PRESENT's proven margin | does a stronger layer pay for itself once it buys fewer rounds? |
| `present-80-sbox-opt1/2` | alternative optimal S-box | differential uniformity 4, linearity 8, same as PRESENT's |
| `present-80-sbox-weak1/2` | differential uniformity 8 | one active S-box can now cost as little as one bit |
| `cipher-D` | 8-bit S-box, 8 rounds, independent round keys, pLayer = the 8x8 bit transpose | an externally supplied design, put through the same pipeline unchanged |
| `cipher-D-lin444-297`, `cipher-D-lin444-1-15-13` | the above with the permutation replaced by `lin444` | a wide S-box makes a real linear layer nearly free — does it then pay for itself? |
| `cipher-D-lin444-297-aes`, `cipher-D-lin444-297-aes-r5` | the above with the AES S-box, at 8 and 5 rounds | does a *structured* wide S-box escape the gate cost that made bitslicing pointless? |

The alternative S-boxes are found by seeded search in `tools/make_variants.py`, not
copied from anywhere, so you can audit or re-run the selection.

## The implementations

| | blocks at a time | what it does |
|---|---|---|
| `ref` | 1 | one bit at a time, straight from the spec — the oracle everything else is tested against |
| `table` | 1 | sBoxLayer and linear layer fused into 8 × 256 × `uint64_t` (16 KiB), built at init |
| `table-x2/x4/x8/x16` | 2–16 | the same tables over N independent blocks, to fill the slots one latency-bound block leaves idle |
| `bitslice` | 64 | one `uint64_t` register per state bit |
| `avx2` | 256 | one `__m256i` per state bit; encryption only |
| `bitslice-bs`, `avx2-bs` | 64, 256 | the same round functions with the transposes skipped, for a caller that already holds its state bitsliced |

Fusing the linear layer into the tables works for *any* linear layer, not just a
permutation: linearity is exactly the statement that `L(x)` is the XOR of `L`
applied to each byte of `x` in isolation. So the table round stays eight lookups
XORed together whatever the layer does, and a denser layer costs nothing at run
time — the whole cost moves into the one-off table build.

Five things make the AVX2 path faster than four times the scalar bitsliced one
rather than merely four times wider:

- **The linear layer costs nothing at all, not even a move.** The scalar version
  writes the S-box output to `cur[]` and then copies `cur → alt` through the
  permutation. The AVX2 version stores each S-box result *straight to its permuted
  destination*, folding the permutation into a store that had to happen anyway. Only
  a permutation can do this; `lin444` still has to run its XOR chain.
- **Every round function is specialised on its layer as well as its S-box.** That
  store-to-permuted-destination only pays if the destinations are compile-time
  immediates; read from `v->pbox[]` it becomes a load and an indexed store, 64 of each
  per round. `tools/gen_c.py` emits one *kernel* per (circuit, layer) pair some variant
  actually uses — fewer functions than the circuit × {pbox, lin444} product it
  replaced — and the backends instantiate them from `PRESENT_KERNEL_ENC_LIST`. After
  this, PRESENT's pLayer, the identity, a rotation and a random permutation all measure
  at exactly 1.000x of each other: the permutation is genuinely free.
- **The circuits are synthesised over AVX2's actual gate set.** AVX2 has `vpand`,
  `vpor`, `vpxor` and `vpandn` but nothing for `~a|b` or `~(a^b)`, which need a
  second `vpxor` against an all-ones register. (`vpternlogd` would cover all of them
  in one instruction, but it is AVX-512.) So `tools/sbox_synth` runs a separate
  search over `{AND, OR, XOR, ANDN}` and the result is one instruction per gate.
- **The circuits are allowed to compute `S(x) ^ B`** for a constant nibble `B`. The
  layer is linear, so the state ends up off by `L(B)`, and XORing that into the next
  round key once at setup cancels it exactly — see `build_key_masks` in
  [present_core.c](src/present_core.c). Decryption's correction is `B` itself, since no
  layer sits between the circuit and the key, so the context carries two key arrays.
  This removes the two NOTs PRESENT's AVX2 circuit ended with, 17 gates down to 15, and
  helps six of the ten shipped S-boxes.
- **The 64×64 bit transpose runs on `__m256i` lanes**, transposing four groups of 64
  blocks for the price of one, and holds its working set in registers. The six
  recursive passes look like six streams through 2 KiB, but the `j = 32, 16, 8` passes
  only ever pair `a[k]` with `a[k+j]`, so all three stay inside
  `{m, m+8, …, m+56}` — eight registers — and `j = 4, 2, 1` likewise stay inside
  `{8n, …, 8n+7}`. Doing each triple with its octet resident cuts the memory traffic
  threefold.

What is left of the transposes is a **fixed 0.31 cyc/B**, measured identically on every
variant regardless of round count or layer, and independently predicted by a two-point
fit across round counts. That is 23% of PRESENT's total. The `-bs` entry points skip
them, which in counter mode is the normal case — the counters can be produced bitsliced
directly, since all but the low bits are shared between blocks.

### Circuit synthesis

The bitsliced S-box is a boolean circuit, and the circuits are **synthesised**, not
hand-written: `tools/sbox_synth.c` breadth-first searches all 65536 four-variable truth
tables for a minimum-cost circuit for each output bit. That is what makes the bitsliced
path work for a new S-box you invent, rather than only for PRESENT's.

Synthesising the four output bits independently and then eliminating common
subexpressions gives 20 gates for PRESENT's S-box. Building them **one at a time, each
output priced against what the previous ones already computed**, and trying all 24
orders, gives 17. Letting each output come out complemented if that is cheaper (above)
gives **15** — a 25% reduction for a few seconds of one-time code generation, on a
circuit that runs 16 times a round, 31 rounds deep, on every block the cipher will ever
process.

The mirror trick on the *input* side — synthesising `S(x ^ a)` and folding `a` into the
round key, which is equally free — was implemented and measured to buy **nothing**: all
16 choices of `a` give an identical gate count on all ten shipped S-boxes on both
backends. The negative result is recorded in `tools/sbox_synth.c` rather than the lever
being left in.

#### Wider S-boxes

None of that scales to eight bits: 2^256 candidate output functions, against 65536.
`tools/sbox_synth8.py` is a different algorithm for the same job — build a shared
reduced ordered BDD over the eight output bit functions and turn each node into a 2:1
multiplexer, three gates in general and one when a branch is constant. Only the BDD
construction is heuristic; **all 8! = 40320 variable orders** are tried and the
cheapest kept.

It works, and the answer is that you should not do it:

| | PRESENT (4-bit) | cipher-D (8-bit) |
|---|---|---|
| gates per S-box | 15 (proven minimal) | 1107 (heuristic) |
| gates per state bit | 3.75 | 138 |
| fastest implementation | `avx2-bs`, 1.02 cyc/B | `table-x8`, 2.47 cyc/B |
| bitsliced vs table | bitslice wins by 8.4x | table wins by 2.8x |

Bitslicing buys a free bit permutation and pays for it in S-box gates. At four bits
that is the trade of the century; at eight it inverts, and the cipher's constant-time
path becomes its slow one. Both 8-bit circuits are checked against the reference
implementation in `tests/test_impls`, encryption, decryption and round-trip, on both
backends. Details in [docs/cipher-D.md](docs/cipher-D.md).

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
12-round search on every permutation variant and a 4-round search on the `lin444`
ones, which are far more expensive to solve:

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

**Branch number 3 saves an 8-bit design too, and it is the only thing that does.**
`cipher-D` is an externally supplied variant: 8-bit S-box, 8 rounds, and a linear layer
that is the 8x8 bit transpose. Its S-box has differential uniformity 4 *and* branch
number 3 — unusual at eight bits, and more than AES's S-box has — and that alone holds
the 8-round bound at 2^-77, exactly searched. Without it the design would fall over,
since its linear layer is a bit permutation with branch number 2 and there is nothing
else in the round to make up the difference. Even so the margin is one round: 7 rounds
already sit at exactly weight 64. See [docs/cipher-D.md](docs/cipher-D.md).

**A wide S-box makes a real linear layer free, and then it pays for itself twice
over.** `lin444` costs PRESENT 1.77-1.85x on the bitsliced paths, because 192 XORs a
round against a 240-gate S-box layer nearly doubles the round. cipher-D's round is
8856 gates, so the same 192 XORs are 2.2% of it — measured at +2-6% bitsliced, and
free on the table paths where the layer is fused into the lookup. What it buys is
large: `cipher-D-lin444-297` proves 2^-64 in **4 rounds** where the permutation needs
7, taking the margin from 1.14x to **2.00x** — past PRESENT's own 1.94x — while its
fastest implementation stays at 2.14x PRESENT's best against the permutation's 2.17x.
The permutation, not the S-box, was cipher-D's weak half, and it is the half that is
free to replace.

**PRESENT's designed permutation beats a random one.** `present-80-randperm-p` reaches
3.75 weight per round against 4.33 — interestingly with *fewer* active S-boxes (17 vs
24 at 12 rounds) but more expensive ones, netting out worse.

**Replacing the permutation with a linear layer buys a lot of security margin, and the
selection heuristics did not predict which constants win.** Minimum active S-boxes and
trail weights over 1-4 rounds:

| rounds | `present-80` | `lin444-213` | `lin444-013` | `lin444-1-15-13` | `lin444-297` |
|---|---|---|---|---|---|
| 2 | 2 / 4 | 4 / 8 | 5 / 10 | 5 / 10 | **6 / 12** |
| 3 | 4 / 8 | 8 / 16 | 9 / 20 | 10 / 21 | **13 / 29** |
| 4 | 6 / 12 | 11 / 28 | 14 / 32 | 16 / 36 | ≥19 / ≥38 |
| 31-round bound | 2^-123 | 2^-196 | 2^-224 | 2^-252 | **2^-290** |

`lin444-297`'s round-4 search hit its 1800s budget and returned a bound rather than an
exact value; its 2^-290 comes from ten disjoint 3-round windows at weight 29.

Two selection criteria were wrong. `bmin`, the single-bit bound on differential branch
number, ranks `(0,1,3)` and `(1,15,13)` at 7 above `(2,9,7)` at 6 — but `(2,9,7)` has
by far the best actual resistance. A single-bit bound says nothing useful about
multi-round trails. The ShiftGen2 composite score picks the winner correctly but
reverses second and third place. And `(1,15,13)`, chosen purely because its constants
make the layer cheaper to evaluate, beats `(0,1,3)`, which gives up nothing on paper.
`(2,1,3)`, the best triple of the cheapest cost tier, comes last on both axes — it is
neither faster nor stronger than `(1,15,13)`.
The full write-up is in [docs/lin444-experiment.md](docs/lin444-experiment.md).

**Which implementation you pick matters far more than which variant you pick.**
Pinned run on an i9-14900HX, `present-80`, cyc/B (lower is better):

| impl | blocks | cyc/B | MB/s | vs `table` |
|---|---|---|---|---|
| `ref` | 1 | 1537.43 | 1.6 | 0.02x |
| `table` | 1 | 23.86 | 101.4 | 1.00x |
| `table-x2` | 2 | 14.79 | 163.6 | 1.61x |
| `table-x4` | 4 | 9.61 | 251.8 | 2.48x |
| `table-x8` | 8 | **8.88** | 272.6 | **2.69x** |
| `table-x16` | 16 | 9.60 | 252.0 | 2.49x |
| `bitslice` | 64 | 5.19 | 466.4 | 4.60x |
| `bitslice-bs` | 64 | 3.04 | 796.3 | 7.85x |
| `avx2` | 256 | **1.30** | **1866.3** | **18.4x** |
| `avx2-bs` | 256 | **1.02** | **2360.6** | **23.3x** |

A single block through the table implementation is **latency**-bound, not
throughput-bound: each round is eight lookups that all index the current state, so
the next round cannot start until this round's XOR tree retires. Interleaving
independent blocks fills those idle slots and wins 2.7x for no new tables and no new
per-variant code — the same effect that dominates the QalqanSpeed work on a
structurally similar cipher. Past eight lanes it reverses, as 16 live states plus
their in-flight loads stop fitting the register file.

The AVX2 bitsliced path is 18x the table baseline and 4x the scalar bitsliced one, and
it is **at its roofline**: 16 S-boxes × (15 gates + 4 key XORs) = 304 vector ALU ops
per round, over three vector ALU ports, is ~101 cycles/round against 104 measured on
`avx2-bs`. The evidence that it really is ALU-bound rather than that being a just-so
story: cutting the S-box from 22 gates to 17 moved the AVX2 path by 11% and the scalar
bitsliced path by nothing at all — the scalar version keeps 64 bit-planes in an array
with 16 general-purpose registers, so it is load/store-bound and does not care what the
gate count is.

### Making the comparison fair

**The first version of this comparison was rigged, unintentionally.** `lin444`'s
rotation constants had been specialised into compile-time immediates; PRESENT's
permutation had not, and was still being read from `v->pbox[]` at run time. Optimising
the baseline afterwards — kernel specialisation, free output complements, the
register-resident transpose, no copy-back on an odd round count — was worth **20–31% to
the permutation variants and 8–11% to the `lin444` ones**:

| variant | before | after | gain |
|---|---|---|---|
| `present-80` | 1.88 | 1.36 | 27.7% |
| `present-80-rotate-p` | 1.82 | 1.34 | 26.4% |
| `present-80-lin444-013` | 2.75 | 2.53 | 8.0% |
| `present-80-lin444-1-15-13` | 2.63 | 2.41 | 8.4% |
| `present-80-lin444-297` | 2.72 | 2.48 | 8.8% |

That ~20-point spread is the size of the unfairness, and it was enough to flip the
headline: `lin444` used to break even against PRESENT at equal proven margin, and now
loses by 9–16%. **The order in which optimisation effort is spent is not neutral.** A
speed comparison between a cipher and a modification of it is a claim about two
*implementations* before it is a claim about two ciphers.

Two habits fell out of this. `tools/compare.sh` measures every variant inside one pinned
process and reports each as a ratio to `present-80` from that same process, because the
cyc/B figures are nominal TSC ticks and a min-across-runs estimator just selects whichever
run boosted hardest. And every optimisation is A/B'd against a round-robin rebuild of both
configurations, so no build can be favoured by frequency drift.

**With both sides specialised, replacing the permutation with a `lin444` linear layer is
free on every table path and costs 1.8x on AVX2** (`tools/compare.sh`, 11 reps, ratio
against full-round `present-80` measured in the same process):

| | table | table-x4 | bitslice | avx2 | avx2-bs | vs `present-80` |
|---|---|---|---|---|---|---|
| `present-80` | 23.86 | 9.61 | 5.19 | 1.34 | 1.03 | 1.000x |
| `present-80-lin444-1-15-13` | 24.39 | 9.61 | 9.36 | 2.41 | 2.06 | **1.769x** |
| `present-80-lin444-297` | 23.20 | 9.80 | 7.77 | 2.45 | 2.13 | 1.821x |
| `present-80-lin444-213` | 23.74 | 9.66 | 11.29 | 2.45 | 2.12 | 1.821x |
| `present-80-lin444-013` | 24.28 | 9.79 | 7.72 | 2.49 | 2.17 | 1.851x |

On the round function alone (`avx2-bs`) the penalty is a clean **2.0x**: one `lin444`
round costs twice a PRESENT round. The all-in `avx2` figure is lower only because the
fixed 0.31 cyc/B of transposes dilutes it.

The table columns are within run-to-run noise, for the linearity reason above. The
bitsliced ones are not, and the gap is structural: PRESENT's pLayer issues no
arithmetic at all, while `lin444` costs three XORs per state bit — 192 XORs per round
on top of 64 key XORs and 16 S-box circuits. Rotation itself is free in bitsliced
form, since `ROTL` is just reading a different register index, and 192 rather than
the ~560 a flattened 64×64 matrix would need, because the chained form lets each
output word reuse the ones computed before it.

### Spending the margin instead: equal-margin round reduction

A stronger layer that costs more per round can still win overall, by needing fewer
rounds. PRESENT runs 31 and proves 2^-64 in 16, a margin of 1.94x; matching that ratio,
`(0,1,3)` needs 16 rounds and `(2,9,7)` needs 18.

| variant | rounds | proven margin | table | table-x4 | avx2 | vs `present-80` |
|---|---|---|---|---|---|---|
| `present-80` | 31 | 1.94x | 23.86 | 9.61 | 1.34 | 1.000x |
| `present-80-lin444-013-r16` | 16 | 2.00x | 10.87 | 5.13 | 1.46 | **1.090x** |
| `present-80-lin444-297-r18` | 18 | 2.00x | 13.14 | 6.18 | 1.57 | **1.164x** |

So the answer depends entirely on the deployment target: on the table paths the round
cut is pure profit, 2.2x and 1.8x, because those paths fuse the layer into a lookup and
charge nothing for it. On a bitsliced vector implementation it is not a win at all — a
`lin444` round costs 2.0x a PRESENT round, cutting 31 rounds to 16 very nearly cancels
that, and then the fixed transpose cost, which does not shrink when rounds are cut,
decides it against `lin444`.

This trade is differential-only. `rounds@64` is what the search *proves* about single
characteristics; cutting to 16 rounds spends margin that also has to cover differential
clustering, linear cryptanalysis, algebraic and related-key attacks, none of which this
harness measures — and the key schedule is unchanged, having been designed around
PRESENT's pLayer.

### What makes the layer fast, in the order it turned out to matter

*Rotation is free only if the constant is a literal.* `BS(w, k - c0)` folds to a
register number when `c0` is known at compile time, and expands to a subtract, an add
and a mask when it is read from the variant descriptor. Left generic, the AVX2 layer
issued **887 instructions of which 548 were scalar address arithmetic**, against 160
vector XORs of actual work — it was limited by index computation, not by anything the
layer exists to do. `tools/gen_c.py` emits one specialised layer body per rotation
triple any variant uses, with the constants baked in; the specialised layer is **334
instructions**. This is the same X-macro treatment the S-box circuits already got, and
it was worth 25% of scalar bitsliced throughput and 13% of AVX2 — and it is exactly the
treatment the permutation was *not* getting, which is what made the comparison unfair.

*The XOR count is not a constant — it depends on the rotation constants.* Two output
words can share a subexpression only when the same pair of operands appears in both
at the same relative rotation:

```
o0 : d0  R(d1,a)  R(d2,b)  R(d3,c)
o1 : d1  R(d2,a)  R(d3,b)  R(o0,c)
o2 : d2  R(d3,a)  R(o0,b)  R(o1,c)
o3 : d3  R(o0,a)  R(o1,b)  R(o2,c)
```

Reading off every repeated pair rather than pattern-matching one gives **three
independent conditions**, which overlap only in the geometric family `(a,2a,3a)`:

| condition | shared pairs | XOR/round | triples |
|---|---|---|---|
| `c = a+b` | `(d1,d3)`, `(d2,o0)`, `(d3,o1)` | **144** | 256 |
| `b = 2a` | `(d1,d2)`, `(d3,o0)` | 160 | 480 combined |
| `c-b = b-a` (progression) | `(d2,d3)`, `(o0,o1)` | 160 | |
| none of them | — | 192 | 3360 |

Decryption's conditions are the **mirror image** (`a = b+c`, `b = 2c`), because the
inverse recovers the last word first, so a triple is normally cheap in one direction
only. `tools/shiftgen_present.c` reports both costs alongside the diffusion metrics.

**This corrects an earlier error.** The first cost rule recognised only the arithmetic
progression, and so priced all 256 triples of the cheapest family at 192 — hiding the
entire 144 tier. `analysis/present_sat/slp.py` now *enumerates* the sharings instead of
naming them, emits the resulting straight-line program as an IR, and `tools/gen_c.py`
compiles that same IR into C. The cost model and the compiled layer therefore cannot
disagree, and every program is checked against `lin444` on all 64 basis vectors before
it is emitted — over all 4096 triples in both directions, in
`analysis/tests/test_linear.py`.

One gap remains, deliberately: the geometric family `(a,2a,3a)` admits reuse of whole
chains and reaches 128, which the pair-only search does not find. Every triple in that
family has two-round avalanche `a2 = 7.75` against one-round `a1 = 7.25` — a second
round barely diffuses further than the first — so no usable constants live there and no
code path is implemented for it.

*Fewer operations is not less work.* A shared temporary is 16 words that cannot stay in
registers — the state is 2 KiB against sixteen YMM registers — so it trades 16 XORs for
16 stores, and stores issue on two ports against three for XORs:

| `c0` | form | XORs | instructions | stores | avx2 cyc/B |
|---|---|---|---|---|---|
| `(2,9,7)` | general | 192 | 391 | 97 | 2.45 |
| `(0,1,3)` | general | 192 | 395 | 98 | 2.49 |
| `(1,15,13)` | progression | 160 | 334 | 98 | **2.41** |
| `(2,1,3)` | `c=a+b` | **144** | 341 | 116 | 2.45 |

Instruction count, not XOR count, tracks runtime — and the scalar `bitslice` column
ranks the same four triples completely differently (`(2,1,3)` is *worst* there, 11.29),
because sixteen general registers cannot hold the temporaries at all. Which form wins
depends on the backend. Capping the generator at two temporaries for `(2,1,3)` was
tried and came out worse (355 instructions), so nothing ships with the cap set.

*Two things that did not work, measured rather than assumed.* Before the constants
were specialised, cutting the layer from 192 to 160 XORs moved AVX2 by 0% — and so did
fusing the dependent loops to save 32 of its 256 loads. Neither XORs nor loads were
the binding resource; the address arithmetic was. Reading the instruction mix
(`objdump` counts above) found in one step what two rounds of plausible optimisation
had missed.

The penalty is 1.77–1.85x on AVX2 and 1.49–2.18x on scalar bitslice — tightly clustered
on the vector path, wildly spread on the scalar one, because on AVX2 the state spills
either way and only the instruction count matters, while on scalar the deciding factor
is how many temporaries the triple needs against sixteen general registers. This is the
roofline story from the other side: once the S-box is cheap and the permutation is
folded into a store, the linear layer is most of what is left.

The reference implementation shows no difference between the layers at all, which is
an artefact of the oracle rather than a result: it drives both from the same
64-column matrix, one column per set input bit, so both cost 64 iterations.

**The S-box only affects speed in the bitsliced implementations**, and only weakly.
On AVX2, `present-80-sbox-weak2` synthesises to 8 gates against PRESENT's 15 — nearly
half — and buys 1.05 vs 1.30 cyc/B, about 19%. The table implementations are within
noise across every variant, because a lookup table does not care what is in it. So on
any table path a stronger S-box is free; on the bitsliced paths it costs a little.

Putting that against the analysis: `present-80-sbox-weak2` gives up 56% of the
security margin (0.89x vs 1.94x) to buy 19% on one implementation and nothing on the
rest. The permutation choice costs nothing on any path — only replacing it with a
non-permutation does.

## Reading the speed numbers

- **cyc/B** is *nominal* TSC ticks per plaintext byte. On modern x86 the TSC runs at
  a fixed rate rather than the core clock, so treat it as a stable relative measure,
  not as true core cycles. **MB/s** is measured against `CLOCK_MONOTONIC` and has no
  such caveat.
- **Do not take a minimum across runs.** Because the ticks are nominal, a run in which
  the core boosted higher does more work per tick and so reports *fewer* ticks per byte
  for the same code; a min-of-mins estimator selects whichever run boosted hardest, not
  the least noisy one. It produced impossible numbers here (a fixed transpose cost of
  0.06 cyc/B) before it was abandoned. Use `tools/compare.sh [impl] [reps]`, which
  measures every variant inside one pinned process and reports each as a **ratio** to
  `present-80` from that same process — the ratio is what the frequency cancels out of.
- Rows in `./build/bench` are ordered fastest-first on purpose. The ~1500 cyc/B `ref`
  row heats the core, and running it first cost the vector rows about 6%.
- The multi-block implementations need that many **independent** blocks in flight.
  Any parallel mode supplies them (CTR, ECB over a buffer, parallel nonces); CBC
  encryption does not. `avx2` needs 256 blocks (2 KiB) and is encryption-only, so it
  is a throughput kernel, not a general-purpose entry point. `ref` and `table` are the
  honest numbers when you have one block and must finish it before you get the next.
- The `-bs` rows skip the two transposes, which are a fixed 0.31 cyc/B — 23% of
  `present-80`. They are the honest numbers for a caller that keeps its state
  bitsliced, as counter mode can.
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
src/present_avx2.c   AVX2 bitsliced kernel, 256 blocks at a time
bench/               speed tests
tests/               C tests: official vectors, implementation equivalence
analysis/present_sat/ CNF construction, differential model, search, reporting
analysis/tests/      Python tests: encodings checked against brute force
analysis/present_sat/slp.py  the layer's straight-line program and its true XOR cost,
                          enumerated rather than pattern-matched; gen_c.py compiles
                          this same IR, so cost model and code cannot disagree
tools/               variant generation, C generation, S-box circuit synthesis
tools/sbox_synth.c   4-bit circuits: exhaustive, so the result is minimal
tools/sbox_synth8.py 8-bit circuits: shared BDD to a multiplexer network, over all
                          8! variable orders
tools/shiftgen_present.c  rotation-constant search for the lin444 layer,
                          reporting each candidate's enc/dec bitsliced XOR cost
tools/known_circuits.py  hand-derived bitslice circuits for S-boxes that have a
                          published one, used in place of BDD synthesis
tools/compare.sh     variant-vs-baseline ratios inside one pinned process
bench/wide_bench.c   the 128-bit block ciphers (real AES, AES-lin444), standalone but
                          on bench_main.c's measurement protocol: T-tables and an AVX2
                          bitslice, no AES-NI and no GFNI
analysis/prove_bound.py  "is every r-round characteristic at least weight W?" in one
                          solver call, where analyze needs a ladder of them
analysis/dump_cnf.py  writes that formula to DIMACS instead of solving it, so one
                          model can be raced across several external solvers
analysis/check_witness.py  replays such a solver's SAT model against the cipher, so a
                          witness found outside the pipeline is held to the same check
ShiftGen2/           the original 128-bit ShiftGen2 utility, plus POSIX shims
third_party/         SAT solver, built by tools/get_solver.sh
results/             benchmark and analysis output
results/bound-search/  the one rounds@64 that a single solver call could not settle:
                          the solver bake-off, the 31-thread portfolio, both witnesses
docs/lin444-experiment.md  the lin444 experiment: constants, speed, strength
docs/cipher-D.md     an externally supplied 8-bit-S-box design put through the same
                          pipeline: speed, gate count, exact 8-round bound, clustering
docs/cipher-D-lin444.md  replacing that design's permutation with lin444: free on its
                          fastest path, and it nearly doubles the proven margin
docs/cipher-D-lin444-297-aes.md  then giving it the AES S-box: 1107 gates -> 132, so
                          the fastest path becomes bitsliced and the cost 2.1x -> 1.3x
docs/speed-at-equal-security.md  all of the above plus real AES, each cut to the same
                          proven differential margin, in cyc/B -- the fair comparison
docs/platform-estimate.md  which variant should win on ARM / AVX-512 / 8-bit /
                          hardware -- estimated, not measured
docs/superpowers/specs/  design document
```

## Limits

- Bounds here are on **single characteristics**. A differential can cluster many
  characteristics with the same input and output difference, and their probabilities
  add; `analysis/cli.py cluster` measures that for a given difference pair. It matters:
  for cipher-D's best 8-round pair, clustering is worth about 7 bits over the single
  best characteristic. It also only ever examines *one* pair — the most probable
  differential need not contain the most probable characteristic.
- Nothing here addresses linear, algebraic, integral or related-key attacks, and a
  bound on characteristic probability is not by itself a proof of resistance to
  differential cryptanalysis.
- **The differential model encodes any GF(2)-linear layer**, but a permutation is the
  cheap case: it contributes zero clauses. A general layer is encoded from the same column
  form the implementations use: output bit `i` of the layer is the XOR of the S-box
  output bits in row `i`, built as a Tseitin chain. A permutation has one entry per
  row, so the chain degenerates to aliasing and costs nothing — the classical
  PRESENT encoding is recovered rather than special-cased. `lin444` rows hold 8.75
  entries on average, so the layer costs ~500 XOR gates and ~2000 clauses per round.
  Every satisfying assignment is replayed against the cipher before it is believed
  (`model.verify_solution`): each S-box transition must appear in the DDT with the
  weight the model claims, and the difference after the layer must match what the
  layer's own column form produces. A mis-encoded layer yields a *satisfiable*
  formula for the wrong cipher — a bound that is too good and looks fine — so this
  check is the thing standing between a refactor and a confidently wrong number.
- S-boxes whose DDT entries are not powers of two get weights rounded *down*, which
  keeps the bound valid (the real trail can only be less probable) but no longer
  tight. `analysis/cli.py sboxes` shows which variants are exact.
- This is analysis code. It is not constant-time and is not meant for protecting
  anything.
