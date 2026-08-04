# Replacing PRESENT's pLayer with the `lin444` XOR-rotate layer

What happens to speed and to differential strength when PRESENT's bit permutation is
replaced by a general GF(2)-linear layer. Every number here is reproducible from this
repository; the commands are given at the end.

Hardware: Intel i9-14900HX, AVX2 + GFNI + VAES, **no** AVX-512, L1d 48 KiB, L2 2 MiB
per core. SAT solver CaDiCaL 3.0.1, single-threaded.

**Measurement protocol.** Cycle counts are nominal TSC ticks, not core clock cycles, so
a run in which the core boosts higher reports *fewer* ticks per byte for the same work.
Taking a minimum across runs does not remove that noise, it selects whichever run
boosted hardest. `tools/compare.sh` therefore measures every variant inside one pinned
process and reports each as a ratio to `present-80` measured in that same process, over
eleven repetitions. The ratios are what to trust; absolute columns are medians and are
only as good as the machine was quiet.

> **This document was rewritten after the baseline was optimised.** An earlier version
> concluded that `lin444` broke even against PRESENT on AVX2 at equal proven margin.
> That conclusion was an artefact of comparing a specialised `lin444` against an
> unspecialised pLayer. See §3.2 and §5.

---

## 1. The layer

`lin444` is ShiftGen2's `lin444_r1`. The 64-bit state is read as four 16-bit words and
each word absorbs three rotations of the others, chained so later words see the
already-updated earlier ones:

```
o0 = d0 ^ R(d1,c0) ^ R(d2,c1) ^ R(d3,c2)
o1 = d1 ^ R(d2,c0) ^ R(d3,c1) ^ R(o0,c2)
o2 = d2 ^ R(d3,c0) ^ R(o0,c1) ^ R(o1,c2)
o3 = d3 ^ R(o0,c0) ^ R(o1,c1) ^ R(o2,c2)
```

Each line introduces exactly one new unknown given the lines above it, so the map is
**unitriangular over GF(2)**: invertible for *every* choice of `c0`, with no search
needed to avoid singular constants, and an inverse obtained by undoing the four lines
bottom-up.

One input bit reaches 8.75 output bits on average, against exactly one for a bit
permutation.

### Choosing the rotation constants

`tools/shiftgen_present.c` is a PRESENT-geometry port of ShiftGen2's search. The
original scores a 128-bit state of four 32-bit words counting active *bytes* (8-bit
S-boxes); PRESENT is 64-bit with 4-bit nibbles, so the search space, the diffusion
counts and the branch counts all differ. The port changes only the geometry and sweeps
all 64 single-bit input differences rather than the original's 32 of 128.

Metrics, averaged over all single-bit input differences: `a1`/`a2` are output bits
flipped after 1 and 2 rounds, `b1`/`b2` active nibbles after 1 and 2 rounds, and `bmin`
is the minimum active nibbles after one round plus one for the active input nibble — a
single-bit upper bound on the differential branch number.

Four triples were carried forward:

| `c0` | variant | why chosen | score | `bmin` | XOR/round enc | dec |
|---|---|---|---|---|---|---|
| `(2,9,7)` | `present-80-lin444-297` | highest score | 13.19 | 6 | 192 | 192 |
| `(0,1,3)` | `present-80-lin444-013` | best `bmin` | 13.11 | 7 | 192 | 192 |
| `(1,15,13)` | `present-80-lin444-1-15-13` | best arithmetic progression | 11.66 | 7 | 160 | 160 |
| `(2,1,3)` | `present-80-lin444-213` | best with `c2 = c0+c1` | 12.25 | 7 | **144** | 192 |

---

## 2. The XOR cost is a function of the constants

Written out plainly each output word is a four-term XOR, so the layer costs 3 XORs per
state bit = 192 per round in bitsliced form. Two output words can share a subexpression
only when the same pair of operands appears in both at the same *relative* rotation:

```
o0 : d0  R(d1,a)  R(d2,b)  R(d3,c)
o1 : d1  R(d2,a)  R(d3,b)  R(o0,c)
o2 : d2  R(d3,a)  R(o0,b)  R(o1,c)
o3 : d3  R(o0,a)  R(o1,b)  R(o2,c)
```

Reading off every repeated pair rather than pattern-matching one gives **three
independent conditions**, which overlap only in the geometric family `(a,2a,3a)`:

| condition | shared pairs | XOR/round |
|---|---|---|
| `c = a+b` | `(d1,d3)`, `(d2,o0)`, `(d3,o1)` | **144** |
| `b = 2a` | `(d1,d2)`, `(d3,o0)` | 160 |
| `c-b = b-a` (progression) | `(d2,d3)`, `(o0,o1)` | 160 |
| none of them | — | 192 |

Over all 4096 triples that is 256 at 144, 480 at 160 and 3360 at 192 — the 160 tier
being what is left of the two two-sharing families once the ones that also satisfy
`c = a+b` have been promoted. Decryption's conditions are the **mirror image**
(`a = b+c`, `b = 2c`), because the inverse recovers the last word first, so a triple is
normally cheap in one direction only. `(2,1,3)` is 144 encrypting and 192 decrypting.

**This corrects an earlier error.** The first cost rule recognised only the arithmetic
progression, and so priced all 256 triples of the cheapest family at 192 — hiding the
entire 144 tier. `analysis/present_sat/slp.py` now enumerates the sharings instead of
naming them, emits the resulting straight-line program as an IR, and `tools/gen_c.py`
compiles that same IR into C. The cost model and the compiled layer therefore cannot
disagree, and every program is checked against `lin444` on all 64 basis vectors before
it is emitted. `analysis/tests/test_linear.py` runs that check over all 4096 triples in
both directions, and `tests/test_variants.c` checks the C closed form against the counts
the Python enumeration actually produced.

A gap remains, deliberately: the geometric family `(a,2a,3a)` admits reuse of whole
chains and reaches 128, which the pair-only search does not find. Every triple in that
family has two-round avalanche `a2 = 7.75` against one-round `a1 = 7.25` — a second
round barely diffuses further than the first — so no usable constants live there.

### The 144 tier is real and buys nothing

Fewer XORs is not less work. A shared temporary is 16 words that cannot stay in
registers — the state is 2 KiB against sixteen YMM registers — so it trades 16 XORs for
16 stores, and stores issue on two ports against three for XORs. Measured on AVX2:

| `c0` | form | XORs | instructions | stores | cyc/B |
|---|---|---|---|---|---|
| `(2,9,7)` | general | 192 | 391 | 97 | 2.45 |
| `(0,1,3)` | general | 192 | 395 | 98 | 2.49 |
| `(1,15,13)` | progression | 160 | 334 | 98 | **2.41** |
| `(2,1,3)` | `c=a+b` | **144** | 341 | 116 | 2.45 |

Instruction count, not XOR count, tracks runtime. Capping the generator at two
temporaries for `(2,1,3)` was tried and came out *worse* (355 instructions), so nothing
ships with the cap set.

---

## 3. Speed

Six measured paths, all validated against the reference on every variant
(`tests/test_impls.c`, 8753 checks).

| impl | blocks | how |
|---|---|---|
| `ref` | 1 | textbook, one column XOR per set input bit |
| `table` | 1 | S-box and linear layer fused into 8 x 256 x u64 (16 KiB) |
| `table-x4` | 4 | the same tables, four independent blocks interleaved |
| `bitslice` | 64 | one `uint64_t` per state bit, synthesised S-box circuit |
| `avx2` | 256 | one `__m256i` per state bit |
| `avx2-bs` | 256 | the same round function, state already transposed |

Table fusion works for *any* linear layer, not just a permutation: `L` is linear, so
`L(x)` is the XOR of `L` applied to each byte of `x` in isolation. That is why the table
columns are flat.

### 3.1 Where the time goes, and what was removed

Four optimisations were applied. `present-80` on AVX2, 31 rounds, cumulative
(round-robin builds so no build can be favoured by frequency drift, medians of 11):

| build | cyc/B | delta |
|---|---|---|
| baseline (layer constants already specialised) | 1.93 | — |
| \+ free S-box output complements | 1.79 | −7.3% |
| \+ pLayer folded into the S-box store as immediates | 1.60 | −10.6% |
| \+ no copy-back on an odd round count | 1.59 | −0.6% |
| \+ register-resident 64x64 transpose | **1.42** | −10.7% |

**Free S-box output complements.** A circuit may compute `S(x) ^ B` for a constant
nibble `B`: the following layer is linear, so the state ends up off by `L(B)`, and
XORing that into the next round key once at setup cancels it exactly. Decryption's
correction is `B` itself, since no layer sits between the circuit and the key, so `ctx`
carries two corrected key arrays. Handing both polarities to the circuit search costs
nothing — one breadth-first search finds either — and it removes the two NOT gates
PRESENT's AVX2 circuit ends with, 17 gates down to 15. Six of the ten S-boxes in the
registry lose gates this way. The mirror trick on the *input* side, synthesising
`S(x ^ a)` and folding `a` into the round key, is equally free and was measured to buy
**nothing**: all 16 choices of `a` give an identical gate count on all ten S-boxes on
both backends.

**The pLayer folded into the store.** The S-box result is written straight to its
permuted destination, so the permutation costs not even a move. That only works with the
destinations as *immediates*; read from `v->pbox[]` it is a load and an indexed store,
64 of each per round. A round function is now specialised on the linear layer as well as
on the S-box (`PRESENT_KERNEL_ENC_LIST`), with only the (circuit, layer) pairs some
variant actually uses instantiated — fewer functions than the circuit × {pbox, lin444}
split it replaced. After this, all four permutation variants in the registry — PRESENT's
pLayer, the identity, a rotation and a random permutation — measure at exactly `1.000x`
of each other. The layer is genuinely free.

**The transpose.** Six passes each streaming 2 KiB through L1. But passes with
`j = 32, 16, 8` only ever pair `a[k]` with `a[k+j]`, so all three stay inside
`{m, m+8, ..., m+56}` — eight registers; passes with `j = 4, 2, 1` likewise stay inside
`{8n, ..., 8n+7}`. Doing each triple with its octet held in registers cuts the memory
traffic threefold, for 0.18 cyc/B.

What remains is the two transposes themselves: **0.31 cyc/B, fixed**, measured
identically (0.30–0.35) on every variant regardless of round count or layer, and
independently predicted by a two-point fit across round counts. That is 23% of
`present-80` and 13% of `lin444`. `present_encrypt_avx2_bs` skips them for a caller
holding its state bitsliced, which in counter mode is the normal case.

### 3.2 Why this section matters more than its contents

Before these changes the comparison was **not fair**. `lin444`'s rotation constants had
been specialised into immediates; PRESENT's permutation had not. Three of the four
optimisations above help a cheap round more than an expensive one, and one of them —
folding the permutation into the store — can only help a permutation at all. The result
is worth 20–31% to the permutation variants and 8–11% to the `lin444` variants:

| variant | before | after | gain |
|---|---|---|---|
| `present-80` | 1.88 | 1.36 | 27.7% |
| `present-80-rotate-p` | 1.82 | 1.34 | 26.4% |
| `present-80-lin444-013` | 2.75 | 2.53 | 8.0% |
| `present-80-lin444-1-15-13` | 2.63 | 2.41 | 8.4% |
| `present-80-lin444-297` | 2.72 | 2.48 | 8.8% |

That ~20-point spread is the size of the unfairness, and it is enough to reverse the
headline conclusion in §4b.

### 3.3 Results

`tools/compare.sh avx2`, 11 repetitions. Ratios are against full 31-round `present-80`.

| variant | table | table-x4 | bitslice | avx2 | avx2-bs | vs `present-80` |
|---|---|---|---|---|---|---|
| `present-80` | 23.86 | 9.61 | 5.19 | 1.34 | 1.03 | 1.000x |
| `present-80-lin444-1-15-13` | 24.39 | 9.61 | 9.36 | 2.41 | 2.06 | **1.769x** |
| `present-80-lin444-297` | 23.20 | 9.80 | 7.77 | 2.45 | 2.13 | 1.821x |
| `present-80-lin444-213` | 23.74 | 9.66 | 11.29 | 2.45 | 2.12 | 1.821x |
| `present-80-lin444-013` | 24.28 | 9.79 | 7.72 | 2.49 | 2.17 | 1.851x |

On the round function alone (`avx2-bs`, no transposes) the penalty is a clean **2.0x**:
one `lin444` round costs twice a PRESENT round. The all-in `avx2` figure is lower only
because the fixed transpose cost dilutes it.

The scalar `bitslice` column ranks the triples completely differently — `(2,1,3)` is
worst there at 11.29 despite having the fewest XORs — because sixteen general registers
cannot hold the temporaries and the spills cost more than the XORs saved. Which form
wins depends on the backend.

---

## 4. Differential strength

### How the layer is encoded

Difference propagation is the clean case: key addition is transparent to differences,
and a linear layer passes a difference through by the same matrix the data uses — no
probability, just wiring and XORs. Only the S-box layer constrains anything
probabilistically.

The layer is encoded from the **column form** every variant already carries. Output bit
`i` is the XOR of the S-box output bits in row `i`, built as a Tseitin chain (one fresh
variable and four clauses per binary XOR). A bit permutation has exactly one entry per
row, so the chain degenerates to aliasing and the layer contributes **zero variables and
zero clauses** — the classical PRESENT encoding is recovered rather than special-cased.
`lin444` rows hold 8.75 entries on average, so the layer costs ~500 XOR gates and ~2000
clauses per round.

**Every satisfying assignment is replayed against the cipher before it is believed**
(`model.verify_solution`): each S-box transition must appear in the DDT with the weight
the model claims, the unary weight encoding must be a well-formed prefix, and the
difference after the layer must equal what the layer's own column form produces. This
matters more than it might appear — a mis-encoded layer does not make the formula
unsatisfiable, it makes it describe a *different cipher* and return a bound that is too
good and looks perfectly fine.

Regression check: vanilla PRESENT reproduces the published sequence of minimum active
S-boxes (1, 2, 4, 6, 10, 12, 14, 16, 18, 20, 22, 24) and its 2-round model is still
exactly 224 variables and 1665 clauses.

### Results

Minimum active S-boxes / minimum trail weight. Probability of the best single
characteristic is `2^-weight`.

| rounds | `present-80` | `lin444-213` | `lin444-013` | `lin444-1-15-13` | `lin444-297` |
|---|---|---|---|---|---|
| 1 | 1 / 2 | 1 / 2 | 1 / 2 | 1 / 2 | 1 / 2 |
| 2 | 2 / 4 | 4 / 8 | 5 / 10 | 5 / 10 | **6 / 12** |
| 3 | 4 / 8 | 8 / 16 | 9 / 20 | 10 / 21 | **13 / 29** |
| 4 | 6 / 12 | 11 / 28 | 14 / 32 | 16 / 36 | >=19 / >=38 |
| **31-round bound** | 2^-123 | 2^-196 | 2^-224 | 2^-252 | **2^-290** |
| `rounds@64` | 16 | 12 | 8 | 8 | 9 |
| margin | 1.94x | 2.58x | 3.88x | 3.88x | 3.44x |

The 31-round bound is not extrapolation: a characteristic over `m*r` rounds restricts to
a valid characteristic on each of its `m` disjoint `r`-round windows, so its weight is
at least `m * W(r)`. PRESENT's 2^-123 is three 10-round windows at weight 41;
`lin444-297`'s 2^-290 is ten 3-round windows at weight 29.

`-297`'s round-4 search exhausted its 1800s budget and returned a bound, not an exact
value. That is the only reason its `rounds@64` reads 9 against `-013`'s 8 — that metric
can use exact rows only. The difference is search depth, not cipher strength.

Solve times, single-threaded CaDiCaL:

| variant | r=3 | r=4 |
|---|---|---|
| `present-80` | 0.02s | 0.08s |
| `lin444-213` | 3.5s | 122s |
| `lin444-013` | 17.3s | 264s |
| `lin444-1-15-13` | 24.3s | 1372s |
| `lin444-297` | 896s | >3220s (unresolved) |

---

## 4b. Spending the margin: equal-margin round reduction

A stronger layer that costs more per round can still win overall, by needing fewer
rounds. PRESENT runs 31 rounds and proves 2^-64 in 16, a margin of 1.94x. Matching that
ratio, `(0,1,3)` needs 16 rounds and `(2,9,7)` needs 18.

| variant | rounds | proven margin | table | table-x4 | bitslice | avx2 | vs `present-80` |
|---|---|---|---|---|---|---|---|
| `present-80` | 31 | 1.94x | 23.86 | 9.61 | 5.19 | 1.34 | 1.000x |
| `present-80-lin444-013-r16` | 16 | 2.00x | 10.87 | 5.13 | 4.84 | 1.46 | **1.090x** |
| `present-80-lin444-297-r18` | 18 | 2.00x | 13.14 | 6.18 | 5.37 | 1.57 | **1.164x** |

**On AVX2, at equal proven differential margin, `lin444` is still 9–16% slower than
PRESENT.** The earlier version of this document reported break-even here; that was
measured against a baseline whose permutation was read from memory and whose S-box
carried two removable NOT gates.

The arithmetic: a `lin444` round costs 2.0x a PRESENT round, so cutting 31 rounds to 16
(a 1.94x saving) very nearly cancels — and then the fixed 0.31 cyc/B of transposes,
which does not shrink when rounds are cut, decides it against `lin444`.

On the table paths the round cut is pure profit — 2.2x and 1.8x — because those paths
fuse the layer into a lookup and charge nothing for it at all. If the deployment target
is a single-block table implementation, `lin444` at reduced rounds is a large win. If it
is a bitsliced vector implementation, it is not a win at all.

Three things this trade rests on, all of them load-bearing:

- **The margin is differential-only.** `rounds@64` is what the search *proves* about
  single characteristics. Cutting to 16 rounds spends margin that also has to cover
  differential clustering, linear cryptanalysis, algebraic attacks and related-key
  attacks, none of which this harness measures. PRESENT's 31 rounds were not chosen on a
  differential bound alone.
- **`(2,9,7)`'s count is conservative.** Its `rounds@64` reads 9 only because round 4 is
  unresolved; if round 4 comes out at weight 38 it becomes 8, and the equal-margin round
  count drops from 18 to 16 — which would put it near `013-r16`'s 1.090x.
- **The key schedule is unchanged**, and was designed around PRESENT's pLayer.

---

## 5. What this overturned

**The baseline was flattering the modification.** Optimising the modification first and
the baseline afterwards produced a 1.59x per-round penalty and a break-even at equal
margin; optimising both produces 1.82x and a 9–16% loss. The order in which optimisation
effort is spent is not neutral, and a speed comparison between a cipher and a
modification of it is a claim about two *implementations* before it is a claim about two
ciphers.

**`bmin` was actively misleading.** `(0,1,3)`, `(1,15,13)` and `(2,1,3)` were selected
partly because their single-bit branch bound is 7 against `(2,9,7)`'s 6. The variant with
the **worst** `bmin` has the **best** actual differential resistance, by a wide margin —
13 active S-boxes at three rounds against 8, 9 and 10. A single-bit bound says nothing
useful about multi-round trails.

**The ShiftGen2 composite score got the winner right but not the order.** It ranked
`(2,9,7)` highest at 13.19, and `(2,9,7)` is indeed strongest. But it ranked
`013 (13.11) > 213 (12.25) > 1-15-13 (11.66)`, and the SAT results rank those three in
the reverse order. The score is a useful filter, not a substitute for a trail search.

**The cheapest triple is dominated on both axes.** `(2,1,3)` was found by fixing the cost
model and is genuinely the best of the 144-XOR family on every ShiftGen2 metric. It is
not faster — 2.45 against `(1,15,13)`'s 2.41, because its extra shared temporary costs
stores — and it is the weakest of the four on differential strength (11 active S-boxes at
four rounds against 14, 16 and 19). Correcting the cost model was worth doing; the
constant it turned up was not worth adopting.

**Fewer operations is not less work.** The 144-XOR form issues more instructions than the
160-XOR form. Two separate optimisations (192 → 160 XORs, and loop fusion to save 32 of
256 loads) each moved AVX2 by 0% before the constants were specialised. Reading the
instruction mix found in one step what two rounds of plausible optimisation had missed.

**Net trade.** `present-80-lin444-297` buys a differential bound of 2^-290 against
PRESENT's 2^-123 — a margin of 3.44x round count against 1.94x — for 1.82x on the fastest
implementation and nothing at all on the table paths. Spent as a round reduction instead,
it is a 1.8x gain on the table paths and a 16% loss on AVX2.

---

## 6. Caveats

- These are **single-characteristic** bounds. A differential can cluster many
  characteristics sharing input and output difference, making the differential more
  probable than the best single characteristic. `analysis/cli.py cluster` measures
  clustering for a specific difference pair; it has not been run for these variants.
- A bound on characteristic probability is not a proof of resistance to differential
  cryptanalysis, and says nothing about linear, algebraic, or related-key attacks. The
  `lin444` variants reuse PRESENT's key schedule unchanged.
- `lin444-297` round 4 is unresolved. Closing it would raise its bound further and is the
  obvious next run.
- The optimisations in §3.1 are the ones that were tried. A further round of work on
  either side could move the ratios again; the honest claim is a ratio between two
  implementations that have each had comparable effort spent on them, not a statement
  about the ciphers in the abstract.
- Cycle counts are nominal TSC ticks, not core clock cycles.
- This is analysis code. It is not constant-time and is not meant to protect anything.

---

## 7. Reproducing

```sh
make                       # build library, tests, bench
make test                  # 8753 + 30 + 276 C checks, 50 Python tests

./build/shiftgen_present   # rotation-constant search, with XOR-cost tiers
./build/shiftgen_present --csv all.csv    # all 4096 triples with enc/dec costs

tools/compare.sh avx2      # variant ratios, the protocol described at the top
tools/compare.sh avx2-bs   # the same, round function only
taskset -c 2 ./build/bench --csv results/speed.csv

python3 analysis/cli.py analyze --variant present-80            --max-rounds 12
python3 analysis/cli.py analyze --variant present-80-lin444-013 --max-rounds 4 \
                                --timeout 900 --budget 1800
python3 analysis/cli.py analyze --variant present-80-lin444-1-15-13 --max-rounds 4 \
                                --timeout 900 --budget 1800
python3 analysis/cli.py analyze --variant present-80-lin444-213 --max-rounds 4 \
                                --timeout 900 --budget 1800
python3 analysis/cli.py analyze --variant present-80-lin444-297 --max-rounds 4 \
                                --timeout 900 --budget 1800

# the equal-margin reduced-round variants are benchmarked, not re-analysed: their
# per-round bounds are those of the full-round variant they are cut from

make report                # -> results/report.md
```

Budget the SAT runs generously: `lin444-297` at four rounds did not finish in 3220s.
