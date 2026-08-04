# cipher-D

An 8-bit-S-box, 8-round block cipher measured with the same harness as every other
variant in this repository: same benchmark, same SAT model, same reference
implementation as the oracle.

The design was supplied as a specification to test, with the stated expectation that
it is weak. This document reports what was measured. The short version: the
differential result did **not** come out weak — 8 rounds of cipher-D admit no
differential characteristic better than 2^-77 — but the speed result did not come out
strong either, and the two together undercut the "extreme lightweight" framing more
than a differential break would have.

The margin it does have is one round, and [replacing the linear
layer](#replacing-the-linear-layer) fixes that at no measurable cost: swapping the bit
permutation for `lin444` with `c0 = (2, 9, 7)` takes the proven margin from 1.14x to
2.00x, past PRESENT's own 1.94x, while the fastest implementation stays within noise
of where it was.

## Specification as implemented

| | |
|---|---|
| block | 64 bits |
| S-box | 8-bit, applied to 8 disjoint bytes of the state |
| linear layer | bit permutation `L(i) = floor(i/8) + 8*(i mod 8)` |
| rounds | 8, plus a 9th key addition (whitening) |
| key | a raw 576 bits, used as 9 independent 64-bit round keys |

Round *r* is `state ^= rk[r]; state = S(state); state = L(state)`, for r = 0..7,
followed by `state ^= rk[8]`.

Two clarifications were needed before implementing and were answered by the designer:
the round count (8, with the 9th key as whitening only) and the key schedule. There
is **no key schedule**: the key is 576 raw bits, split into nine independent round
keys, with nothing shorter behind it.

That is the strongest possible assumption in the design's favour, and it is exactly
the assumption the differential model makes anyway — every published bound of this
kind assumes independent round keys, and here it is literally true rather than an
idealisation. It also removes exhaustive key search from the adversary model
entirely, so nothing below is limited by key length: the differential and structural
results are the binding constraints, and they are what this document measures.

The flip side is that the design has no key-agility story and no compression from a
short secret. Everything the analysis finds is a property of the round function
alone.

`variants/cipher-D.json` holds the S-box and permutation tables.

### The linear layer is a transpose

Write the 64-bit state as an 8x8 bit matrix `M[j][k]` = bit *k* of S-box *j*. Then

```
L(8j + k) = j + 8k
```

so bit *k* of S-box *j* becomes bit *j* of S-box *k*: `L` is exactly the matrix
transpose, and therefore an **involution**. The round function is "substitute along
rows, then transpose", which makes the cipher a two-dimensional SPN — the same shape
as a Square-like design.

Diffusion is correspondingly fast. Measured by dependency propagation:

| after round | every state bit depends on |
|---|---|
| 1 | >= 8 of the 64 input bits |
| 2 | all 64 |

Full diffusion in 2 rounds, against 3 for PRESENT. But PRESENT runs 31 rounds, about
10x its diffusion depth, where cipher-D runs 8, about 4x. Fast diffusion buys a
smaller margin than it looks like it should, because the round count fell faster than
the diffusion depth did.

### The S-box is good

Computed from the supplied table, not assumed:

| property | cipher-D | for comparison |
|---|---|---|
| bijective | yes | |
| differential uniformity | 4 | AES 4, PRESENT 4 (on 4 bits) |
| DDT entries | only 0, 2 and 4 | |
| differential branch number | **3** | AES 2 |
| linearity | 32 | AES 32 |
| algebraic degree | 7 | AES 7, the maximum |
| fixed points | only S(0) = 0 | |

Two consequences matter for the rest of this document.

**The weights are exact.** Every nonzero DDT entry is a power of two — 4 or 2 — so
the transition probabilities are exactly 2^-6 and 2^-7 with nothing rounded off. The
SAT model's weights `[0, 6, 7]` are the true costs, so its bounds are tight rather
than conservative.

**Branch number 3 is unusually good for an 8-bit S-box.** It means no single input bit
difference can produce a single output bit difference, so the cheapest way to keep
one S-box active per round is not available. This is a real strength and it is what
makes the differential bound below as high as it is. AES's S-box does not have it;
AES relies on MixColumns for that role, and cipher-D's linear layer is a bit
permutation with branch number 2, so the S-box is carrying it alone.

The S-box is **not** affine-equivalent to inversion in GF(2^8) over any of the 30
irreducible degree-8 polynomials, checked exhaustively. So there is no GFNI or AES-NI
shortcut for it, which turns out to matter for the speed result.

## Differential strength: exact to 8 rounds

The full 8 rounds were searched to exactness — these are optimal values, not bounds.

| rounds | min active S-boxes | min weight | probability | solver |
|---|---|---|---|---|
| 1 | 1 | 6 | 2^-6 | 0.09 s |
| 2 | 2 | 12 | 2^-12 | 0.28 s |
| 3 | 4 | 24 | 2^-24 | 0.85 s |
| 4 | 6 | 36 | 2^-36 | 2.57 s |
| 5 | 7 | 44 | 2^-44 | 12.60 s |
| 6 | 8 | 51 | 2^-51 | 20.95 s |
| 7 | 10 | 64 | 2^-64 | 63.28 s |
| 8 | 12 | 77 | 2^-77 | 145.70 s |

The 8-round model is 1024 variables and 795123 clauses.

**No differential characteristic distinguishes 8 rounds.** The best is 2^-77 against a
2^64 codebook. This is not the weakness the design was expected to show.

The margin is thin, though. Seven rounds sit at exactly weight 64 — the full
codebook — so the entire security margin against single-characteristic differential
cryptanalysis is **one round**:

| | cipher-D | PRESENT-80 |
|---|---|---|
| rounds | 8 | 31 |
| smallest round count proven past 2^-64 | 7 | 16 |
| margin | **1.14x** | 1.94x |

The best 8-round characteristic:

```
input  difference  00000000001b001b
output difference  0006000606060006
active S-boxes     12,  weight 77

round  difference         active S-boxes (index:weight)
    0  00000000001b001b  0:6 2:6
    1  0005000000000000  6:7
    2  0040000000000000  6:6
    3  0000000000004040  0:6 1:6
    4  0000000000000303  0:7 1:7
    5  0000000000030000  2:7
    6  0000000000040000  2:7
    7  0000000000040400  1:6 2:6
  out  0006000606060006
```

Note rounds 1 and 2: a single active S-box, twice running. Branch number 3 forbids
1 bit in -> 1 bit out, but it does not forbid 2 bits in -> 1 bit out, and the
transpose is happy to route a two-bit difference in one row into a one-bit difference
in one column.

### Encoding an 8-bit S-box for SAT

Worth recording, because it is what made the search possible at all.

The 4-bit model states one relation per S-box over `2n + maxw = 8 + 7 = 15` variables
and encodes it by covering the off-set with prime implicants. At 8 bits that relation
has `2n + maxw = 16 + 7 = 23` variables, and the covering does not finish.

It is split in two instead:

- a **support** relation over the 16 variables `(a, b)`, accepting exactly the DDT's
  nonzero entries;
- one **threshold** relation per distinct weight `t`, over the 17 variables
  `(a, b, u_t)`, forcing `u_t` when the transition's weight is at least `t`, with
  prefix constraints `u_j -> u_{j-1}`.

The weight is then `sum u_t`. The encoding is one-sided: `u_t` is *forced* to 1 when
the true weight reaches `t`, but nothing forces it to 0, so a given trail's modelled
weight can exceed its true weight. That is the harmless direction in both uses:

- **Minimising** is still exact. The cheapest modelled weight consistent with a trail
  is the one with no spurious `u_t` set, which is the true weight, so the minimum over
  all trails is the true minimum. The table above is optimal values, not bounds.
- **Counting** under `sum u_t <= w` admits exactly the trails whose true weight is at
  most `w`, for the same reason.

What the relaxation does cost is that a *returned* assignment may carry spurious
`u_t`, so the solution checker verifies the weight against the real DDT and accepts
`>=` rather than `==` when the tiered encoding is in use.

Two things made the covering fast:

**Point sets instead of bitsets.** The off-set of a 16-variable relation is dense —
each of the 256 input differences has 127 valid outputs out of 256 — so a maximal
cube contains only a handful of points. Representing a cube by its point list rather
than a 65536-bit mask turned the irredundancy pass from O(k^2) big-integer ORs into
coverage counting: **353 s -> 0.2 s** for the same 10680 clauses.

**Don't-cares.** The non-support transitions are handed to the threshold relations as
don't-cares, since the support relation has already rejected them. Cubes then grow
across those points, and the threshold-6 relation collapses from thousands of clauses
to **8 two-literal clauses**.

### Clustering

With only 1.14x of margin, the question is whether many characteristics share the
best (input, output) pair — their probabilities add, and the *differential* can be far
more probable than the best characteristic in it.

Enumeration for the pair above, by SAT, blocking each solution's intermediate
differences:

| weight | characteristics (cumulative) | at exactly this weight | differential >= | tier's contribution |
|---|---|---|---|---|
| 77 | 4 | 4 | 2^-75.00 | — |
| 78 | 37 | 33 | 2^-72.64 | 4.12x the previous tier |
| 79 | 177 | 140 | 2^-71.21 | 2.12x |

Each unit of weight is worth half as much per characteristic, so clustering matters
only while the count grows faster than 2x per unit. It does — 8.2x then 4.2x — but
the *net* gain per tier is already down from 4.12x to 2.12x and falling by about half
each time. Extrapolating that decay, the series converges near **2^-70**:

| enumerated through weight | differential >= |
|---|---|
| 79 (measured) | 2^-71.21 |
| 80 | 2^-70.47 |
| 81 | 2^-70.19 |
| 83 and beyond | 2^-70.11 |

So clustering is worth roughly **7 bits** — a real and substantial effect, three
times what the single best characteristic suggests in log terms — but it lands around
2^-70, still about 6 bits short of the 2^-64 needed to distinguish 8 rounds with the
full codebook.

**cipher-D clusters far harder than PRESENT does.** The same measurement on PRESENT-80
over the same number of rounds, for its own best 8-round pair:

| | cipher-D | PRESENT-80 |
|---|---|---|
| best 8-round characteristic | 2^-77 | 2^-32 |
| characteristics at +0 / +1 / +2 weight (cumulative) | 4 / 37 / 177 | 1 / 2 / 4 |
| differential after those three tiers | 2^-71.21 | 2^-30.91 |
| **gain from clustering** | **5.8 bits** | **1.1 bits** |

The cause is the shape of the DDT. Each row of cipher-D's DDT has 127 nonzero entries
— one 4 and 126 twos — so from any input difference there are 126 output differences
that all cost the same 2^-7. Near-optimal characteristics are therefore abundant, and
a great many of them land on the same output difference. PRESENT's 4-bit S-box has a
sparse DDT by comparison, and its best pair has essentially no company.

This is a real structural cost of the wide S-box, and it eats most of the margin: the
gap from the best characteristic to a distinguisher is 13 bits, and clustering closes
about 7 of them.

Two caveats, both in the direction of the design:

- This is one (input, output) pair, the one containing the single best characteristic.
  The most probable *differential* need not be the one containing the most probable
  *characteristic*, and no search over pairs was run.
- The extrapolation past weight 79 is a fit to three points, not a measurement.
  Enumeration cost grew 22 s -> 153 s -> 654 s per tier and weight 80 did not finish
  in the time budgeted.

The measured part — 2^-71.2 through weight 79 — is a genuine lower bound and stands on
its own.

## Speed

Measured on the same machine, same run, pinned with `taskset -c 2`. Nominal TSC
ticks per byte, median of 15 trials of 8192 blocks; lower is better.

| implementation | cipher-D | PRESENT-80 | notes |
|---|---|---|---|
| `ref` | 403.27 | 1662.51 | bit-by-bit, the correctness oracle |
| `table` | 4.49 | 24.55 | fused S-box+pLayer, one block |
| `table-x2` | 3.68 | 14.85 | |
| `table-x4` | 2.56 | 9.77 | |
| **`table-x8`** | **2.47** | 8.61 | cipher-D's best |
| `table-x16` | 2.60 | 9.97 | |
| `bitslice` | 18.25 | 4.89 | 64 blocks, scalar |
| `bitslice-bs` | 16.14 | 3.03 | ditto, transposes hoisted out |
| `avx2` | 7.21 | 1.29 | 256 blocks |
| **`avx2-bs`** | 6.96 | **1.02** | PRESENT's best |

Read the two columns' *best* rows against each other:

**cipher-D is 2.4x slower than PRESENT-80** — 2.47 against 1.02 cyc/B — while running
8 rounds against 31. Per round it is **9.4x more expensive**.

The ordering of implementations inverts between the two ciphers, and that is the whole
story:

- On **table-driven** implementations cipher-D wins, 3.5x at `table-x8` and 5.5x at
  single-block `table`. The per-round cost of a fused S-box+pLayer table lookup is
  identical for the two ciphers — both index 8 byte-wide tables — so the ratio is just
  31/8, the round counts. cipher-D is doing exactly what a reduced-round design should
  do here.
- On **bitsliced** implementations cipher-D loses badly, and table-driven code beats
  its own bitsliced code by 6.5x scalar and 2.8x on AVX2. For PRESENT the bitsliced
  path wins by 8.4x.

### Why bitslicing fails for it

Bitslicing makes a bit permutation completely free — it is register renaming — and
prices the S-box in gates. That trade is excellent when the S-box is small. It is a
disaster at 8 bits.

An 8-bit S-box has 2^256 candidate output functions, so the exhaustive search that
gives PRESENT's 4-bit S-box a proven-minimal 15-gate circuit is out of reach. What
`tools/sbox_synth8.py` does instead: build a shared reduced ordered BDD over the eight
output bit functions, turn each node into a 2:1 multiplexer — three gates in general,
`ite(s, hi, lo) = lo ^ (s & (lo ^ hi))`, and one gate when a branch is constant — and
try **all 8! = 40320 variable orders**, keeping the cheapest. The order search is
exhaustive; only the BDD construction is heuristic.

Result: **1107 gates** (u64) / **1117** (AVX2), from 402 BDD nodes.

| | PRESENT | cipher-D |
|---|---|---|
| gates per S-box | 15 | 1107 |
| state bits covered | 4 | 8 |
| gates per state bit | 3.75 | 138 |
| gates per round (64 bits) | 240 | 8856 |
| gates for the whole cipher | 7440 (31 rounds) | 70848 (8 rounds) |

37x the gate count per round, and still 9.5x for the whole cipher even at a quarter
of the rounds. The measured
2.4x-and-inverted-ordering result follows directly, plus register pressure: eight live
inputs, eight live outputs and hundreds of temporaries against sixteen architectural
registers means the AVX2 circuit spills heavily, which is why AVX2 only recovers 2.3x
over the scalar bitsliced path instead of the ~4x its width implies.

Both 8-bit circuits are verified against the reference implementation for encryption,
decryption and round-trip, on both backends — `tests/test_impls` grew from 8976 to
9300 checks when they were added.

Being unable to bitslice is not only a speed problem. Bitsliced implementations are
the standard way to get a *constant-time* block cipher on a general-purpose CPU;
table-driven ones are the ones with key-dependent cache access. cipher-D's fast path
is the one with the timing side channel, and its constant-time path is 2.8x slower
than its fast path and 6.8x slower than PRESENT's.

### Lightweight footprint

The claim to test is "extreme lightweight". The two implementations in this repository
both use byte-indexed tables, so they do not separate the ciphers on memory — but the
underlying designs differ:

| | PRESENT | cipher-D |
|---|---|---|
| S-box as a table | 16 nibbles = 8 bytes | 256 bytes |
| key material to keep | 80-bit key, round keys derived on the fly | 576 bits = 72 bytes, all of it |
| bitsliced circuit | 15 gates | 1107 gates |

On a small MCU the S-box is 32x the ROM, and the key is 72 bytes that must all be
stored: with no key schedule there is nothing shorter to recompute them from. PRESENT
keeps 10 bytes and generates each round key as it goes. For a design described as
extreme lightweight, 72 bytes of key in RAM plus 256 bytes of S-box in ROM is the
larger part of a small microcontroller's budget, and it is the part that does not
shrink with the round count.

## Replacing the linear layer

cipher-D's margin is one round and rests entirely on the S-box. The obvious lever is
the other half of the round: swap the bit permutation, which has differential branch
number 2 by construction and can never make a difference cost anything, for a layer
that actually mixes.

Doing that with `lin444` and `c0 = (2, 9, 7)` takes the proven margin from **1.14x to
2.00x** — past PRESENT's own 1.94x — and the fastest implementation does not measurably
change, 2.14x PRESENT's best against 2.17x. Four rounds then already exceed the full
codebook, where the permutation needs seven.

It is free for two separate reasons: on the table paths any linear layer is fused into
the lookup, and on the bitsliced paths `lin444`'s 192 XORs a round are 2.2% of
cipher-D's 8856 gates of S-box — the same 192 XORs nearly double PRESENT's 240-gate
round, which is why they cost PRESENT 1.8x and cipher-D nothing.

The full experiment, both constant triples, the measurement caveats and what was not
searched: **[docs/cipher-D-lin444.md](cipher-D-lin444.md)**.

## Verification

Known-answer vectors generated by this implementation, each checked for
round-trip and for agreement between the reference and table paths. The key is the
full 72-byte stream, most significant byte first; round key *r* is bytes 8r..8r+7.

| key (72 bytes) | plaintext | ciphertext |
|---|---|---|
| all zero | `0000000000000000` | `0000000000000000` |
| all zero | `0123456789abcdef` | `069d25824aac5d1a` |
| all `ff` | `0000000000000000` | `4cc3f13c91a700aa` |
| `00 01 02 ... 47` | `0000000000000000` | `9e3cf90363599cdb` |
| `00 01 02 ... 47` | `ffffffffffffffff` | `e6a88e175acd8d7a` |

The first is a structural fixed point rather than a coincidence: S(0) = 0 and the
transpose fixes the all-zero state, so an all-zero key gives an all-zero ciphertext
for an all-zero plaintext. That is worth knowing but is not by itself an attack —
it is one point of a 2^64 codebook, and it is a property PRESENT shares in the same
degenerate case.

## Reproducing

```sh
make                                   # builds, and synthesises the 8-bit circuits
make test                              # includes the 8-bit bitsliced paths
taskset -c 2 ./build/bench --variant cipher-D

python3 tools/sbox_synth8.py --variant cipher-D          # gate count, all 8! orders
python3 analysis/cli.py analyze --variant cipher-D --max-rounds 8
python3 analysis/cli.py trail   --variant cipher-D --rounds 8
python3 analysis/cli.py cluster --variant cipher-D --rounds 8 --extra-weight 4
```

## Summary

| question | answer |
|---|---|
| Differential characteristics over 8 rounds? | best is 2^-77; **not** a distinguisher |
| Margin | 1.14x (7 rounds already reach 2^-64), against PRESENT's 1.94x |
| With `lin444-297` instead of the permutation | margin **2.00x**, at 2.14x PRESENT's best instead of 2.17x — free |
| Clustering | measured to 2^-71.2, extrapolates to ~2^-70 — ~7 bits, still short of 2^-64 |
| Fastest implementation | table-x8, 2.47 cyc/B |
| Against PRESENT-80's fastest | **2.4x slower**, at a quarter of the rounds |
| Bitsliceable? | yes, but 1107 gates — the table path beats it by 2.8-6.5x |
| Constant-time path | 2.8x slower than its own fast path |
| Key | 576 raw bits, no schedule — key search is not a factor, but nothing compresses |

The design does not fail to differential cryptanalysis at 8 rounds. It fails the
"extreme lightweight" claim on a general-purpose CPU, where an 8-bit S-box costs more
than the four rounds of PRESENT it replaces — and the margin it does have is one
round, resting entirely on the S-box's branch number of 3. Clustering closes about 7
of the 13 bits between the best characteristic and a distinguisher, and stops there.

The thin margin, at least, is cheap to fix. The S-box is the good half of the round
and the expensive half; the permutation is the weak half and the free half. Replacing
it with `lin444-297` nearly doubles the proven margin and costs nothing measurable,
because on the table paths a linear layer is fused into the lookup and on the
bitsliced paths 192 XORs disappear next to 8856 gates of S-box.
