# Giving cipher-D-lin444-297 the AES S-box

An experiment on top of [cipher-D-lin444-297](cipher-D-lin444.md): keep the `lin444`
`c0 = (2, 9, 7)` linear layer, keep the 8 rounds, keep the raw 576-bit key, and
replace only the supplied 8-bit S-box with the AES S-box.

**Result: the cipher gets both faster and stronger. The fastest implementation goes
from 2.1x PRESENT-80's best to 1.3x, the proven 8-round bound goes from 2^-136 to
2^-146, and the fastest implementation stops being a table lookup and becomes the
AVX2 bitsliced one.**

The previous two experiments in this series each traded something. This one does not,
and the reason is narrow and worth stating up front: it is not that the AES S-box is
cryptographically better — on the properties this harness measures it is a wash, and
on one of them it is *worse*. It is that the AES S-box has algebraic structure a
bitslice circuit can exploit, and cipher-D's supplied table does not.

## What was changed

| | `cipher-D-lin444-297` | this experiment |
|---|---|---|
| S-box | 8-bit, supplied as a table | **AES S-box** (FIPS-197) |
| linear layer | `lin444`, `c0 = (2, 9, 7)`, 192 XORs/round | unchanged |
| rounds | 8 + whitening | unchanged (and a 5-round cut, below) |
| key | raw 576 bits, 9 independent round keys | unchanged |

The S-box is *derived* in `tools/make_variants.py` — inversion in GF(2^8) mod 0x11B,
then the AES affine map — not pasted as 256 constants, and checked against four
published entries. That is the same rule the rest of the variant generator follows.

Variant definitions: `variants/cipher-D-lin444-297-aes.json`,
`variants/cipher-D-lin444-297-aes-r5.json`.

## The two S-boxes are nearly indistinguishable on paper

Computed from the tables, not assumed:

| property | cipher-D's S-box | AES S-box | better |
|---|---|---|---|
| differential uniformity | 4 | 4 | tie |
| linearity | 32 | 32 | tie |
| algebraic degree | 7 | 7 | tie |
| differential branch number | 3 | **2** | cipher-D |
| fixed points | 1 | **0** | AES |
| SAT weight model | `[0, 6, 7]`, exact | `[0, 6, 7]`, exact | tie |

Three of the four headline properties are identical, and the weight model the SAT
search uses is *literally the same* — both S-boxes have DDT entries of only 0, 2 and 4,
so an active S-box costs 6 or 7 bits in both ciphers. The one clear difference favours
cipher-D: branch number 3 against 2, which was the property [the previous
document](cipher-D-lin444.md#why-the-permutation-was-the-weak-half) identified as
carrying all of cipher-D's differential resistance before `lin444` arrived.

So on paper this swap should have been neutral at best and a small regression at
worst. It was neither.

## Speed: the S-box structure is the whole story

### Why the generic synthesiser had to be bypassed

`tools/sbox_synth8.py` builds a circuit for any 8-bit S-box by sharing a BDD across
the eight output bit functions. Run on the AES S-box it produces **1100 gates** —
against 1107 for cipher-D's supplied table. Measured that way the AES S-box is worth
nothing at all.

That number is an artefact of the method, not a property of the cipher. A BDD only
ever sees 256 table entries; it cannot recover that the S-box is a field inversion.
Boyar and Peralta's circuit does exactly that — map into a tower of GF(2) subfields,
invert there, map back — and this repository now carries it in
`tools/known_circuits.py`:

| | cipher-D's S-box | AES S-box |
|---|---|---|
| BDD synthesis (`sbox_synth8`) | 1107 u64 / 1117 avx2 | 1100 / 1111 |
| published circuit | none exists | **132 / 132** |

**8.4x fewer gates.** The 132 counts 94 XOR + 34 AND + 4 NOT under this repository's
cost model, which prices every operation at 1. Boyar and Peralta report smaller
figures for later revisions of the circuit and under an accounting that prices XNOR as
one gate; the order of magnitude is the point, not the last few gates.

The circuit is verified against all 256 inputs at generation time, and the whole build
then re-verifies it end to end: `test_impls` checks that the bitsliced and AVX2 paths
reproduce the reference implementation for every variant (11488 checks, passing).

### Measured

Within-process ratios from `tools/compare.sh <impl> 51`, each variant divided by
`present-80` measured in the same process on the same implementation — the frequency
state cancels out of that, which raw cyc/B does not.

| implementation | `cipher-D-lin444-297` | `-aes` | `-aes-r5` |
|---|---|---|---|
| `table` | 0.259 | 0.259 | 0.161 |
| `table-x2` | 0.241 | 0.243 | 0.140 |
| `table-x4` | 0.267 | 0.264 | 0.169 |
| `table-x8` | 0.261 | 0.260 | 0.168 |
| `table-x16` | 0.250 | 0.249 | 0.158 |
| `bitslice` | 3.732 | **0.911** | 0.711 |
| `bitslice-bs` | 5.704 | **0.917** | 0.578 |
| `avx2` | 5.056 | **1.213** | 0.851 |
| `avx2-bs` | 6.252 | **1.287** | 0.807 |

A second run after a `make distclean` rebuild reproduced these to within 3%
(`avx2-bs`: 6.319, 1.303, 0.835; `table-x8` identical to three digits), which is the
run-to-run spread these ratios carry.

Two clean halves:

- **The table paths do not move at all** — 0.259 against 0.259, 0.260 against 0.261.
  Expected: the S-box is fused into the lookup table there, so only the table
  *contents* change and any bijection costs the same. This is the same reason
  `lin444` was free on the table paths.
- **The bitsliced paths collapse by 4.1x to 6.2x.** `avx2-bs` goes from 6.25x
  PRESENT-80 to 1.29x; `bitslice-bs` from 5.70x to 0.92x, which is to say it becomes
  *faster than PRESENT-80's own bitsliced implementation* despite running an 8-bit
  S-box.

### The fastest implementation changes identity

Absolute cyc/B, all implementations measured inside one process per variant, median of
5 runs — this is the comparison that decides which path wins for a given cipher:

| variant | table | table-x4 | table-x8 | bitslice-bs | avx2 | avx2-bs | fastest |
|---|---|---|---|---|---|---|---|
| `present-80` | 24.08 | 9.65 | 8.98 | 2.84 | 1.42 | **1.11** | `avx2-bs` |
| `cipher-D-lin444-297` | 4.47 | 2.65 | **2.39** | 17.02 | 7.01 | 6.78 | `table-x8` |
| `cipher-D-lin444-297-aes` | 4.15 | 2.42 | 2.17 | 2.50 | 1.68 | **1.37** | `avx2-bs` |
| `cipher-D-lin444-297-aes-r5` | 2.34 | 1.62 | 1.40 | 1.57 | 1.29 | **0.95** | `avx2-bs` |

cipher-D's fastest path was `table-x8`, and [the previous
document](cipher-D-lin444.md#speed-free) explained why: a 1107-gate S-box makes
bitslicing pointless, so the design was pushed onto lookup tables where its wide S-box
costs a 256-entry table per byte instead of 16 entries per nibble. With a 132-gate
S-box that inversion reverses. `avx2-bs` wins, and it wins by 1.6x over the best table
path.

Best-implementation against best-implementation, PRESENT-80 = 1.00x:

| variant | fastest path | vs PRESENT-80's best |
|---|---|---|
| `present-80` | `avx2-bs` | 1.00x |
| `cipher-D-lin444-297` | `table-x8` | 2.1x |
| `cipher-D-lin444-297-aes` | `avx2-bs` | **1.3x** |
| `cipher-D-lin444-297-aes-r5` | `avx2-bs` | **0.82x** |

The 1.3x is read straight off `compare.sh` (1.287x and 1.303x on two runs) — both
ciphers' fastest path is `avx2-bs`, so no cross-implementation arithmetic is needed and
that ratio is direct. The cross-implementation table above puts it at 1.23x instead;
the two anchors disagree by about 5%, which is the honest width of the measurement.

### A gate count predicts it

Total bitsliced gates for a whole encryption, S-box circuits plus linear-layer XORs:

| variant | per round | rounds | total | vs PRESENT | measured `avx2-bs` |
|---|---|---|---|---|---|
| `present-80` | 16 x 15 = 240 | 31 | 7440 | 1.00x | 1.00x |
| `cipher-D-lin444-297` | 8 x 1107 + 192 = 9048 | 8 | 72384 | 9.7x | 6.3x |
| `cipher-D-lin444-297-aes` | 8 x 132 + 192 = 1248 | 8 | 9984 | 1.34x | **1.29x** |
| `cipher-D-lin444-297-aes-r5` | 1248 | 5 | 6240 | 0.84x | **0.81-0.84x** |

For the AES variants the gate count predicts the measurement to within 4%, which is
what you expect when a kernel is purely gate-bound. cipher-D's own row misses badly in
the other direction (9.7x predicted, 6.3x measured) because 9048 gates per round
overflows the register file and the kernel becomes memory-bound rather than gate-bound
— the circuit is so large it stops being the binding constraint.

## Strength: also better, despite the worse branch number

Exact SAT results, `cadical 3.0.1`, all rows exact:

| rounds | `cipher-D-lin444-297` active / weight | `-aes` active / weight |
|---|---|---|
| 1 | 1 / 6 | 1 / 6 |
| 2 | 4 / 24 | 4 / 24 |
| 3 | 8 / 52 | 8 / **50** |
| 4 | 10 / 68 | **11** / **73** |

Rounds 1 and 2 are identical. Round 3 is slightly *worse* for AES — 50 against 52,
with the same 8 active S-boxes, so the AES S-box lets a trail take two more of the
cheap weight-6 transitions. Round 4 reverses it decisively: 11 active S-boxes against
10, and weight 73 against 68.

**Four rounds already exceed the full codebook** (73 > 64), the same round count at
which the supplied S-box crosses, but with 5 more bits of margin.

| | `cipher-D` | `cipher-D-lin444-297` | `-aes` | `-aes-r5` | PRESENT-80 |
|---|---|---|---|---|---|
| rounds | 8 | 8 | 8 | 5 | 31 |
| smallest round count proven past 2^-64 | 7 | 4 | **4** | 4 | 16 |
| margin | 1.14x | 2.00x | **2.00x** | 1.25x | 1.94x |
| bound over the full round count | 2^-77 | 2^-136 | **2^-146** | 2^-73 | 2^-123 |
| cost, fastest implementation | 2.1x PRESENT | 2.1x PRESENT | **1.3x** | **0.82x** | 1.00x |

The 2^-146 is a window bound, not a search result: an 8-round characteristic restricts
to two disjoint 4-round windows, each of weight at least 73.

That branch number 2 does not hurt is the interesting part. A branch number of 3
guarantees one active S-box becomes at least two — but `lin444` already forces a
single active S-box to spread across four words, so the guarantee is redundant. It was
load-bearing only while the linear layer was a bit permutation, which could not spread
anything by construction. Once the linear layer does real mixing, the branch number
stops being the binding constraint, and the two S-boxes tie at 4 on differential
uniformity, which is what sets the per-S-box cost.

Why AES then comes out *ahead* at round 4 — 11 active S-boxes against 10 — is not
explained by any property in the table above, since the two tie on all of them or lose.
It is a property of how this particular S-box's DDT support interacts with these
particular rotation constants, and this harness measures the outcome without
attributing it. Worth remembering before generalising the result to another layer.

## The 5-round cut

Since the bound is reached at 4 rounds, a 5-round variant was built and measured, and
it is the fastest cipher in this repository: **0.82x PRESENT-80's best implementation**,
at 0.95 cyc/B against PRESENT's 1.11.

It should not be adopted on that basis. Its margin is 5/4 = **1.25x**, well under
PRESENT's 1.94x, and margin is the thing this repository has consistently used to
compare designs at equal security rather than equal round count. Matching PRESENT's
1.94x needs 4 x 1.94 = 7.8, so **8 rounds** — which is the unmodified round count, and
the 1.3x variant above. The 5-round measurement answers the speed question that was
asked; it does not identify a better operating point.

| round count | margin | vs PRESENT-80's best | verdict |
|---|---|---|---|
| 8 | 2.00x | 1.3x | matches PRESENT's margin, 30% slower |
| 5 | 1.25x | 0.82x | faster than PRESENT, but 36% less margin |

## Caveats

- **Only the forward S-box got the published circuit.** The inverse still uses BDD
  synthesis (1074 gates), so bitsliced *decryption* is unchanged. Only encryption is
  benchmarked, so no number above depends on this, but a decrypting deployment would
  not see the speedup without also transcribing Boyar-Peralta's inverse circuit.
- **Rounds 5-8 were not searched.** Round 4 took 634 s and the cost is growing by
  roughly an order of magnitude per round. The search was stopped once the weight
  passed 64, which is what the margin claim depends on; rounds 1-4 are exact and the
  8-round figure is a window bound.
- **Differential-only, single characteristics.** No clustering measurement was made
  for either variant, and cipher-D's differentials are known to cluster heavily (about
  7 bits for the permutation version). Nothing here addresses linear, algebraic,
  integral or related-key attacks — and the AES S-box's *algebraic* structure, which is
  what makes it fast here, is exactly the property that has attracted algebraic
  attention on AES itself. That trade is not measured by this harness.
- **The AES S-box is 8 bits wide and so is cipher-D's.** This experiment says nothing
  about whether a wide S-box is a good idea; it holds the width fixed and changes only
  whether the table has exploitable structure.
- The two speed anchors disagree by ~5% (1.23x against 1.29x). Both are within-process
  ratios; they differ in what they hold constant. Neither supports a claim finer than
  "about 1.3x".

## Reproducing

```sh
python3 tools/make_variants.py          # derives the AES S-box, writes both variants
make                                    # regenerates kernels and circuits, then builds
make test                               # 11488 impl cross-checks, incl. the BP circuit

tools/compare.sh avx2-bs 51             # within-process ratios, the trustworthy view
tools/compare.sh table-x8 51

python3 analysis/cli.py analyze --variant cipher-D-lin444-297-aes \
        --max-rounds 8 --stop-at-weight 64 --timeout 7200
```

Generation prints which circuit each 8-bit S-box got:

```
circuit c0: 8-bit, BDD synthesis, u64 1107 gates, avx2 1117 gates      # cipher-D S
circuit c1: 8-bit, BDD synthesis, u64 1118 gates, avx2 1125 gates      # cipher-D S^-1
circuit c2: 8-bit, published aes circuit, u64 132 gates, avx2 132 gates
circuit c3: 8-bit, BDD synthesis, u64 1074 gates, avx2 1087 gates      # AES S^-1
```

## Summary

| question | answer |
|---|---|
| Is the AES S-box cryptographically better here? | no — same du, linearity and degree; *worse* branch number |
| Did the differential bound improve anyway? | yes, 2^-136 -> 2^-146 over 8 rounds; 11 active S-boxes at round 4 against 10 |
| Why is it faster? | 132-gate published circuit against 1107 for an unstructured table |
| Would generic synthesis have found that? | no — BDD gives the AES S-box 1100 gates, no better than cipher-D's |
| What does it buy? | 2.1x PRESENT's best -> **1.3x**, and `avx2-bs` replaces `table-x8` as the fastest path |
| Does the table path change? | no, identical — the S-box is fused into the lookup either way |
| Is the 5-round cut worth taking? | it is 0.82x PRESENT and the fastest thing here, but its margin is 1.25x against PRESENT's 1.94x |
