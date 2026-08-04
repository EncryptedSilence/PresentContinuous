# Replacing cipher-D's linear layer

An experiment on top of [cipher-D](cipher-D.md): keep the 8-bit S-box, keep the 8
rounds, keep the raw 576-bit key, and replace only the bit permutation with the
`lin444` XOR-and-rotate layer.

**Result: the proven differential margin goes from 1.14x to 2.00x — past PRESENT's own
1.94x — and the fastest implementation does not measurably change.**

That is an unusually clean outcome for this harness, where nearly every strength gain
has cost something. The reason it comes free is specific to a wide S-box, and is the
one respect in which cipher-D's expensive S-box works in its favour.

## What was changed

| | cipher-D | this experiment |
|---|---|---|
| S-box | 8-bit, differential uniformity 4, branch number 3 | unchanged |
| rounds | 8 + whitening | unchanged |
| key | raw 576 bits, 9 independent round keys | unchanged |
| linear layer | `L(i) = i/8 + 8*(i%8)`, the 8x8 bit transpose | `lin444`, four 16-bit words |

`lin444` is the layer from ShiftGen2's `lin444_r1`, already used on PRESENT in
[docs/lin444-experiment.md](lin444-experiment.md): the state is read as four 16-bit
words and each word absorbs three rotations of the others, chained so later words see
the already-updated earlier ones. It is unitriangular over GF(2), so it is invertible
for every choice of rotation constants, and its inverse is the same four lines run
bottom-up at identical cost.

Two variants were built:

- **`cipher-D-lin444-297`**, `c0 = (2, 9, 7)` — the *strongest* of the four constant
  triples on PRESENT (2^-290 over 31 rounds, against `(0,1,3)`'s 2^-224 and
  `(1,15,13)`'s 2^-252). 192 XORs per round.
- **`cipher-D-lin444-1-15-13`**, `c0 = (1, 15, 13)` — the *fastest* on PRESENT, 160
  XORs per round instead of 192, kept here as a speed control only.

Worth stating plainly, because it is easy to misremember: on PRESENT, `(2,9,7)` was
the strongest triple, not the fastest. The fastest was `(1,15,13)` at a 1.769x penalty
against `(2,9,7)`'s 1.821x. On cipher-D the distinction turns out not to matter,
because neither costs anything.

## Speed: free

Ratios to PRESENT-80's fastest implementation (`avx2-bs`), median of 4 full benchmark
runs, each normalised inside its own process so that frequency state cancels:

| variant | table | table-x4 | table-x8 | table-x16 | bitslice-bs | avx2-bs |
|---|---|---|---|---|---|---|
| `cipher-D` | 4.00 | 2.36 | **2.17** | 2.36 | 14.71 | 6.07 |
| `cipher-D-lin444-297` | 4.02 | 2.37 | **2.14** | 2.33 | 15.00 | 6.43 |
| `cipher-D-lin444-1-15-13` | 4.04 | 2.37 | **2.14** | 2.40 | 15.55 | 6.48 |
| `present-80` | 22.12 | 8.57 | 7.75 | 8.85 | 2.71 | **1.00** |

The fastest implementation of each cipher-D variant is `table-x8`, and all three land
at 2.14-2.17x PRESENT's best — indistinguishable. `tools/compare.sh` over 9
repetitions agrees at higher precision: on `table-x8` the three measure 0.270x, 0.270x
and 0.271x of PRESENT's `table-x8`.

Two different mechanisms, worth separating because only one of them is new:

- On the **table paths** the layer is fused into the lookup, exactly as it is for
  PRESENT. Any GF(2)-linear layer is free there; only the table contents change. This
  is not news — it is why `lin444` was already free on PRESENT's table paths.
- On the **bitsliced paths** it is nearly free for a reason specific to a wide S-box.
  `lin444` adds 192 XORs per round either way. cipher-D's round is 8 S-box circuits of
  1107 gates = 8856 gates, so 192 XORs is **2.2%** of the round; measured, +2-6%.
  PRESENT's round is 16 circuits of 15 gates = 240 gates, so the same 192 XORs nearly
  double it — hence the 1.77-1.85x it costs there.

**The bigger the S-box, the cheaper a real linear layer is.** A design paying 1107
gates per S-box has already spent so much that a genuine mixing layer rounds to
nothing, whereas a lightweight 4-bit design cannot afford one.

### Measurement caveat

These runs were taken on a machine carrying roughly six cores of unrelated load, which
inflates absolute cyc/B (`present-128`'s `table` row read 36.0 against 27.1 when the
machine was quiet). Every figure above is a within-process ratio, which that cancels
out of; the absolute columns in [results/report.md](../results/report.md) are not
directly comparable against numbers taken at another time. `tools/compare.sh` exists
for exactly this reason.

## Strength: a large gain

Differential search, `c0 = (2, 9, 7)`, against the permutation version. All values
exact.

| rounds | cipher-D active / weight | `lin444-297` active / weight |
|---|---|---|
| 1 | 1 / 6 | 1 / 6 |
| 2 | 2 / 12 | 4 / **24** |
| 3 | 4 / 24 | 8 / **52** |
| 4 | 6 / 36 | 10 / **68** |
| 5 | 7 / 44 | not searched |
| 6 | 8 / 51 | not searched |
| 7 | 10 / **64** | not searched |
| 8 | 12 / 77 | not searched |

**Four rounds of `cipher-D-lin444-297` already exceed the full codebook** — weight 68,
against the 64 that cipher-D's permutation does not reach until round 7.

| | cipher-D | `cipher-D-lin444-297` | PRESENT-80 |
|---|---|---|---|
| rounds | 8 | 8 | 31 |
| smallest round count proven past 2^-64 | 7 | **4** | 16 |
| margin | 1.14x | **2.00x** | 1.94x |
| bound over the full round count | 2^-77 | **2^-136** | 2^-123 |
| cost, fastest implementation | 2.17x PRESENT | **2.14x PRESENT** | 1.00x |

The 2^-136 is a window bound, not a search result: a characteristic over 8 rounds
restricts to two disjoint 4-round windows, each of weight at least 68.

### Why the permutation was the weak half

A bit permutation has differential branch number 2 by construction — it moves bits
around and can never make a difference cost anything. So all of cipher-D's differential
resistance had to come from the S-box's branch number of 3, which is enough to turn one
active S-box into two but no more. That is exactly what the permutation version's
active-S-box counts show: 1, 2, 4, 6 over four rounds, barely more than doubling.

`lin444` is not a permutation — each output bit is an XOR of three input bits — so a
single active S-box is forced to spread much wider: 1, 4, 8, 10 over the same four
rounds. The S-box was already the good half of cipher-D's round, and the expensive
half. The permutation was the weak half, and the free half.

## Caveats

- The differential search for `(1, 15, 13)` was **not run**. It exists as the speed
  control, and since `lin444` costs nothing on cipher-D's fastest path there is no
  speed argument for preferring it over the stronger `(2, 9, 7)`.
- Rounds 5-8 for `(2, 9, 7)` were **not searched**. A non-permutation layer contributes
  clauses where a permutation contributes none, so the model is much harder: 400 s at
  four rounds against 2.6 s for the permutation version. The search was stopped once
  the weight passed 64, which is what the margin claim depends on; rounds 3 and 4 are
  exact.
- Everything here is **differential-only**, on single characteristics. cipher-D's
  differentials cluster heavily (about 7 bits for the permutation version, see
  [docs/cipher-D.md](cipher-D.md#clustering)), and no clustering measurement was made
  for the `lin444` variants. Nothing here addresses linear, algebraic, integral or
  related-key attacks.
- **The round count was not reduced.** The new margin is reported as margin, not spent.
  Cutting rounds to match PRESENT's 1.94x — which would be 8 rounds still, since 4 x
  1.94 = 7.8 — turns out not to leave room anyway, so the gain is best read as margin
  rather than as speed.

## Reproducing

```sh
make                                    # regenerates variants, kernels and circuits
make test
tools/compare.sh table-x8 9             # within-process ratios, the trustworthy view

python3 analysis/cli.py analyze --variant cipher-D-lin444-297 \
        --max-rounds 8 --stop-at-weight 64 --timeout 3600
```

Variant definitions: `variants/cipher-D-lin444-297.json`,
`variants/cipher-D-lin444-1-15-13.json`.

## Summary

| question | answer |
|---|---|
| Does `lin444` cost cipher-D anything? | no — 2.14x PRESENT's best against 2.17x, within noise |
| Why is it free bitsliced, when it costs PRESENT 1.8x? | 192 XORs against 8856 gates of S-box is 2.2% of the round |
| What does it buy? | 2^-64 proven in 4 rounds instead of 7 |
| Margin | 1.14x -> **2.00x**, past PRESENT's 1.94x |
| Bound over 8 rounds | 2^-77 -> **2^-136** |
| Which triple? | `(2,9,7)`, the strongest — the faster `(1,15,13)` has no advantage here |
