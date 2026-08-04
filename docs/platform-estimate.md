# Which wins on which platform: 31-round PRESENT vs 16-round `lin444-297`

**This document is an estimate, not a measurement.** Only the x86-64 rows were measured
on the hardware in this repository (i9-14900HX, AVX2 + GFNI + VAES, no AVX-512); every
other row is reasoning from the structure of the two round functions and the instruction
set in question. Treat it as a prediction to be tested, not as a result. Everything that
*was* measured is in [lin444-experiment.md](lin444-experiment.md).

## The whole question in one line

**Does the platform's fastest implementation make a bit-permutation free?**

That is the only place PRESENT's pLayer has an advantage over a general linear layer,
and where it applies it is worth about 2x per round. Where it does not apply, `lin444`
costs nothing extra and the round reduction is pure profit.

The arithmetic is trivial: 31/16 = 1.94, so 16-round `lin444-297` wins if and only if
its per-round penalty is below **1.94x**.

## Estimate

`p` is the per-round cost of `lin444-297` relative to PRESENT's round. The last column
is total time for 16-round `lin444-297` divided by total time for 31-round PRESENT, so
**below 1.00 means `lin444` is faster**.

| platform / implementation | `p` | 16r vs 31r | basis |
|---|---|---|---|
| AVX2 bitsliced | 2.0x | ~1.03 — dead tie | **measured** |
| AVX-512 bitsliced | 2.0–2.2x | ~1.05–1.15, PRESENT | estimate |
| ARM NEON / SVE2 bitsliced | 1.8–2.1x | ~0.95–1.10 — tie | estimate |
| scalar 64-bit bitsliced | 1.50x | ~0.77 — `lin444` by 1.3x | **measured** |
| any table-driven path (x86, ARM, 32-bit MCU) | 1.0x | ~0.50 — `lin444` by 2x | **measured** |
| 8-bit MCU (AVR, 8051) | ~0.5–1.0x | ~0.25–0.5 — `lin444` by 2–4x | estimate, least confident |
| hardware, round-based | ~2x area, 1.0x latency | 1.9x faster at ~2x the gates | structural |

## Reasoning, per platform

### AVX2 bitsliced — measured, a tie

A `lin444` round costs exactly 2.0x a PRESENT round on the round function alone
(`avx2-bs`: 2.13 against 1.03 cyc/B). 16 rounds against 31 gives 1.03 — PRESENT ahead by
a nose, inside the noise. The shipped `297-r18` measures 1.164x, and dropping two rounds
from that accounts for the difference.

This is `lin444`'s **worst case**, and it is worth understanding why: the permutation is
folded into a store that had to happen anyway, so it issues no instructions at all, while
`lin444` must run its XOR chain no matter what. Both variants also pay the same fixed
0.31 cyc/B for the two transposes, which does not shrink when rounds are cut — so the
fixed cost is a headwind for the reduced-round variant specifically.

### AVX-512 bitsliced — slightly *worse* for `lin444`

Counter-intuitive, but it follows from what `vpternlogd` compresses. A 4-term XOR chain
goes 3 ops to 2, a 33% cut. An S-box circuit typically compresses by more like 40–50%,
because arbitrary 3-input boolean functions are exactly what a synthesised circuit is
full of. Shrinking the part both variants *share* by more than the part only `lin444`
pays makes the ratio worse, not better.

Working against that: 32 zmm registers instead of 16 ymm. The state is 64 x 64 B = 4 KiB
either way, so neither variant fits, but `lin444`'s temporaries have somewhere to live
that they do not on AVX2. Net: about the same as AVX2, plausibly a shade worse.

### ARM NEON / SVE2 bitsliced — a tie

Structurally the same story. `EOR3` (ARMv8.2-SHA3) is the `vpternlogd` case for XOR
chains, and `BCAX` covers the S-box's AND-XOR patterns, so both sides compress in the
same proportions as on AVX-512. NEON's 128-bit vectors mean the bitsliced state spills
more relative to the register file, which slightly favours whichever variant needs fewer
live temporaries — PRESENT. SVE2 at 256 bits and above converges on the AVX2 picture.

Call it a tie, with the sign depending on the specific core's port counts.

### Scalar 64-bit bitsliced — measured, `lin444` by 1.3x

`p` is only 1.50x here, well under 1.94, so 16 rounds wins by about 1.3x.

The reason `p` is so much lower than on AVX2 is that the permutation is **not** free on
this path: with 16 general-purpose registers the round function keeps its bit-planes in
an array, so the pLayer costs a real copy of 64 words through the permutation.
`lin444`'s marginal cost is measured against a baseline that is already paying something.

Note the spread across constants is much wider here — 1.49x for `(2,9,7)`, 2.18x for
`(2,1,3)` — because on a register-starved path the deciding factor is how many
temporaries the triple needs, not how many XORs it saves. `(2,9,7)` happens to be at the
good end.

### Table-driven, any platform — measured, `lin444` by ~2x

`p` = 1.0, exactly. Fusing the linear layer into the lookup tables works for *any*
GF(2)-linear layer: linearity is the statement that `L(x)` is the XOR of `L` applied to
each byte of `x` in isolation, so the round stays eight lookups XORed together whatever
the layer does. The whole cost moves into the one-off table build.

So the round reduction is unopposed. `297-r18` already measures 13.14 against PRESENT's
23.86 cyc/B on the single-block table path (0.55x); at 16 rounds it would be about 0.49x.

This is the largest and best-supported win, and it covers a lot of real deployments:
anything single-block, latency-bound, or without a usable SIMD unit.

### 8-bit MCU — estimate, `lin444` by 2–4x, lowest confidence

This should be `lin444`'s best platform and it is the row I would least trust without
measuring.

PRESENT's pLayer is genuinely hostile to an 8-bit core. Done directly it is 64
bit-extract/bit-insert pairs per round; done by table it wants flash you may not have.
`lin444` is twelve rotations of 16-bit words by compile-time constants plus twelve
16-bit XORs — ordinary register work, no tables, no bit addressing. It is entirely
plausible that a `lin444` round is *cheaper* than a PRESENT round on AVR, i.e. `p` < 1,
in which case the 1.94x round saving is profit on top of a per-round saving.

Published AVR figures for PRESENT vary by nearly an order of magnitude depending on how
much flash the implementation is allowed for pLayer tables, which is itself the tell:
the permutation dominates. The range in the table reflects that uncertainty, not a
measurement.

### Hardware, round-based — `lin444` loses

The one clear loss, and it is the case PRESENT was designed for.

In silicon the pLayer is free wiring: zero gates, zero delay beyond routing. `lin444`
costs ~192 XOR gates per round, roughly 480 GE, against a round function of 16 S-boxes
at ~28 GE each — so it roughly doubles the combinational area of a round.

A round-based (serial) implementation would finish in 16 clocks instead of 31, so ~1.9x
the throughput, but at ~2x the round-function area. Fully unrolled it is a wash on area
and 1.9x on latency. Either way, on the area-per-bit metric lightweight hardware ciphers
are actually judged on, `lin444` gives up the thing PRESENT exists to provide.

## Two caveats on the premise

**16 rounds is currently one round optimistic for `(2,9,7)`.** Its proven margin at 16
rounds is 16/9 = 1.78x against PRESENT's 1.94x. The shipped equal-margin variant is
`297-r18` for that reason. The `9` is conservative — round 4 exhausted its 1800s budget
and returned a bound rather than an exact weight — and if it resolves at weight 38 then
`rounds@64` becomes 8 and 16 rounds is a clean 2.00x margin. `(0,1,3)` at 16 rounds is
matched today, at a per-round penalty about 3% higher than `(2,9,7)`'s.

**The margin being spent is differential-only.** `rounds@64` is what the SAT search
*proves* about single characteristics. Cutting 31 rounds to 16 also spends the margin
that has to cover differential clustering, linear cryptanalysis, algebraic and
related-key attacks — none of which this harness measures — and the key schedule is
unchanged from one designed around PRESENT's pLayer. The round reduction is the
aggressive half of this trade; the speed estimate above is the easy half.

## Summary

If the target is a bitsliced SIMD implementation, it is a wash and PRESENT is the simpler
choice. Anywhere else — tables, scalar, small cores — `lin444` at reduced rounds is a
real 1.3–2x win, and the smaller the machine the larger it gets. Only in silicon does it
clearly lose.

To turn any estimated row into a measured one: the harness already generates every
implementation from the variant JSON, so a new backend needs only a round-function port,
and `tools/compare.sh <impl>` will produce the ratio directly.
