# Cost at equal differential margin

Seven ciphers, each cut to the same proven differential margin, each measured with its own
best software kernel, all in cycles per byte.

Comparing ciphers at their designed round counts answers the wrong question. PRESENT-80 runs
31 rounds and cipher-D runs 8; whichever comes out faster, the number mostly reflects that
choice of round count, not the cost of the round function or how much security each round
buys. So every cipher here is cut to the **same** point:

> **X = (fewest rounds for which the SAT model proves every differential characteristic has
> probability at most 2^-64) + 1.**

One round of margin over the proof, for all of them. That round count is settled by
`analysis/prove_bound.py`, one solver call per round count — see
[How X is decided](#how-x-is-decided) for the method, the results, and what it does not cover.

Ground rules for the speed side:

- **No hardware GF acceleration.** No AES-NI, no GFNI, no VAES. Every kernel is AVX2 or
  narrower general-purpose SIMD.
- **Best kernel per cipher**, picked from the full set each was measured with rather than
  fixed in advance. Which kernel wins is not the same for all of them, and forcing one would
  be its own unfairness.
- **Same measurement protocol** for the 64-bit and 128-bit programs: 64 KiB working set, 3
  warm-up passes, median of 15 trials, TSC cycles, pinned to one core, machine otherwise idle.

---

## The table

Cost of encrypting a byte, each cipher at its equal-margin round count X.

| cipher | block | X | cyc/B | cyc/B per round |
|---|---:|---:|---:|---:|
| **PRESENT-lin444-297** | 64 | 7 | **0.502** | 0.072 |
| **PRESENT-80** | 64 | 16 | **0.553** | 0.035 |
| **cipher-D-AES** | 64 | 5 | **0.868** | 0.174 |
| **AES-lin444** | 128 | 4 | **1.185** | 0.296 |
| **AES** | 128 | 5 | **1.269** | 0.254 |
| **cipher-D-lin444-297** | 64 | 5 | **1.531** | 0.306 |
| **cipher-D** | 64 | 8 | **2.415** | 0.302 |

Every X here is pinned exactly, and PRESENT-lin444-297's took by far the most work to get —
see [How X is decided](#how-x-is-decided). **Replacing PRESENT's bit permutation with lin444
buys more security per round than it costs in speed**: the round is 2.0× dearer (0.072 against
0.035 cyc/B) but the cipher reaches the same proven margin in 7 rounds instead of 16, and the
2.3× reduction in rounds more than pays for it.

The same seven at the round counts their designs actually specify, for reference:

| cipher | block | rounds | cyc/B | vs. its own X row |
|---|---:|---:|---:|---:|
| cipher-D-AES-r5 | 64 | 5 | 0.868 | — (r5 *is* X) |
| PRESENT-80 | 64 | 31 | 1.046 | 1.89× the 16-round cost |
| cipher-D-AES | 64 | 8 | 1.501 | 1.73× |
| PRESENT-lin444-297 | 64 | 31 | 2.118 | 4.22× |
| cipher-D-lin444-297 | 64 | 8 | 2.382 | 1.56× |
| cipher-D | 64 | 8 | 2.415 | — (8 *is* X) |

The figure that motivated this document is in there: **cipher-D-AES-r5 at 0.868 cyc/B is the
fastest of the cipher-D family, and it is still 1.57× the cost of PRESENT-80 run at the same
margin.** Against PRESENT-80 *as designed* (31 rounds, 1.046) it looks like a clear win; at
equal margin it is not.

---

## Relative cost

Normalised to PRESENT-80 at X = 16, the reference the rest of the repository is written
against. Every X below is pinned exactly.

| cipher | opt. method | complexity (cyc/B) | relative | block | const-time |
|---|---|---:|---:|---:|:--:|
| PRESENT-lin444-297-r7 | AVX2 bitslice, 256 blocks | 0.502 | **0.91×** | 64 | yes |
| PRESENT-80-r16 | AVX2 bitslice, 256 blocks | 0.553 | **1.00×** | 64 | yes |
| cipher-D-AES-r5 | AVX2 bitslice, 256 blocks | 0.868 | 1.57× | 64 | yes |
| AES-lin444-r4 | AVX2 bitslice, 256 blocks | 1.185 | 2.14× | 128 | yes |
| AES-r5 | AVX2 bitslice, 256 blocks | 1.269 | 2.29× | 128 | yes |
| cipher-D-lin444-297-r5 | T-table, 8 blocks interleaved | 1.531 | 2.77× | 64 | no |
| cipher-D-r8 | T-table, 8 blocks interleaved | 2.415 | 4.37× | 64 | no |

PRESENT-lin444-297 is the only row below the reference: at equal proven margin it costs 0.91×
what PRESENT-80 does, a 1.10× speed advantage.

The two rows that fall back to tables are the ones built on the searched 8-bit S-box. Its best
bitslice circuit is **1117 gates**; the AES S-box's published Boyar-Peralta circuit is **132**.
That 8.5× difference decides whether a cipher can use the bitslice kernel at all, and it is
why cipher-D-AES is 1.6-1.8× the speed of cipher-D-lin444-297 at the same round count with the
same linear layer (1.59× at 8 rounds, 1.76× at 5). It is a property of the S-box's algebraic
structure, not of its differential quality — the two S-boxes tie on differential uniformity,
linearity and degree, and cipher-D's is *better* on branch number.

### Where the cost actually goes

The `cyc/B per round` column spans 8.7× (0.035 to 0.306) while the round counts span 4× the
other way (16 down to 4). The ranking is decided by the round function, not by how few rounds
a design needs — with one exception, PRESENT-80, which is cheapest *despite* needing the most
rounds by a wide margin.

| | cyc/B per round | why |
|---|---:|---|
| PRESENT-80 | 0.035 | 4-bit S-box, 15 gates for 4 state bits, and a bit permutation is free in bitslice — it is a rename, not an instruction |
| PRESENT-lin444-297 | 0.071 | same S-box; lin444 costs 3 XORs per state bit that the permutation did not, and that doubles the round |
| cipher-D-AES | 0.174 | 132 gates per 8 state bits = 16.5 gates/bit, 4.4× PRESENT's 3.75 |
| AES | 0.254 | same S-box cost per byte, plus MixColumns (~20% of the round) and a heavier transpose for a 128-bit block |
| AES-lin444 | 0.296 | same S-box cost per byte, but a dearer linear layer than AES's despite doing *fewer* XORs (384 against MixColumns' 528) — the rotation amounts arrive at run time, so each operand is an indexed load rather than an immediate offset |
| cipher-D-lin444-297 | 0.306 | 8-bit searched S-box; no viable bitslice, so this is table-bound |
| cipher-D | 0.302 | same, and the pLayer is free in the table kernel too, so it ties lin444 |

---

## How X is decided

For each cipher and round count r, one solver call asks: *is there an r-round differential
characteristic of weight ≤ 63?* SAT returns one, and it is replayed against the cipher before
being believed. UNSAT proves every r-round characteristic costs at least 2^-64. `rounds@64` is
the smallest r that comes back UNSAT.

Results, from [results/rounds-at-64.csv](../results/rounds-at-64.csv):

| cipher | r−1: witness found | r: proven | rounds@64 | X |
|---|---|---|---:|---:|
| PRESENT-80 | 14 rounds, weight 62 | 15 rounds | 15 | 16 |
| PRESENT-lin444-297 | 5 rounds, weight 63 | 6 rounds | 6 | 7 |
| cipher-D | 6 rounds, weight 60 | 7 rounds | 7 | 8 |
| cipher-D-lin444-297 | 3 rounds, weight 63 | 4 rounds | 4 | 5 |
| cipher-D-AES | 3 rounds, weight 57 | 4 rounds | 4 | 5 |
| AES | 3 rounds, weight 57 | 4 rounds | 4 | 5 |
| AES-lin444 (0,8,15) | 2 rounds, weight 63 | 3 rounds | 3 | 4 |
| AES-lin444 (1,10,15) | 3 rounds, weight 63 | 4 rounds | 4 | 5 |

Two things about this method are worth stating, because both changed the answer.

**It is tighter than the window bound.** `results/report.md` derives its `rounds@64` column by
multiplying an exact W(r) across disjoint windows, which is only as good as the deepest exact
search — for PRESENT-80 it reports 16 where the direct question answers 15, and for
AES-lin444 (0,8,15) it reports 4 where the answer is 3. It is also much cheaper: the direct
call proves PRESENT-80's 15-round bound in 90 seconds, where pinning W(15) exactly is a ladder
of calls that was never going to finish.

**The rotation constants move the round count, not just the speed.** AES-lin444 with
`c0 = (0,8,15)` reaches 2^-64 in three rounds; with `c0 = (1,10,15)` it needs four. Both have
identical 1- and 2-round optima (weight 6 and 36), so the difference only shows up at depth
three, where the (0,8,15) trail the solver returns has 13 active S-boxes against (1,10,15)'s 9.
That is a full round of margin from the choice of three constants, and it is why the table
reports the (0,8,15) set: at X = 4 it costs 1.185 cyc/B against 1.501 for the other at X = 5.

**The row that cost the most.** PRESENT-lin444-297's `rounds@64 = 6` needed three results, not
one: a verified weight-49 characteristic at 4 rounds, a verified weight-63 one at 5 rounds
(both ruling those round counts out), and the 6-round UNSAT. These were the failures along the
way:

| attempt | budget | outcome |
|---|---:|---|
| 6 rounds, weight ≥ 64, one cadical thread | 2 h | no answer |
| 5 rounds, weight ≥ 64, one cadical thread | 2 h | no answer |
| 6 rounds, via ≥ 32 active S-boxes | 1.5 h | no answer |
| 5 rounds, via ≥ 32 active S-boxes | 1.5 h | a 31-active characteristic exists, so this route cannot prove it |

and this was the success: a **31-thread randomised portfolio** over kissat 4.0.4 and cadical
3.0.1, both with `--unsat` and one seed per thread. Six threads carried the 6-round instance;
`cadical --seed=1005` returned UNSAT at **20002 s**, while the other five — including three
kissat threads — were still running at that moment and had to be killed. Re-running the proof
on six fresh seeds as an independent check reproduced it: `cadical --seed=4005`, UNSAT at
**20719 s**.

The 5-round question then took another 36688 s, and answered **SAT**: a weight-63
characteristic exists, so 5 rounds do not reach the margin and `rounds@64` is exactly 6. That
witness was replayed through the cipher by `analysis/check_witness.py` before being accepted,
the same check every SAT answer here gets.

The spread across threads is the whole point. CDCL runtimes on hard combinatorial UNSAT are
heavy-tailed, so N randomised copies for time T beat one copy for time N·T — of the 64 threads
spent on these two instances, 3 answered and 61 did not. The instances were never out of
reach; a single thread was simply the wrong way to spend the budget.

Which solver to run is less obvious than the calibration below suggests. kissat won all four
calibration instances, then lost the 6-round instance twelve times over while cadical took it
twice in six; and the 5-round instance went the other way, to kissat. Rankings measured on
instances that finish in minutes did not transfer to the ones that took hours, which is an
argument for a mixed portfolio rather than for picking a winner.

Composition could not have closed it. The 4-round optimum is at most 49 — a weight-49
characteristic exists, found directly and replayed against the cipher — so W(4) + W(2) ≤ 61
and W(3) + W(3) = 58, both short of 64. Six rounds cannot be reached by splitting on any
boundary, whatever W(4) turns out to be. The direct proof was the only route.

See [results/bound-search/](../results/bound-search/) for the full search record, including
both verified characteristics.

### What the bound covers

Single-trail differential characteristics, at every round count, with no key-schedule
assumption — the SAT model gives each round an independent key, which is the assumption most
favourable to the attacker. It does **not** cover linear cryptanalysis, differential
clustering into differentials, related-key attacks, or any structural attack. X is a
comparison yardstick applied to all seven on identical terms; it is not a claim that any of
them is secure at X rounds. The `+1` is the entire safety margin, far less than any of these
designs ships with.

"AES reduced to 5 rounds" in particular is not a cipher anyone should use. It is AES's round
function priced at the same yardstick as everything else, which is the only way the comparison
becomes legible.

---

## Every kernel, not just the winner

64-bit block ciphers, one `build/bench` run so the rows share a process and are directly
comparable (cyc/B; **bold** = the kernel the tables above use):

| variant | r | table | table-x4 | table-x8 | table-x16 | bitslice | bitslice-bs | avx2 | avx2-bs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| present-80 | 31 | 25.54 | 9.81 | 9.24 | 9.61 | 5.54 | 2.78 | 1.29 | **1.05** |
| present-80-r16 | 16 | 13.14 | 4.84 | 4.27 | 4.76 | 3.55 | 1.45 | 0.81 | **0.55** |
| present-80-lin444-297 | 31 | 26.45 | 9.55 | 8.69 | 9.21 | 8.50 | 5.97 | 2.63 | **2.12** |
| present-80-lin444-297-r6 | 6 | 4.96 | 1.77 | 1.66 | 1.79 | 2.95 | 1.17 | 0.70 | **0.43** |
| present-80-lin444-297-r7 | 7 | 5.76 | 2.05 | 1.98 | 2.08 | 3.13 | 1.36 | 0.77 | **0.50** |
| present-80-lin444-297-r8 | 8 | 6.72 | 2.34 | 2.24 | 2.37 | 3.33 | 1.55 | 0.84 | **0.57** |
| cipher-D | 8 | 6.58 | 2.51 | **2.42** | 2.57 | 16.77 | 16.15 | 6.72 | 6.31 |
| cipher-D-lin444-297 | 8 | 6.94 | 2.56 | **2.38** | 2.58 | 18.25 | 16.44 | 7.25 | 7.00 |
| cipher-D-lin444-297-r5 | 5 | 4.32 | 1.57 | **1.53** | 1.66 | 12.72 | 10.57 | 4.53 | 4.47 |
| cipher-D-lin444-297-aes | 8 | 6.76 | 2.33 | 2.25 | 2.59 | 4.47 | 2.49 | 1.79 | **1.50** |
| cipher-D-lin444-297-aes-r5 | 5 | 4.18 | 1.51 | 1.43 | 1.51 | 3.66 | 1.68 | 1.13 | **0.87** |

128-bit block ciphers, `build/wide_bench`, median of 5 whole-program runs (10 for `aes` at
r = 5, which both rotation-set runs measure). The CSVs in `results/` hold the final single run
rather than the median, so individual cells there differ by a few percent — for `aes` at r = 4
the single run reads 1.149 against the 1.070 median, the widest gap in the set:

| cipher | r | table | table-x4 | table-x8 | table-x16 | avx2-bs |
|---|---:|---:|---:|---:|---:|---:|
| aes | 4 | 2.00 | 1.43 | 1.43 | — | **1.07** |
| aes | 5 | 2.36 | 1.69 | 1.69 | — | **1.27** |
| aes-lin444, c0 = (0,8,15) | 4 | 3.24 | 1.99 | 1.95 | 1.92 | **1.19** |
| aes-lin444, c0 = (0,8,15) | 5 | 4.37 | 2.46 | 2.42 | 2.39 | **1.47** |
| aes-lin444, c0 = (1,10,15) | 5 | 4.38 | 2.51 | 2.46 | 2.48 | **1.50** |

The two rotation sets are within 2% of each other on every kernel — they differ in security,
not in cost. Rotation amounts are baked into the table at setup, so they cannot affect the
table kernels at all; the small gap in the bitslice kernel is index arithmetic.

The `bitslice`/`avx2` columns include the bit transposes and the `-bs` ones do not. The `-bs`
form is the right one to quote for counter-mode-style bulk encryption, where the caller keeps
its state bitsliced across calls. Both are shown because the difference between them is the
transpose cost, and at these short round counts it is a large fraction of the total —
for present-80-r16 it is 0.26 of 0.81.

---

## Cross-checks

The 128-bit kernels are new code, so they are anchored two ways.

**Correctness.** `build/wide_bench` times nothing until: AES matches the FIPS-197 C.1
known-answer vector; AES-lin444 matches a scalar reference written straight from its
definition; and every interleaved and bitsliced kernel matches the single-block one on random
inputs at every round count it will time. The bitslice kernel transposes, substitutes and
mixes along entirely different axes from the table kernel, so agreement on 256 random blocks
at 11 round counts is a real check of the plane indexing.

Its AES S-box is the generated `present_circuit8_avx2_c2`, included from
`src/gen/sbox_circuits.h` — the same circuit the 64-bit variants use, so the substitution
layer is literally the same code on both sides of the comparison rather than a second
implementation of it.

`analysis/prove_bound.py` is checked against the independently computed exact optima in
`results/*-differential.csv`: for cipher-D it reports 6 rounds SAT and 7 rounds UNSAT, against
a table that says W(6) = 51 and W(7) = 64. Its `--mode active` path reproduces cipher-D's
known `min_active = 10` at 7 rounds.

**Speed.** Against `QalqanSpeed/docs/2026-05-25-qalqan-encryption-optimization-report.md`,
which measured the same two constructions on different hardware with MSVC:

| | there | here | note |
|---|---:|---:|---|
| AES T-table ×4, 14 rounds | 6.01 | 4.28 | same construction; this machine and gcc are faster |
| lin444 T-table, 16 rounds | 7.92 (×8) | 8.28 (×4) | within 5%, and 𝓜 there carries two extra modular-add key layers |
| lin444 AVX2 bitslice, 16 rounds | 11.30 | 4.32 | 2.6× — that report's bitslice is over 128 bit-planes, this one over 256 |

The T-table agreement is what validates the port. The bitslice difference is why this document
does not simply reuse that report's numbers: at 128 planes the bitslice loses to T-tables, at
256 it wins decisively, and which is true changes the answer.

---

## Caveats

- **PRESENT-lin444-297 leads by 1.10×**, which is close enough to be worth reading alongside
  the run-to-run drift caveat below. It is a within-table comparison — both rows come from one
  `bench` process — so it is on the tight side of that, but it is not a wide margin.
- **Cross-program comparison carries a few percent.** The 64-bit and 128-bit figures come from
  two programs. They share a protocol and a core, but run-to-run drift is 5-10% even on an
  idle machine, so treat gaps under ~10% as ties — AES-lin444-r4 against AES-r5, or cipher-D
  against cipher-D-lin444-297 at 8 rounds. Comparisons *within* one table are much tighter,
  since those rows share a process.
- **`-bs` kernels assume bitsliced state at the boundary.** They suit bulk counter-mode
  encryption, not single-block latency. For a single block every cipher here is latency-bound
  and the ranking is different.
- **The 8-bit searched S-box may not be at its floor.** Its 1117-gate circuit comes from BDD
  synthesis over all 8! variable orders, the best this repository can do. A hand-derived
  tower-field construction like Boyar-Peralta's for AES could be far smaller and would move
  cipher-D and cipher-D-lin444-297 onto the bitslice kernel. Their table-bound rows are a fact
  about the circuit that was found, not a proof that none is better.
- **X is a yardstick, not a security level.** See [What the bound covers](#what-the-bound-covers).

---

## Reproducing

```sh
make                                    # build everything, generate the circuits
taskset -c 2 ./build/bench --csv results/speed.csv
taskset -c 2 ./build/wide_bench --rounds 4 --c0 0 8 15 --csv results/wide-speed-r4.csv
taskset -c 2 ./build/wide_bench --rounds 5 --c0 0 8 15 --csv results/wide-speed-r5.csv
taskset -c 2 ./build/wide_bench --rounds 5 --c0 1 10 15      # the other rotation set
tools/compare.sh avx2-bs 51             # within-process ratios, immune to TSC drift

# the security side: one call per (cipher, round count)
python3 analysis/prove_bound.py --variant present-80 --rounds 15 --weight 64 \
        --csv results/rounds-at-64.csv
python3 analysis/prove_bound.py --variants-dir variants/wide \
        --variant aes-lin444-0-8-15 --rounds 3 --weight 64
```

The 128-bit variants live in `variants/wide/` rather than `variants/`, because the C pipeline
is 64-bit throughout and only the SAT model is width-agnostic; `load_all()` does not walk into
subdirectories, so the code generator never sees them.

Machine: i9-14900HX, gcc 13.3.0, `-O3 -march=native` (→ `alderlake`), pinned to core 2,
Linux 6.17, otherwise idle. The exact toolchain, commit, firmware and power configuration are
in [measurement-environment.md](measurement-environment.md) — read its caveats before quoting
absolute figures anywhere: **`cyc/B` here counts nominal TSC ticks at ≈ 2.42 GHz, not core
cycles**, so true cycles per byte are up to ~2.3× these numbers. Ratios within this document
are unaffected.
