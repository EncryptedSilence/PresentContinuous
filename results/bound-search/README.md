# The open bound: present-80-lin444-297

Every other cipher in [docs/speed-at-equal-security.md](../../docs/speed-at-equal-security.md)
has its `rounds@64` pinned by a single `prove_bound` call. This one does not, and this
directory is the record of the attempt to close it.

## What is established

| fact | how |
|---|---|
| W(1) = 2, W(2) = 12, W(3) = 29 | exact, `analyze` |
| W(4) ∈ [38, 49] | lower from 19 active S-boxes × 2; upper from the verified witness in `w4-trail.txt` |
| rounds@64 ≥ 5 | a 4-round characteristic of weight 63 exists |
| rounds@64 ≤ 7 | W(3) + W(4) ≥ 29 + 38 = 67 over two disjoint windows |

So **X ∈ [6, 8]**, and the measured speeds for that bracket (0.434 / 0.502 / 0.569 cyc/B)
straddle PRESENT-80's 0.553 — which is why this one bound decides the top of the table.

## What would settle it

Composition is exhausted. Splitting a 6-round characteristic on any boundary gives at most
W(4) + W(2) ≤ 61 or W(3) + W(3) = 58, both short of 64, and that holds whatever W(4) turns
out to be. Only two questions remain, and either one is enough:

| probe | UNSAT proves | X | cyc/B |
|---|---|---:|---:|
| `--rounds 5 --weight 64` | rounds@64 = 5 | 6 | 0.434 |
| `--rounds 5 --weight 62` | W(6) ≥ W(5) + W(1) ≥ 64 | ≤ 7 | ≤ 0.502 |
| `--rounds 6 --weight 64` | rounds@64 ≤ 6 | 7 | 0.502 |

All three beat PRESENT-80. Only the failure of all three leaves X = 8 open.

A **SAT** answer on the `r5 ≥ 56/58/60` rungs is also informative: it caps W(5) below 62 and
kills the composition route, leaving the direct 6-round probe as the only path.

## The search

The first attempts were one cadical thread per probe and returned UNKNOWN at their budgets:
5 rounds and 6 rounds at 7200s each, plus 5 and 6 rounds in `--mode active` at 5400s. CDCL
runtimes on hard combinatorial UNSAT are heavy-tailed, so N randomised copies for time T beat
one copy for N·T — the current run is a 31-thread portfolio over kissat 4.0.4 and cadical
3.0.1, both with `--unsat` and varied seeds, on a 12-hour budget.

Solver choice was measured rather than assumed, on four instances with known answers:

| instance | kissat | cadical | cryptominisat 5.11.15 |
|---|---:|---:|---:|
| cipher-D r7 | **20.1s** | 19.2s | 62.2s |
| cipher-D-lin444-297 r4 | **24.0s** | 31.9s | 52.9s |
| present-80 r15 | **37.9s** | 58.4s | 91.8s |
| aes-lin444-0-8-15 r3 | **346.1s** | 352.0s | 498.5s |

CryptoMiniSat loses on all four despite its native XOR/Gauss support, and loses by the least
on the *most* XOR-dense instance — the opposite of what a Gauss win looks like. The hard part
of these formulas is cardinality reasoning over S-box weights, not the linear layer. kissat is
the pick, worth up to 1.54× over the cadical everything else was run on.

GPUs do not apply. UNSAT proofs come only from CDCL, which is latency-bound pointer-chasing
over a mutating clause database; GPU-friendly local search can find a satisfying assignment
but can never prove one absent.

## Files

    README.md        this
    w4-trail.txt     the verified weight-49 four-round characteristic
    results.csv      one row per portfolio job: instance, solver, seed, status, seconds
    decided.log      instances that reached SAT or UNSAT, with the winning solver and seed

`results.csv` and `decided.log` are mirrored from the live run and are the artefacts to read
once it finishes. Any decided row should be reproduced through `analysis/prove_bound.py`
before being quoted, so the witness gets replayed against the cipher.

## Reproducing

    python3 analysis/dump_cnf.py --variant present-80-lin444-297 --rounds 5 --weight 62 \
            --out r5-w62.cnf
    third_party/kissat/build/kissat --unsat --seed=1000 r5-w62.cnf
