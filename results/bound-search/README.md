# The open bound: present-80-lin444-297

Every other cipher in [docs/speed-at-equal-security.md](../../docs/speed-at-equal-security.md)
has its `rounds@64` pinned by a single `prove_bound` call. This one does not, and this
directory is the record of the attempt to close it.

## Result: rounds@64 = 6, X = 7

Closed. **0.502 cyc/B**, against PRESENT-80's 0.553 — a 1.10× lead at equal proven margin.

| fact | how |
|---|---|
| W(1) = 2, W(2) = 12, W(3) = 29 | exact, `analyze` |
| W(4) ≤ 49 | verified witness, `w4-trail.txt` — rules out 4 rounds |
| W(5) ≤ 63 | verified witness, `w5-trail.txt` — rules out 5 rounds |
| **every 6-round characteristic ≥ 64** | **UNSAT, proven twice: 20002 s and 20719 s** |

Both witnesses were replayed through the real S-box and linear layer before being accepted —
`w4-trail.txt` via `prove_bound.py`, `w5-trail.txt` via `check_witness.py`, which also
re-checks all 46097 clauses against the assignment the external solver returned.

Composition could not have produced this. Splitting a 6-round characteristic on any boundary
gives at most W(4) + W(2) ≤ 61 or W(3) + W(3) = 58, both short of 64, whatever W(4) turns out
to be. The direct proof was the only route.

## The search

The first attempts were one cadical thread per probe and returned UNKNOWN at their budgets:
5 rounds and 6 rounds at 7200 s each, plus 5 and 6 rounds in `--mode active` at 5400 s.

CDCL runtimes on hard combinatorial UNSAT are heavy-tailed, so N randomised copies for time T
beat one copy for N·T. The run that succeeded was a 31-thread portfolio over kissat 4.0.4 and
cadical 3.0.1, both with `--unsat`, one seed per thread. Six of those threads carried the
6-round instance and the outcome was decisively lopsided:

| thread | result at 20002 s |
|---|---|
| cadical seed=1005 | **UNSAT** |
| cadical seed=1001, 1003 | still running |
| kissat seed=1000, 1002, 1004 | still running |

One seed in six, and the five siblings had to be killed. A single thread was never going to
be the right way to spend this budget — the instance was not out of reach, the search was
just serialised.

The proof was then re-run from scratch on six fresh seeds as an independent check, and
**cadical seed=4005 returned UNSAT at 20719 s** — a second search trajectory, same answer.
Both rows are in `../rounds-at-64.csv`.

Across both batches the solver split is worth recording, because it inverts the calibration:

| solver | attempts on the 6-round instance | solved |
|---|---:|---:|
| cadical | 6 | **2** |
| kissat | 6 | 0 |

kissat won every calibration instance in the table above and then lost this one twelve times
over — while taking the 5-round instance, which cadical lost 25 times. Rankings measured on
instances that finish in minutes do not transfer to the ones that take hours, and neither
solver dominates: at this difficulty the seed matters at least as much as the binary, which is
the argument for a mixed portfolio rather than for picking a winner.

## Final tally

Across the whole run, 64 threads and roughly 380 core-hours:

| instance | threads | answered | time |
|---|---:|---:|---|
| 6 rounds, weight ≥ 64 | 12 | 2 UNSAT | 20002 s, 20719 s |
| 5 rounds, weight ≥ 64 | 32 | 1 SAT | 36688 s |
| 4 rounds, weight ≥ 50 | 4 | 1 SAT | 226 s |
| `r5 ≥ 56/58/60/62` rungs | 15 | none | killed as dominated once 6 rounds landed |

Three answers out of 64 threads. That ratio is the case for the portfolio: any one of those
threads run alone, for any budget short of ten hours, would most likely have returned nothing.

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

The 6-round proof, on the winning seed — expect it to take about 5.5 hours:

    python3 analysis/dump_cnf.py --variant present-80-lin444-297 --rounds 6 --weight 64 \
            --out r6.cnf
    third_party/cadical/build/cadical --unsat --seed=1005 r6.cnf     # UNSAT, ~20000 s

Other seeds may take much longer or not finish; that is the nature of the instance, not a
sign of a bad build. To re-run the whole portfolio rather than the one winner, use several
seeds across both solvers in parallel and take the first answer.

The open 5-round probe:

    python3 analysis/dump_cnf.py --variant present-80-lin444-297 --rounds 5 --weight 64 \
            --out r5.cnf
    third_party/kissat/build/kissat --unsat --seed=N r5.cnf
