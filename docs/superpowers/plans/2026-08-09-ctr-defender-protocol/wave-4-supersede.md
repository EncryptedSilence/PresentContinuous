# Wave 4 — Supersede the old results and regenerate the tables

Runs last, after every campaign has produced its `summary.csv`. See [README.md](README.md) for global constraints.

---

## Task 8: Supersede the old results and wire up the manifest

**Files:**
- Modify: `results/speed.csv`, `results/speed-arm.csv`, `results/wide-speed-arm.csv`, `results/wide-speed-r4.csv`, `results/wide-speed-r5.csv`, `results/m4-speed.csv`, `results/gpu-speed.csv`, `results/gpu-speed-optimized.csv`, `results/gpu-speed-16m.csv`
- Modify: `artifact-manifest.json`, `docs/arm-optimizations.md`, `docs/m4-optimizations.md`, `docs/gpu-optimizations.md`, `docs/speed-at-equal-security.md`, `docs/lin444-experiment.md`
- Modify: `paper/tables/` (generated, not edited)

**Interfaces:**
- Consumes: every `results/v2/*/summary.csv` produced by Tasks 4b, 5, 6b and 7; `tools/make_tables.py` from Task 4a.

- [ ] **Step 1: Add the SUPERSEDED header**

As the first lines of each superseded CSV:

```
# SUPERSEDED by results/v2/<file>: this file measured the round function, not a
# complete CTR operation. Its bitsliced rows additionally assume the state was
# already transposed, which no byte-oriented caller can. Kept for provenance and
# for the round-function comparison it does support; do not quote it as
# achievable throughput.
```

Name the actual replacement file in each, not a placeholder. The GPU CSVs get a variant naming `results/v2/cuda/block-eval.csv` and stating that the metric was renamed from `tests/s` to block evaluations per second because that is what it always measured.

- [ ] **Step 2: Verify nothing still reads the old files as current**

Run: `grep -rn "results/speed-arm.csv\|results/m4-speed.csv\|results/wide-speed-arm.csv" docs/ paper/ README.md`
Expected: every remaining reference is either inside a superseded-file's own header, or in a document that Step 3 updates.

- [ ] **Step 3: Point each document at its replacement**

One sentence near the top of each affected document, naming the new file and what changed about the operation.

**Do not rewrite the analysis.** The reasoning about *why* a cipher is fast — the permutation folding into a store, the transpose being a fixed cost that does not shrink with round count, the register pressure on 32-bit ARM — is unaffected by the change of operation. Only the numbers move. Rewriting the prose would risk losing arguments that were already checked, which is the failure mode `docs/platform-estimate.md` exists to guard against.

`docs/platform-estimate.md` needs one specific update: its "ARM NEON / SVE2 bitsliced" row was an estimate, and Task 3 turns it into a measurement. Update that row and mark it `**measured**` like the others.

- [ ] **Step 4: Update the manifest**

`artifact-manifest.json` describes both sets and marks which is current. Every new file gets a `reproduction_command` — the single `tools/campaign.py` invocation that produced it — and a `classification` matching the existing vocabulary (`source`, `measured`, `derived`, `external`).

Run: `python3 tools/validate_artifact.py`
Expected: PASS with the new entries and no missing required paths.

- [ ] **Step 4b: Publish the kernel ceiling as its own artifact**

`bench/bench_main.c` is unchanged by this plan and still measures the round function with the state already bitsliced. That is a real and useful number; it just is not throughput. Point its output at `results/v2/kernel-ceiling-<target>.csv` and give it this header:

```
# Kernel ceiling: the round function with the state ALREADY BITSLICED, and with
# the transpose outside the timed region. No byte-oriented caller can reach these
# figures -- a caller must transpose in and out, which results/v2/<target>/summary.csv
# measures. Published so the gap between the two is visible rather than implied.
# Not comparable with the main table, and not a throughput figure.
```

Run: `./build/bench --csv results/v2/kernel-ceiling-x86.csv`
Expected: the file exists and every row exceeds its counterpart in `results/v2/x86/summary.csv`. If any ceiling row is *below* the CTR row for the same cipher and kernel family, something is wrong with one of the two harnesses — stop and investigate rather than publishing both.

- [ ] **Step 5: Regenerate the tables**

Run: `make tables && git diff --stat paper/tables/`
Expected: every table changed.

- [ ] **Step 6: Verify no hand-carried numbers survive**

For each numeric figure in a regenerated table, confirm it appears in some `results/v2/*/summary.csv`.

Run: `python3 tools/make_tables.py --check`
Expected: PASS. This mode re-derives every table from the CSVs and diffs against what is on disk, so a manually edited table fails. It is the mechanical form of the rule that no number reaches a paper table by hand — the mismatched-revision problem that `results/m4-speed.csv`'s own header documents is exactly what manual transfer produces.

- [ ] **Step 7: Run the whole suite**

Run: `make test`
Expected: every C test and both Python discovery roots pass — `analysis/tests` and `tools/tests`. Both invocations are needed; listing only the first is how `tools/tests/test_cipher_set.py` ran nowhere at all for twelve tasks.

- [ ] **Step 8: Commit**

```bash
git add results artifact-manifest.json docs paper/tables
git commit -m "Mark the round-function results superseded and regenerate the tables"
```

---

## Done criteria for the whole plan

- [ ] `make test` passes, including `test_ctr` with every registered backend and both Python discovery roots.
- [ ] Each of x86, A7, M4 and CUDA has a `results/v2/<target>/` directory containing `env.json`, `kat.json`, `runs.csv`, `tuning.json` and `summary.csv`, each produced by one command.
- [ ] Every `tuning.json` was committed **before** the corresponding `--measure` run, verifiable from `git log`.
- [ ] The main defender table reports complete CTR throughput in Mbit/s with intervals; the kernel ceiling is a separate artifact whose header says it is not attainable on byte-oriented data.
- [ ] All seven constructions have a bitslice row on both x86 and the A7.
- [ ] The M4's 12 Mbit/s verdict is stated explicitly, for the complete CTR operation.
- [ ] The attacker tables say **block evaluations/s** and **block evaluations in 4 h**; master-key candidates appear only for the three constructions that have a master-key schedule.
- [ ] `python3 tools/make_tables.py --check` passes, so no table contains a hand-carried number.
