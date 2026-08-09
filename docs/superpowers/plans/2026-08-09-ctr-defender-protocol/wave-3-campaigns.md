# Wave 3 — Statistics and measurement campaigns

Task 7 is pure Python and blocks the three campaign tasks. Tasks 8, 9 and 10 split into a development half (parallel) and a measurement half (Wave 4, strictly serial for x86 and CUDA). See [README.md](README.md) for global constraints.

---

## Task 7: Statistics and table generation

**Files:**
- Create: `tools/summarize.py`, `tools/make_tables.py`, `tools/tests/test_summarize.py`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `runs.csv` with columns `run_index,order_index,cipher,impl,size_bytes,mbit_per_sec,temp_c,freq_khz`.
- Produces, in `tools/summarize.py`:
  - `median_ci(values, resamples=10000, seed=0) -> (median, lo, hi)`
  - `paired_ratio_ci(runs, cipher, baseline, resamples=10000, seed=0) -> (median, lo, hi)`
  - `top_group(stats) -> list[str]` where each `stats` entry has keys `cipher`, `median`, `lo`, `hi`
  - `ranking_stable(by_size) -> (bool, str)` where `by_size` maps size to an ordered list of cipher names
  - `summarize(runs_csv_path, baseline, seed) -> list[dict]`, also writing `summary.csv` beside the input

- [ ] **Step 1: Write the failing tests**

Create `tools/tests/test_summarize.py`:

```python
"""Statistics with known answers, so a regression in the interval code is caught
here rather than by a reader noticing an implausible interval in the paper."""
import unittest

from tools import summarize


class TestMedianCI(unittest.TestCase):
    def test_median_of_odd_sample(self):
        med, lo, hi = summarize.median_ci([1.0, 2.0, 3.0], seed=1)
        self.assertEqual(med, 2.0)
        self.assertLessEqual(lo, med)
        self.assertLessEqual(med, hi)

    def test_zero_variance_gives_degenerate_interval(self):
        med, lo, hi = summarize.median_ci([5.0] * 20, seed=1)
        self.assertEqual((med, lo, hi), (5.0, 5.0, 5.0))

    def test_seed_makes_it_reproducible(self):
        a = summarize.median_ci([1.0, 4.0, 9.0, 16.0, 25.0], seed=7)
        b = summarize.median_ci([1.0, 4.0, 9.0, 16.0, 25.0], seed=7)
        self.assertEqual(a, b)


class TestPairedRatio(unittest.TestCase):
    def test_common_drift_cancels(self):
        """Absolute speed swings 2x between runs; the ratio is exactly 2.0 in
        both. The paired interval must be degenerate where the unpaired one is
        wide -- this is the entire reason the A7 campaign reports ratios."""
        runs = [
            {"run_index": 0, "cipher": "fast", "mbit_per_sec": 200.0},
            {"run_index": 0, "cipher": "slow", "mbit_per_sec": 100.0},
            {"run_index": 1, "cipher": "fast", "mbit_per_sec": 400.0},
            {"run_index": 1, "cipher": "slow", "mbit_per_sec": 200.0},
        ]
        med, lo, hi = summarize.paired_ratio_ci(runs, "fast", "slow", seed=1)
        self.assertEqual(med, 2.0)
        self.assertEqual((lo, hi), (2.0, 2.0))

        unpaired = summarize.median_ci([200.0, 400.0], seed=1)
        self.assertGreater(unpaired[2] - unpaired[1], 0.0)

    def test_a_run_missing_the_baseline_is_skipped_not_guessed(self):
        runs = [
            {"run_index": 0, "cipher": "fast", "mbit_per_sec": 200.0},
            {"run_index": 0, "cipher": "slow", "mbit_per_sec": 100.0},
            {"run_index": 1, "cipher": "fast", "mbit_per_sec": 400.0},
        ]
        med, _, _ = summarize.paired_ratio_ci(runs, "fast", "slow", seed=1)
        self.assertEqual(med, 2.0)


class TestTopGroup(unittest.TestCase):
    def test_overlapping_intervals_are_one_group(self):
        """The current 416 / 366 / 353 Mbit/s problem, in miniature: the first
        two overlap and must not be ranked against each other."""
        stats = [
            {"cipher": "a", "median": 416.0, "lo": 400.0, "hi": 430.0},
            {"cipher": "b", "median": 366.0, "lo": 350.0, "hi": 410.0},
            {"cipher": "c", "median": 120.0, "lo": 118.0, "hi": 122.0},
        ]
        self.assertEqual(summarize.top_group(stats), ["a", "b"])

    def test_a_clear_leader_is_alone(self):
        stats = [
            {"cipher": "a", "median": 400.0, "lo": 390.0, "hi": 410.0},
            {"cipher": "b", "median": 300.0, "lo": 290.0, "hi": 310.0},
        ]
        self.assertEqual(summarize.top_group(stats), ["a"])


class TestRankingStability(unittest.TestCase):
    def test_same_order_at_every_size_is_stable(self):
        by_size = {4096: ["a", "b", "c"], 16384: ["a", "b", "c"], 65536: ["a", "b", "c"]}
        ok, msg = summarize.ranking_stable(by_size)
        self.assertTrue(ok, msg)

    def test_a_flip_is_reported_with_both_orders(self):
        by_size = {4096: ["b", "a", "c"], 65536: ["a", "b", "c"]}
        ok, msg = summarize.ranking_stable(by_size)
        self.assertFalse(ok)
        self.assertIn("4096", msg)
        self.assertIn("65536", msg)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest discover -s tools/tests -t . -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tools.summarize'`.

- [ ] **Step 3: Implement `tools/summarize.py`**

Standard library only; `random.Random(seed)` drives the bootstrap so a rerun reproduces the interval exactly.

- `median_ci`: 10 000 resamples with replacement, percentile interval at 2.5% and 97.5%.
- `paired_ratio_ci`: group rows by `run_index`, form the ratio only for runs containing both ciphers, bootstrap over those per-run ratios. A run missing the baseline is skipped, never imputed.
- `top_group`: sort by median descending, return every cipher whose `hi` reaches the leader's `lo`.
- `ranking_stable`: compare the ordering at each size; when they differ, return `(False, msg)` where `msg` names both sizes and both orders. A ranking that depends on working-set size is a result about cache, not about ciphers, and the summarizer must say so rather than leave it to be spotted.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest discover -s tools/tests -t . -v`
Expected: all pass, including the pre-existing `tools/tests/test_cipher_set.py`.

- [ ] **Step 5: Implement `tools/make_tables.py`**

Reads `summary.csv`, writes `paper/tables/<target>-ctr.tex`. Columns: cipher, chosen impl, throughput in Mbit/s with its interval in brackets, and the paired ratio against `present-80-r16` with its own interval. Top-group members are marked so the reader sees a group rather than a spurious ordering.

Add a `make tables` target that regenerates every table from every `summary.csv` under `results/v2/`.

- [ ] **Step 6: Commit**

```bash
git add tools/summarize.py tools/make_tables.py tools/tests/test_summarize.py Makefile
git commit -m "Publish medians with intervals and paired ratios, not bare numbers"
```

---

## Task 8: x86 campaign driver

**Files:**
- Create: `tools/campaign.py`, `tools/tests/test_campaign.py`
- Modify: `Makefile`, `artifact-manifest.json`
- Produces: `results/v2/x86/{env.json,kat.json,runs.csv,tuning.json,summary.csv}`

**Interfaces:**
- Consumes: `build/ctr_bench`; `tools.cipher_set.resolve()`; `tools.summarize.summarize`.
- Produces: `campaign.load_tuning`, `campaign.check_tuning`, `campaign.require_clean`, and the exceptions `FrozenChoiceMissing`, `FrozenChoiceStale`, `DirtyTree`, which Tasks 9 and 10 reuse unchanged.

- [ ] **Step 1: Write the failing tests**

Create `tools/tests/test_campaign.py` covering the three guards, with no hardware in the loop:

```python
import tempfile
import unittest

from tools import campaign


class TestGuards(unittest.TestCase):
    def test_measure_refuses_without_tuning(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(campaign.FrozenChoiceMissing):
                campaign.load_tuning(d)

    def test_measure_refuses_an_impl_that_no_longer_exists(self):
        tuning = {"present-80-r16": "ctr-bitslice-avx512"}
        with self.assertRaises(campaign.FrozenChoiceStale):
            campaign.check_tuning(tuning, available={"ctr-table", "ctr-bitslice-avx2"})

    def test_a_frozen_choice_that_still_exists_is_accepted(self):
        tuning = {"present-80-r16": "ctr-bitslice-avx2"}
        campaign.check_tuning(tuning, available={"ctr-table", "ctr-bitslice-avx2"})

    def test_dirty_tree_aborts(self):
        with self.assertRaises(campaign.DirtyTree):
            campaign.require_clean(["Makefile", "src/"], dirty=["Makefile"])

    def test_a_dirty_file_outside_the_watched_set_is_fine(self):
        campaign.require_clean(["Makefile", "src/"], dirty=["README.md"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m unittest tools.tests.test_campaign -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tools.campaign'`.

- [ ] **Step 3: Implement the guards and the two phases**

`--tune` runs every backend 5 times and writes `tuning.json` containing the winner per cipher **and the medians that justified it**, so the choice is auditable rather than merely asserted.

`--measure` loads `tuning.json`, raises `FrozenChoiceMissing` or `FrozenChoiceStale` as above, and measures only the frozen winners for 25 runs.

`require_clean` watches `Makefile`, `bench/`, `src/`, `include/`, `fw/` — the inputs that can change a measured byte, following the precedent already in `tools/run_m4_bench.py`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tools.tests.test_campaign -v`
Expected: all pass.

- [ ] **Step 5: Implement provenance capture**

`env.json` records: commit SHA and dirty flag; `cc --version` and the verbatim compile command from `make -n`; the `/proc/cpuinfo` model; the pinned CPU; the governor; whether the hyperthread sibling was left idle; whether `isolcpus`/`nohz_full` appear in `/proc/cmdline`; the kernel version; and the sha256 of `build/ctr_bench`.

Each is **recorded as observed, never asserted.** `docs/measurement-environment.md` already has to explain that parts of it are "a record of the defaults the machine happened to have"; a file that reports the truth needs no such apology.

- [ ] **Step 6: Confirm the machine-control findings are captured**

Run: `python3 tools/campaign.py x86 --tune`
Expected on an unprepared machine: `env.json` shows `"governor": "powersave"` and reports the pinned CPU and sibling state honestly. The point of this step is that the file reports the machine as it is, not as intended.

- [ ] **Step 6b: Capture the KAT verdict**

`build/ctr_bench` already refuses to write a CSV unless every backend it will measure reproduces `ctr-ref` byte for byte. The campaign records that verdict rather than discarding it: add a `--kat-json PATH` flag to the harness that writes one entry per (cipher, impl) with `pass` or the offending byte offset, and have `campaign.py` write it to `results/v2/<target>/kat.json` before any timing row exists.

Run: `python3 tools/campaign.py x86 --tune && python3 -c "import json;d=json.load(open('results/v2/x86/kat.json'));print(len(d),all(e['pass'] for e in d))"`
Expected: one entry per measured backend, all passing.

- [ ] **Step 6c: Measure the three working-set sizes**

The campaign runs at 4096, 16384 and 65536 bytes, writing `size_bytes` into every `runs.csv` row. Only 65536 is published; the other two exist so `summarize.ranking_stable` can check whether the ordering depends on working-set size.

Run: `python3 tools/summarize.py results/v2/x86/runs.csv --baseline present-80-r16`
Expected: `summary.csv` written, and either a clean ranking-stability check or an explicit message naming the two sizes whose orders disagree. A flip is not a failure of the campaign — it is a result about cache that must be reported rather than hidden by publishing one size.

- [ ] **Step 7: Freeze the choice**

```bash
git add results/v2/x86/tuning.json
git commit -m "Freeze the x86 kernel choice before measuring"
```

The freeze is a separate commit on purpose: it is what makes "the winner was not chosen by the published numbers" checkable from the history rather than from a claim.

- [ ] **Step 8: Run the measurement campaign (Wave 4 — quiet machine)**

Prepare per the spec's §6 assumption: `governor=performance`, pinned to CPU 8 with CPU 9 idle, browser and editor closed, no other session building.

Run: `python3 tools/campaign.py x86 --measure && python3 tools/summarize.py results/v2/x86/runs.csv`
Expected: 25 runs, `summary.csv` written, intervals visibly tighter than an unprepared run.

- [ ] **Step 9: Commit**

```bash
git add tools/campaign.py tools/tests/test_campaign.py results/v2/x86 \
        artifact-manifest.json Makefile
git commit -m "Produce the x86 numbers from one command with its provenance"
```

---

## Task 9: Cortex-A7 campaign

**Files:**
- Modify: `tools/campaign.py` (the `a7` subcommand), `artifact-manifest.json`
- Create: `results/v2/a7/{env.json,kat.json,runs.csv,tuning.json,summary.csv}`

**Interfaces:**
- Consumes: `campaign.load_tuning`, `campaign.check_tuning`, `campaign.require_clean` from Task 8; `tools.summarize` from Task 7.

- [ ] **Step 1: Implement the SSH driver**

`python3 tools/campaign.py a7 --host <host>` does: rsync the tree to the board → `make` there → run the campaign → collect `runs.csv` back. It refuses to start if the board's `scaling_governor` is not `performance` or its clock is not pinned at 1296 MHz, and it records both in `env.json` either way.

- [ ] **Step 2: Implement per-run randomisation**

Within each run, the order of the seven ciphers is a fresh permutation from `random.Random(seed + run_index)`. Both the seed and the resulting `order_index` go into `runs.csv`, so rerunning with the same seed reproduces the same orders and a reader can check whether position correlates with result.

- [ ] **Step 3: Implement the thermal guard**

Read `/sys/class/thermal/thermal_zone0/temp` and `scaling_cur_freq` before and after each cipher. If the clock leaves 1296 MHz or the temperature crosses the configured ceiling, discard that run, log the discard with its readings, and retake it. Cap the retakes so a persistently hot board fails loudly instead of looping forever.

- [ ] **Step 4: Verify the guard fires**

Run: set the ceiling artificially low (e.g. 40 °C) and start a short campaign.
Expected: every run is discarded, the log names the temperature that caused each discard, and the driver exits non-zero on hitting the retake cap. Restore the real ceiling.

- [ ] **Step 5: Tune, freeze, then measure**

```bash
python3 tools/campaign.py a7 --host <host> --tune
git add results/v2/a7/tuning.json && git commit -m "Freeze the A7 kernel choice"
python3 tools/campaign.py a7 --host <host> --measure
```

25 runs, all seven ciphers per run.

- [ ] **Step 6: Check the protocol's own claim**

Run: `python3 tools/summarize.py results/v2/a7/runs.csv --baseline present-80-r16`

Expected: paired-ratio intervals materially tighter than the absolute ones. That is the claim the protocol makes — absolute speed may wander 10% while a ratio holds to 1–2%.

**If it does not hold, say so** in the CSV header and the write-up rather than presenting the ratios as though it did. A paired analysis that fails to cancel drift is itself a finding about the board.

- [ ] **Step 7: Commit**

```bash
git add results/v2/a7 tools/campaign.py artifact-manifest.json
git commit -m "Measure all seven constructions on the A7 in one paired campaign"
```

---

## Task 10: M4 CTR campaign and layout-sensitivity bound

Depends on Task 1 (the workload) and Task 2 (the fixed section).

**Files:**
- Create: `fw/m4/ctr_m4_main.c`
- Modify: `tools/campaign.py` (the `m4` subcommand), `Makefile`
- Create: `results/v2/m4/{env.json,kat.json,runs.csv,summary.csv}`, `results/v2/m4-memory-configurations.csv`

- [ ] **Step 1: Port the workload to firmware**

`fw/m4/ctr_m4_main.c` runs the same 64 KiB in-place CTR workload, one cipher per image via `PRESENT_ONE_CIPHER`, KAT-gated before it times anything — as the existing firmware already does — and timed with DWT. Built with `-DPRESENT_ENC_ONLY`, linking `src/keyschedule_portable.c` and never `src/keyschedule.c`.

- [ ] **Step 2: Confirm the buffer fits**

Run: `make m4-bench-fw && arm-none-eabi-size build/m4/*.elf`
Expected: the 64 KiB in-place buffer plus the runtime-built tables plus stack fit inside 128 KiB SRAM + 64 KiB CCM, and `product.ld`'s CCM assertion still holds. In-place is what makes this fit — separate input and output buffers would need the output in CCM, evicting the tables and leaving zero headroom.

- [ ] **Step 3: Build one image per (cipher, winning impl)**

Extend the per-cipher split from commit `840b230`. Every image places its timed section at the same address; `tools/tests/test_m4_layout.py` from Task 2 enforces it and fails the build otherwise.

- [ ] **Step 4: Measure the layout-sensitivity bound**

Build the same kernel at successive 16-byte offsets — `0x08010000`, `0x08010010`, and so on through one 128-bit fetch line — measure each, and record the spread.

This replaces a statistical CI. DWT is effectively deterministic, so the honest uncertainty is measurement resolution plus residual placement sensitivity, and a bootstrap interval over deterministic numbers would be theatre.

- [ ] **Step 5: Publish product only**

The main CSV carries the product (flash + ART) configuration alone. `flash-noart` and `sram-noart` go to `results/v2/m4-memory-configurations.csv` with a header stating they are an architectural experiment and not defender performance.

- [ ] **Step 6: Answer the 12 Mbit/s question**

Derive Mbit/s from cycles at the measured core clock and state pass or fail explicitly, for the real mode rather than inside the kernel. Put the verdict in the CSV header, not only in prose — it is the single number a reader of this project most wants, and it should not require arithmetic on their part.

- [ ] **Step 7: Commit**

```bash
git add fw/m4/ctr_m4_main.c tools/campaign.py results/v2/m4 \
        results/v2/m4-memory-configurations.csv Makefile
git commit -m "Measure the M4 on the complete CTR workload at a fixed layout"
```
