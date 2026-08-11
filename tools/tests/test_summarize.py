"""Statistics with known answers, so a regression in the interval code is caught
here rather than by a reader noticing an implausible interval in the paper.

Every expected value below is derived independently of the implementation -- by
hand from the bootstrap's own combinatorics, or by construction of an input whose
answer is forced. Asserting whatever the code currently prints would bless a bug
rather than catch one.

Worked example for the percentile indices, used by several tests. With
`resamples=10000` the interval is `boot[250]` and `boot[9749]` of the sorted
bootstrap medians. For the sample [1, 2, 3] a resample's median is 1 exactly when
at least two of its three draws are 1, so P(median = 1) = 3*(1/3)^2*(2/3) +
(1/3)^3 = 7/27 = 0.2593, and by symmetry P(median = 3) = 7/27. Index 250 therefore
lands inside the run of 1.0s (2593 of them, expected) and index 9749 inside the
run of 3.0s, giving exactly (2.0, 1.0, 3.0) for any seed.
"""
import itertools
import math
import os
import tempfile
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

    def test_percentile_endpoints_match_the_hand_computed_lattice(self):
        """See the module docstring: (2.0, 1.0, 3.0) is forced by P(median=1)=7/27."""
        for seed in (0, 1, 12345):
            self.assertEqual(summarize.median_ci([1.0, 2.0, 3.0], seed=seed),
                             (2.0, 1.0, 3.0))

    def test_even_sample_median_is_the_midpoint(self):
        med, _, _ = summarize.median_ci([1.0, 2.0, 3.0, 4.0], seed=1)
        self.assertEqual(med, 2.5)

    def test_result_does_not_depend_on_the_order_of_the_input(self):
        """A reordering of the same measurements is the same sample. If the answer
        moved with row order, two runs of the campaign that recorded the ciphers in
        a different randomised order would publish different intervals."""
        values = [3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0, 6.0]
        self.assertEqual(summarize.median_ci(values, seed=3),
                         summarize.median_ci(list(reversed(values)), seed=3))

    def test_single_sample_is_degenerate_not_an_error(self):
        self.assertEqual(summarize.median_ci([7.5], seed=1), (7.5, 7.5, 7.5))

    def test_empty_sample_is_an_error_not_a_nan(self):
        with self.assertRaises(ValueError):
            summarize.median_ci([], seed=1)

    def test_the_interval_matches_the_exactly_enumerated_bootstrap(self):
        """The strongest check available without a statistics library: for a small
        sample the bootstrap distribution of the median can be enumerated in full --
        all n**n resamples -- and its 2.5%/97.5% points computed exactly. The
        10 000-resample estimate must land on the same lattice points. This pins the
        resampling and the percentile convention together, against an answer derived
        without running the implementation's own sampling path."""
        for values in ([1.0, 2.0, 3.0],
                       [1.0, 2.0, 3.0, 4.0],
                       [1.0, 4.0, 9.0, 16.0, 25.0],
                       [10.0, 10.5, 11.0, 30.0, 31.0, 31.5]):
            self.assertEqual(summarize.median_ci(values, seed=0),
                             exact_bootstrap_median_ci(values), values)


def exact_bootstrap_median_ci(values):
    """(median, lo, hi) from the complete bootstrap distribution, by enumeration.

    Deliberately written from the definition rather than by calling anything in
    summarize beyond the median itself: it is the independent answer that
    test_the_interval_matches_the_exactly_enumerated_bootstrap checks against.
    """
    n = len(values)
    counts = {}
    for resample in itertools.product(values, repeat=n):
        ordered = sorted(resample)
        mid = n // 2
        median = ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2.0
        counts[median] = counts.get(median, 0) + 1

    total = n ** n
    lo_rank = int(math.floor(0.025 * total))
    hi_rank = int(math.ceil(0.975 * total)) - 1
    lo = hi = None
    seen = 0
    for value in sorted(counts):
        start, seen = seen, seen + counts[value]
        if lo is None and start <= lo_rank < seen:
            lo = value
        if hi is None and start <= hi_rank < seen:
            hi = value

    ordered = sorted(values)
    mid = n // 2
    median = ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2.0
    return (median, lo, hi)


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

    def test_the_ratios_are_bootstrapped_not_the_absolutes(self):
        """Ratios 1, 2, 3 by construction, so the answer is the same hand-computed
        lattice as median_ci([1, 2, 3]) -- which pins that the bootstrap resamples
        per-run ratios rather than, say, the ratio of two independent bootstraps."""
        runs = []
        for i, top in enumerate((100.0, 200.0, 300.0)):
            runs.append({"run_index": i, "cipher": "x", "mbit_per_sec": top})
            runs.append({"run_index": i, "cipher": "b", "mbit_per_sec": 100.0})
        self.assertEqual(summarize.paired_ratio_ci(runs, "x", "b", seed=2),
                         (2.0, 1.0, 3.0))

    def test_row_order_does_not_change_the_answer(self):
        runs = []
        for i, top in enumerate((110.0, 240.0, 330.0, 480.0, 150.0)):
            runs.append({"run_index": i, "cipher": "x", "mbit_per_sec": top})
            runs.append({"run_index": i, "cipher": "b", "mbit_per_sec": 100.0})
        self.assertEqual(summarize.paired_ratio_ci(runs, "x", "b", seed=5),
                         summarize.paired_ratio_ci(list(reversed(runs)), "x", "b", seed=5))

    def test_baseline_against_itself_is_exactly_one(self):
        runs = [
            {"run_index": 0, "cipher": "b", "mbit_per_sec": 137.0},
            {"run_index": 1, "cipher": "b", "mbit_per_sec": 986.0},
        ]
        self.assertEqual(summarize.paired_ratio_ci(runs, "b", "b", seed=1),
                         (1.0, 1.0, 1.0))

    def test_no_run_holds_both_ciphers_is_an_error_not_an_empty_interval(self):
        runs = [
            {"run_index": 0, "cipher": "fast", "mbit_per_sec": 200.0},
            {"run_index": 1, "cipher": "slow", "mbit_per_sec": 100.0},
        ]
        with self.assertRaises(ValueError):
            summarize.paired_ratio_ci(runs, "fast", "slow", seed=1)

    def test_two_rows_for_one_cipher_in_one_run_is_refused(self):
        """runs.csv carries three working-set sizes, so `run_index` alone is not a
        unique key across the whole file. Pairing on it regardless would silently
        divide a 4 KiB number by a 64 KiB one. The caller must stratify first, and
        this is what tells it so."""
        runs = [
            {"run_index": 0, "cipher": "fast", "size_bytes": 4096, "mbit_per_sec": 500.0},
            {"run_index": 0, "cipher": "fast", "size_bytes": 65536, "mbit_per_sec": 200.0},
            {"run_index": 0, "cipher": "slow", "size_bytes": 4096, "mbit_per_sec": 250.0},
            {"run_index": 0, "cipher": "slow", "size_bytes": 65536, "mbit_per_sec": 100.0},
        ]
        with self.assertRaises(ValueError) as ctx:
            summarize.paired_ratio_ci(runs, "fast", "slow", seed=1)
        self.assertIn("fast", str(ctx.exception))

    def test_a_zero_baseline_is_refused_rather_than_dividing(self):
        runs = [
            {"run_index": 0, "cipher": "fast", "mbit_per_sec": 200.0},
            {"run_index": 0, "cipher": "slow", "mbit_per_sec": 0.0},
        ]
        with self.assertRaises(ValueError):
            summarize.paired_ratio_ci(runs, "fast", "slow", seed=1)


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

    def test_input_order_does_not_matter(self):
        stats = [
            {"cipher": "c", "median": 120.0, "lo": 118.0, "hi": 122.0},
            {"cipher": "b", "median": 366.0, "lo": 350.0, "hi": 410.0},
            {"cipher": "a", "median": 416.0, "lo": 400.0, "hi": 430.0},
        ]
        self.assertEqual(summarize.top_group(stats), ["a", "b"])

    def test_touching_at_a_single_point_still_overlaps(self):
        stats = [
            {"cipher": "a", "median": 400.0, "lo": 390.0, "hi": 410.0},
            {"cipher": "b", "median": 300.0, "lo": 290.0, "hi": 390.0},
        ]
        self.assertEqual(summarize.top_group(stats), ["a", "b"])

    def test_a_wide_interval_joins_the_group_even_from_far_below(self):
        """Not a bug: an interval that wide says the measurement cannot tell the
        two apart, and the top-group rule exists to report exactly that."""
        stats = [
            {"cipher": "a", "median": 400.0, "lo": 390.0, "hi": 410.0},
            {"cipher": "b", "median": 100.0, "lo": 20.0, "hi": 395.0},
        ]
        self.assertEqual(summarize.top_group(stats), ["a", "b"])

    def test_empty_input_is_an_empty_group(self):
        self.assertEqual(summarize.top_group([]), [])

    def test_equal_medians_are_ordered_by_name_for_reproducibility(self):
        stats = [
            {"cipher": "b", "median": 400.0, "lo": 390.0, "hi": 410.0},
            {"cipher": "a", "median": 400.0, "lo": 390.0, "hi": 410.0},
        ]
        self.assertEqual(summarize.top_group(stats), ["a", "b"])


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

    def test_a_single_size_cannot_be_unstable(self):
        ok, _ = summarize.ranking_stable({65536: ["a", "b"]})
        self.assertTrue(ok)

    def test_no_sizes_at_all_is_stable_and_says_nothing(self):
        ok, _ = summarize.ranking_stable({})
        self.assertTrue(ok)

    def test_a_size_measuring_a_different_cipher_set_is_reported(self):
        """Not a ranking flip but a hole in the campaign, and it must not be
        silently compared away."""
        by_size = {4096: ["a", "b"], 65536: ["a", "b", "c"]}
        ok, msg = summarize.ranking_stable(by_size)
        self.assertFalse(ok)
        self.assertIn("c", msg)

    def test_the_message_names_both_orders_not_only_the_sizes(self):
        by_size = {4096: ["b", "a"], 65536: ["a", "b"]}
        _, msg = summarize.ranking_stable(by_size)
        self.assertIn("b, a", msg)
        self.assertIn("a, b", msg)


class TestModality(unittest.TestCase):
    """Task 4 found the x86 host has two discrete performance states about 2.15x
    apart, entered unpredictably. A percentile interval around the median of a
    sample drawn from both describes neither state, so the summariser has to say
    the sample is multimodal instead of quietly publishing a tidy bracket."""

    # 12 samples in each of two states 2.15x apart, each state jittering by well
    # under a percent -- the shape Task 4 measured.
    BIMODAL = ([193.0, 193.4, 192.6, 193.1, 192.9, 193.3,
                192.7, 193.2, 192.8, 193.5, 192.5, 193.0] +
               [415.0, 416.2, 414.8, 415.6, 415.1, 416.0,
                414.9, 415.4, 415.8, 415.2, 414.7, 416.1])

    def test_two_separated_states_are_reported_as_multimodal(self):
        got = summarize.modality(self.BIMODAL)
        self.assertTrue(got["multimodal"])
        self.assertEqual([m["n"] for m in got["modes"]], [12, 12])
        self.assertAlmostEqual(got["modes"][0]["median"], 193.0, places=6)
        # Sorted upper mode: ... 415.2, 415.4 ... -- the two middle of twelve.
        self.assertAlmostEqual(got["modes"][1]["median"], 415.3, places=6)

    def test_an_evenly_spread_sample_is_not_multimodal(self):
        """1..20 in unit steps: the widest interior gap is 1 and the tighter half
        spans 9, so no split has a gap wider than twice the spread it separates."""
        got = summarize.modality([float(v) for v in range(1, 21)])
        self.assertFalse(got["multimodal"])
        self.assertEqual(got["modes"], [])

    def test_one_outlier_is_not_a_mode(self):
        """A single stall is an outlier, not a second performance state. Calling it
        a mode would flag nearly every real sample and the flag would stop meaning
        anything."""
        got = summarize.modality([100.0] * 11 + [4000.0])
        self.assertFalse(got["multimodal"])

    def test_a_sample_too_small_to_judge_is_not_flagged(self):
        """Six points can look like anything. Reporting bimodality from six would
        be a claim the sample cannot support."""
        got = summarize.modality([100.0, 100.5, 101.0, 400.0, 400.5, 401.0])
        self.assertFalse(got["multimodal"])
        self.assertIn("too small", got["reason"])

    def test_two_exactly_discrete_states_are_multimodal(self):
        got = summarize.modality([1.0] * 5 + [2.0] * 5)
        self.assertTrue(got["multimodal"])
        self.assertEqual([m["median"] for m in got["modes"]], [1.0, 2.0])

    def test_shares_sum_to_one_and_describe_the_split(self):
        got = summarize.modality([1.0] * 4 + [2.0] * 12)
        self.assertTrue(got["multimodal"])
        self.assertAlmostEqual(got["modes"][0]["share"], 0.25, places=9)
        self.assertAlmostEqual(got["modes"][1]["share"], 0.75, places=9)

    def test_order_does_not_matter(self):
        shuffled = list(reversed(self.BIMODAL))
        self.assertEqual(summarize.modality(shuffled)["multimodal"],
                         summarize.modality(self.BIMODAL)["multimodal"])

    def test_a_degenerate_sample_is_unimodal(self):
        self.assertFalse(summarize.modality([5.0] * 30)["multimodal"])


def write_runs_csv(path, rows, provenance="CAMPAIGN"):
    header = "run_index,order_index,cipher,impl,size_bytes,mbit_per_sec,temp_c,freq_khz"
    with open(path, "w", encoding="ascii") as fh:
        if provenance is not None:
            fh.write("# provenance: %s\n" % provenance)
        fh.write(header + "\n")
        for row in rows:
            fh.write(",".join(str(c) for c in row) + "\n")


class TestSummarize(unittest.TestCase):
    """End to end over a runs.csv built so every published figure is known ahead
    of time."""

    SIZES = (4096, 16384, 65536)
    # Per-run baseline throughput, deliberately drifting by 25% across the runs so
    # that the absolute interval is wide and the paired one is not.
    DRIFT = (100.0, 110.0, 120.0, 125.0, 105.0, 115.0, 118.0, 122.0, 108.0)
    # Exact ratio each cipher holds against the baseline in every single run.
    RATIOS = {"present-80-r16": 1.0, "fastish": 1.5, "slowish": 0.5}

    def build(self, directory, provenance="CAMPAIGN"):
        rows = []
        for size in self.SIZES:
            for run, base in enumerate(self.DRIFT):
                for order, (cipher, ratio) in enumerate(sorted(self.RATIOS.items())):
                    rows.append((run, order, cipher, "ctr-table", size,
                                 "%.6f" % (base * ratio), "NA", "NA"))
        path = os.path.join(directory, "runs.csv")
        write_runs_csv(path, rows, provenance=provenance)
        return path

    def test_summary_csv_is_written_beside_the_input(self):
        with tempfile.TemporaryDirectory() as d:
            self.build(d)
            summarize.summarize(os.path.join(d, "runs.csv"), "present-80-r16", 0)
            self.assertTrue(os.path.exists(os.path.join(d, "summary.csv")))

    def test_one_row_per_cipher_per_size(self):
        with tempfile.TemporaryDirectory() as d:
            got = summarize.summarize(self.build(d), "present-80-r16", 0)
            self.assertEqual(len(got), len(self.SIZES) * len(self.RATIOS))
            self.assertEqual({r["size_bytes"] for r in got}, set(self.SIZES))

    def test_the_ratios_are_exact_and_their_intervals_degenerate(self):
        """Every run holds the ratio exactly, so the paired interval must collapse
        while the absolute one stays open. That is the protocol's own claim."""
        with tempfile.TemporaryDirectory() as d:
            got = summarize.summarize(self.build(d), "present-80-r16", 0)
            for row in got:
                if row["size_bytes"] != 65536:
                    continue
                expect = self.RATIOS[row["cipher"]]
                self.assertEqual(row["ratio_median"], expect)
                self.assertEqual((row["ratio_lo"], row["ratio_hi"]), (expect, expect))
                self.assertGreater(row["ci_hi"] - row["ci_lo"], 0.0)

    def test_non_numeric_sensor_columns_do_not_break_the_parse(self):
        """temp_c and freq_khz are 'NA' on a target with no such sensor, exactly as
        ctr_bench writes 'NA' for tsc_per_byte off x86. That must not abort a
        campaign summary."""
        with tempfile.TemporaryDirectory() as d:
            got = summarize.summarize(self.build(d), "present-80-r16", 0)
            self.assertTrue(got)

    def test_a_bad_throughput_field_is_refused_rather_than_dropped(self):
        """mbit_per_sec is the measurement. Skipping an unparseable one would
        quietly shrink the sample the interval is computed from."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, [(0, 0, "a", "ctr-table", 65536, "NA", "NA", "NA")])
            with self.assertRaises(ValueError):
                summarize.summarize(path, "a", 0)

    def test_the_ranking_stability_verdict_reaches_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            summarize.summarize(self.build(d), "present-80-r16", 0)
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                text = fh.read()
            self.assertIn("ranking_stability:", text)
            self.assertIn("STABLE", text)

    def test_a_size_dependent_ranking_is_named_in_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            rows = []
            # "a" wins at 4096 and loses at 65536: a cache result, not a cipher one.
            for size, speeds in ((4096, {"a": 200.0, "b": 100.0}),
                                 (65536, {"a": 100.0, "b": 200.0})):
                for run in range(9):
                    for order, (cipher, v) in enumerate(sorted(speeds.items())):
                        rows.append((run, order, cipher, "ctr-table", size,
                                     "%.6f" % v, "NA", "NA"))
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            summarize.summarize(path, "a", 0)
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                text = fh.read()
            self.assertIn("UNSTABLE", text)
            self.assertIn("4096", text)
            self.assertIn("65536", text)

    def test_a_bimodal_cipher_is_flagged_in_the_summary(self):
        with tempfile.TemporaryDirectory() as d:
            rows = []
            for run, v in enumerate(TestModality.BIMODAL):
                rows.append((run, 0, "bimodal", "ctr-table", 65536,
                             "%.6f" % v, "NA", "NA"))
                rows.append((run, 1, "steady", "ctr-table", 65536,
                             "%.6f" % 300.0, "NA", "NA"))
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            got = {r["cipher"]: r for r in summarize.summarize(path, "steady", 0)}
            self.assertEqual(got["bimodal"]["modality"], "multimodal")
            self.assertEqual(got["steady"]["modality"], "unimodal")
            self.assertIn("193", got["bimodal"]["mode_medians"])
            self.assertIn("415", got["bimodal"]["mode_medians"])

    def test_provenance_is_carried_into_the_summary(self):
        with tempfile.TemporaryDirectory() as d:
            summarize.summarize(self.build(d, provenance="SMOKE-RUN"),
                                "present-80-r16", 0)
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                self.assertIn("# provenance: SMOKE-RUN", fh.read())

    def test_a_runs_file_without_a_marker_says_unknown_rather_than_assuming(self):
        with tempfile.TemporaryDirectory() as d:
            summarize.summarize(self.build(d, provenance=None), "present-80-r16", 0)
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                self.assertIn("# provenance: UNKNOWN", fh.read())

    def test_a_missing_baseline_is_refused_before_anything_is_written(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.build(d)
            with self.assertRaises(ValueError):
                summarize.summarize(path, "no-such-cipher", 0)
            self.assertFalse(os.path.exists(os.path.join(d, "summary.csv")))

    def test_rerunning_reproduces_the_file_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.build(d)
            summarize.summarize(path, "present-80-r16", 0)
            with open(os.path.join(d, "summary.csv"), "rb") as fh:
                first = fh.read()
            summarize.summarize(path, "present-80-r16", 0)
            with open(os.path.join(d, "summary.csv"), "rb") as fh:
                self.assertEqual(fh.read(), first)


class TestCsvReading(unittest.TestCase):
    """The shared reader, which has to cope with the two shapes already in
    results/v2/: one file carries a `status` column that must be filtered on, the
    other has no such column and must not raise for the lack of it."""

    def test_comment_lines_are_not_data(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.csv")
            with open(path, "w", encoding="ascii") as fh:
                fh.write("# provenance: CAMPAIGN\n# note\na,b\n1,2\n")
            prov, rows = summarize.read_csv_with_provenance(path)
            self.assertEqual(prov, "CAMPAIGN")
            self.assertEqual(rows, [{"a": "1", "b": "2"}])

    def test_rows_that_are_not_measurements_are_filtered_out(self):
        rows = [{"cipher": "a", "status": "measured", "rate": "1.0"},
                {"cipher": "b", "status": "inapplicable", "rate": ""},
                {"cipher": "c", "status": "unwritten", "rate": ""}]
        self.assertEqual([r["cipher"] for r in summarize.measured_rows(rows)], ["a"])

    def test_a_file_without_a_status_column_is_not_a_key_error(self):
        rows = [{"cipher": "a", "rate": "1.0"}, {"cipher": "b", "rate": "2.0"}]
        self.assertEqual([r["cipher"] for r in summarize.measured_rows(rows)], ["a", "b"])

    def test_the_real_block_eval_file_survives_both_rules(self):
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "..", "results", "v2", "cuda", "block-eval.csv")
        prov, rows = summarize.read_csv_with_provenance(path)
        self.assertIn(prov, ("SMOKE-RUN", "CAMPAIGN"))
        kept = summarize.measured_rows(rows)
        self.assertEqual(len(rows) - len(kept), 21)
        for row in kept:
            float(row["gb_per_sec"])

    def test_the_real_master_key_file_has_no_status_and_still_reads(self):
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "..", "results", "v2", "cuda",
                            "master-key-search.csv")
        prov, rows = summarize.read_csv_with_provenance(path)
        self.assertIn(prov, ("SMOKE-RUN", "CAMPAIGN"))
        self.assertEqual(len(summarize.measured_rows(rows)), len(rows))


if __name__ == "__main__":
    unittest.main()
