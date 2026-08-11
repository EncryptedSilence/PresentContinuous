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

# 40 points spread over [100, 120), from a linear-congruential recurrence so the
# literal is reproducible rather than magic. What matters about it is verified in
# test_the_seed_is_load_bearing_on_a_sample_whose_endpoints_can_move: the bootstrap
# endpoints land strictly inside the sample and move with the seed, which is what
# makes a determinism assertion over it mean something.
SEED_FIXTURE = [
    110.2774, 103.5148, 103.1052, 102.9253, 105.6944, 118.5818, 100.175, 117.7842,
    102.7516, 104.5159, 105.5947, 115.8775, 108.1756, 110.8851, 118.0485, 108.9837,
    103.6868, 108.6338, 116.8114, 106.6732, 105.0772, 112.0323, 102.1582, 119.2589,
    111.2487, 116.4152, 111.5843, 100.3649, 114.6992, 118.5606, 112.3768, 108.5718,
    113.3105, 118.4058, 114.4489, 119.4662, 110.0572, 112.9031, 106.7248, 113.2061,
]


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

    def test_the_seed_is_load_bearing_on_a_sample_whose_endpoints_can_move(self):
        """The brief's own reproducibility fixture cannot detect an unseeded RNG.

        On three or five points the bootstrap endpoints saturate to the sample's own
        min and max and are then invariant to the draws, so mutating
        `random.Random(seed)` to `random.Random()` leaves the answer unchanged and the
        determinism test passes while guaranteeing nothing. SEED_FIXTURE is 40 points
        spread over a continuous range, where the endpoints land strictly inside the
        sample and do move: 5 distinct results over 200 seeds, and two consecutive
        unseeded runs differ.

        Three assertions, because each defends a different thing: the endpoints are
        interior (so the fixture is still capable of detecting a changed RNG at all --
        this is the guard that stopped the previous test being vacuous), the same seed
        reproduces exactly (which fails under an unseeded RNG), and two particular
        seeds disagree (so the seed is genuinely an input and not ignored).
        """
        med, lo, hi = summarize.median_ci(SEED_FIXTURE, seed=1)
        self.assertGreater(lo, min(SEED_FIXTURE))
        self.assertLess(hi, max(SEED_FIXTURE))

        self.assertEqual(summarize.median_ci(SEED_FIXTURE, seed=1), (med, lo, hi))
        self.assertNotEqual(summarize.median_ci(SEED_FIXTURE, seed=29), (med, lo, hi))

    def test_the_paired_ratio_bootstrap_is_seeded_too(self):
        runs = []
        for i, value in enumerate(SEED_FIXTURE):
            runs.append({"run_index": i, "cipher": "x", "mbit_per_sec": value})
            runs.append({"run_index": i, "cipher": "b", "mbit_per_sec": 1.0})
        first = summarize.paired_ratio_ci(runs, "x", "b", seed=1)
        self.assertEqual(summarize.paired_ratio_ci(runs, "x", "b", seed=1), first)
        self.assertNotEqual(summarize.paired_ratio_ci(runs, "x", "b", seed=29), first)

    def test_the_bootstrap_parameters_are_the_ones_the_spec_names(self):
        """10 000 resamples at 2.5%/97.5%, recorded in the file the tables read."""
        self.assertEqual(summarize.DEFAULT_RESAMPLES, 10000)
        self.assertEqual((summarize.CI_LOW, summarize.CI_HIGH), (0.025, 0.975))

    def test_the_docstring_does_not_claim_unmeasured_coverage(self):
        """The nominal 95% is not the delivered coverage at these n, and the measured
        figure has to travel with the number rather than live in a report."""
        self.assertIn("0.86", summarize.CI_COVERAGE_NOTE)
        self.assertIn("0.91", summarize.CI_COVERAGE_NOTE)

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

    def test_rows_are_paired_within_a_working_set_size(self):
        """runs.csv carries three working-set sizes, so `run_index` alone is not a
        unique key across the whole file. Each size pairs with itself: the ratio is
        2.0 at both, and 500/100 = 5.0 or 200/250 = 0.8 would mean a 4 KiB figure had
        been divided by a 64 KiB one."""
        runs = [
            {"run_index": 0, "cipher": "fast", "size_bytes": 4096, "mbit_per_sec": 500.0},
            {"run_index": 0, "cipher": "fast", "size_bytes": 65536, "mbit_per_sec": 200.0},
            {"run_index": 0, "cipher": "slow", "size_bytes": 4096, "mbit_per_sec": 250.0},
            {"run_index": 0, "cipher": "slow", "size_bytes": 65536, "mbit_per_sec": 100.0},
        ]
        self.assertEqual(summarize.paired_ratio_ci(runs, "fast", "slow", seed=1),
                         (2.0, 2.0, 2.0))

    def test_a_cipher_measured_at_only_one_size_does_not_pair_across_sizes(self):
        """The reviewer's case: one row per cipher per run, so no duplicate exists to
        catch, but the two rows are different working-set sizes. Bucketing on
        run_index alone returns 4.0 from a 4 KiB / 64 KiB division. There is no
        comparable pair here and saying so is the only correct answer."""
        runs = [
            {"run_index": 0, "cipher": "fast", "size_bytes": 4096, "mbit_per_sec": 400.0},
            {"run_index": 0, "cipher": "slow", "size_bytes": 65536, "mbit_per_sec": 100.0},
        ]
        with self.assertRaises(ValueError) as ctx:
            summarize.paired_ratio_ci(runs, "fast", "slow", seed=1)
        self.assertIn("same working-set size", str(ctx.exception))

    def test_two_impls_of_one_cipher_in_one_run_at_one_size_is_refused(self):
        """Tuning output holds several impls per cipher per run. Picking one would be
        arbitrary, so it is an error."""
        runs = [
            {"run_index": 0, "cipher": "fast", "size_bytes": 4096, "impl": "a",
             "mbit_per_sec": 500.0},
            {"run_index": 0, "cipher": "fast", "size_bytes": 4096, "impl": "b",
             "mbit_per_sec": 480.0},
            {"run_index": 0, "cipher": "slow", "size_bytes": 4096, "impl": "a",
             "mbit_per_sec": 250.0},
        ]
        with self.assertRaises(ValueError) as ctx:
            summarize.paired_ratio_ci(runs, "fast", "slow", seed=1)
        self.assertIn("fast", str(ctx.exception))

    def test_the_ratio_sample_is_available_for_its_own_modality_check(self):
        runs = []
        for i, top in enumerate((100.0, 200.0, 300.0)):
            runs.append({"run_index": i, "cipher": "x", "mbit_per_sec": top})
            runs.append({"run_index": i, "cipher": "b", "mbit_per_sec": 100.0})
        self.assertEqual(summarize.paired_ratios(runs, "x", "b"), [1.0, 2.0, 3.0])

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


class TestSeparableFlips(unittest.TestCase):
    """`ranking_stable` is a strict order comparison and most of its alarms are two
    near-tied ciphers swapping on noise -- 46% of campaigns at 1% within-cipher noise
    with the true means held identical at every size. Only a flip between ciphers the
    campaign actually separated says anything about cache, and only that kind may
    reach a caption."""

    def test_a_flip_between_ciphers_that_never_separated_does_not_count(self):
        order = {4096: ["a", "b"], 65536: ["b", "a"]}
        stats = {4096: {"a": (99.0, 105.0), "b": (98.0, 104.0)},
                 65536: {"a": (98.0, 104.0), "b": (99.0, 105.0)}}
        self.assertEqual(summarize.separable_flips(order, stats), [])

    def test_a_flip_between_ciphers_separated_at_both_sizes_counts(self):
        order = {4096: ["a", "b"], 65536: ["b", "a"]}
        stats = {4096: {"a": (200.0, 210.0), "b": (100.0, 110.0)},
                 65536: {"a": (100.0, 110.0), "b": (200.0, 210.0)}}
        self.assertEqual(summarize.separable_flips(order, stats),
                         [(4096, 65536, "a", "b")])

    def test_separation_at_only_one_size_is_not_enough(self):
        order = {4096: ["a", "b"], 65536: ["b", "a"]}
        stats = {4096: {"a": (200.0, 210.0), "b": (100.0, 110.0)},
                 65536: {"a": (100.0, 210.0), "b": (150.0, 205.0)}}
        self.assertEqual(summarize.separable_flips(order, stats), [])

    def test_no_flip_at_all_is_no_flip(self):
        order = {4096: ["a", "b"], 65536: ["a", "b"]}
        stats = {4096: {"a": (200.0, 210.0), "b": (100.0, 110.0)},
                 65536: {"a": (200.0, 210.0), "b": (100.0, 110.0)}}
        self.assertEqual(summarize.separable_flips(order, stats), [])

    def test_one_size_cannot_flip(self):
        self.assertEqual(summarize.separable_flips({65536: ["a", "b"]},
                                                   {65536: {"a": (1.0, 2.0),
                                                            "b": (3.0, 4.0)}}), [])


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

    def test_the_minimum_sample_size_is_where_the_false_positive_rate_is_tolerable(self):
        """MODALITY_MIN_N is 12 because that is where the measured false-positive rate
        on a unimodal normal sample falls to about 1% (5.8% at n=8, 2.7% at n=10). A
        sample of 11 is refused a verdict rather than given a 3%-wrong one."""
        eleven = [100.0 + 0.1 * i for i in range(6)] + [400.0 + 0.1 * i for i in range(5)]
        twelve = [100.0 + 0.1 * i for i in range(6)] + [400.0 + 0.1 * i for i in range(6)]
        self.assertFalse(summarize.modality(eleven)["judged"])
        self.assertTrue(summarize.modality(twelve)["judged"])
        self.assertTrue(summarize.modality(twelve)["multimodal"])

    def test_two_exactly_discrete_states_are_multimodal(self):
        got = summarize.modality([1.0] * 6 + [2.0] * 6)
        self.assertTrue(got["multimodal"])
        self.assertEqual([m["median"] for m in got["modes"]], [1.0, 2.0])

    def test_one_point_stranded_between_the_states_does_not_hide_them(self):
        """The scale statistic's whole reason for being. A run that straddles a state
        transition leaves a single observation in the void between the two states. It
        joins one cluster; with the cluster *range* as the scale it inflates that
        range to span the void and a blatant 2.15x bimodality is reported unimodal --
        measured at 4.8% detection with one straddler, down from 100%. With the
        interquartile range the straddler is outside both quartiles and the states are
        still found."""
        self.assertTrue(summarize.modality(self.BIMODAL + [300.0])["multimodal"])
        self.assertTrue(
            summarize.modality(self.BIMODAL + [290.0, 300.0, 310.0])["multimodal"])

    def test_the_scale_statistic_is_the_interquartile_range_not_the_range(self):
        """Pins the choice as a number rather than as a comment: two clusters of eight
        consecutive integers each span a range of 7 and an IQR of exactly 3.5 (the
        quartiles of 0..7 sit at 1.75 and 5.25). With a gap of 8.75 the reported
        gap/spread is 2.5 under the IQR and would be 1.25 under the range."""
        values = [float(i) for i in range(8)] + [15.75 + i for i in range(8)]
        got = summarize.modality(values)
        self.assertAlmostEqual(got["gap"], 8.75, places=9)
        self.assertAlmostEqual(got["spread"], 3.5, places=9)
        self.assertAlmostEqual(got["gap_over_spread"], 2.5, places=9)

    def test_the_gap_factor_threshold_is_pinned_from_both_sides(self):
        """Two fixtures either side of MODALITY_GAP_FACTOR, built so their gap/spread
        is exactly 2.5 and exactly 3.5 (see the test above for the arithmetic). Only a
        threshold in (2.5, 3.5] passes both, so relaxing the constant -- the reviewer
        took it from 3.0 to 0.5 with the whole suite still green -- fails the first,
        and tightening it fails the second."""
        below = [float(i) for i in range(8)] + [15.75 + i for i in range(8)]
        above = [float(i) for i in range(8)] + [19.25 + i for i in range(8)]
        self.assertAlmostEqual(summarize.modality(below)["gap_over_spread"], 2.5)
        self.assertAlmostEqual(summarize.modality(above)["gap_over_spread"], 3.5)
        self.assertFalse(summarize.modality(below)["multimodal"])
        self.assertTrue(summarize.modality(above)["multimodal"])

    def test_the_minimum_cluster_share_is_pinned_from_both_sides(self):
        """At n = 16 the share floor of 15% admits a cluster of 3 and refuses one of
        2, so a two-point excursion cannot become a "performance state" while a
        three-point one can. Lowering the constant fails the first, raising it the
        second."""
        two = [10.0 + 0.1 * i for i in range(14)] + [500.0, 500.5]
        three = [10.0 + 0.1 * i for i in range(13)] + [500.0, 500.5, 501.0]
        self.assertFalse(summarize.modality(two)["multimodal"])
        self.assertTrue(summarize.modality(three)["multimodal"])

    def test_gap_over_spread_is_reported_even_when_not_flagged(self):
        """A near miss has to be visible as a number. Rounding it into a clean
        "unimodal" is how a 2.9 gets read the same as a 0.1."""
        below = [float(i) for i in range(8)] + [15.75 + i for i in range(8)]
        self.assertFalse(summarize.modality(below)["multimodal"])
        self.assertIsNotNone(summarize.modality(below)["gap_over_spread"])
        self.assertIn("not flagged", summarize.modality(below)["reason"])
        self.assertIn("not 'one mode proved'", summarize.modality(below)["reason"])

    def test_a_sample_too_small_is_not_judged_rather_than_called_unimodal(self):
        got = summarize.modality([100.0, 100.5, 101.0, 400.0, 400.5, 401.0])
        self.assertFalse(got["judged"])
        self.assertFalse(got["multimodal"])

    def test_a_judged_sample_says_so(self):
        self.assertTrue(summarize.modality(self.BIMODAL)["judged"])

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
    # Fourteen runs, not nine. At nine every row in this fixture came back
    # `not-judged`, so the twelve end-to-end tests built on it never once exercised a
    # real modality verdict -- the main path through the summariser was untested while
    # the file looked thoroughly covered. Fourteen clears MODALITY_MIN_N with the
    # drift kept deliberately even (widest gap 3 against an interquartile spread of 6,
    # so gap/spread 0.5) and the verdict lands on `unimodal`, which is the branch the
    # published campaign will actually take.
    DRIFT = (100.0, 110.0, 120.0, 125.0, 105.0, 115.0, 118.0, 122.0, 108.0,
             102.0, 112.0, 124.0, 106.0, 116.0)
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
                # 14, not 9: below MODALITY_MIN_N every row comes back `not-judged`,
                # so a fixture of 9 exercises only the branch that declines to look.
                for run in range(14):
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

    def test_a_bimodal_ratio_is_flagged_even_when_both_absolutes_are_not(self):
        """The reviewer's reproduction of the critical finding. The host drifts
        smoothly, so neither cipher's absolute sample is bimodal -- but in a third of
        runs the state changes *between* the two ciphers' measurements, and then the
        ratio is precisely what stops cancelling. The per-run ratios come out in two
        discrete states and the summary must say so, or the primary column publishes
        `1.132 [1.132, 2.433]` under a caption asserting that drift cancelled."""
        rows = []
        for run in range(24):
            drift = 300.0 + 4.0 * run          # smooth, so absolutes are unimodal
            flipped = (run % 3 == 0)           # a third of runs straddle a transition
            rows.append((run, 0, "base", "ctr-table", 65536,
                         "%.6f" % drift, "NA", "NA"))
            rows.append((run, 1, "other", "ctr-table", 65536,
                         "%.6f" % (drift * (2.15 if flipped else 1.0)), "NA", "NA"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            got = {r["cipher"]: r for r in summarize.summarize(path, "base", 0)}
        self.assertEqual(got["other"]["modality"], "unimodal")
        self.assertEqual(got["other"]["ratio_modality"], "multimodal")
        self.assertIn("1.0", got["other"]["ratio_mode_medians"])
        self.assertIn("2.15", got["other"]["ratio_mode_medians"])

    def test_a_row_flagged_on_only_one_of_its_two_samples_reaches_the_header(self):
        """The sibling of the not_judged `or`, and it was undefended: mutating the
        flagged list to `and` survived a sweep, because the test above checks the
        row's columns and nothing checked the header built from them. The whole point
        of the ratio check is the case where the absolute sample looks fine, so `and`
        -- requiring both samples to be flagged -- reports `multimodal_samples: none`
        over exactly the campaign the check exists to catch.

        Same construction as the test above: smooth drift keeps both absolutes
        unimodal while a third of runs straddle a state transition between the two
        ciphers' measurements, so only the ratio is in two states."""
        rows = []
        for run in range(24):
            drift = 300.0 + 4.0 * run
            flipped = (run % 3 == 0)
            rows.append((run, 0, "base", "ctr-table", 65536, "%.6f" % drift,
                         "NA", "NA"))
            rows.append((run, 1, "other", "ctr-table", 65536,
                         "%.6f" % (drift * (2.15 if flipped else 1.0)), "NA", "NA"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            got = {r["cipher"]: r for r in summarize.summarize(path, "base", 0)}
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                text = fh.read()
        # the asymmetry: flagged on the ratio only, and the only flag in the file
        self.assertEqual(got["other"]["modality"], "unimodal")
        self.assertEqual(got["other"]["ratio_modality"], "multimodal")
        self.assertEqual(got["base"]["modality"], "unimodal")
        self.assertEqual(got["base"]["ratio_modality"], "unimodal")
        self.assertNotIn("# multimodal_samples: none", text)
        self.assertIn("other@65536 (ratio)", text)
        self.assertIn("other@65536 ratio: two separated states", text)

    def test_the_new_modality_columns_reach_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            summarize.summarize(self.build(d), "present-80-r16", 0)
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                header = [ln for ln in fh if not ln.startswith("#")][0]
        for column in ("modality_reason", "gap_over_spread", "ratio_modality",
                       "ratio_gap_over_spread", "ratio_modality_reason"):
            self.assertIn(column, header)

    def test_a_sample_too_small_is_written_as_not_judged_not_as_unimodal(self):
        """`modality` declines to judge below 12 points. Writing that as `unimodal`
        would launder "we did not look" into "we looked and found one mode"."""
        rows = []
        for run in range(6):
            rows.append((run, 0, "a", "ctr-table", 65536, "%.6f" % (100.0 + run),
                         "NA", "NA"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            got = summarize.summarize(path, "a", 0)
        self.assertEqual(got[0]["modality"], "not-judged")
        self.assertEqual(got[0]["ratio_modality"], "not-judged")
        self.assertIn("too small", got[0]["modality_reason"])

    def test_an_unjudged_row_counts_no_modes(self):
        """`len(modes) or 1` wrote `1` for a sample nobody examined -- the same small
        untruth as calling it unimodal, in a column instead of a verdict. One mode is
        a finding; blank is the absence of one."""
        rows = [(run, 0, "a", "ctr-table", 65536, "%.6f" % (100.0 + run), "NA", "NA")
                for run in range(6)]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            got = summarize.summarize(path, "a", 0)
        self.assertEqual(got[0]["mode_count"], "")
        self.assertEqual(got[0]["ratio_mode_count"], "")
        self.assertEqual(got[0]["gap_over_spread"], "n/a")

    def test_a_judged_unimodal_row_still_counts_one_mode(self):
        """The blank above is specific to `not-judged`; a sample that was examined and
        found to hold one mode says one, because that is a result."""
        rows = [(run, 0, "a", "ctr-table", 65536, "%.6f" % (100.0 + run), "NA", "NA")
                for run in range(14)]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            got = summarize.summarize(path, "a", 0)
        self.assertEqual(got[0]["modality"], "unimodal")
        self.assertEqual(got[0]["mode_count"], 1)

    def test_the_gap_over_spread_column_carries_the_computed_value(self):
        """The column, not just its name. It is the whole visibility mechanism: it
        exists so a near miss is a number a reader can see rather than an absence.
        Only the header was tested, so writing a wrong value here went unnoticed.

        Both fixtures are two clusters of eight consecutive integers, whose IQR is
        exactly 3.5 (quartiles of 0..7 at 1.75 and 5.25). `near` leaves a gap of 8.75
        for a ratio of exactly 2.5, just under the threshold of 3, so it must be
        reported unimodal *with its 2.5 visible*. `split` leaves 12.25 for exactly
        3.5, just over."""
        near = [100.0 + i for i in range(8)] + [115.75 + i for i in range(8)]
        split = [100.0 + i for i in range(8)] + [119.25 + i for i in range(8)]
        rows = []
        for run, (a, b) in enumerate(zip(near, split)):
            rows.append((run, 0, "near", "ctr-table", 65536, "%.6f" % a, "NA", "NA"))
            rows.append((run, 1, "split", "ctr-table", 65536, "%.6f" % b, "NA", "NA"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            got = {r["cipher"]: r for r in summarize.summarize(path, "near", 0)}
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                text = fh.read()
        self.assertEqual(got["near"]["modality"], "unimodal")
        self.assertEqual(got["near"]["gap_over_spread"], "2.5")
        self.assertEqual(got["split"]["modality"], "multimodal")
        self.assertEqual(got["split"]["gap_over_spread"], "3.5")
        # and it survives the trip through the file, not only the returned dict
        self.assertIn(",2.5,", text)
        self.assertIn(",3.5,", text)

    def test_gap_over_spread_formatting_says_what_it_means(self):
        """Three cases that are not numbers: no verdict, two states with no spread at
        all, and a genuine value. `n/a` and `inf` are distinguishable from 0."""
        self.assertEqual(summarize._fmt_ratio(None), "n/a")
        self.assertEqual(summarize._fmt_ratio(float("inf")), "inf")
        self.assertEqual(summarize._fmt_ratio(0.0), "0")
        self.assertEqual(summarize._fmt_ratio(2.5), "2.5")

    def test_the_header_does_not_claim_none_when_nothing_was_judged(self):
        """`multimodal_samples: none` reads as "we looked and found nothing". For an
        8-to-11-run campaign nothing was looked at, and this band became reachable
        only when MODALITY_MIN_N went from 8 to 12."""
        rows = [(run, 0, "a", "ctr-table", 65536, "%.6f" % (100.0 + run), "NA", "NA")
                for run in range(9)]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            summarize.summarize(path, "a", 0)
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                text = fh.read()
        self.assertNotIn("# multimodal_samples: none\n", text)
        self.assertIn("1 not judged", text)
        self.assertIn("# not_judged_samples: a@65536", text)
        self.assertIn("too small to judge", text)

    def test_the_shared_fixture_actually_reaches_a_verdict(self):
        """A guard on the fixture itself, not on the code. While DRIFT held nine
        values every end-to-end test in this class ran entirely inside the
        `not-judged` branch, so the summariser's main path was untested and nothing
        said so. If DRIFT is ever trimmed back below MODALITY_MIN_N, this fails
        instead of the coverage quietly evaporating."""
        self.assertGreaterEqual(len(self.DRIFT), summarize.MODALITY_MIN_N)
        with tempfile.TemporaryDirectory() as d:
            got = summarize.summarize(self.build(d), "present-80-r16", 0)
        for row in got:
            self.assertEqual(row["modality"], "unimodal")
            self.assertEqual(row["ratio_modality"], "unimodal")
            self.assertEqual(row["n_runs"], len(self.DRIFT))

    def test_a_row_unjudged_on_only_one_of_its_two_samples_still_counts(self):
        """The absolute and ratio samples of one row can have different n, because a
        run that measured a cipher but not the baseline is kept for the absolute
        median and skipped for the pairing. So a row can be judged on one and not the
        other, and the `or` in the not_judged list is what catches it -- with `and`
        the header would print `not_judged_samples: none` over a row whose own
        ratio_modality column reads `not-judged`.

        Built so this row is the ONLY unjudged verdict in the file: `a` is measured in
        runs 0-12 (13 runs, judged) and `b` in runs 2-15 (14 runs, judged), so they
        share only runs 2-12 and `a`'s ratio sample is 11 -- one short of the twelve
        the check needs. A fixture where the baseline were also unjudged would let
        `and` pass on the baseline's row instead."""
        rows = []
        for run in range(13):
            rows.append((run, 0, "a", "ctr-table", 65536,
                         "%.6f" % (150.0 + 0.5 * (run % 4)), "NA", "NA"))
        for run in range(2, 16):
            rows.append((run, 1, "b", "ctr-table", 65536,
                         "%.6f" % (100.0 + 0.5 * (run % 4)), "NA", "NA"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            got = {r["cipher"]: r for r in summarize.summarize(path, "b", 0)}
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                text = fh.read()
        # the asymmetry the fixture exists to create
        self.assertEqual(got["a"]["modality"], "unimodal")
        self.assertEqual(got["a"]["ratio_modality"], "not-judged")
        self.assertEqual(got["b"]["modality"], "unimodal")
        self.assertEqual(got["b"]["ratio_modality"], "unimodal")
        # and the header must not report the file as fully judged
        self.assertNotIn("# not_judged_samples: none\n", text)
        self.assertNotIn("# multimodal_samples: none\n", text)
        self.assertIn("1 not judged", text)
        self.assertIn("a@65536 (ratio)", text)

    def test_the_header_says_none_when_everything_was_judged_and_clean(self):
        """The bare `none` is still correct when it is earned. Note this needs its own
        14-run fixture: the shared one in this file has 9 runs, so every row in it is
        `not-judged` -- and before this round it was reported as
        `multimodal_samples: none`, which is the bug in miniature."""
        rows = []
        for run in range(14):
            for order, (cipher, v) in enumerate((("a", 100.0), ("b", 150.0))):
                rows.append((run, order, cipher, "ctr-table", 65536,
                             "%.6f" % (v + 0.25 * (run % 5)), "NA", "NA"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            summarize.summarize(path, "a", 0)
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                text = fh.read()
        self.assertIn("# multimodal_samples: none\n", text)
        self.assertIn("# not_judged_samples: none\n", text)

    def test_the_measured_coverage_reaches_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            summarize.summarize(self.build(d), "present-80-r16", 0)
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                text = fh.read()
        self.assertIn("ci_coverage:", text)
        self.assertIn("0.86", text)
        self.assertIn("10000 resamples", text)
        self.assertIn("2.5%/97.5%", text)

    def test_an_unresolvable_flip_is_marked_unpublishable(self):
        """UNSTABLE from two ciphers a hair apart must not travel to a caption."""
        with tempfile.TemporaryDirectory() as d:
            rows = []
            for size, speeds in ((4096, {"a": 100.0, "b": 100.4}),
                                 (65536, {"a": 100.4, "b": 100.0})):
                for run in range(12):
                    jitter = 0.35 * ((run % 5) - 2)
                    for order, (cipher, v) in enumerate(sorted(speeds.items())):
                        rows.append((run, order, cipher, "ctr-table", size,
                                     "%.6f" % (v + jitter), "NA", "NA"))
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            summarize.summarize(path, "a", 0)
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                text = fh.read()
        self.assertIn("UNSTABLE", text)
        self.assertIn("ranking_stability_publishable: no", text)

    def test_a_resolvable_flip_is_marked_publishable(self):
        with tempfile.TemporaryDirectory() as d:
            rows = []
            for size, speeds in ((4096, {"a": 200.0, "b": 100.0}),
                                 (65536, {"a": 100.0, "b": 200.0})):
                for run in range(12):
                    for order, (cipher, v) in enumerate(sorted(speeds.items())):
                        rows.append((run, order, cipher, "ctr-table", size,
                                     "%.6f" % (v + 0.01 * run), "NA", "NA"))
            path = os.path.join(d, "runs.csv")
            write_runs_csv(path, rows)
            summarize.summarize(path, "a", 0)
            with open(os.path.join(d, "summary.csv"), encoding="ascii") as fh:
                text = fh.read()
        self.assertIn("UNSTABLE", text)
        self.assertIn("ranking_stability_publishable: yes", text)

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

    def test_only_campaign_and_unknown_are_publishable(self):
        """Exact equality against `SMOKE-RUN` is a deny-list on free text, and the
        reviewer walked straight past it: `SMOKE-RUN (3 runs, do not publish)` and
        `SMOKE RUN` both fail to match. Task 8's campaign.py, which will write these
        markers, does not exist yet, so the grammar is not fixed anywhere. An
        allow-list fails safe."""
        for marker in ("CAMPAIGN", "UNKNOWN"):
            self.assertTrue(summarize.is_publishable_provenance(marker), marker)
        for marker in ("SMOKE-RUN",
                       "SMOKE-RUN (3 RUNS, DO NOT PUBLISH)",
                       "SMOKE RUN",
                       "SMOKERUN",
                       "TRIAL",
                       "CAMPAIGN (PRELIMINARY)",
                       ""):
            self.assertFalse(summarize.is_publishable_provenance(marker), marker)

    def test_require_campaign_narrows_it_to_one(self):
        self.assertTrue(
            summarize.is_publishable_provenance("CAMPAIGN", require_campaign=True))
        self.assertFalse(
            summarize.is_publishable_provenance("UNKNOWN", require_campaign=True))

    def test_the_real_master_key_file_has_no_status_and_still_reads(self):
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "..", "results", "v2", "cuda",
                            "master-key-search.csv")
        prov, rows = summarize.read_csv_with_provenance(path)
        self.assertIn(prov, ("SMOKE-RUN", "CAMPAIGN"))
        self.assertEqual(len(summarize.measured_rows(rows)), len(rows))


if __name__ == "__main__":
    unittest.main()
