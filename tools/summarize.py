#!/usr/bin/env python3
"""Turn a campaign's raw per-run measurements into the figures a paper may quote.

Reads `results/v2/<target>/runs.csv` -- one row per (run, cipher, working-set size)
written by tools/campaign.py -- and writes `summary.csv` beside it. Nothing here
measures anything; it exists so that no number reaches a table by hand, and so that
every published figure carries the uncertainty it was measured with.

What it publishes, and why each part is here
--------------------------------------------

*Medians with a bootstrap 95% CI.* The repository currently publishes bare medians
-- 416, 366, 353 Mbit/s -- and then ranks the ciphers by them. Three numbers with no
interval cannot support an ordering claim. The interval is a percentile bootstrap,
10 000 resamples, driven by `random.Random(seed)` so that a rerun reproduces it
exactly rather than approximately.

*Paired ratios, which are the primary comparison.* Drift common to a run largely
cancels within that run, so a ratio formed between two ciphers measured in the same
run is stable even where their absolute figures wander. The ratio against the
baseline is therefore computed per run and then bootstrapped over those per-run
ratios -- never as the ratio of two independently summarised medians, which would
throw away exactly the pairing that makes it trustworthy. A run that is missing
either cipher is skipped, never imputed.

*A top group instead of a ranking.* When a cipher's interval overlaps the leader's,
the measurement cannot separate them, and reporting them in order would assert
something the data does not support. `top_group` returns the set that must be
reported together, and the table generator marks them.

*A ranking-stability check across working-set sizes.* The campaign measures 4 KiB,
16 KiB and 64 KiB and publishes 64 KiB. If the ordering changes with the working
set, that is a result about cache, not about ciphers, and it is stated in the
summary file rather than left to be noticed.

*A modality check, because one host is bimodal rather than merely noisy.* Task 4
established that the x86 measurement host has two discrete performance states about
2.15x apart and that which one a run lands in is not controllable: the same binary
at warmups 3/20/100/500 gave 1.72 / 0.81 / 1.72 / 0.78 cyc/B. A percentile interval
around the median of a sample drawn from both states is a bracket that spans the
gap between them and describes neither -- it looks like a wide but ordinary
interval, which is precisely the misreading to avoid. So every sample is tested for
a second mode, and when one is found the summary says so and reports each mode's
median and share. `tools/make_tables.py` then prints the modes in place of the
interval. The interval is still computed and still written to `summary.csv`, marked
as belonging to a multimodal sample, because suppressing it would hide how wide the
spread is; what must not happen is a multimodal sample being published as a tidy
`median [lo, hi]` with nothing to say it is one.

Standard library only, deliberately: the repository has no third-party dependency
and the bootstrap is twenty lines.
"""

import argparse
import csv
import math
import os
import random
import sys

# The construction every other one is reported against.
DEFAULT_BASELINE = "present-80-r16"

# Spec §5: bootstrap 95% CI, 10 000 resamples, seeded.
DEFAULT_RESAMPLES = 10000
CI_LOW = 0.025
CI_HIGH = 0.975

# What the interval actually delivers, measured rather than assumed. The percentile
# bootstrap of a *median* under-covers at the sample sizes a campaign produces:
# simulated coverage of the nominal 95% interval is 0.858 to 0.905 for n = 7 to 25.
# The endpoints are also confined to values that actually occur in the sample, so the
# interval moves in discrete steps and cannot be read as a smooth 95% bracket. Stated
# here, in the file header and in the table caption rather than being quietly labelled
# "95%", because the honest claim is the measured one.
CI_COVERAGE_NOTE = ("nominal 95%; measured coverage 0.86-0.91 for n = 7 to 25, and "
                    "the endpoints can only take values present in the sample")

# Spec §2: three working-set sizes are measured, 64 KiB is the published one. The
# other two exist so the ranking-stability check has something to compare.
PUBLISHED_SIZE_BYTES = 65536

# Modality thresholds. A sample is called multimodal when the best two-cluster split
# leaves a gap between the clusters wider than MODALITY_GAP_FACTOR times the larger
# cluster's interquartile range, with each cluster holding at least MODALITY_MIN_SHARE
# of the sample. The share floor is what keeps a single stalled run from being
# promoted to a "performance state"; the gap factor is what keeps ordinary spread from
# being split in two. Below MODALITY_MIN_N points the question is not answerable and
# the answer is "not judged" rather than "unimodal by default".
#
# The scale statistic is the IQR and not the cluster range, and that is the whole
# point of it. With the range, a *single* observation landing between the two states
# -- exactly what a run that straddles a state transition produces -- joins one
# cluster, inflates that cluster's range to span the void, and collapses a blatant
# 2.15x bimodality to "unimodal". Measured: adding one point at 300 to a clean
# 193/415 sample took detection from 100% to 4.8%. With the IQR the same sample is
# still detected at 100% with up to three straddlers.
#
# The IQR is a smaller number than the range, so the factor had to rise with it. The
# pair (IQR, 3.0) was chosen by simulation, not by taste:
#
#   false positives on a unimodal normal sample, 6000 trials per point
#     n=8 5.8%   n=10 2.7%   n=12 1.1%   n=14 0.2%   n=16 0.2%   n=20 0.02%  n=25 0.0%
#   detection of two equal normal modes k sigma apart at n=24, 800 trials per point
#     6sd 18%    8sd 63%     10sd 95%    12sd 100%
#
# The predecessor (range, 2.0) detected 0.7% / 7.8% / 40% / 75% at those separations,
# so this is a large sensitivity gain, and the false-negative direction is the
# dangerous one: it publishes a two-state sample as a tidy interval, which is the
# single failure this apparatus exists to prevent. MODALITY_MIN_N rose from 8 to 12
# to keep the false-positive rate at or below about 1%; a sample of 8 to 11 runs is
# reported as "not judged", which is what it is.
MODALITY_MIN_N = 12
MODALITY_MIN_SHARE = 0.15
MODALITY_GAP_FACTOR = 3.0

REQUIRED_RUN_COLUMNS = ("run_index", "cipher", "impl", "size_bytes", "mbit_per_sec")

# The modality verdicts. "unimodal" means *not flagged*, never "shown to be
# unimodal": the detector's sensitivity is bounded (see MODALITY_GAP_FACTOR) and a
# separation below its threshold reads as unimodal. "not-judged" is a separate value
# rather than being laundered into "unimodal", because a sample too small to judge has
# not earned the reassuring label.
MODALITY_MULTIMODAL = "multimodal"
MODALITY_UNIMODAL = "unimodal"
MODALITY_NOT_JUDGED = "not-judged"

SUMMARY_COLUMNS = (
    "target", "size_bytes", "cipher", "impl", "n_runs",
    "median_mbit_per_sec", "ci_lo", "ci_hi",
    "baseline", "ratio_median", "ratio_lo", "ratio_hi",
    "modality", "mode_count", "mode_medians", "mode_shares",
    "gap_over_spread", "modality_reason",
    "ratio_modality", "ratio_mode_count", "ratio_mode_medians", "ratio_mode_shares",
    "ratio_gap_over_spread", "ratio_modality_reason",
    "in_top_group", "in_ratio_top_group", "published",
)


# --- CSV plumbing ------------------------------------------------------------------
#
# Both shapes already present under results/v2/ have to survive this. block-eval.csv
# carries a `status` column whose non-`measured` rows have empty rate fields, so a
# consumer that parses rates without filtering crashes on them. master-key-search.csv
# has no `status` column at all, so a consumer that filters unconditionally raises
# KeyError on it. Hence one reader that does both, used by every tool here.

def provenance_of(comment_lines):
    """The `# provenance: CAMPAIGN` / `# provenance: SMOKE-RUN` marker, or UNKNOWN.

    The marker is what stops a trial run reaching the paper; a file that does not
    carry one is reported as UNKNOWN rather than assumed good.
    """
    for line in comment_lines:
        body = line.lstrip("#").strip()
        if body.lower().startswith("provenance:"):
            return body.split(":", 1)[1].strip().upper()
    return "UNKNOWN"


# The only two markers a tool will publish from. Anything else -- a decorated
# `SMOKE-RUN (3 runs, do not publish)`, a `SMOKE RUN` with a space, a marker a future
# harness invents -- is refused. Matching `SMOKE-RUN` exactly would let every one of
# those through, and Task 8's campaign.py, which will write these markers, has not
# been written yet, so the grammar is not fixed anywhere. An allow-list fails safe
# where a deny-list fails open.
PROVENANCE_CAMPAIGN = "CAMPAIGN"
PROVENANCE_UNKNOWN = "UNKNOWN"
PUBLISHABLE_PROVENANCE = (PROVENANCE_CAMPAIGN, PROVENANCE_UNKNOWN)


def is_publishable_provenance(marker, require_campaign=False):
    """Whether a table may be built from data carrying this provenance marker."""
    if require_campaign:
        return marker == PROVENANCE_CAMPAIGN
    return marker in PUBLISHABLE_PROVENANCE


def read_csv_with_provenance(path):
    """Returns (provenance, rows). Lines beginning with '#' are header prose, not
    data -- the convention results/m4-speed.csv and the v2 CUDA files already use."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    comments = [ln for ln in lines if ln.startswith("#")]
    body = [ln for ln in lines if not ln.startswith("#")]
    rows = [dict(row) for row in csv.DictReader(body)]
    return provenance_of(comments), rows


def measured_rows(rows, status_column="status", measured="measured"):
    """Keeps only rows that record a measurement.

    A file with no `status` column has nothing to filter and every row is kept; that
    is not an error, and treating it as one is the KeyError that master-key-search.csv
    provokes in a consumer written against block-eval.csv alone.
    """
    return [r for r in rows
            if status_column not in r or r.get(status_column) == measured]


def _as_float(text, column, where=""):
    """Strict: a measurement that will not parse is an error, not a dropped row.

    Silently skipping it would shrink the sample the interval is computed from
    without saying so, which is the one failure this whole file exists to prevent.
    """
    if isinstance(text, (int, float)):
        return float(text)
    try:
        return float(text)
    except (TypeError, ValueError):
        raise ValueError("%s%s: %r is not a number" % (where, column, text))


def _optional_float(text):
    """For the sensor columns. `temp_c` and `freq_khz` are 'NA' on a target with no
    such sensor -- as ctr_bench writes 'NA' for tsc_per_byte off x86 -- and that must
    not abort a summary of numbers that do not depend on them."""
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _sort_key(key):
    """Orders run indices and sizes that may have arrived as ints or as strings."""
    try:
        return (0, float(key), "")
    except (TypeError, ValueError):
        return (1, 0.0, str(key))


def _describe_pair_key(key):
    """A pairing bucket, for error messages: `(run_index, size_bytes)`."""
    run_index, size_bytes = key
    if size_bytes is None:
        return "run %r" % (run_index,)
    return "run %r at size %r" % (run_index, size_bytes)


# --- statistics --------------------------------------------------------------------

def _median(sorted_values):
    n = len(sorted_values)
    if n == 0:
        raise ValueError("median of an empty sample")
    mid = n // 2
    if n % 2:
        return sorted_values[mid]
    return (sorted_values[mid - 1] + sorted_values[mid]) / 2.0


def _percentile_index(count, quantile, upper):
    """Index into `count` sorted bootstrap statistics for a percentile endpoint.

    The lower endpoint takes the largest index at or below `quantile`, the upper the
    smallest at or above it, so the interval never sits inside the nominal 95% by
    rounding. At 10 000 resamples that is index 250 and index 9749.
    """
    if upper:
        idx = int(math.ceil(quantile * count)) - 1
    else:
        idx = int(math.floor(quantile * count))
    return min(max(idx, 0), count - 1)


def median_ci(values, resamples=DEFAULT_RESAMPLES, seed=0):
    """Sample median with a percentile bootstrap interval, nominally 95%.

    **What "95%" is worth at these sample sizes.** The percentile bootstrap of a
    *median* under-covers on small samples: simulated coverage of this interval is
    0.858 to 0.905 for n = 7 to 25, not 0.95. The endpoints are also confined to
    values that actually occur in the sample, so the interval moves in discrete steps
    and a very tight one on a small sample should not be over-read. This is a property
    of the estimator, not a defect to be fixed by relabelling: `CI_COVERAGE_NOTE`
    carries the measured figure into summary.csv's header and the table caption. No
    lower bound on n is enforced, because the brief's contract admits n = 3 and a
    refusal would be a worse answer than a stated caveat.

    The sample is sorted before resampling, so the answer depends on the multiset of
    measurements and not on the order the campaign happened to record them in: two
    runs that measured the same things in a different randomised order must publish
    the same interval.

    A sample with no spread short-circuits to a degenerate interval instead of
    resampling a constant 10 000 times.
    """
    vals = sorted(_as_float(v, "value") for v in values)
    if not vals:
        raise ValueError("median_ci of an empty sample")
    if resamples < 1:
        raise ValueError("resamples must be >= 1, got %r" % (resamples,))
    med = _median(vals)
    if vals[0] == vals[-1]:
        return (med, vals[0], vals[-1])

    n = len(vals)
    pick = random.Random(seed).randrange
    boot = [_median(sorted(vals[pick(n)] for _ in range(n))) for _ in range(resamples)]
    boot.sort()
    return (med,
            boot[_percentile_index(resamples, CI_LOW, upper=False)],
            boot[_percentile_index(resamples, CI_HIGH, upper=True)])


def paired_ratios(runs, cipher, baseline):
    """The per-run ratios `cipher / baseline`, in run order.

    Split out of `paired_ratio_ci` so the ratio *sample* can be modality-checked in
    its own right. A run can straddle a state transition -- the host changes state
    between the two ciphers' measurements -- and when it does, the ratio is precisely
    what stops cancelling, so the ratio sample can be bimodal while both absolute
    samples are not. See `paired_ratio_ci` for the pairing rules.
    """
    per_run = {}
    for row in runs:
        for column in ("run_index", "cipher", "mbit_per_sec"):
            if column not in row:
                raise ValueError("row is missing column %r: %r" % (column, row))
        name = row["cipher"]
        if name != cipher and name != baseline:
            continue
        key = (row["run_index"], row.get("size_bytes"))
        slot = per_run.setdefault(key, {})
        if name in slot:
            raise ValueError(
                "%s has more than one row for cipher %r; one run measures one impl "
                "per cipher per size, so summarising tuning output -- which holds "
                "several -- would pick one arbitrarily. Group the rows before "
                "pairing them" % (_describe_pair_key(key), name))
        slot[name] = _as_float(row["mbit_per_sec"], "mbit_per_sec",
                               where="%s, cipher %r: " % (_describe_pair_key(key), name))

    ratios = []
    for key in sorted(per_run, key=lambda k: tuple(_sort_key(part) for part in k)):
        slot = per_run[key]
        if cipher not in slot or baseline not in slot:
            continue
        denominator = slot[baseline]
        if denominator == 0.0:
            raise ValueError(
                "%s measured baseline %r at 0 Mbit/s; that is a broken measurement, "
                "not a ratio" % (_describe_pair_key(key), baseline))
        ratios.append(slot[cipher] / denominator)

    if not ratios:
        raise ValueError(
            "no run measured both %r and %r at the same working-set size, so there "
            "is no paired ratio to report" % (cipher, baseline))
    return ratios


def paired_ratio_ci(runs, cipher, baseline, resamples=DEFAULT_RESAMPLES, seed=0):
    """Median of the per-run ratio `cipher / baseline`, with its own bootstrap CI.

    `runs` is a list of dicts carrying at least `run_index`, `cipher` and
    `mbit_per_sec`. The ratio is formed inside each run, which is what makes drift
    common to that run cancel; the bootstrap then resamples those per-run ratios.

    A run holding only one of the two is skipped -- never imputed, never back-filled
    from another run's value for the missing cipher.

    Rows are bucketed on `run_index` *and* `size_bytes` where that column exists.
    runs.csv carries three working-set sizes, so `run_index` alone is not a unique key
    over a whole file: bucketing on it regardless silently divides a 4 KiB figure by a
    64 KiB one whenever the two ciphers' rows for a run come from different sizes,
    which a duplicate check alone does not catch because neither bucket has a
    duplicate in it. Two rows landing in the same bucket for the same cipher -- two
    impls of it in one run, as tuning output has -- is still an error rather than a
    coin flip. Callers stratify first (`summarize` does) and these are what tell them
    when they have not.

    The interval is only meaningful if the ratio sample is unimodal; call `modality`
    on `paired_ratios(...)` to find out, as `summarize` does.
    """
    return median_ci(paired_ratios(runs, cipher, baseline),
                     resamples=resamples, seed=seed)


def top_group(stats):
    """The ciphers that must be reported together rather than ranked.

    `stats` entries carry `cipher`, `median`, `lo`, `hi`. The leader is the highest
    median; every cipher whose interval reaches down to -- or up to -- the leader's
    lower bound is in the group, because the measurement cannot order it against the
    leader. This is the rule that replaces the bare 416 / 366 / 353 Mbit/s ranking.

    A cipher far behind on the median but carrying a very wide interval joins the
    group. That is the intended reading, not a defect: an interval that wide says
    the campaign cannot tell the two apart, and saying so is the point.
    """
    if not stats:
        return []
    ordered = sorted(stats, key=lambda s: (-float(s["median"]), str(s["cipher"])))
    leader_lo = float(ordered[0]["lo"])
    return [str(s["cipher"]) for s in ordered if float(s["hi"]) >= leader_lo]


def ranking_stable(by_size):
    """Whether the ordering of the ciphers is the same at every working-set size.

    `by_size` maps a size to that size's ordered list of cipher names. Returns
    `(True, note)` when every size agrees, `(False, msg)` otherwise, where `msg`
    names the two sizes and both orders in full.

    A ranking that depends on the working set is a result about cache, not about
    ciphers. It is not a failure of the campaign and it does not abort anything --
    but it has to be stated, because publishing one size and staying quiet is how it
    would otherwise be presented as a property of the constructions.
    """
    sizes = sorted(by_size, key=_sort_key)
    if len(sizes) < 2:
        return (True, "only %d working-set size measured; nothing to compare"
                      % len(sizes))

    reference = sizes[0]
    reference_order = list(by_size[reference])
    problems = []
    for size in sizes[1:]:
        order = list(by_size[size])
        if set(order) != set(reference_order):
            only = sorted(set(order) ^ set(reference_order))
            problems.append(
                "sizes %s and %s did not measure the same ciphers (%s appears at "
                "only one of them): %s vs %s"
                % (reference, size, ", ".join(only),
                   ", ".join(reference_order), ", ".join(order)))
        elif order != reference_order:
            problems.append(
                "ranking differs between size %s and size %s: %s vs %s"
                % (reference, size, ", ".join(reference_order), ", ".join(order)))
    if problems:
        return (False, "; ".join(problems))
    return (True, "ranking identical at all %d sizes: %s"
                  % (len(sizes), ", ".join(reference_order)))


def _sum_squared_deviation(part):
    mean = sum(part) / len(part)
    return sum((v - mean) ** 2 for v in part)


def _quantile(sorted_part, q):
    """Linear-interpolation quantile over sorted values."""
    n = len(sorted_part)
    if n == 1:
        return sorted_part[0]
    position = q * (n - 1)
    low = int(math.floor(position))
    high = min(low + 1, n - 1)
    return sorted_part[low] + (position - low) * (sorted_part[high] - sorted_part[low])


def _iqr(sorted_part):
    """Interquartile range: the cluster scale statistic. Robust to a few observations
    stranded between the two states, which the range is not."""
    return _quantile(sorted_part, 0.75) - _quantile(sorted_part, 0.25)


def modality(values, min_n=MODALITY_MIN_N, min_share=MODALITY_MIN_SHARE,
             gap_factor=MODALITY_GAP_FACTOR):
    """Detect a sample drawn from two separated states rather than one noisy one.

    The method is an exact one-dimensional 2-means split -- every admissible split of
    the sorted sample is tried and the one minimising within-cluster sum of squares
    wins, which is tractable here because the data are one-dimensional and there are
    at most a few dozen points -- followed by a separation test: the empty space
    between the two clusters must be wider than `gap_factor` times the larger
    cluster's interquartile range.

    The separation test is what makes the answer mean something. 2-means always
    returns two clusters; cutting an ordinary noisy sample in half is not evidence of
    anything. Requiring the gap to dominate the spread it separates is the difference
    between "two discrete states" and "one distribution, cut arbitrarily".

    **The verdict is one-sided.** `multimodal` False means *not flagged*, never
    "shown to be unimodal": detection at n = 24 is about 18% at 6 sigma of separation,
    63% at 8 and 95% at 10 (see MODALITY_GAP_FACTOR), so a real second mode closer
    than that reads as unimodal. `gap_over_spread` is returned, and written to
    summary.csv, so a near miss is visible as a number rather than rounded away into a
    clean verdict.

    Returns a dict with `judged`, `multimodal`, `modes` (each with `n`, `share`,
    `median`, `min`, `max`), `gap`, `spread`, `gap_over_spread` and a human-readable
    `reason`.
    """
    vals = sorted(_as_float(v, "value") for v in values)
    n = len(vals)
    result = {"judged": False, "multimodal": False, "modes": [], "gap": 0.0,
              "spread": 0.0, "gap_over_spread": None, "reason": ""}

    if n < min_n:
        result["reason"] = ("sample of %d is too small to judge modality; %d points "
                            "are needed before either verdict is claimed" % (n, min_n))
        return result

    floor_n = max(2, int(math.ceil(min_share * n)))
    if 2 * floor_n > n:
        result["reason"] = ("sample of %d cannot hold two clusters of %d"
                            % (n, floor_n))
        return result

    result["judged"] = True
    best_k = None
    best_wss = None
    for k in range(floor_n, n - floor_n + 1):
        wss = _sum_squared_deviation(vals[:k]) + _sum_squared_deviation(vals[k:])
        if best_wss is None or wss < best_wss:
            best_wss, best_k = wss, k

    lower, upper = vals[:best_k], vals[best_k:]
    gap = upper[0] - lower[-1]
    spread = max(_iqr(lower), _iqr(upper))
    result["gap"] = gap
    result["spread"] = spread
    if spread > 0.0:
        result["gap_over_spread"] = gap / spread
    else:
        # Two clusters each with no interquartile spread at all: the sample takes
        # essentially two values. Infinite separation, and reported as such rather
        # than as a division that would raise.
        result["gap_over_spread"] = float("inf") if gap > 0.0 else 0.0

    if gap > gap_factor * spread:
        result["multimodal"] = True
        result["modes"] = [{"n": len(part),
                            "share": len(part) / float(n),
                            "median": _median(part),
                            "min": part[0],
                            "max": part[-1]}
                           for part in (lower, upper)]
        result["reason"] = (
            "two separated states: %d runs around %g and %d runs around %g, "
            "separated by %g against an interquartile spread of %g "
            "(gap/spread %s, threshold %g)"
            % (len(lower), _median(lower), len(upper), _median(upper), gap, spread,
               _fmt_ratio(result["gap_over_spread"]), gap_factor))
    else:
        result["reason"] = (
            "not flagged: the widest separation is %g against an interquartile "
            "spread of %g (gap/spread %s, threshold %g). This is 'no second mode "
            "found', not 'one mode proved'"
            % (gap, spread, _fmt_ratio(result["gap_over_spread"]), gap_factor))
    return result


def _fmt_ratio(value):
    if value is None:
        return "n/a"
    if value == float("inf"):
        return "inf"
    return "%.3g" % value


# --- the summary -------------------------------------------------------------------

def _target_of(runs_csv_path):
    """`results/v2/x86/runs.csv` -> `x86`. The target names the file it came from,
    so it is read from the path rather than passed as a flag that could disagree."""
    return os.path.basename(os.path.dirname(os.path.abspath(runs_csv_path))) or "unknown"


def _fmt(value):
    return "%.6f" % value


def _load_runs(runs_csv_path):
    """Parsed rows, grouped size -> cipher -> list of (run_index, mbit_per_sec).

    Also returns the impl seen per (size, cipher) and the raw rows per size, which
    paired_ratio_ci needs.
    """
    provenance, raw = read_csv_with_provenance(runs_csv_path)
    raw = measured_rows(raw)
    if not raw:
        raise ValueError("%s holds no measured rows" % runs_csv_path)

    missing = [c for c in REQUIRED_RUN_COLUMNS if c not in raw[0]]
    if missing:
        raise ValueError("%s is missing column(s): %s"
                         % (runs_csv_path, ", ".join(missing)))

    by_size = {}
    impls = {}
    seen = set()
    for row in raw:
        size = int(_as_float(row["size_bytes"], "size_bytes"))
        cipher = row["cipher"]
        run_index = row["run_index"]
        value = _as_float(row["mbit_per_sec"], "mbit_per_sec",
                          where="%s, run %r, cipher %r, size %r: "
                                % (runs_csv_path, run_index, cipher, size))
        key = (size, run_index, cipher)
        if key in seen:
            raise ValueError(
                "%s has two rows for size %d, run %r, cipher %r. One run measures "
                "one impl per cipher per size; summarising tuning output, which "
                "holds several, would pick one arbitrarily"
                % (runs_csv_path, size, run_index, cipher))
        seen.add(key)
        # Read but not used for any published figure; parsed here so that a target
        # writing 'NA' for a sensor it does not have cannot abort the summary.
        _optional_float(row.get("temp_c"))
        _optional_float(row.get("freq_khz"))
        by_size.setdefault(size, {}).setdefault(cipher, []).append((run_index, value))
        impls.setdefault((size, cipher), set()).add(row.get("impl", ""))
    return provenance, by_size, impls


def _modality_fields(modes, prefix):
    """The CSV columns describing one modality verdict, under `` or `ratio_`.

    `not-judged` is its own value rather than being folded into `unimodal`: the
    detector's negative verdict is already only "not flagged", so a sample it could
    not even examine must not borrow the reassuring label.
    """
    if not modes["judged"]:
        verdict = MODALITY_NOT_JUDGED
    elif modes["multimodal"]:
        verdict = MODALITY_MULTIMODAL
    else:
        verdict = MODALITY_UNIMODAL
    # An unjudged sample has no mode count. Writing `1` there -- which is what
    # `len(modes) or 1` did -- states the finding the whole `not-judged` verdict
    # exists to withhold: one mode is a result, and no one looked. Blank says
    # nothing, which is the truth.
    if not modes["judged"]:
        mode_count = ""
    else:
        mode_count = len(modes["modes"]) or 1
    return {
        prefix + "modality": verdict,
        prefix + "mode_count": mode_count,
        prefix + "mode_medians": ";".join(_fmt(m["median"]) for m in modes["modes"]),
        prefix + "mode_shares": ";".join(_fmt(m["share"]) for m in modes["modes"]),
        prefix + "gap_over_spread": _fmt_ratio(modes["gap_over_spread"]),
        prefix + "modality_reason": modes["reason"],
    }


def separable_flips(order_by_size, stats_by_size):
    """The order flips between working-set sizes that the campaign actually resolved.

    `ranking_stable` is a strict comparison of orderings with no reference to the
    intervals, which is right for an internal check -- over-reporting is the safe
    direction -- but it means most of its alarms are two near-tied ciphers swapping on
    noise. Simulated on the real 7-cipher set with the true means held *identical* at
    every size, so that every alarm is spurious by construction, it reports UNSTABLE
    in 17% of campaigns at 0.5% within-cipher noise, 46% at 1% and 78% at 2%.

    A flip is counted here only when the two ciphers' intervals are disjoint at both
    sizes -- that is, when the campaign separated them at each size and they still
    changed places. That is the only kind of flip that supports a claim about cache,
    and so the only kind that may reach a paper caption.

    `stats_by_size` maps size -> cipher -> (lo, hi). Returns a list of
    (size_a, size_b, cipher_a, cipher_b) tuples.
    """
    sizes = sorted(order_by_size, key=_sort_key)
    if len(sizes) < 2:
        return []
    reference = sizes[0]
    found = []
    for size in sizes[1:]:
        first = order_by_size[reference]
        second = order_by_size[size]
        shared = set(first) & set(second)
        rank_first = {c: i for i, c in enumerate(first)}
        rank_second = {c: i for i, c in enumerate(second)}
        for cipher_a in sorted(shared):
            for cipher_b in sorted(shared):
                if cipher_a >= cipher_b:
                    continue
                flipped = ((rank_first[cipher_a] < rank_first[cipher_b])
                           != (rank_second[cipher_a] < rank_second[cipher_b]))
                if not flipped:
                    continue
                if all(_disjoint(stats_by_size[s][cipher_a], stats_by_size[s][cipher_b])
                       for s in (reference, size)):
                    found.append((reference, size, cipher_a, cipher_b))
    return found


def _disjoint(one, other):
    """Whether two (lo, hi) intervals fail to overlap at all."""
    return one[1] < other[0] or other[1] < one[0]


def summarize(runs_csv_path, baseline=DEFAULT_BASELINE, seed=0,
              resamples=DEFAULT_RESAMPLES):
    """Summarise `runs.csv` into `summary.csv` beside it; returns the rows.

    One row per (working-set size, cipher): the median throughput with its bootstrap
    interval, the paired ratio against `baseline` with its own, the modality verdict,
    and the two top-group memberships. The ranking-stability verdict and the source
    file's provenance marker go into the file's `#` header, where a table generator
    can act on them.
    """
    provenance, by_size, impls = _load_runs(runs_csv_path)
    target = _target_of(runs_csv_path)

    for size in sorted(by_size):
        if baseline not in by_size[size]:
            raise ValueError(
                "baseline %r was not measured at size %d, so no paired ratio can be "
                "formed there; measured: %s"
                % (baseline, size, ", ".join(sorted(by_size[size]))))

    published_size = (PUBLISHED_SIZE_BYTES if PUBLISHED_SIZE_BYTES in by_size
                      else max(by_size))

    rows = []
    order_by_size = {}
    stats_by_size = {}
    for size in sorted(by_size):
        absolute = []
        ratio = []
        per_cipher = {}
        for cipher in sorted(by_size[size]):
            samples = [value for _, value in by_size[size][cipher]]
            med, lo, hi = median_ci(samples, resamples=resamples, seed=seed)
            # Deduplicated: for the baseline itself the two names are the same
            # cipher, and feeding its rows twice would trip the duplicate guard.
            paired_names = [cipher] if cipher == baseline else [cipher, baseline]
            paired_rows = [{"run_index": run_index, "cipher": name,
                            "mbit_per_sec": value}
                           for name in paired_names
                           for run_index, value in by_size[size][name]]
            ratios = paired_ratios(paired_rows, cipher, baseline)
            r_med, r_lo, r_hi = median_ci(ratios, resamples=resamples, seed=seed)
            # Both samples are modality-checked. The ratio is the declared primary
            # quantity, so leaving it unchecked would apply the whole apparatus to
            # the secondary column only -- and a run that straddles a state
            # transition makes the ratio bimodal while both absolute samples stay
            # unimodal, so the absolute check does not stand in for this one.
            modes = modality(samples)
            ratio_modes = modality(ratios)
            per_cipher[cipher] = {
                "target": target,
                "size_bytes": size,
                "cipher": cipher,
                "impl": "+".join(sorted(impls[(size, cipher)])),
                "n_runs": len(samples),
                "median_mbit_per_sec": med,
                "ci_lo": lo,
                "ci_hi": hi,
                "baseline": baseline,
                "ratio_median": r_med,
                "ratio_lo": r_lo,
                "ratio_hi": r_hi,
                "published": "yes" if size == published_size else "no",
            }
            per_cipher[cipher].update(_modality_fields(modes, ""))
            per_cipher[cipher].update(_modality_fields(ratio_modes, "ratio_"))
            absolute.append({"cipher": cipher, "median": med, "lo": lo, "hi": hi})
            ratio.append({"cipher": cipher, "median": r_med, "lo": r_lo, "hi": r_hi})

        in_absolute = set(top_group(absolute))
        in_ratio = set(top_group(ratio))
        for cipher, row in per_cipher.items():
            row["in_top_group"] = "yes" if cipher in in_absolute else "no"
            row["in_ratio_top_group"] = "yes" if cipher in in_ratio else "no"
        ordered = sorted(absolute, key=lambda s: (-s["median"], s["cipher"]))
        order_by_size[size] = [s["cipher"] for s in ordered]
        stats_by_size[size] = {s["cipher"]: (s["lo"], s["hi"]) for s in absolute}
        rows.extend(per_cipher[s["cipher"]] for s in ordered)

    stable, stability_note = ranking_stable(order_by_size)
    separable = separable_flips(order_by_size, stats_by_size)
    flagged = [r for r in rows
               if r["modality"] == MODALITY_MULTIMODAL
               or r["ratio_modality"] == MODALITY_MULTIMODAL]
    # Rows the detector could not examine at all. Tracked separately from `flagged`
    # because they are a third state, not a quiet member of the clean one: with
    # MODALITY_MIN_N at 12, an 8-to-11-run campaign lands here, and a header reading
    # `multimodal_samples: none` would report "we looked and found nothing" for a
    # campaign where nothing was looked at.
    not_judged = [r for r in rows
                  if r["modality"] == MODALITY_NOT_JUDGED
                  or r["ratio_modality"] == MODALITY_NOT_JUDGED]

    out_path = os.path.join(os.path.dirname(os.path.abspath(runs_csv_path)),
                            "summary.csv")
    _write_summary(out_path, rows, provenance, target, baseline, seed, resamples,
                   published_size, stable, stability_note, separable, flagged,
                   not_judged)
    return rows


def _drift_median(values):
    """Median with internal sorting -- distinct from `_median`, which requires its
    input already sorted. Kept separate so neither contract has to bend to the other."""
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


# "Materially tighter" is the ratio interval being at least this many times tighter on
# the median cipher (and tighter for a majority of ciphers, with no multimodal ratio).
DRIFT_TIGHTER_FACTOR = 1.5


def drift_verdict(rows, baseline):
    """Does the paired ratio actually cancel the host's drift, as the protocol claims?

    The protocol's premise is that absolute speed wanders while a within-run ratio holds,
    so the ratio is the trustworthy quantity. This measures whether that happened: for
    each published, non-baseline cipher it compares the paired-ratio interval width
    against the absolute interval width, both relative to the point estimate. Returns the
    per-cipher numbers, the medians, the tighter factor, and a boolean `claim_held`. The
    factor is returned whether or not the claim held, so a near miss is visible rather
    than rounded to a verdict.

    summarize emits this into summary.csv's header itself, so the documented
    `summarize.py ... --baseline ...` command produces the honest verdict directly and
    there is no second writer with a blind spot to clobber it.
    """
    published = [r for r in rows
                 if r.get("published") == "yes" and r["cipher"] != baseline]
    per_cipher = []
    for row in published:
        med = row["median_mbit_per_sec"]
        r_med = row["ratio_median"]
        abs_w = ((row["ci_hi"] - row["ci_lo"]) / med) if med else None
        rat_w = ((row["ratio_hi"] - row["ratio_lo"]) / r_med) if r_med else None
        per_cipher.append({
            "cipher": row["cipher"],
            "absolute_rel_width": abs_w,
            "ratio_rel_width": rat_w,
            "ratio_modality": row.get("ratio_modality"),
            "absolute_modality": row.get("modality"),
        })
    abs_widths = [c["absolute_rel_width"] for c in per_cipher
                  if c["absolute_rel_width"] is not None]
    rat_widths = [c["ratio_rel_width"] for c in per_cipher
                  if c["ratio_rel_width"] is not None]
    result = {
        "per_cipher": per_cipher,
        "median_absolute_rel_width": _drift_median(abs_widths),
        "median_ratio_rel_width": _drift_median(rat_widths),
        "n_ciphers": len(per_cipher),
    }
    ma, mr = result["median_absolute_rel_width"], result["median_ratio_rel_width"]
    result["tighter_factor"] = (ma / mr) if (ma is not None and mr) else None
    tighter_each = sum(1 for c in per_cipher
                       if c["ratio_rel_width"] is not None
                       and c["absolute_rel_width"] is not None
                       and c["ratio_rel_width"] < c["absolute_rel_width"])
    result["ciphers_ratio_tighter"] = tighter_each
    multimodal = [c["cipher"] for c in per_cipher
                  if c["ratio_modality"] == MODALITY_MULTIMODAL]
    result["multimodal_ratio_ciphers"] = multimodal
    result["claim_held"] = (result["tighter_factor"] is not None
                            and result["tighter_factor"] >= DRIFT_TIGHTER_FACTOR
                            and tighter_each * 2 >= len(per_cipher)
                            and not multimodal)
    return result


def drift_verdict_lines(result, prefix):
    """The drift-verdict block for summary.csv's header and the console. `prefix` is the
    full leading comment token, e.g. `# a7_drift_check:`; continuation lines are `#   `."""
    ma = result["median_absolute_rel_width"]
    mr = result["median_ratio_rel_width"]
    factor = result["tighter_factor"]
    head = prefix + " "
    if result["n_ciphers"] == 0 or ma is None or mr is None or factor is None:
        return [head + "not computed as a factor: the published ratio intervals are "
                "degenerate or the rows carry no usable interval "
                "(median absolute width %s, median ratio width %s)."
                % ("n/a" if ma is None else "%.1f%%" % (ma * 100.0),
                   "n/a" if mr is None else "%.1f%%" % (mr * 100.0))]
    verdict = ("HELD" if result["claim_held"] else "DID NOT HOLD")
    lines = [
        "%sthe protocol's pairing claim %s on this board." % (head, verdict),
        "#   Median absolute-throughput CI is %.1f%% of the estimate; median paired-"
        "ratio CI is %.1f%% of the ratio." % (ma * 100.0, mr * 100.0),
        "#   Paired ratio intervals are %.2fx %s than absolute; tighter for %d of %d "
        "ciphers." % (factor, "tighter" if factor >= 1.0 else "WIDER",
                      result["ciphers_ratio_tighter"], result["n_ciphers"]),
    ]
    if result["multimodal_ratio_ciphers"]:
        lines.append("#   Ratio sample multimodal for: %s -- the pairing did not "
                     "cancel a state change there."
                     % ", ".join(result["multimodal_ratio_ciphers"]))
    if not result["claim_held"]:
        lines.append("#   A paired analysis that does not materially cancel the drift "
                     "is itself a result about this board; the ratios are NOT presented "
                     "as though the claim held.")
    return lines


_HEADER_PROSE = """\
# Medians with bootstrap confidence intervals and paired ratios, generated from
# runs.csv by tools/summarize.py. Every figure here is computed, never typed; the
# table generator reads this file and no number is transcribed between the two.
#
# median_mbit_per_sec / ci_lo / ci_hi
#     Sample median over the runs at that working-set size, with a percentile
#     bootstrap interval: %(coverage)s. The interval describes
#     run-to-run variation of this measurement on this host, and nothing else.
# ratio_median / ratio_lo / ratio_hi
#     The PRIMARY comparison. Formed inside each run as cipher/baseline and then
#     bootstrapped over those per-run ratios, so drift common to a run cancels -- but
#     only when ratio_modality says it did. A run missing either cipher is skipped,
#     never imputed.
# in_top_group / in_ratio_top_group
#     yes when the cipher's interval overlaps the leader's, on the absolute figure
#     and on the ratio respectively. Members of a top group are not ranked against
#     each other; the measurement cannot order them.
# modality / mode_count / mode_medians / mode_shares / gap_over_spread
# ratio_modality / ratio_mode_count / ratio_mode_medians / ratio_mode_shares
# ratio_gap_over_spread
#     Applied to the absolute sample and, separately, to the sample of per-run
#     ratios. A run that straddles a host state transition makes the RATIO bimodal
#     while both absolute samples stay unimodal, so the two checks are not
#     substitutes and the ratio one guards the primary quantity.
#     Values: multimodal (with each state's median and share), unimodal, or
#     not-judged for a sample too small to examine -- three states, not two. A
#     not-judged row leaves mode_count blank (nobody counted) and gap_over_spread
#     `n/a` (nothing was divided), is listed under not_judged_samples below, and is
#     marked in the generated table so it is not read as having come back clean.
#     `unimodal` means NOT FLAGGED and
#     never "shown to be unimodal": detection at n = 24 is about 18%% at 6 sigma of
#     separation, 63%% at 8 and 95%% at 10, so a closer second mode reads as unimodal.
#     gap_over_spread is the detector's own statistic against a threshold of %(factor)g,
#     published so a near miss is visible instead of rounded into a clean verdict.
#     A multimodal sample's confidence interval spans the gap between two states and
#     describes neither: read it as the modes, not as median-plus-or-minus. The
#     interval is still written rather than blanked, so the spread stays visible.
# published
#     yes for the working-set size the paper publishes; the other sizes exist so the
#     ranking-stability check has something to compare against.
"""


def _write_summary(out_path, rows, provenance, target, baseline, seed, resamples,
                   published_size, stable, stability_note, separable, flagged,
                   not_judged):
    """Written whole, and with nothing time-varying in it, so that rerunning the
    summariser on unchanged input reproduces the file byte for byte."""
    lines = ["# provenance: %s" % provenance]
    if provenance != PROVENANCE_CAMPAIGN:
        lines.append("# The provenance marker above is not CAMPAIGN. Only CAMPAIGN "
                     "and UNKNOWN are publishable; tools/make_tables.py refuses "
                     "anything else, including a decorated SMOKE-RUN marker.")
    # The drift verdict goes here, near the top where a reader looks, and is emitted by
    # the summariser itself so the documented Step 6 command carries it -- no separate
    # annotate step that a later re-run of that command could overwrite.
    lines.extend(drift_verdict_lines(drift_verdict(rows, baseline),
                                     "# %s_drift_check:" % target))
    lines.append((_HEADER_PROSE % {"coverage": CI_COVERAGE_NOTE,
                                   "factor": MODALITY_GAP_FACTOR}).rstrip("\n"))
    lines.append("#")
    lines.append("# target: %s" % target)
    lines.append("# baseline: %s" % baseline)
    lines.append("# bootstrap: %d resamples, percentile 2.5%%/97.5%%, seed %d"
                 % (resamples, seed))
    lines.append("# ci_coverage: %s" % CI_COVERAGE_NOTE)
    lines.append("# published_size_bytes: %d" % published_size)
    lines.append("# ranking_stability: %s -- %s"
                 % ("STABLE" if stable else "UNSTABLE", stability_note))

    # Whether that verdict may be repeated in a paper caption. `ranking_stable` is a
    # strict order comparison and most of its alarms are near-tied ciphers swapping on
    # noise; only a flip between two ciphers the campaign separated at both sizes says
    # anything about cache. See separable_flips.
    if stable:
        publishable = "yes -- the ordering is identical at every size measured"
    elif separable:
        publishable = ("yes -- %s changed places between sizes %s and %s with "
                       "non-overlapping intervals at both"
                       % (", ".join("%s/%s" % (a, b) for _, _, a, b in separable),
                          separable[0][0], separable[0][1]))
    else:
        publishable = ("no -- the ordering does differ between sizes, but only among "
                       "ciphers whose intervals overlap there, so no separable pair "
                       "changed order and the verdict must not reach a caption")
    lines.append("# ranking_stability_publishable: %s" % publishable)
    if not stable:
        lines.append("#   A ranking that moves with the working set is a result "
                     "about cache, not about ciphers, and is reported as one -- but "
                     "only when the campaign resolved the pair that moved.")

    if flagged:
        lines.append("# multimodal_samples: %s"
                     % ", ".join("%s@%d%s" % (r["cipher"], r["size_bytes"],
                                              _flag_which(r))
                                 for r in flagged))
        for row in flagged:
            if row["modality"] == MODALITY_MULTIMODAL:
                lines.append("#   %s@%d absolute: %s"
                             % (row["cipher"], row["size_bytes"],
                                row["modality_reason"]))
            if row["ratio_modality"] == MODALITY_MULTIMODAL:
                lines.append("#   %s@%d ratio: %s"
                             % (row["cipher"], row["size_bytes"],
                                row["ratio_modality_reason"]))
    elif not_judged:
        # "none" here would be a claim about samples nobody examined. The count is
        # stated in the same line a reader greps for, not only in the detail below.
        lines.append("# multimodal_samples: none found, %d not judged -- see "
                     "not_judged_samples" % len(not_judged))
    else:
        lines.append("# multimodal_samples: none")

    if not_judged:
        lines.append("# not_judged_samples: %s"
                     % ", ".join("%s@%d%s" % (r["cipher"], r["size_bytes"],
                                              _flag_which(r, MODALITY_NOT_JUDGED))
                                 for r in not_judged))
        for row in not_judged:
            if row["modality"] == MODALITY_NOT_JUDGED:
                lines.append("#   %s@%d absolute: %s"
                             % (row["cipher"], row["size_bytes"],
                                row["modality_reason"]))
            if row["ratio_modality"] == MODALITY_NOT_JUDGED:
                lines.append("#   %s@%d ratio: %s"
                             % (row["cipher"], row["size_bytes"],
                                row["ratio_modality_reason"]))
        lines.append("#   These rows carry an interval that no modality check stands "
                     "behind. tools/make_tables.py marks them in the table rather "
                     "than typesetting them as though they had passed.")
    else:
        lines.append("# not_judged_samples: none")

    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        for line in lines:
            fh.write(line + "\n")
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(SUMMARY_COLUMNS)
        for row in rows:
            writer.writerow([
                row["target"], row["size_bytes"], row["cipher"], row["impl"],
                row["n_runs"],
                _fmt(row["median_mbit_per_sec"]), _fmt(row["ci_lo"]), _fmt(row["ci_hi"]),
                row["baseline"],
                _fmt(row["ratio_median"]), _fmt(row["ratio_lo"]), _fmt(row["ratio_hi"]),
                row["modality"], row["mode_count"], row["mode_medians"],
                row["mode_shares"], row["gap_over_spread"], row["modality_reason"],
                row["ratio_modality"], row["ratio_mode_count"],
                row["ratio_mode_medians"], row["ratio_mode_shares"],
                row["ratio_gap_over_spread"], row["ratio_modality_reason"],
                row["in_top_group"], row["in_ratio_top_group"],
                row["published"],
            ])


def _flag_which(row, verdict=MODALITY_MULTIMODAL):
    """Which of the row's two samples carry `verdict`, as ` (absolute+ratio)`."""
    which = []
    if row["modality"] == verdict:
        which.append("absolute")
    if row["ratio_modality"] == verdict:
        which.append("ratio")
    return " (%s)" % "+".join(which)


# --- CLI ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Summarise a campaign's runs.csv into summary.csv beside it.")
    parser.add_argument("runs_csv")
    parser.add_argument("--baseline", default=DEFAULT_BASELINE,
                        help="cipher every ratio is formed against "
                             "(default: %(default)s)")
    parser.add_argument("--seed", type=int, default=0,
                        help="bootstrap seed (default: %(default)s)")
    parser.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES,
                        help="bootstrap resamples (default: %(default)s)")
    args = parser.parse_args(argv)

    rows = summarize(args.runs_csv, args.baseline, args.seed, args.resamples)
    out_path = os.path.join(os.path.dirname(os.path.abspath(args.runs_csv)),
                            "summary.csv")
    print("wrote %s (%d rows)" % (out_path, len(rows)))

    published = [r for r in rows if r["published"] == "yes"]
    if published:
        size = published[0]["size_bytes"]
        print("\npublished working-set size: %d bytes" % size)
        print("  interval: %s" % CI_COVERAGE_NOTE)
        for row in published:
            mark = " *" if row["in_ratio_top_group"] == "yes" else "  "
            flags = []
            if row["modality"] == MODALITY_MULTIMODAL:
                flags.append("MULTIMODAL")
            if row["ratio_modality"] == MODALITY_MULTIMODAL:
                flags.append("MULTIMODAL-RATIO")
            print("%s %-30s %10.2f [%.2f, %.2f] Mbit/s   x%.4f [%.4f, %.4f] vs %s%s"
                  % (mark, row["cipher"], row["median_mbit_per_sec"], row["ci_lo"],
                     row["ci_hi"], row["ratio_median"], row["ratio_lo"],
                     row["ratio_hi"], row["baseline"],
                     ("  " + " ".join(flags)) if flags else ""))
        print("  * top group on the paired ratio: not ranked against each other.")

    order_by_size = {}
    for row in rows:
        order_by_size.setdefault(row["size_bytes"], []).append(row["cipher"])
    stable, note = ranking_stable(order_by_size)
    print("\nranking stability: %s -- %s" % ("STABLE" if stable else "UNSTABLE", note))

    for row in rows:
        for kind, verdict, reason in (
                ("absolute", row["modality"], row["modality_reason"]),
                ("ratio", row["ratio_modality"], row["ratio_modality_reason"])):
            if verdict != MODALITY_MULTIMODAL:
                continue
            print("multimodal %s sample: %s at %d bytes -- %s"
                  % (kind, row["cipher"], row["size_bytes"], reason))
            print("  its interval spans the gap between the states and describes "
                  "neither; report the modes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
