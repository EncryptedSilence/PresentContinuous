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

# Spec §2: three working-set sizes are measured, 64 KiB is the published one. The
# other two exist so the ranking-stability check has something to compare.
PUBLISHED_SIZE_BYTES = 65536

# Modality thresholds. A sample is called multimodal when the best two-cluster split
# leaves a gap between the clusters wider than MODALITY_GAP_FACTOR times the widest
# cluster it separates, with each cluster holding at least MODALITY_MIN_SHARE of the
# sample. The share floor is what keeps a single stalled run from being promoted to
# a "performance state"; the gap factor is what keeps ordinary spread from being
# split in two. Below MODALITY_MIN_N points the question is not answerable and the
# answer is "not judged" rather than "unimodal by default".
MODALITY_MIN_N = 8
MODALITY_MIN_SHARE = 0.15
MODALITY_GAP_FACTOR = 2.0

REQUIRED_RUN_COLUMNS = ("run_index", "cipher", "impl", "size_bytes", "mbit_per_sec")

SUMMARY_COLUMNS = (
    "target", "size_bytes", "cipher", "impl", "n_runs",
    "median_mbit_per_sec", "ci_lo", "ci_hi",
    "baseline", "ratio_median", "ratio_lo", "ratio_hi",
    "modality", "mode_count", "mode_medians", "mode_shares",
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
    """Sample median with a percentile bootstrap 95% CI.

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


def paired_ratio_ci(runs, cipher, baseline, resamples=DEFAULT_RESAMPLES, seed=0):
    """Median of the per-run ratio `cipher / baseline`, with its own bootstrap CI.

    `runs` is a list of dicts carrying at least `run_index`, `cipher` and
    `mbit_per_sec`. The ratio is formed inside each run, which is what makes drift
    common to that run cancel; the bootstrap then resamples those per-run ratios.

    A run holding only one of the two is skipped -- never imputed, never back-filled
    from another run's value for the missing cipher.

    A run holding *two* rows for the same cipher is an error rather than a coin
    flip. runs.csv carries three working-set sizes and, during tuning, several impls
    per cipher, so `run_index` alone is not a unique key over a whole file; pairing
    on it regardless would silently divide a 4 KiB figure by a 64 KiB one. Callers
    stratify first (`summarize` does) and this is what tells them when they have not.
    """
    per_run = {}
    for row in runs:
        for column in ("run_index", "cipher", "mbit_per_sec"):
            if column not in row:
                raise ValueError("row is missing column %r: %r" % (column, row))
        name = row["cipher"]
        if name != cipher and name != baseline:
            continue
        key = row["run_index"]
        slot = per_run.setdefault(key, {})
        if name in slot:
            raise ValueError(
                "run %r has more than one row for cipher %r; run_index alone does "
                "not identify a measurement (size_bytes and impl also vary) -- "
                "group the rows before pairing them" % (key, name))
        slot[name] = _as_float(row["mbit_per_sec"], "mbit_per_sec",
                               where="run %r, cipher %r: " % (key, name))

    ratios = []
    for key in sorted(per_run, key=_sort_key):
        slot = per_run[key]
        if cipher not in slot or baseline not in slot:
            continue
        denominator = slot[baseline]
        if denominator == 0.0:
            raise ValueError(
                "run %r measured baseline %r at 0 Mbit/s; that is a broken "
                "measurement, not a ratio" % (key, baseline))
        ratios.append(slot[cipher] / denominator)

    if not ratios:
        raise ValueError(
            "no run measured both %r and %r, so there is no paired ratio to report"
            % (cipher, baseline))
    return median_ci(ratios, resamples=resamples, seed=seed)


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


def modality(values, min_n=MODALITY_MIN_N, min_share=MODALITY_MIN_SHARE,
             gap_factor=MODALITY_GAP_FACTOR):
    """Detect a sample drawn from two separated states rather than one noisy one.

    The method is an exact one-dimensional 2-means split -- every admissible split of
    the sorted sample is tried and the one minimising within-cluster sum of squares
    wins, which is tractable here because the data are one-dimensional and there are
    at most a few dozen points -- followed by a separation test: the empty space
    between the two clusters must be wider than `gap_factor` times the wider cluster.

    The separation test is what makes the answer mean something. 2-means always
    returns two clusters; cutting an ordinary noisy sample in half is not evidence of
    anything. Requiring the gap to dominate the spread it separates is the difference
    between "two discrete states" and "one distribution, cut arbitrarily".

    Returns a dict with `multimodal`, `modes` (each with `n`, `share`, `median`,
    `min`, `max`), `gap`, `spread` and a human-readable `reason`.
    """
    vals = sorted(_as_float(v, "value") for v in values)
    n = len(vals)
    result = {"multimodal": False, "modes": [], "gap": 0.0, "spread": 0.0,
              "reason": ""}

    if n < min_n:
        result["reason"] = ("sample of %d is too small to judge modality; %d points "
                            "are needed before a second mode is claimed" % (n, min_n))
        return result

    floor_n = max(2, int(math.ceil(min_share * n)))
    if 2 * floor_n > n:
        result["reason"] = ("sample of %d cannot hold two clusters of %d"
                            % (n, floor_n))
        return result

    best_k = None
    best_wss = None
    for k in range(floor_n, n - floor_n + 1):
        wss = _sum_squared_deviation(vals[:k]) + _sum_squared_deviation(vals[k:])
        if best_wss is None or wss < best_wss:
            best_wss, best_k = wss, k

    lower, upper = vals[:best_k], vals[best_k:]
    gap = upper[0] - lower[-1]
    spread = max(lower[-1] - lower[0], upper[-1] - upper[0])
    result["gap"] = gap
    result["spread"] = spread

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
            "separated by %g with neither spanning more than %g"
            % (len(lower), _median(lower), len(upper), _median(upper), gap, spread))
    else:
        result["reason"] = (
            "one mode: the widest separation in the sample is %g, which does not "
            "exceed %g times the %g it would have to separate" % (gap, gap_factor, spread))
    return result


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
            r_med, r_lo, r_hi = paired_ratio_ci(paired_rows, cipher, baseline,
                                                resamples=resamples, seed=seed)
            modes = modality(samples)
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
                "modality": "multimodal" if modes["multimodal"] else "unimodal",
                "mode_count": len(modes["modes"]) or 1,
                "mode_medians": ";".join(_fmt(m["median"]) for m in modes["modes"]),
                "mode_shares": ";".join(_fmt(m["share"]) for m in modes["modes"]),
                "modality_reason": modes["reason"],
                "published": "yes" if size == published_size else "no",
            }
            absolute.append({"cipher": cipher, "median": med, "lo": lo, "hi": hi})
            ratio.append({"cipher": cipher, "median": r_med, "lo": r_lo, "hi": r_hi})

        in_absolute = set(top_group(absolute))
        in_ratio = set(top_group(ratio))
        for cipher, row in per_cipher.items():
            row["in_top_group"] = "yes" if cipher in in_absolute else "no"
            row["in_ratio_top_group"] = "yes" if cipher in in_ratio else "no"
        ordered = sorted(absolute, key=lambda s: (-s["median"], s["cipher"]))
        order_by_size[size] = [s["cipher"] for s in ordered]
        rows.extend(per_cipher[s["cipher"]] for s in ordered)

    stable, stability_note = ranking_stable(order_by_size)
    multimodal = [r for r in rows if r["modality"] == "multimodal"]

    out_path = os.path.join(os.path.dirname(os.path.abspath(runs_csv_path)),
                            "summary.csv")
    _write_summary(out_path, rows, provenance, target, baseline, seed, resamples,
                   published_size, stable, stability_note, multimodal)
    return rows


_HEADER_PROSE = """\
# Medians with bootstrap 95% confidence intervals and paired ratios, generated from
# runs.csv by tools/summarize.py. Every figure here is computed, never typed; the
# table generator reads this file and no number is transcribed between the two.
#
# median_mbit_per_sec / ci_lo / ci_hi
#     Sample median over the runs at that working-set size, with a percentile
#     bootstrap 95% interval. The interval describes run-to-run variation of this
#     measurement on this host, and nothing else.
# ratio_median / ratio_lo / ratio_hi
#     The PRIMARY comparison. Formed inside each run as cipher/baseline and then
#     bootstrapped over those per-run ratios, so drift common to a run cancels. A run
#     missing either cipher is skipped, never imputed.
# in_top_group / in_ratio_top_group
#     yes when the cipher's interval overlaps the leader's, on the absolute figure
#     and on the ratio respectively. Members of a top group are not ranked against
#     each other; the measurement cannot order them.
# modality / mode_count / mode_medians / mode_shares
#     unimodal, or multimodal with each state's median and share. A multimodal
#     sample's confidence interval spans the gap between two states and describes
#     neither: it must be read as the two modes, not as median-plus-or-minus. The
#     interval is still written rather than blanked, so the spread stays visible.
# published
#     yes for the working-set size the paper publishes; the other sizes exist so the
#     ranking-stability check has something to compare against.
"""


def _write_summary(out_path, rows, provenance, target, baseline, seed, resamples,
                   published_size, stable, stability_note, multimodal):
    """Written whole, and with nothing time-varying in it, so that rerunning the
    summariser on unchanged input reproduces the file byte for byte."""
    lines = ["# provenance: %s" % provenance]
    if provenance != "CAMPAIGN":
        lines.append("# The provenance marker above is not CAMPAIGN. This file is "
                     "not publishable; tools/make_tables.py refuses a SMOKE-RUN.")
    lines.append(_HEADER_PROSE.rstrip("\n"))
    lines.append("#")
    lines.append("# target: %s" % target)
    lines.append("# baseline: %s" % baseline)
    lines.append("# bootstrap: %d resamples, percentile 2.5%%/97.5%%, seed %d"
                 % (resamples, seed))
    lines.append("# published_size_bytes: %d" % published_size)
    lines.append("# ranking_stability: %s -- %s"
                 % ("STABLE" if stable else "UNSTABLE", stability_note))
    if not stable:
        lines.append("#   A ranking that moves with the working set is a result "
                     "about cache, not about ciphers, and is reported as one.")
    if multimodal:
        lines.append("# multimodal_samples: %s"
                     % ", ".join("%s@%d" % (r["cipher"], r["size_bytes"])
                                 for r in multimodal))
        for row in multimodal:
            lines.append("#   %s@%d: %s"
                         % (row["cipher"], row["size_bytes"], row["modality_reason"]))
    else:
        lines.append("# multimodal_samples: none")

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
                row["mode_shares"], row["in_top_group"], row["in_ratio_top_group"],
                row["published"],
            ])


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
        for row in published:
            mark = " *" if row["in_ratio_top_group"] == "yes" else "  "
            print("%s %-30s %10.2f [%.2f, %.2f] Mbit/s   x%.4f [%.4f, %.4f] vs %s%s"
                  % (mark, row["cipher"], row["median_mbit_per_sec"], row["ci_lo"],
                     row["ci_hi"], row["ratio_median"], row["ratio_lo"],
                     row["ratio_hi"], row["baseline"],
                     "  MULTIMODAL" if row["modality"] == "multimodal" else ""))
        print("  * top group on the paired ratio: not ranked against each other.")

    order_by_size = {}
    for row in rows:
        order_by_size.setdefault(row["size_bytes"], []).append(row["cipher"])
    stable, note = ranking_stable(order_by_size)
    print("\nranking stability: %s -- %s" % ("STABLE" if stable else "UNSTABLE", note))

    for row in rows:
        if row["modality"] == "multimodal":
            print("multimodal sample: %s at %d bytes -- %s"
                  % (row["cipher"], row["size_bytes"], row["modality_reason"]))
            print("  its interval spans the gap between the states and describes "
                  "neither; report the modes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
