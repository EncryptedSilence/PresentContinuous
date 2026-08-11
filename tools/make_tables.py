#!/usr/bin/env python3
"""Render a campaign's summary.csv as the LaTeX table the paper includes.

This is the only path by which a measured number reaches a paper table. Manual
transfer is what produced the mismatched-revision problem that results/m4-speed.csv
documents in its own header, so there is no second path and no hand-typed figure.

Three things it refuses to do, each of which would produce a table that looks fine
and is wrong:

1. **Publish from a file marked `# provenance: SMOKE-RUN`.** That marker exists
   precisely to stop a trial run reaching the paper. It is a refusal, not a warning:
   a warning on stderr is invisible in a build log. `--require-campaign` extends the
   refusal to files carrying no marker at all.
2. **Parse rate columns out of rows that are not measurements.** Where the input
   carries a `status` column, only `measured` rows are read -- results/v2/cuda's
   block evaluation records absent kernels with empty rate fields, and averaging or
   printing those would credit a cipher for a kernel nobody wrote. Where there is no
   `status` column the filter is skipped rather than raising KeyError, which is the
   shape results/v2/cuda/master-key-search.csv has.
3. **Print a ranking the measurement does not support.** Members of a top group --
   ciphers whose intervals overlap the leader's -- are marked, and the caption says
   they are not ranked against each other. A sample the summariser found multimodal
   is printed as its modes, not as a median with a bracket around it: an interval
   spanning the gap between two host performance states describes neither, and
   typeset as `median [lo, hi]` it reads as an ordinary noisy measurement.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import summarize  # noqa: E402

# Marks used in the table body, explained in the caption. Kept as module constants so
# the tests refer to the same strings the renderer emits rather than to a copy.
TOP_GROUP_MARK = r"$^{\dagger}$"
RATIO_GROUP_MARK = r"$^{\S}$"
MULTIMODAL_MARK = r"$^{\ddagger}$"
# The third state. Not a variant of "clean": the sample was never examined, and the
# whole point of separating it from `unimodal` in summary.csv is lost if the table
# then typesets it identically to a row that passed.
NOT_JUDGED_MARK = r"$^{\P}$"

_TEX_ESCAPES = (
    ("\\", r"\textbackslash{}"),
    ("&", r"\&"), ("%", r"\%"), ("$", r"\$"), ("#", r"\#"),
    ("_", r"\_"), ("{", r"\{"), ("}", r"\}"),
    ("~", r"\textasciitilde{}"), ("^", r"\textasciicircum{}"),
)


class SmokeRunRefused(Exception):
    """Raised rather than rendering a table from a file that says it is not a
    measurement result."""


def tex_escape(text):
    out = str(text)
    for char, replacement in _TEX_ESCAPES:
        out = out.replace(char, replacement)
    return out


def _mono(text):
    """Cipher and impl names, in a typewriter face. Typewriter has no ligatures, so
    the hyphens in `present-80-r16` stay hyphens instead of becoming an en-dash."""
    return r"\texttt{%s}" % tex_escape(text)


def header_field(comment_lines, name):
    """Value of a `# name: value` line from the summary's header block, or None."""
    prefix = name.lower() + ":"
    for line in comment_lines:
        body = line.lstrip("#").strip()
        if body.lower().startswith(prefix):
            return body.split(":", 1)[1].strip()
    return None


def load_summary(summary_path, require_campaign=False):
    """Returns (provenance, comment lines, publishable rows).

    Refuses a SMOKE-RUN outright, and an unmarked file too when the caller asks for
    that. Filters to `status == measured` if the file has a status column, and to the
    working-set size the summariser marked as published.
    """
    with open(summary_path, encoding="utf-8") as fh:
        comments = [ln for ln in fh.read().splitlines() if ln.startswith("#")]
    provenance, rows = summarize.read_csv_with_provenance(summary_path)

    # An allow-list, not a `== "SMOKE-RUN"` test. Verified against the free-text
    # marker: `# provenance: SMOKE-RUN (3 runs, do not publish)` and
    # `# provenance: SMOKE RUN` both slip past exact equality, and Task 8's
    # campaign.py -- which will write these markers -- has not been written, so the
    # grammar is not fixed anywhere yet. Refusing everything that is not exactly
    # CAMPAIGN or exactly UNKNOWN fails safe instead of failing open.
    if not summarize.is_publishable_provenance(provenance, require_campaign):
        if require_campaign:
            raise SmokeRunRefused(
                "%s carries provenance %s, not CAMPAIGN, and --require-campaign was "
                "given." % (summary_path, provenance))
        raise SmokeRunRefused(
            "%s is marked `# provenance: %s`; no paper table may be built from it. "
            "Only %s are publishable -- anything else, including a decorated "
            "SMOKE-RUN marker, is refused. Re-run the campaign on a quiet machine."
            % (summary_path, provenance,
               " and ".join(summarize.PUBLISHABLE_PROVENANCE)))

    rows = summarize.measured_rows(rows)
    published = [r for r in rows if r.get("published", "yes") == "yes"]
    if not published:
        raise ValueError(
            "%s has no rows marked published; there is nothing to tabulate"
            % summary_path)
    return provenance, comments, published


def _group_is_marked(rows, column):
    """A group of one is a clear leader, not a group.

    `top_group` always returns the leader, so a singleton means the measurement did
    separate it from everything else. Marking it and then explaining in the caption
    that marked rows "are not ranked against each other" would say the opposite of
    what happened.
    """
    return sum(1 for r in rows if r.get(column) == "yes") > 1


def _modes_cell(row, prefix, fmt):
    """The per-state medians and shares, or None when the sample was not flagged.

    Shared by the throughput and ratio columns: both are samples, both can be
    bimodal, and both must refuse to typeset a bracket across the gap between two
    states. The ratio is the primary quantity, so exempting it would have applied the
    whole apparatus to the secondary column only.
    """
    if row.get(prefix + "modality") != summarize.MODALITY_MULTIMODAL:
        return None
    medians = [float(v) for v in row.get(prefix + "mode_medians", "").split(";") if v]
    if not medians:
        return None
    shares = [float(v) for v in row.get(prefix + "mode_shares", "").split(";") if v]
    if len(shares) != len(medians):
        shares = [float("nan")] * len(medians)
    return " / ".join((fmt + " (%.0f\\%%)") % (m, 100.0 * s)
                      for m, s in zip(medians, shares)) + MULTIMODAL_MARK


def _not_judged_mark(row, prefix):
    """The mark for a cell whose sample the detector never examined.

    A row of 8 to 11 runs is below MODALITY_MIN_N, so `summary.csv` honestly records
    `not-judged` -- and the table then rendered it as an ordinary bracket, identical
    to a row that was checked and came back clean. The interval is still printed,
    because the spread is real; the mark is what stops it being read as having passed
    a check that never ran.
    """
    if row.get(prefix + "modality") == summarize.MODALITY_NOT_JUDGED:
        return NOT_JUDGED_MARK
    return ""


def _throughput_cell(row, mark_group=True):
    """`median [lo, hi]` normally; the modes themselves when the sample is
    multimodal, because a bracket across two performance states describes neither."""
    modes = _modes_cell(row, "", "%.1f")
    if modes is not None:
        return modes
    cell = "%.1f [%.1f, %.1f]" % (float(row["median_mbit_per_sec"]),
                                  float(row["ci_lo"]), float(row["ci_hi"]))
    if mark_group and row.get("in_top_group") == "yes":
        cell += TOP_GROUP_MARK
    return cell + _not_judged_mark(row, "")


def _ratio_cell(row, mark_group=True):
    """Same rule as the throughput cell. A run that straddles a host state transition
    is exactly the case where the ratio stops cancelling drift, so per-run ratios can
    be two discrete states -- 1.132 sixteen times and 2.433 eight times -- which as
    `1.132 [1.132, 2.433]` reads as one noisy measurement."""
    modes = _modes_cell(row, "ratio_", "%.3f")
    if modes is not None:
        return modes
    cell = "%.3f [%.3f, %.3f]" % (float(row["ratio_median"]),
                                  float(row["ratio_lo"]), float(row["ratio_hi"]))
    if mark_group and row.get("in_ratio_top_group") == "yes":
        cell += RATIO_GROUP_MARK
    return cell + _not_judged_mark(row, "ratio_")


def _run_count_phrase(rows):
    """`n_runs` is per (cipher, size) and differs whenever a run failed for one
    cipher -- which the pairing explicitly supports by skipping such runs. Stating
    `rows[0]`'s count as the count would be false for every other row."""
    counts = sorted({int(float(r["n_runs"])) for r in rows if r.get("n_runs")})
    if not counts:
        return "an unrecorded number of runs"
    if len(counts) == 1:
        return "%d runs" % counts[0]
    return "%d to %d runs, varying by cipher where a run was discarded" % (
        counts[0], counts[-1])


def render(summary_path, require_campaign=False):
    """The complete LaTeX table, as a string. Deterministic: nothing here varies
    between two runs over the same input."""
    provenance, comments, rows = load_summary(summary_path, require_campaign)

    target = rows[0].get("target") or os.path.basename(os.path.dirname(
        os.path.abspath(summary_path)))
    baseline = rows[0].get("baseline", summarize.DEFAULT_BASELINE)
    size_bytes = rows[0].get("size_bytes", "")
    stability = header_field(comments, "ranking_stability") or "not recorded"
    bootstrap = header_field(comments, "bootstrap") or "bootstrap parameters not recorded"
    coverage = header_field(comments, "ci_coverage")
    ratio_multimodal = [r for r in rows
                        if r.get("ratio_modality") == summarize.MODALITY_MULTIMODAL]
    ratio_not_judged = [r for r in rows
                        if r.get("ratio_modality") == summarize.MODALITY_NOT_JUDGED]

    # Whether the stability verdict may be repeated here at all. summarize.py works it
    # out because only it sees every working-set size; a verdict that is right about
    # half the time is tolerable in a log and not in a caption. Absent the field --
    # a summary from before it existed -- only a STABLE verdict is carried, since the
    # spurious-alarm direction is UNSTABLE.
    publishable = header_field(comments, "ranking_stability_publishable")
    if publishable is None:
        stability_publishable = stability.upper().startswith("STABLE")
    else:
        stability_publishable = publishable.lower().startswith("yes")

    out = []
    out.append("%% Generated by tools/make_tables.py from %s -- do not edit."
               % tex_escape(os.path.normpath(summary_path)))
    out.append("% Every figure below is computed from the run data; none is typed.")
    out.append("%% provenance: %s" % provenance)
    out.append(r"\begin{table}[t]")
    out.append(r"\centering")
    out.append(r"\begin{tabular}{llrr}")
    out.append(r"\hline")
    out.append(r"Cipher & Implementation & Throughput (Mbit/s) & Ratio \\")
    out.append(r"\hline")
    mark_absolute = _group_is_marked(rows, "in_top_group")
    mark_ratio = _group_is_marked(rows, "in_ratio_top_group")
    body = []
    for row in rows:
        body.append("%s & %s & %s & %s \\\\"
                    % (_mono(row["cipher"]), _mono(row.get("impl", "")),
                       _throughput_cell(row, mark_absolute),
                       _ratio_cell(row, mark_ratio)))
    out.extend(body)
    out.append(r"\hline")
    out.append(r"\end{tabular}")

    # Explain only the marks that were actually used. A caption that describes a
    # symbol absent from the table sends a reader looking for something not there --
    # which happens whenever the leader's own sample turned out to be multimodal and
    # so carries no interval to mark.
    used = "\n".join(body)
    caption = [
        "Complete-CTR throughput on the %s target at a %s-byte working set, median "
        "over %s per cipher; bootstrap: %s."
        % (tex_escape(target), tex_escape(size_bytes),
           tex_escape(_run_count_phrase(rows)), tex_escape(bootstrap)),
    ]
    if coverage:
        caption.append("Interval coverage: %s." % tex_escape(coverage))

    # The "drift cancels" claim is conditional on the check that decides whether it
    # did, and the check has THREE outcomes, not two. Branching on `if
    # ratio_multimodal:` alone made "not judged" fall into the else and print "checked
    # ... and none was found", which is the laundering that `not-judged` exists to
    # prevent -- relocated from summary.csv into the paper, where it is worse. Raising
    # MODALITY_MIN_N to 12 is what made an 8-to-11-run campaign reach it.
    caption.append(
        "The Ratio column is the primary comparison, formed inside each run against "
        "%s so that variation common to a run has the chance to cancel."
        % tex_escape(baseline))
    if ratio_multimodal:
        caption.append(
            "For %s it did not cancel: the per-run ratios are themselves in two "
            "separated states, which is what a run straddling a change of host "
            "performance state produces. Those rows give the states rather than an "
            "interval."
            % ", ".join(_mono(r["cipher"]) for r in ratio_multimodal))
    if ratio_not_judged:
        caption.append(
            "Whether it cancelled is not established for %s: fewer than %d runs is "
            "too few for the modality check to return a verdict either way, so those "
            "ratio intervals are reported without it and no claim of cancellation is "
            "made for them."
            % (", ".join(_mono(r["cipher"]) for r in ratio_not_judged),
               summarize.MODALITY_MIN_N))
    if not ratio_multimodal and not ratio_not_judged:
        caption.append(
            "The per-run ratios were checked for a second mode and none was found, "
            "so drift common to a run cancelled.")

    marked = [(TOP_GROUP_MARK, "the absolute figure"),
              (RATIO_GROUP_MARK, "the ratio")]
    marked = [(mark, what) for mark, what in marked if mark in used]
    if marked:
        caption.append(
            "%s: their intervals overlap the leader's, so they are reported as a "
            "top group and are not ranked against each other."
            % "; ".join("%s marks the top group on %s" % (mark, what)
                        for mark, what in marked))
    if MULTIMODAL_MARK in used:
        caption.append(
            "%s marks a sample the summariser found multimodal, on the throughput or "
            "on the ratio. Those cells give each state's median and share of runs "
            "instead of a confidence interval, because an interval spanning the gap "
            "between two states describes neither of them, and typeset as "
            "median-plus-interval it would read as an ordinary noisy measurement."
            % MULTIMODAL_MARK)
    if NOT_JUDGED_MARK in used:
        caption.append(
            "%s marks a sample the modality check could not judge: below %d runs it "
            "returns no verdict either way. Those cells carry an interval that no "
            "check stands behind, and are not to be read as having come back clean."
            % (NOT_JUDGED_MARK, summarize.MODALITY_MIN_N))
    if stability_publishable:
        caption.append("Ranking stability across working-set sizes: %s."
                       % tex_escape(stability))
    if provenance != "CAMPAIGN":
        caption.append("Provenance of the source data: %s." % tex_escape(provenance))

    out.append(r"\caption{%s}" % " ".join(caption))
    out.append(r"\label{tab:%s-ctr}" % target)
    out.append(r"\end{table}")
    return "\n".join(out) + "\n"


def write_table(summary_path, out_dir, require_campaign=False):
    """Renders first and creates nothing until it has succeeded, so a refusal leaves
    no half-written table behind for a later build to pick up."""
    text = render(summary_path, require_campaign)
    target = os.path.basename(os.path.dirname(os.path.abspath(summary_path)))
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "%s-ctr.tex" % target)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path


def find_summaries(root):
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        if "summary.csv" in filenames:
            found.append(os.path.join(dirpath, "summary.csv"))
    return sorted(found)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Render summary.csv files as paper/tables/<target>-ctr.tex.")
    parser.add_argument("summaries", nargs="*")
    parser.add_argument("--all", action="store_true",
                        help="render every summary.csv under --results-root")
    parser.add_argument("--results-root", default=os.path.join("results", "v2"))
    parser.add_argument("--out-dir", default=os.path.join("paper", "tables"))
    parser.add_argument("--require-campaign", action="store_true",
                        help="also refuse a summary with no provenance marker")
    args = parser.parse_args(argv)

    summaries = list(args.summaries)
    if args.all:
        summaries.extend(find_summaries(args.results_root))
    if not summaries:
        print("no summary.csv found under %s; nothing to render (the measurement "
              "campaigns produce them)" % args.results_root)
        return 0

    refused = 0
    for path in sorted(set(summaries)):
        try:
            written = write_table(path, args.out_dir, args.require_campaign)
        except SmokeRunRefused as exc:
            sys.stderr.write("REFUSED: %s\n" % exc)
            refused += 1
            continue
        print("wrote %s" % written)
    if refused:
        sys.stderr.write(
            "%d summary file(s) refused. A file marked SMOKE-RUN is not a "
            "measurement result and no table was built from it.\n" % refused)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
