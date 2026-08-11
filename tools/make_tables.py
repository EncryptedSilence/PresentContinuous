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

    if provenance == "SMOKE-RUN":
        raise SmokeRunRefused(
            "%s is marked `# provenance: SMOKE-RUN`; no paper table may be built "
            "from it. Re-run the campaign on a quiet machine." % summary_path)
    if require_campaign and provenance != "CAMPAIGN":
        raise SmokeRunRefused(
            "%s carries provenance %s, not CAMPAIGN, and --require-campaign was "
            "given." % (summary_path, provenance))

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


def _throughput_cell(row, mark_group=True):
    """`median [lo, hi]` normally; the modes themselves when the sample is
    multimodal, because a bracket across two performance states describes neither."""
    if row.get("modality") == "multimodal" and row.get("mode_medians"):
        medians = [float(v) for v in row["mode_medians"].split(";") if v != ""]
        shares = [float(v) for v in row.get("mode_shares", "").split(";") if v != ""]
        if len(shares) != len(medians):
            shares = [float("nan")] * len(medians)
        states = " / ".join("%.1f (%.0f\\%%)" % (m, 100.0 * s)
                            for m, s in zip(medians, shares))
        return states + MULTIMODAL_MARK
    cell = "%.1f [%.1f, %.1f]" % (float(row["median_mbit_per_sec"]),
                                  float(row["ci_lo"]), float(row["ci_hi"]))
    if mark_group and row.get("in_top_group") == "yes":
        cell += TOP_GROUP_MARK
    return cell


def _ratio_cell(row, mark_group=True):
    cell = "%.3f [%.3f, %.3f]" % (float(row["ratio_median"]),
                                  float(row["ratio_lo"]), float(row["ratio_hi"]))
    if mark_group and row.get("in_ratio_top_group") == "yes":
        cell += RATIO_GROUP_MARK
    return cell


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
    multimodal = [r for r in rows if r.get("modality") == "multimodal"]

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
        "Complete-CTR throughput on the %s target at a %s-byte working set, "
        "median over %s runs per cipher; bootstrap: %s."
        % (tex_escape(target), tex_escape(size_bytes),
           tex_escape(rows[0].get("n_runs", "?")), tex_escape(bootstrap)),
        "The Ratio column is the primary comparison: it is formed inside each run "
        "against %s and then bootstrapped over those per-run ratios, so drift "
        "common to a run cancels."
        % tex_escape(baseline),
    ]
    marked = [(TOP_GROUP_MARK, "the absolute figure"),
              (RATIO_GROUP_MARK, "the ratio")]
    marked = [(mark, what) for mark, what in marked if mark in used]
    if marked:
        caption.append(
            "%s: their intervals overlap the leader's, so they are reported as a "
            "top group and are not ranked against each other."
            % "; ".join("%s marks the top group on %s" % (mark, what)
                        for mark, what in marked))
    if multimodal and MULTIMODAL_MARK in used:
        caption.append(
            "%s marks a sample the summariser found multimodal. Those rows give each "
            "performance state's median and share of runs instead of a confidence "
            "interval, because an interval spanning the gap between two states "
            "describes neither of them, and typeset as median-plus-interval it would "
            "read as an ordinary noisy measurement."
            % MULTIMODAL_MARK)
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
