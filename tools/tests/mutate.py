#!/usr/bin/env python3
"""Mutation testing for the measurement layer: summarize.py, make_tables.py, campaign.py.

A passing test suite proves that the code does something. It does not prove that the
suite would notice if the code did something *else* -- and for this layer that
distinction is the whole point, because almost every constant here is a judgement call
(a bootstrap seed, a percentile, a gap threshold, a minimum sample size) whose wrong
value produces output that still looks entirely reasonable. A test that asserts
`modality()` returns a dict with a `gap_over_spread` key passes just as happily when
that key holds the wrong number.

So: change the code deliberately, one edit at a time, and check the suite goes red.
A mutation the suite does not notice is called a *survivor*, and it marks a constant or
a branch that nothing is actually defending.

    python3 tools/tests/mutate.py            # all mutations
    python3 tools/tests/mutate.py --list     # what they are, without running them
    python3 tools/tests/mutate.py -k seed    # only mutations whose name matches

Exit status is 0 only when every mutation was killed.

WHY THIS RUNS ON A COPY
-----------------------
An earlier version of this harness restored the source between mutations with
`git checkout -- tools/`. Run against a working tree with uncommitted work in it, that
reverts the very changes being tested -- and it then reported all fourteen mutations as
killed, because with the new code gone none of the patterns matched any more and every
"mutation" was a no-op against a suite that was already green. Two failure modes
compounded: the harness destroyed its subject, and it was silent about not finding what
it was looking for.

Both are fixed here, and the second matters more than the first:

  * The subject is a `git archive HEAD` copy in a temporary directory. The working tree
    is never written to, so the harness cannot destroy anything even if it is wrong.
  * `apply_mutation` raises `PatternNotFound` when its pattern does not appear -- or
    appears more than once, which means the pattern no longer identifies the single
    line it was written for. A mutation that cannot be applied is a hard error that
    fails the run, never a pass. `tools/tests/test_mutate.py` pins that behaviour,
    because "the harness is loud when its patterns rot" is itself a property that has
    to be checked by something other than care.

A refactor that moves this code will therefore break this file loudly rather than
quietly reducing it to a no-op that congratulates you.

WHY THERE ARE NEGATIVE CONTROLS
-------------------------------
The above fixed a harness that could not apply its mutations. It did not fix a harness
that kills everything -- and the next version was one. It ran the suite over
`tools/tests` inside the mutated copy, which collected `test_mutate.py`, whose pattern
check reads the source of the file that had just been mutated and fails. That failure
was new relative to the baseline, so it scored as a kill. Every mutation self-killed;
no survivor was reportable under any circumstances; the sweep printed "25 killed, 0
survived" and certified nothing.

The lesson is that "all mutations died" and "the harness is broken" produce identical
output, so the run has to contain something whose *expected* result is survival:

  * `CONTROLS` are comment edits. They cannot change behaviour, so they must survive.
    A killed control fails the run outright -- the numbers in it mean nothing.
  * `EXCLUDED_FROM_SUBJECT` keeps the harness's own source-reading tests out of the
    suite the sweep runs, which is what made every mutation self-kill.
  * Any test that kills *every* mutation, including unrelated ones in another file, is
    reported as invalidating: that is the signature of a test asserting over source
    text rather than exercising it.

Exit status: 0 clean sweep, 1 real survivors, 2 the sweep itself is not trustworthy.
"""
import argparse
import collections
import os
import re
import shutil
import subprocess
import sys
import tempfile


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SUMMARIZE = "tools/summarize.py"
MAKE_TABLES = "tools/make_tables.py"
CAMPAIGN = "tools/campaign.py"
RUN_M4 = "tools/run_m4_bench.py"


class PatternNotFound(Exception):
    """A mutation's pattern does not appear exactly once in its target file.

    Raised for zero matches (the code moved or was rewritten) and for several (the
    pattern no longer picks out one line). Both mean the mutation is not the edit it
    claims to be, and neither may be reported as a pass.
    """


Mutation = collections.namedtuple("Mutation", "name path old new defends control")
Mutation.__new__.__defaults__ = (False,)


# Negative controls: edits that cannot change behaviour, because they change a comment.
# These MUST survive. If one is reported killed, the harness is measuring something
# other than the code -- and a harness that kills everything reports a clean sweep it
# did not earn, which is indistinguishable from a real one until you check.
#
# This is not hypothetical. Before these existed, `mutate.py` ran `unittest discover`
# over `tools/tests` *inside the mutated copy*, which collected `test_mutate.py`, whose
# `TestMutationsStillApply` re-checks every mutation pattern against the file that had
# just been mutated -- and failed, every time, for every mutation. That failure was
# absent from the baseline, so it scored as a kill. Every mutation self-killed and no
# survivor was reportable under any circumstances. The sweep said 25/0 and meant
# nothing. `EXCLUDED_FROM_SUBJECT` is the fix; these controls are the alarm that would
# have caught it, and that will catch the next instance of it.
CONTROLS = [
    Mutation("control-comment-in-summarize", SUMMARIZE,
             "# --- the summary ", "# --- THE SUMMARY ",
             "MUST SURVIVE: a comment edit that changes no behaviour", control=True),
    Mutation("control-comment-in-make-tables", MAKE_TABLES,
             "    # Explain only the marks that were actually used.",
             "    # Explain ONLY the marks that were actually used.",
             "MUST SURVIVE: a comment edit that changes no behaviour", control=True),
    Mutation("control-comment-in-campaign", CAMPAIGN,
             "# --- the guards, all pure ---",
             "# --- THE GUARDS, ALL PURE ---",
             "MUST SURVIVE: a comment edit that changes no behaviour", control=True),
    Mutation("control-comment-in-run-m4", RUN_M4,
             "# Mirrors tools/campaign.py's PORCELAIN_LINE.",
             "# MIRRORS tools/campaign.py's PORCELAIN_LINE.",
             "MUST SURVIVE: a comment edit that changes no behaviour", control=True),
]


# The harness must not be its own subject. `test_mutate.py` asserts things *about the
# source text* rather than about its behaviour, so it fails under every mutation
# regardless of what the mutation does. Its job -- catching pattern rot -- belongs to
# `make test`, where the tree is unmutated and the assertion means something.
EXCLUDED_FROM_SUBJECT = ("tools/tests/test_mutate.py",)


MUTATIONS = [
    # --- the bootstrap ------------------------------------------------------------
    Mutation("bootstrap-ignores-seed", SUMMARIZE,
             "pick = random.Random(seed).randrange",
             "pick = random.Random(1234).randrange",
             "the seed is honoured, so a published interval is reproducible"),
    Mutation("bootstrap-without-replacement", SUMMARIZE,
             "boot = [_median(sorted(vals[pick(n)] for _ in range(n)))",
             "boot = [_median(sorted(vals[i] for i in range(n)))",
             "resampling is with replacement; without it every resample is the sample"),
    Mutation("ci-low-percentile", SUMMARIZE,
             "CI_LOW = 0.025", "CI_LOW = 0.05",
             "the lower endpoint is the 2.5th percentile"),
    Mutation("ci-high-percentile", SUMMARIZE,
             "CI_HIGH = 0.975", "CI_HIGH = 0.95",
             "the upper endpoint is the 97.5th percentile"),

    # --- pairing ------------------------------------------------------------------
    Mutation("pairing-ignores-size", SUMMARIZE,
             'key = (row["run_index"], row.get("size_bytes"))',
             'key = (row["run_index"], None)',
             "a 4 KiB row is never divided by a 64 KiB one"),

    # --- the modality detector ----------------------------------------------------
    Mutation("gap-factor-loosened", SUMMARIZE,
             "MODALITY_GAP_FACTOR = 3.0", "MODALITY_GAP_FACTOR = 0.5",
             "the separation threshold, from below"),
    Mutation("gap-factor-tightened", SUMMARIZE,
             "MODALITY_GAP_FACTOR = 3.0", "MODALITY_GAP_FACTOR = 5.0",
             "the separation threshold, from above"),
    Mutation("scale-is-range-not-iqr", SUMMARIZE,
             "spread = max(_iqr(lower), _iqr(upper))",
             "spread = max(lower[-1] - lower[0], upper[-1] - upper[0])",
             "the robust scale statistic; the range collapses on one straddling run"),
    Mutation("min-share-lowered", SUMMARIZE,
             "MODALITY_MIN_SHARE = 0.15", "MODALITY_MIN_SHARE = 0.05",
             "a two-point excursion cannot become a performance state"),
    Mutation("min-share-raised", SUMMARIZE,
             "MODALITY_MIN_SHARE = 0.15", "MODALITY_MIN_SHARE = 0.30",
             "a genuine minority state is still found"),
    Mutation("min-n-lowered", SUMMARIZE,
             "MODALITY_MIN_N = 12", "MODALITY_MIN_N = 8",
             "the sample size below which no verdict is returned"),
    Mutation("not-judged-laundered-to-unimodal", SUMMARIZE,
             "        verdict = MODALITY_NOT_JUDGED",
             "        verdict = MODALITY_UNIMODAL",
             "'we did not look' is never written as 'we looked and found one mode'"),
    Mutation("not-judged-counts-one-mode", SUMMARIZE,
             '        mode_count = ""', "        mode_count = 1",
             "an unexamined sample counts no modes"),
    Mutation("gap-over-spread-value-wrong", SUMMARIZE,
             'prefix + "gap_over_spread": _fmt_ratio(modes["gap_over_spread"]),',
             'prefix + "gap_over_spread": _fmt_ratio(modes["gap"]),',
             "the near-miss column carries the ratio, not just the column name"),
    Mutation("header-claims-none-when-nothing-judged", SUMMARIZE,
             "    elif not_judged:", "    elif False:",
             "`multimodal_samples: none` is never claimed over unexamined samples"),
    Mutation("not-judged-list-needs-both-samples", SUMMARIZE,
             '    not_judged = [r for r in rows\n'
             '                  if r["modality"] == MODALITY_NOT_JUDGED\n'
             '                  or r["ratio_modality"] == MODALITY_NOT_JUDGED]',
             '    not_judged = [r for r in rows\n'
             '                  if r["modality"] == MODALITY_NOT_JUDGED\n'
             '                  and r["ratio_modality"] == MODALITY_NOT_JUDGED]',
             "a row unjudged on ONE of its two samples is still unjudged"),
    Mutation("flagged-list-needs-both-samples", SUMMARIZE,
             '    flagged = [r for r in rows\n'
             '               if r["modality"] == MODALITY_MULTIMODAL\n'
             '               or r["ratio_modality"] == MODALITY_MULTIMODAL]',
             '    flagged = [r for r in rows\n'
             '               if r["modality"] == MODALITY_MULTIMODAL\n'
             '               and r["ratio_modality"] == MODALITY_MULTIMODAL]',
             "the same, for the multimodal list"),

    # --- provenance ---------------------------------------------------------------
    Mutation("provenance-deny-list", SUMMARIZE,
             "    return marker in PUBLISHABLE_PROVENANCE",
             '    return marker != "SMOKE-RUN"',
             "provenance is an allow-list; a decorated SMOKE-RUN marker is refused"),

    # --- ranking stability --------------------------------------------------------
    Mutation("flips-need-not-be-separable", SUMMARIZE,
             "    return one[1] < other[0] or other[1] < one[0]",
             "    return True",
             "only a flip between ciphers separated at both sizes is publishable"),

    # --- the table generator ------------------------------------------------------
    Mutation("ratio-cell-always-a-bracket", MAKE_TABLES,
             '    modes = _modes_cell(row, "ratio_", "%.3f")', "    modes = None",
             "a bimodal ratio prints its states, not an interval across the gap"),
    Mutation("throughput-cell-always-a-bracket", MAKE_TABLES,
             '    modes = _modes_cell(row, "", "%.1f")', "    modes = None",
             "the same, for the absolute column"),
    Mutation("unjudged-cell-unmarked", MAKE_TABLES,
             "        return NOT_JUDGED_MARK", '        return ""',
             "a row nobody could judge is not typeset like one that passed"),
    Mutation("caption-collapses-three-states-to-two", MAKE_TABLES,
             "    if ratio_not_judged:", "    if False:",
             "not-judged gets its own caption sentence, not the clean one"),
    Mutation("caption-ignores-a-missing-modality-column", MAKE_TABLES,
             "    if ratio_unrecorded:", "    if False:",
             "a summary with no modality column is a fourth state, not a clean one"),
    Mutation("unrecorded-disclaimer-printed-unconditionally", MAKE_TABLES,
             "    if ratio_unrecorded:", "    if True:",
             "the 'no modality check recorded' sentence appears only for a summary "
             "that records none, not beside the clean claim it contradicts"),
    Mutation("unrecorded-modality-treated-as-checked", MAKE_TABLES,
             '    ratio_unrecorded = [r for r in rows if not r.get("ratio_modality")]',
             "    ratio_unrecorded = []",
             "an absent field never counts as a check that ran"),
    Mutation("drift-cancels-claimed-unconditionally", MAKE_TABLES,
             "    if not ratio_multimodal and not ratio_not_judged "
             "and not ratio_unrecorded:", "    if True:",
             "the cancellation claim is made only when the check supports it"),
    Mutation("clean-branch-drops-the-unrecorded-guard", MAKE_TABLES,
             "    if not ratio_multimodal and not ratio_not_judged "
             "and not ratio_unrecorded:",
             "    if not ratio_multimodal and not ratio_not_judged:",
             "the unrecorded state specifically, not just the branch as a whole"),
    Mutation("not-judged-header-names-the-wrong-samples", SUMMARIZE,
             "_flag_which(r, MODALITY_NOT_JUDGED)", "_flag_which(r)",
             "the not-judged list names which sample was unjudged, not which was "
             "flagged"),
    Mutation("run-count-from-first-row", MAKE_TABLES,
             '    counts = sorted({int(float(r["n_runs"])) for r in rows'
             ' if r.get("n_runs")})',
             '    counts = [int(float(rows[0]["n_runs"]))]',
             "the caption's run count covers every row, not just the first"),
    Mutation("stability-caption-unconditional", MAKE_TABLES,
             "    if stability_publishable:", "    if True:",
             "an unresolvable UNSTABLE verdict does not reach a caption"),
    Mutation("singleton-top-group-marked", MAKE_TABLES,
             '    return sum(1 for r in rows if r.get(column) == "yes") > 1',
             '    return sum(1 for r in rows if r.get(column) == "yes") > 0',
             "a 'top group' of one is not marked, nor described as unranked"),

    # --- the campaign driver: what it refuses ---------------------------------------
    Mutation("watched-set-loses-a-build-input", CAMPAIGN,
             'WATCHED_BUILD_INPUTS = ("Makefile", "bench/", "src/", "include/", "fw/")',
             'WATCHED_BUILD_INPUTS = ("Makefile", "bench/", "include/", "fw/")',
             "every input that can change a measured byte is watched"),
    Mutation("watched-directories-match-by-bare-prefix", CAMPAIGN,
             '"Makefile", "bench/", "src/", "include/", "fw/")',
             '"Makefile", "bench", "src", "include", "fw")',
             "a watched directory is a directory: src/ must not match src-notes/"),
    Mutation("dirty-rename-keeps-only-the-destination", CAMPAIGN,
             "            paths.append(before.strip().strip('\"'))\n"
             "            paths.append(after.strip().strip('\"'))",
             "            paths.append(after.strip().strip('\"'))",
             "a file moved OUT of a watched directory still dirties it"),
    Mutation("porcelain-parsed-by-fixed-column", CAMPAIGN,
             'PORCELAIN_LINE = re.compile(r"^(?:[ MADRCU?!]{1,2})\\s+(?P<path>.+)$")',
             'PORCELAIN_LINE = re.compile(r"^...(?P<path>.+)$")',
             "a stripped git status line does not shift every path left by one"),
    Mutation("dirty-check-passes-everything", CAMPAIGN,
             "    if offending:", "    if False:",
             "a modified build input stops the campaign"),

    # --- the campaign driver: the frozen choice -------------------------------------
    Mutation("stale-backend-accepted", CAMPAIGN,
             "        if impl not in here:", "        if False:",
             "a frozen winner that no longer exists is refused"),
    Mutation("availability-not-checked-per-cipher", CAMPAIGN,
             "        if isinstance(available, collections.abc.Mapping):",
             "        if False:",
             "ctr-bitslice-avx2 exists, but not for every cipher"),
    Mutation("uncovered-cipher-accepted", CAMPAIGN,
             "    missing = [c for c in ciphers if c not in tuning]",
             "    missing = []",
             "a cipher with no frozen winner is not silently dropped from the table"),
    Mutation("empty-choice-accepted-as-a-freeze", CAMPAIGN,
             "    if not isinstance(choice, dict) or not choice:",
             "    if not isinstance(choice, dict):",
             "a tuning.json that freezes nothing is not a freeze"),
    Mutation("freeze-need-not-be-committed", CAMPAIGN,
             "    if not in_head:", "    if False:",
             "the freeze is checkable from git log, which needs it committed"),
    Mutation("freeze-may-be-edited-after-committing", CAMPAIGN,
             "    if modified:", "    if False:",
             "the choice measured is the choice the history records"),

    # --- the campaign driver: the run-count floor -----------------------------------
    Mutation("unfrozen-header-reads-like-a-freeze", CAMPAIGN,
             '    if not freeze.get("in_head"):', "    if False:",
             "a file measured with --allow-unfrozen says so where the commit would go"),
    Mutation("edited-freeze-header-reads-like-a-clean-one", CAMPAIGN,
             '    if freeze.get("modified_in_worktree"):', "    if False:",
             "an edited tuning.json is not described as the committed choice"),
    Mutation("run-floor-is-a-local-number", CAMPAIGN,
             "MIN_PUBLISHABLE_RUNS = summarize.MODALITY_MIN_N",
             "MIN_PUBLISHABLE_RUNS = 8",
             "the floor IS summarize's modality minimum, not a copy of today's value"),
    Mutation("run-floor-not-enforced", CAMPAIGN,
             "    if runs < MIN_PUBLISHABLE_RUNS:", "    if False:",
             "a campaign below the floor publishes only not-judged rows"),
    Mutation("protocol-band-not-mentioned", CAMPAIGN,
             "    if not PROTOCOL_RUNS_MIN <= runs <= PROTOCOL_RUNS_MAX:",
             "    if False:",
             "a run count outside 20-30 is said out loud"),
    Mutation("default-run-count-below-the-band", CAMPAIGN,
             "DEFAULT_MEASURE_RUNS = 25", "DEFAULT_MEASURE_RUNS = 5",
             "the default campaign is inside the protocol's band"),

    # --- the campaign driver: provenance --------------------------------------------
    Mutation("marker-always-says-campaign", CAMPAIGN,
             "    if campaign and not (allow_dirty or allow_unfrozen):\n"
             "        return PROVENANCE_CAMPAIGN\n"
             "    return PROVENANCE_SMOKE",
             "    return PROVENANCE_CAMPAIGN",
             "the marker comes from the flag; a trial cannot wear a campaign's label"),
    Mutation("marker-ignores-the-escape-hatches", CAMPAIGN,
             "    if campaign and not (allow_dirty or allow_unfrozen):",
             "    if campaign:",
             "the writer's own second defence: --campaign with a hatch open is not a "
             "campaign whatever route reached the writer"),
    Mutation("trial-prose-omitted", CAMPAIGN,
             "    if marker != PROVENANCE_CAMPAIGN:\n"
             "        lines += [\"# \" + line for line in SMOKE_HEADER]",
             "    if False:\n        lines += [\"# \" + line for line in SMOKE_HEADER]",
             "a trial's file says in prose that it is one, not only in the marker"),
    Mutation("trial-prose-follows-the-flag-not-the-marker", CAMPAIGN,
             "    if marker != PROVENANCE_CAMPAIGN:", "    if not campaign:",
             "a file marked SMOKE-RUN always carries the paragraph saying what that "
             "means, including when the marker was taken away rather than not asked for"),
    Mutation("a-trial-may-overwrite-a-campaign", CAMPAIGN,
             "    if campaign or not os.path.exists(path):", "    if True:",
             "a trial run does not clobber the published campaign's only copy"),
    Mutation("run-index-drops-the-campaign-uid", CAMPAIGN,
             '    return "%s#%0*d" % (campaign_uid, width, seq)',
             '    return "%0*d" % (width, seq)',
             "two campaigns' rows cannot pair across campaigns"),
    Mutation("run-index-not-zero-padded", CAMPAIGN,
             "    width = max(2, len(str(max(total - 1, 0))))", "    width = 1",
             "run 2 sorts before run 10"),

    # --- the campaign driver: the correctness gate ----------------------------------
    Mutation("empty-kat-is-a-vacuous-pass", CAMPAIGN,
             "    if not entries:", "    if False:",
             "all([]) is True; a gate that checked nothing authorises nothing"),
    Mutation("kat-coverage-not-checked", CAMPAIGN,
             "        if uncovered:", "        if False:",
             "a backend with no verdict is not measured as though it had one"),

    # --- the campaign driver: the measurement protocol -------------------------------
    Mutation("cipher-order-never-varies", CAMPAIGN,
             "        rng.shuffle(order)", "        order.sort()",
             "position bias becomes spread across runs, not a constant offset"),
    Mutation("published-size-need-not-be-measured", CAMPAIGN,
             "    if summarize.PUBLISHED_SIZE_BYTES not in args.sizes:",
             "    if False:",
             "a campaign that measures no publishable size is refused up front"),
    Mutation("target-may-be-a-path", CAMPAIGN,
             '    if os.sep in args.target or args.target in (".", ".."):',
             "    if False:",
             "the target names a directory under results/v2, not an arbitrary path"),
    Mutation("only-the-published-size-is-measured", CAMPAIGN,
             "SIZES = (4096, 16384, summarize.PUBLISHED_SIZE_BYTES)",
             "SIZES = (summarize.PUBLISHED_SIZE_BYTES,)",
             "ranking stability across working-set sizes has something to compare"),
    Mutation("the-pin-is-dropped", CAMPAIGN,
             "    if cpu is not None:\n        cmd += [\"taskset\", \"-c\", str(cpu)]",
             "    if False:\n        cmd += [\"taskset\", \"-c\", str(cpu)]",
             "the harness runs on the CPU the campaign says it ran on"),

    # --- the campaign driver: tuning evidence ----------------------------------------
    Mutation("winner-picked-by-its-luckiest-run", CAMPAIGN,
             '    ranked.sort(key=lambda c: (-c["median_mbit_per_sec"], c["impl"]))',
             '    ranked.sort(key=lambda c: (-c["max_mbit_per_sec"], c["impl"]))',
             "the freeze follows the median, not one lucky run on a bimodal host"),
    Mutation("lone-candidate-called-separated", CAMPAIGN,
             "    if len(ranked) < 2:\n        return None",
             "    if len(ranked) < 2:\n        return True",
             "an unopposed winner is not a decided comparison"),
    Mutation("one-run-each-called-separated", CAMPAIGN,
             '    if any(candidate["runs"] < 2 for candidate in ranked[:2]):\n'
             "        return None",
             '    if any(candidate["runs"] < 0 for candidate in ranked[:2]):\n'
             "        return None",
             "a candidate measured once has no range to be separated from"),
    Mutation("separation-compares-medians-not-spreads", CAMPAIGN,
             '    return ranked[0]["min_mbit_per_sec"] > ranked[1]["max_mbit_per_sec"]',
             '    return ranked[0]["median_mbit_per_sec"] > '
             'ranked[1]["median_mbit_per_sec"]',
             "'separated' means the ranges did not overlap, not that a median won"),

    # --- the campaign driver: what the provenance probes may invent ------------------
    Mutation("busy-fraction-counts-iowait-as-busy", CAMPAIGN,
             "    idle = delta[3] + delta[4]", "    idle = delta[3]",
             "iowait is not the sibling running work"),
    Mutation("busy-fraction-invents-zero-for-an-absent-cpu", CAMPAIGN,
             "    if first is None or second is None:\n        return None",
             "    if first is None or second is None:\n        return 0.0",
             "'the sibling was idle' is never invented from a missing file"),
    Mutation("busy-fraction-matches-a-cpu-prefix", CAMPAIGN,
             '            if parts and parts[0] == "cpu%d" % cpu:',
             '            if parts and parts[0].startswith("cpu%d" % cpu):',
             "cpu9 is not answered by cpu90 or by the aggregate cpu line"),
    Mutation("package-sensor-ignored", CAMPAIGN,
             '        if zone.get("type") == "x86_pkg_temp":', "        if False:",
             "the temperature column tracks the measured core, not a disk"),
    Mutation("cmdline-flag-matched-loosely", CAMPAIGN,
             '            if token.startswith(key + "="):',
             '            if key in token:',
             "isolcpus= is an option, not a substring"),

    # --- the campaign driver: the wiring, not the guards -----------------------------
    # Everything above this block mutates a guard's body. These mutate the *calls*, and
    # they are here because a review's own sweep of exactly this layer killed 3 of 23:
    # the guards were correct, tested and -- as far as the suite could tell -- optional.
    # Deleting `require_frozen(...)` from phase_measure left every test green. Only the
    # end-to-end suite that drives campaign.main against a stub harness kills these.
    Mutation("cli-permits-a-campaign-with-a-hatch-open", CAMPAIGN,
             "        require_no_escape_hatch(args.campaign, args.allow_dirty, "
             "args.allow_unfrozen)\n",
             "",
             "--campaign --allow-unfrozen is refused, not published with a caveat that "
             "reaches runs.csv and never reaches summary.csv"),
    Mutation("cli-lets-a-trial-run-into-a-campaigns-directory", CAMPAIGN,
             "        require_no_downgrade(out_dir, args.campaign)\n", "",
             "a trial does not overwrite a campaign's env.json and kat.json before "
             "discovering it should not have"),
    Mutation("cli-skips-the-clean-tree-check", CAMPAIGN,
             "            require_clean(WATCHED_BUILD_INPUTS)\n",
             "            pass\n",
             "the commit a campaign stamps itself with describes the binary measured"),
    Mutation("cli-skips-the-run-count-floor", CAMPAIGN,
             "            for warning in require_run_count(args.runs, args.campaign):\n"
             '                print("WARNING: %s" % warning, file=sys.stderr)',
             "            pass",
             "a campaign below summarize's bimodality threshold is refused, not "
             "published as a table of not-judged rows"),
    Mutation("cli-ignores-a-summary-that-would-not-form", CAMPAIGN,
             "        if runs_path and not _summarize(runs_path):\n            return 1",
             "        if runs_path:\n            _summarize(runs_path)",
             "a campaign whose summary never formed exits non-zero, because the tables "
             "are formed from the summary and from nothing else"),
    Mutation("cli-measures-a-repeated-size-twice", CAMPAIGN,
             "    args.sizes = deduplicated",
             "    args.sizes = list(args.sizes)",
             "two processes never share one (run_index, size_bytes) bucket, which "
             "summarize would pair against each other"),
    Mutation("env-omits-the-freeze", CAMPAIGN,
             '            extra["tuning_freeze"] = tuning_freeze_record(out_dir)',
             "            pass",
             "env.json records which commit froze the choice these numbers measure"),
    Mutation("measure-skips-the-freeze-check", CAMPAIGN,
             '        require_frozen(freeze["path"], freeze["in_head"],\n'
             '                       freeze["modified_in_worktree"])',
             "        pass",
             "the freeze-before-measure claim is enforced, not merely reported"),
    Mutation("measure-behaves-as-if-allow-unfrozen-were-always-on", CAMPAIGN,
             "    if args.allow_unfrozen:\n", "    if True:\n",
             "the escape hatch is taken only when it was asked for"),
    Mutation("measure-skips-the-coverage-check", CAMPAIGN,
             "    check_tuning_covers(choice, ciphers)\n", "",
             "a cipher missing from the freeze is refused, not silently dropped from "
             "the published table"),
    Mutation("measure-skips-the-stale-backend-check", CAMPAIGN,
             "    check_tuning(choice, registered_backends(binary, cpu=args.cpu))\n",
             "",
             "a frozen winner that this build no longer registers is refused up front"),
    Mutation("measure-does-not-demand-gate-coverage", CAMPAIGN,
             "    check_kat(entries, expected={(c, choice[c]) for c in ciphers})",
             "    check_kat(entries)",
             "the gate's verdict covers every backend about to be measured, not just "
             "whichever ones it happened to check"),
    Mutation("measure-gives-every-run-the-same-index", CAMPAIGN,
             "        run_index = make_run_index(args.campaign_uid, seq, args.runs)",
             "        run_index = make_run_index(args.campaign_uid, 0, args.runs)",
             "each whole-program run is its own pairing bucket"),
    Mutation("measure-ignores-the-order-seed", CAMPAIGN,
             "    orders = cipher_orders(ciphers, args.runs, args.seed)",
             "    orders = cipher_orders(ciphers, args.runs, 0)",
             "the recorded seed is the seed the order came from"),
    Mutation("measure-drops-the-freeze-note", CAMPAIGN,
             "        freeze_note(freeze),\n", "",
             "runs.csv names the commit that froze the choice, so the claim is "
             "checkable from the published file alone"),
    Mutation("measure-drops-the-dirty-note", CAMPAIGN,
             "    note = dirty_note(args.allow_dirty, watched_dirty)",
             "    note = None",
             "--allow-dirty marks the file, not only stderr; stderr is not the artefact"),
    Mutation("measure-writes-the-rows-as-a-campaign-regardless", CAMPAIGN,
             "    write_runs_csv(runs_path, rows, args.campaign, notes,\n"
             "                   args.allow_dirty, args.allow_unfrozen)",
             "    write_runs_csv(runs_path, rows, True, notes)",
             "the marker on the rows is the one the invocation asked for"),
    Mutation("tune-gates-nothing", CAMPAIGN,
             "                              kat_json=kat_path if run == 0 else None)",
             "                              kat_json=None)",
             "tuning freezes a winner only after the correctness gate has passed"),
    Mutation("tune-does-not-check-the-gate-it-ran", CAMPAIGN,
             '            print("  correctness gate: %d backends, all passing"\n'
             "                  % check_kat(entries))",
             '            print("  correctness gate: %d backends" % len(entries))',
             "the gate's verdict file is read, not merely written"),
    Mutation("default-tuning-runs-cannot-separate-anything", CAMPAIGN,
             "TUNING_RUNS = 5", "TUNING_RUNS = 1",
             "the default freeze has enough runs per candidate for `separated` to be "
             "capable of saying True"),
    Mutation("default-pin-lands-on-cpu-zero", CAMPAIGN,
             "DEFAULT_CPU = 8", "DEFAULT_CPU = 0",
             "the default pinned CPU is not the one the kernel puts timers and unbound "
             "IRQs on"),
    Mutation("campaign-uid-is-one-nibble", CAMPAIGN,
             "CAMPAIGN_UID_CHARS = 12", "CAMPAIGN_UID_CHARS = 1",
             "two campaigns' run_index values do not collide, so concatenating their "
             "rows cannot pair one campaign's numerator with another's denominator"),
    Mutation("git-strips-its-output-again", CAMPAIGN,
             '    return proc.stdout.rstrip("\\n")', "    return proc.stdout.strip()",
             "`git status --porcelain`'s blank first column survives, so a "
             "working-tree-only change is not read as a path one character short"),

    # --- the M4 driver: the same provenance parse, whose bug was live ----------------
    # tools/run_m4_bench.py stamps results/m4-speed.csv with HEAD and refuses to run a
    # dirty tree; both defences rest on reading `git status --porcelain` without losing
    # the blank index column. Its git() strip + fixed-offset slice was a live bug (a
    # single modified build input went undetected); these pin the fix.
    Mutation("m4-git-strips-its-output", RUN_M4,
             '                          capture_output=True, text=True).stdout.rstrip("\\n")',
             '                          capture_output=True, text=True).stdout.strip()',
             "git() keeps the porcelain status field's blank first column, so a "
             "working-tree-only change is not shortened by one character"),
    Mutation("m4-porcelain-parsed-by-fixed-column", RUN_M4,
             '        match = PORCELAIN_LINE.match(line)\n'
             "        if not match:\n"
             "            continue\n"
             '        path = match.group("path").strip().strip(\'"\')',
             "        path = line[3:].strip().strip('\"')",
             "the path comes from the parsed status field, so a caller that ate the "
             "leading blank column cannot shift a fixed slice off the front of it"),
]


def apply_mutation(text, mutation):
    """Return `text` with `mutation` applied, or raise `PatternNotFound`.

    The pattern must appear exactly once. Zero matches means the code moved and the
    mutation would silently test nothing; several means the pattern has stopped
    identifying the one line it was written for. Both are errors, and being loud about
    them is this function's whole job -- a harness that quietly skips a mutation it
    cannot apply reports a clean sweep it did not earn.
    """
    count = text.count(mutation.old)
    if count == 1:
        return text.replace(mutation.old, mutation.new)
    raise PatternNotFound(
        "mutation %r: pattern appears %d times in %s, expected exactly once. The "
        "code it was written against has changed; update the mutation rather than "
        "dropping it, or the constant it defends goes unchecked.\n  pattern: %r"
        % (mutation.name, count, mutation.path, mutation.old))


FAILURE_LINE = re.compile(r"^(?:FAIL|ERROR): \S+ \(([^)\s]+)")


def failing_tests(output):
    """The set of test ids unittest reported as FAIL or ERROR."""
    return {m.group(1) for m in
            (FAILURE_LINE.match(line) for line in output.splitlines()) if m}


# The two discovery roots `make test` uses. The C tests are not run: every mutation
# here is in a Python file, and nothing in the C suite reads them.
SUITES = (("-s", "tools/tests", "-t", "."),
          ("-s", "analysis/tests", "-t", "analysis"))


def run_suite(root):
    """Run both Python suites in `root`; return the set of failing test ids."""
    failures = set()
    for suite in SUITES:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover"] + list(suite),
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True)
        # Per suite, not against the accumulated set. Testing `failures` meant that
        # once the first suite had failed anything at all, the second suite's "did it
        # even run?" guard could never fire again -- so an analysis suite that died on
        # an import error was silently treated as having passed.
        named = failing_tests(proc.stdout)
        failures |= named
        if proc.returncode != 0 and not named:
            # A suite that died without naming a test -- an import error, say -- is
            # not a kill; it is a broken run, and counting it as a kill would credit
            # the suite for noticing something it never executed.
            failures.add("<suite-did-not-report: %s>" % " ".join(suite))
    return failures


def isolated_copy(dest):
    """`git archive HEAD` unpacked into `dest`: the committed tree, and nothing else.

    Deliberately not a copy of the working tree. The harness must be unable to touch
    uncommitted work even when it is wrong about something else.
    """
    archive = subprocess.run(["git", "archive", "HEAD"], cwd=REPO_ROOT,
                             stdout=subprocess.PIPE, check=True).stdout
    subprocess.run(["tar", "-x", "-C", dest], input=archive, check=True)
    # Build artefacts are not in the archive, and one test asserts over a compiled
    # ELF. Copying them keeps the baseline clean; if they are absent the baseline
    # simply carries that failure and every mutation is judged against it.
    build = os.path.join(REPO_ROOT, "build")
    if os.path.isdir(build):
        shutil.copytree(build, os.path.join(dest, "build"), dirs_exist_ok=True)
    # The harness is not its own subject; see EXCLUDED_FROM_SUBJECT.
    for relative in EXCLUDED_FROM_SUBJECT:
        path = os.path.join(dest, relative)
        if os.path.exists(path):
            os.remove(path)
    return dest


def revision():
    """(short sha, dirty) for the tree the sweep will actually test.

    The sweep runs on `git archive HEAD`, so uncommitted work is invisible to it. A
    harness that does not say which revision it tested lets someone edit a file, run
    the sweep, and read the result as being about the edit.
    """
    sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT,
                         stdout=subprocess.PIPE, universal_newlines=True,
                         check=True).stdout.strip()
    status = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_ROOT,
                            stdout=subprocess.PIPE, universal_newlines=True,
                            check=True).stdout.strip()
    return sha, bool(status)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Mutation-test the statistics layer.")
    parser.add_argument("--list", action="store_true",
                        help="print the mutations and exit")
    parser.add_argument("-k", metavar="SUBSTRING", default="",
                        help="only mutations whose name contains SUBSTRING")
    args = parser.parse_args(argv)

    chosen = [m for m in CONTROLS + MUTATIONS if args.k in m.name]
    if not chosen:
        print("no mutation matches %r" % args.k)
        return 2

    if args.list:
        for m in chosen:
            print("%-42s %-22s %s%s" % (m.name, os.path.basename(m.path),
                                        "[control] " if m.control else "", m.defends))
        print("\n%d mutations (%d of them controls)"
              % (len(chosen), sum(1 for m in chosen if m.control)))
        return 0

    sha, dirty = revision()
    print("testing revision %s (git archive HEAD)" % sha)
    if dirty:
        print("  WARNING: the working tree is DIRTY. This sweep tests HEAD, not your\n"
              "  uncommitted changes -- commit them first or the result is about\n"
              "  code you are not running.")

    with tempfile.TemporaryDirectory() as tmp:
        root = isolated_copy(tmp)
        pristine = {path: open(os.path.join(root, path), encoding="utf-8").read()
                    for path in {m.path for m in chosen}}

        print("baseline (unmutated) ...", end=" ", flush=True)
        baseline = run_suite(root)
        print("%d failing" % len(baseline))
        for test in sorted(baseline):
            print("    pre-existing failure, not counted as a kill: %s" % test)

        killed, survived, kill_sets = [], [], {}
        for mutation in chosen:
            mutated = apply_mutation(pristine[mutation.path], mutation)
            target = os.path.join(root, mutation.path)
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(mutated)
            try:
                new_failures = run_suite(root) - baseline
            finally:
                with open(target, "w", encoding="utf-8") as fh:
                    fh.write(pristine[mutation.path])
            kill_sets[mutation.name] = new_failures
            label = "control " if mutation.control else ""
            if new_failures:
                killed.append((mutation, new_failures))
                print("  %-8s killed   %-42s (%d tests)"
                      % (label, mutation.name, len(new_failures)))
            else:
                survived.append(mutation)
                print("  %-8s SURVIVED %-42s -- nothing defends: %s"
                      % (label, mutation.name, mutation.defends))

    invalid = []

    # A control that dies means the harness is reacting to something other than the
    # behaviour of the code, and every other number in this run is suspect.
    for mutation, tests in killed:
        if mutation.control:
            invalid.append(
                "control %r was KILLED by %s. A comment edit cannot change behaviour, "
                "so the suite is failing for a reason unrelated to the mutation and "
                "no kill in this run can be trusted."
                % (mutation.name, ", ".join(sorted(tests))))

    # A test that dies under every unrelated mutation is asserting over the source
    # text rather than exercising it, which inflates every kill and can make a
    # survivor impossible to report. Needs a few mutations before the signal means
    # anything, hence the floor.
    real = [m for m in chosen if not m.control]
    if len(real) >= 5:
        universal = set.intersection(*(kill_sets[m.name] for m in real)) \
            if all(kill_sets[m.name] for m in real) else set()
        for test in sorted(universal):
            invalid.append(
                "%s killed EVERY one of the %d mutations, including unrelated ones in "
                "different files. That is the signature of a test that reads the "
                "source rather than running it; it inflates every kill count by one "
                "and can hide survivors entirely." % (test, len(real)))

    print("\n%d killed, %d survived, of %d (%d controls, which must survive)"
          % (len(killed), len(survived), len(chosen),
             sum(1 for m in chosen if m.control)))
    for mutation in survived:
        if mutation.control:
            continue
        print("  survivor: %s (%s)" % (mutation.name, mutation.path))
        print("    undefended: %s" % mutation.defends)

    if invalid:
        print("\nSWEEP INVALID -- the harness is not measuring what it claims:")
        for problem in invalid:
            print("  * %s" % problem)
        return 2
    return 1 if [m for m in survived if not m.control] else 0


if __name__ == "__main__":
    sys.exit(main())
