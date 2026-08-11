#!/usr/bin/env python3
"""Mutation testing for the statistics layer: tools/summarize.py and tools/make_tables.py.

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
    Mutation("unrecorded-modality-treated-as-checked", MAKE_TABLES,
             '    ratio_unrecorded = [r for r in rows if not r.get("ratio_modality")]',
             "    ratio_unrecorded = []",
             "an absent field never counts as a check that ran"),
    Mutation("drift-cancels-claimed-unconditionally", MAKE_TABLES,
             "    if not ratio_multimodal and not ratio_not_judged "
             "and not ratio_unrecorded:", "    if True:",
             "the cancellation claim is made only when the check supports it"),
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
