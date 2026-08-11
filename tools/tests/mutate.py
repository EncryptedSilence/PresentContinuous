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


Mutation = collections.namedtuple("Mutation", "name path old new defends")


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
    Mutation("drift-cancels-claimed-unconditionally", MAKE_TABLES,
             "    if not ratio_multimodal and not ratio_not_judged:", "    if True:",
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
        failures |= failing_tests(proc.stdout)
        if proc.returncode != 0 and not failures:
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
    return dest


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Mutation-test the statistics layer.")
    parser.add_argument("--list", action="store_true",
                        help="print the mutations and exit")
    parser.add_argument("-k", metavar="SUBSTRING", default="",
                        help="only mutations whose name contains SUBSTRING")
    args = parser.parse_args(argv)

    chosen = [m for m in MUTATIONS if args.k in m.name]
    if not chosen:
        print("no mutation matches %r" % args.k)
        return 2

    if args.list:
        for m in chosen:
            print("%-42s %-22s %s" % (m.name, os.path.basename(m.path), m.defends))
        print("\n%d mutations" % len(chosen))
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        root = isolated_copy(tmp)
        pristine = {path: open(os.path.join(root, path), encoding="utf-8").read()
                    for path in {m.path for m in chosen}}

        print("baseline (unmutated) ...", end=" ", flush=True)
        baseline = run_suite(root)
        print("%d failing" % len(baseline))
        for test in sorted(baseline):
            print("    pre-existing failure, not counted as a kill: %s" % test)

        killed, survived = [], []
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
            if new_failures:
                killed.append((mutation, new_failures))
                print("  killed   %-42s (%d tests)"
                      % (mutation.name, len(new_failures)))
            else:
                survived.append(mutation)
                print("  SURVIVED %-42s -- nothing defends: %s"
                      % (mutation.name, mutation.defends))

    print("\n%d killed, %d survived, of %d" % (len(killed), len(survived),
                                               len(chosen)))
    for mutation in survived:
        print("  survivor: %s (%s)" % (mutation.name, mutation.path))
        print("    undefended: %s" % mutation.defends)
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
