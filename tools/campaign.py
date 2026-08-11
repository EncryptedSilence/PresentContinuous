#!/usr/bin/env python3
"""Run a measurement campaign as one reproducible command, and record what it ran on.

Two phases, deliberately separated, and a provenance file that makes the separation
checkable by someone who was not there.

WHY THE TWO PHASES ARE SEPARATE COMMANDS
----------------------------------------
`--tune` measures every registered backend and writes `tuning.json`: the winner per
cipher **and the medians that justified it**. `--measure` refuses to start until that
file exists, is committed, and names backends that still exist -- and then measures
only those frozen winners.

Choosing the winner with the same noisy measurements that are later published is
selection bias with a clean-looking audit trail: whichever kernel got lucky is both
declared best and reported at its lucky number. Splitting the phases removes it, but
only if the split is verifiable, so `--measure` requires `tuning.json` to be present in
`HEAD` and unmodified in the working tree, and it stamps the freeze commit and the
file's sha256 into `env.json` and into `runs.csv`'s own header. "Was the choice frozen
before the numbers were taken?" is then answerable from the published file, not only
from someone's memory of the order they ran things in.

WHY EVERY COMPARISON IS PAIRED, AND WHAT THAT COSTS
---------------------------------------------------
Task 4 established that the x86 host has two discrete performance states about 2.15x
apart, and that which one a run lands in is not controllable: the same binary at
warmups 3/20/100/500 gave 1.72 / 0.81 / 1.72 / 0.78 cyc/B. This is not noise around a
mean, and it has one consequence that shapes this whole file: **an absolute figure from
one file compared against an absolute figure from another file can show a factor of two
that does not exist.** No such comparison is publishable on this target.

So every cipher a comparison touches is measured inside one `ctr_bench` process,
against the baseline measured in that same process. `bench/ctr_bench.c --select` exists
for that reason, and `tools/summarize.py` pairs on `(run_index, size_bytes)` to enforce
it. Three things here make the unpaired comparison hard to reach by accident:

  * one process per (run, working-set size) measures all seven ciphers, so a paired
    ratio always exists and an unpaired one has to be constructed deliberately;
  * `run_index` is namespaced with the campaign's own uid, so rows from two campaigns
    concatenated into one file collide in `summarize`'s duplicate check instead of
    quietly pairing across campaigns;
  * every row carries `campaign_uid`, so a summary built from mixed sources is visible
    in the raw data rather than only in the intent of whoever built it.

WHY THE RUN COUNT HAS A FLOOR
-----------------------------
`tools/summarize.py` will not judge a sample for bimodality below
`summarize.MODALITY_MIN_N` points and reports `not-judged`, which the table then marks
and does not certify. A campaign below that floor therefore publishes a table covered
in "could not be judged" marks -- the interval is still printed, and nothing stands
behind it. `--campaign` refuses outright below the floor; a trial warns loudly and
carries the SMOKE-RUN marker that stops it reaching a table anyway. The floor is
imported from `summarize`, never restated, so raising it there raises it here.

THE PROVENANCE MARKER
---------------------
Line 1 of `runs.csv` is exactly `# provenance: CAMPAIGN` or `# provenance: SMOKE-RUN`,
the convention `bench/gpu_bench.cu` set. It is written from a flag by the program that
produced the file, never edited in by hand afterwards, so a trial cannot be left behind
wearing a campaign's label because someone forgot. `tools/summarize.py` copies it onto
`summary.csv` and `tools/make_tables.py --require-campaign` refuses anything else.

EVERYTHING IN env.json IS OBSERVED, NEVER ASSERTED
--------------------------------------------------
The governor, the pinned CPU, the sibling's idleness, `isolcpus`, the temperatures: all
are read and recorded as found. Nothing here sets them and nothing here fails because
they are not what a quiet machine would have. `docs/measurement-environment.md` has to
apologise that parts of it are "a record of the defaults the machine happened to have";
a file that reports the truth needs no such apology, and a campaign run on an
unprepared machine should produce a file that says so rather than one that cannot.

Standard library only, like every other tool here.
"""

import argparse
import collections.abc
import csv
import datetime
import hashlib
import io
import json
import os
import random
import re
import statistics
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cipher_set  # noqa: E402
import summarize  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Everything whose change can alter a measured byte. The precedent is
# tools/run_m4_bench.py's BUILD_INPUTS: an allowlist, so that getting it wrong
# produces a spurious refusal rather than a results file stamped with a commit that
# does not describe the binary that produced it. Directory entries end in "/" so that
# "src/" cannot match a hypothetical "src-notes/".
WATCHED_BUILD_INPUTS = ("Makefile", "bench/", "src/", "include/", "fw/")

# The harness, and where a campaign's files go.
DEFAULT_BINARY = os.path.join("build", "ctr_bench")
RESULTS_ROOT = os.path.join("results", "v2")

# Phase 1 measures every backend this many times. Small on purpose -- it is a
# selection, not a publication -- but see `separated` in tuning.json: five runs on a
# bimodal host cannot always tell two backends apart, and when it cannot, the file
# says so rather than presenting the winner as decided.
TUNING_RUNS = 5

# Phase 2. The protocol asks for 20 to 30 whole-program runs with the cipher order
# varied between them; 25 is the middle of that band.
DEFAULT_MEASURE_RUNS = 25
PROTOCOL_RUNS_MIN = 20
PROTOCOL_RUNS_MAX = 30

# Below this, tools/summarize.py returns `not-judged` instead of a modality verdict and
# the table marks every row as uncertified. Imported rather than restated: there is one
# such number in this repository and it lives in summarize.
MIN_PUBLISHABLE_RUNS = summarize.MODALITY_MIN_N

# Three working-set sizes so that summarize.ranking_stable has something to compare;
# only summarize.PUBLISHED_SIZE_BYTES is published. A flip between sizes is a result
# about cache, and the alternative -- measuring one size -- hides it.
SIZES = (4096, 16384, summarize.PUBLISHED_SIZE_BYTES)

PROVENANCE_CAMPAIGN = summarize.PROVENANCE_CAMPAIGN
PROVENANCE_SMOKE = "SMOKE-RUN"

# Spec §6's assumption about this host: measure on CPU 8 with its hyperthread sibling
# left idle. Recorded as observed either way -- see the module docstring.
DEFAULT_CPU = 8

TUNING_FILENAME = "tuning.json"
ENV_FILENAME = "env.json"
KAT_FILENAME = "kat.json"
RUNS_FILENAME = "runs.csv"

RUNS_COLUMNS = (
    "target", "campaign_uid", "run_index", "run_seq", "order_position",
    "size_bytes", "cipher", "impl", "rounds", "block_bytes",
    "mbit_per_sec", "ns_median", "ns_min", "prepare_ns", "tsc_per_byte",
    "temp_c", "freq_khz", "started_utc",
)

SMOKE_HEADER = (
    "NOT A MEASUREMENT RESULT, and not a candidate for one. This file came out of a",
    "trial run -- a short run, or a loaded machine, or both -- and exists only to show",
    "that the columns are well formed. No number in it may be quoted, plotted,",
    "averaged or cited, and tools/make_tables.py refuses to build a table from it.",
    "The campaign runs on a quiet machine and writes CAMPAIGN on the first line.",
)


# --- the exceptions Tasks 9 and 10 reuse ---------------------------------------------

class CampaignError(Exception):
    """Anything that stops a campaign before it produces a number."""


class FrozenChoiceError(CampaignError):
    """The frozen kernel choice cannot be used as it stands.

    A base class so a caller can catch every way the freeze can be wrong without
    enumerating them, while the three specific failures stay distinguishable: they
    have different fixes -- run --tune, re-run --tune, or commit what you have.
    """


class FrozenChoiceMissing(FrozenChoiceError):
    """No tuning.json, or one that names no choice for a cipher being measured."""


class FrozenChoiceStale(FrozenChoiceError):
    """tuning.json names a backend that is no longer registered or available."""


class FrozenChoiceUnfrozen(FrozenChoiceError):
    """tuning.json exists but is not committed, or differs from the committed copy.

    Uncommitted, the freeze is not checkable from `git log`, which is the whole
    mechanism by which "the winner was not chosen by the published numbers" stops
    being a claim and becomes a fact about the history.
    """


class DirtyTree(CampaignError):
    """A watched build input has uncommitted changes, so the stamped commit would lie."""


class RunCountTooLow(CampaignError):
    """Fewer runs than tools/summarize.py will judge for bimodality."""


class KatFailed(CampaignError):
    """The harness's correctness gate did not pass for every measured backend.

    In the normal path the *failing-verdict* branch of `check_kat` is unreachable:
    ctr_bench writes kat.json and then exits 1 when any backend fails, so `run_harness`
    raises HarnessFailed before the file is ever read. That is deliberate belt and
    braces -- the check exists so the exit status is not the only thing standing between
    a broken backend and a published number, and it fires the day the harness's exit
    status and its verdict file disagree. `test_campaign.py`'s stub harness can be told
    to produce exactly that disagreement, which is how the branch is exercised. The other
    two branches (no verdicts at all, and a verdict missing for a backend about to be
    measured) are reachable today.
    """


class HarnessFailed(CampaignError):
    """build/ctr_bench exited non-zero."""


class EscapeHatchInCampaign(CampaignError):
    """--campaign was combined with --allow-dirty or --allow-unfrozen.

    A campaign is by definition measured from a clean tree against a frozen choice.
    The hatches exist for trials, and a trial that calls itself a campaign is the exact
    failure the provenance marker was invented to prevent.
    """


# --- the guards, all pure -------------------------------------------------------------

# `XY<space>PATH`, with the status field matched rather than assumed to be two
# characters wide. Slicing a fixed `line[3:]` is what turned ` M bench/ctr_bench.c`
# into `ench/ctr_bench.c` here the first time: an unmodified-index entry leads with a
# space, and any caller that strips its git output -- which is the normal thing to do
# with a command's stdout -- eats it and shifts the whole line left by one. The result
# is a path that matches no watched prefix, so the campaign calls a dirty tree clean.
# The `git` helper below no longer strips leading whitespace, and this pattern makes
# the parser survive a caller that does.
PORCELAIN_LINE = re.compile(r"^(?:[ MADRCU?!]{1,2})\s+(?P<path>.+)$")


def dirty_paths_from_porcelain(text):
    """Paths with uncommitted changes, from `git status --porcelain` output.

    Both halves of a rename are returned, not just the destination. Moving
    `src/present.c` to `notes/present.c` changes the build, and a parser that keeps
    only the new path reports that one as `notes/present.c` -- which no watched prefix
    matches, so the campaign would run against a source tree missing a file and stamp
    itself clean.
    """
    paths = []
    for line in (text or "").splitlines():
        match = PORCELAIN_LINE.match(line.rstrip())
        if not match:
            continue
        path = match.group("path").strip()
        if " -> " in path:
            before, after = path.split(" -> ", 1)
            paths.append(before.strip().strip('"'))
            paths.append(after.strip().strip('"'))
        else:
            paths.append(path.strip('"'))
    return paths


def require_clean(watched, dirty=None):
    """Raise DirtyTree if any path in `dirty` is under a watched build input.

    `dirty` is a list of repository-relative paths; it defaults to asking git, which
    is the only part of this function that touches the machine. Directory entries in
    `watched` end in "/" and match by prefix; anything else matches by prefix too,
    which over-reports (a watched "Makefile" also matches "Makefile.bak") in the safe
    direction: a spurious refusal costs a `--allow-dirty`, a missed one costs a
    results file whose commit does not describe its binary.
    """
    if dirty is None:
        dirty = dirty_paths_from_porcelain(git("status", "--porcelain"))
    watched = tuple(watched)
    offending = sorted({p for p in dirty if watched and p.startswith(watched)})
    if offending:
        raise DirtyTree(
            "uncommitted changes under the watched build inputs (%s), so the commit "
            "this campaign would stamp itself with does not describe the binary it "
            "measured:\n  %s\nCommit them first, or pass --allow-dirty to produce a "
            "file that says the tree was dirty."
            % (", ".join(watched), "\n  ".join(offending)))
    return sorted(dirty)


def check_tuning(tuning, available):
    """Raise FrozenChoiceStale if a frozen winner is no longer there to measure.

    `available` is either a flat set of backend names or, better, a mapping from
    cipher to the backends registered *for that cipher*. The mapping form is the real
    check: `ctr-bitslice-avx2` exists, but not for `aes-r5`, and a flat set cannot
    tell the difference -- it would pass the guard and then fail inside the harness
    partway through a campaign.
    """
    stale = []
    for cipher in sorted(tuning):
        impl = tuning[cipher]
        if isinstance(available, collections.abc.Mapping):
            here = available.get(cipher)
            if here is None:
                stale.append("%s=%s: no backend is registered for that cipher at all"
                             % (cipher, impl))
                continue
        else:
            here = available
        if impl not in here:
            stale.append("%s=%s: registered for that cipher now: %s"
                         % (cipher, impl, ", ".join(sorted(here)) or "(none)"))
    if stale:
        raise FrozenChoiceStale(
            "the frozen kernel choice names %d backend(s) that cannot be measured "
            "today:\n  %s\nThe choice was frozen against a different build. Re-run "
            "--tune and commit the new tuning.json before measuring."
            % (len(stale), "\n  ".join(stale)))
    return True


def check_tuning_covers(tuning, ciphers):
    """Raise unless the frozen choice names exactly the cipher set, no more, no less.

    Separate from `check_tuning` because they answer different questions and the
    brief's contract for `check_tuning` is a per-entry check: a caller may legitimately
    check one entry. A campaign, though, publishes a table with a row per cipher, and
    a cipher absent from tuning.json would silently become a row absent from the table.
    """
    missing = [c for c in ciphers if c not in tuning]
    if missing:
        raise FrozenChoiceMissing(
            "the frozen kernel choice covers no backend for %d of the cipher set: %s. "
            "A cipher with no frozen winner cannot be measured, and dropping it would "
            "publish a table with a row missing and nothing to say why."
            % (len(missing), ", ".join(missing)))
    unknown = [c for c in sorted(tuning) if c not in ciphers]
    if unknown:
        raise FrozenChoiceStale(
            "the frozen kernel choice names %d cipher(s) that tools/cipher_set.py no "
            "longer resolves: %s. The cipher set moved after the freeze."
            % (len(unknown), ", ".join(unknown)))
    return True


def require_frozen(path, in_head, modified):
    """Raise FrozenChoiceUnfrozen unless tuning.json is committed and unmodified.

    Pure: the caller supplies what git said. `in_head` is whether the path exists in
    the committed tree, `modified` whether the working copy differs from it. Both have
    to hold, and for different reasons -- an uncommitted freeze leaves no timestamp in
    the history to compare against the measurement commit, and a modified one means
    the choice being measured is not the choice the history records.
    """
    if not in_head:
        raise FrozenChoiceUnfrozen(
            "%s is not committed. The plan's done-criterion is that every tuning.json "
            "was committed *before* the corresponding --measure run, checkable from "
            "git log; an uncommitted file cannot satisfy it. Commit it (on its own, so "
            "the freeze is one identifiable commit) and measure after." % path)
    if modified:
        raise FrozenChoiceUnfrozen(
            "%s differs from the committed copy. The choice about to be measured is "
            "not the choice the history records as frozen, so the freeze commit proves "
            "nothing about these numbers. Commit the change, or restore the committed "
            "file." % path)
    return True


def require_run_count(runs, campaign):
    """Warnings for this run count; RunCountTooLow when a campaign is below the floor.

    Returns a list of warning strings rather than printing, so that the decision to be
    loud belongs to the CLI and the rule itself stays testable without capturing
    stdout.
    """
    if runs < 1:
        raise ValueError("a campaign needs at least one run, got %r" % (runs,))
    warnings = []
    if runs < MIN_PUBLISHABLE_RUNS:
        if campaign:
            raise RunCountTooLow(
                "%d runs is below the %d tools/summarize.py needs before it will judge "
                "a sample for bimodality. Below it every row is reported `not-judged` "
                "and the table marks it as uncertified, so the campaign would publish "
                "intervals that nothing stands behind. Use at least %d runs (the "
                "protocol asks for %d to %d)."
                % (runs, MIN_PUBLISHABLE_RUNS, MIN_PUBLISHABLE_RUNS,
                   PROTOCOL_RUNS_MIN, PROTOCOL_RUNS_MAX))
        warnings.append(
            "%d runs is below the %d needed for a modality verdict; every row in the "
            "summary will read `not-judged`." % (runs, MIN_PUBLISHABLE_RUNS))
    if not PROTOCOL_RUNS_MIN <= runs <= PROTOCOL_RUNS_MAX:
        warnings.append(
            "%d runs is outside the protocol's %d to %d whole-program runs."
            % (runs, PROTOCOL_RUNS_MIN, PROTOCOL_RUNS_MAX))
    return warnings


def require_no_escape_hatch(campaign, allow_dirty, allow_unfrozen):
    """Raise EscapeHatchInCampaign if a campaign was asked for with a hatch open.

    Why this is a refusal and not a warning, and not a caveat written into the file:
    `tools/summarize.py` copies the provenance marker onto `summary.csv` and **nothing
    else** -- not the freeze note, not the dirty note, neither of which exists in the
    summary's schema. `summary.csv` is the only file `tools/make_tables.py` opens. So a
    caveat in `runs.csv` is invisible to the switch that decides publication, and
    `--campaign --allow-unfrozen` would put a CAMPAIGN marker on a table whose kernel
    choice was never frozen -- with `--require-campaign` on, which is the switch this
    task exists to enable.

    Refusing the combination is what makes the marker mean what it says without
    requiring the summary schema to grow two more columns that a future consumer would
    have to remember to read.
    """
    open_hatches = []
    if allow_dirty:
        open_hatches.append("--allow-dirty")
    if allow_unfrozen:
        open_hatches.append("--allow-unfrozen")
    if campaign and open_hatches:
        raise EscapeHatchInCampaign(
            "--campaign cannot be combined with %s. A campaign is measured from a "
            "clean tree against a committed frozen choice; the hatches exist for "
            "trials. The caveat would reach runs.csv and stop there -- summarize.py "
            "copies only the provenance marker onto summary.csv, and summary.csv is "
            "the only file make_tables --require-campaign reads, so the table would be "
            "published with nothing to say the guarantee was waived. Fix the tree or "
            "commit the freeze, or drop --campaign and keep the SMOKE-RUN marker."
            % " and ".join(open_hatches))
    return True


def check_kat(entries, expected=None):
    """Raise KatFailed unless the gate passed for every measured backend.

    An empty verdict list is a failure, not a vacuous pass: `all(...)` over nothing is
    True, and a harness that gated nothing is exactly the case where that reading is
    most wrong. `expected` is the set of (cipher, impl) pairs about to be measured; a
    verdict file that does not cover one of them authorises a number it never checked.
    """
    if not entries:
        raise KatFailed(
            "the correctness gate recorded no verdicts at all. No backend was checked, "
            "so no timing number from this run is authorised by anything.")
    failed = [e for e in entries if not e.get("pass")]
    if failed:
        raise KatFailed(
            "the correctness gate failed for %d of %d backend(s):\n  %s"
            % (len(failed), len(entries),
               "\n  ".join("%s / %s: %s%s"
                           % (e.get("cipher"), e.get("impl"), e.get("check"),
                              "" if e.get("offset") is None
                              else " at byte %s" % e.get("offset"))
                           for e in failed)))
    if expected is not None:
        seen = {(e.get("cipher"), e.get("impl")) for e in entries}
        uncovered = sorted(set(expected) - seen)
        if uncovered:
            raise KatFailed(
                "the correctness gate has no verdict for %d backend(s) about to be "
                "measured: %s"
                % (len(uncovered), ", ".join("%s/%s" % p for p in uncovered)))
    return len(entries)


def provenance_of_file(path):
    """The provenance marker of any file a campaign writes, or None if it has none.

    Two shapes, because a campaign's output directory holds two: the CSVs carry the
    marker as their first `#` line, and the JSON files carry it as a `provenance` key.
    """
    if not os.path.exists(path):
        return None
    try:
        if path.endswith(".json"):
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            marker = doc.get("provenance") if isinstance(doc, dict) else None
            return None if marker is None else str(marker).upper()
        with open(path, encoding="utf-8") as fh:
            first = fh.readline()
    except (OSError, ValueError):
        return None
    if not first.startswith("#"):
        return None
    marker = summarize.provenance_of([first])
    return None if marker == summarize.PROVENANCE_UNKNOWN else marker


# Everything a phase writes into the output directory. Listed so the downgrade check
# can look at all of it *before* the first byte is written, rather than each file
# guarding itself on the way out.
CAMPAIGN_OUTPUTS = (RUNS_FILENAME, "summary.csv", ENV_FILENAME, TUNING_FILENAME,
                    KAT_FILENAME)


def require_no_downgrade(out_dir, campaign, outputs=CAMPAIGN_OUTPUTS):
    """Raise unless this run may write into `out_dir`.

    Checked once, up front, over every file a phase will touch. Guarding only runs.csv
    on the way out is not enough and was actively harmful: `env.json` is written before
    the phase starts and `kat.json` before the rows are collected, so a trial aimed at a
    campaign's directory used to destroy the campaign's machine record and its gate
    verdict, then refuse to overwrite runs.csv and abort -- leaving the published
    numbers beside an env.json describing a different, unpublishable run, which the
    abort also left incomplete. `--tune` had no guard at all and would replace the
    frozen tuning.json outright.
    """
    if campaign:
        return True
    blocking = []
    for name in outputs:
        marker = provenance_of_file(os.path.join(out_dir, name))
        if marker == PROVENANCE_CAMPAIGN:
            blocking.append(name)
    if blocking:
        raise CampaignError(
            "%s already holds measurement-campaign output (%s marked `provenance: "
            "%s`); refusing to run a trial into it. Everything a phase writes -- "
            "env.json and kat.json among them -- would be overwritten before any "
            "refusal could fire, so the campaign's record would be destroyed by the "
            "command trying to protect it. Use --out-dir for the trial, or delete the "
            "campaign's files deliberately if they really are being replaced."
            % (out_dir, ", ".join(blocking), PROVENANCE_CAMPAIGN))
    return True


def refuse_downgrade(path, campaign):
    """Raise unless writing `campaign`-marked data over `path` is an upgrade or equal.

    A trial must not overwrite a campaign. The published file is the campaign's only
    copy, the trial is worth nothing, and the two are one careless command apart.
    """
    if campaign or not os.path.exists(path):
        return True
    with open(path, encoding="utf-8") as fh:
        first = fh.readline()
    marker = summarize.provenance_of([first] if first.startswith("#") else [])
    if marker == PROVENANCE_CAMPAIGN:
        raise CampaignError(
            "%s is marked `# provenance: %s`; refusing to overwrite a measurement "
            "campaign with a trial run. Write the trial elsewhere with --out-dir, or "
            "delete the campaign's file deliberately if it really is being replaced."
            % (path, PROVENANCE_CAMPAIGN))
    return True


# --- the frozen choice on disk ---------------------------------------------------------

def load_tuning_document(directory):
    """The whole tuning.json, including the evidence behind the choice."""
    path = os.path.join(directory, TUNING_FILENAME)
    if not os.path.exists(path):
        raise FrozenChoiceMissing(
            "%s does not exist. --measure will not choose a kernel for itself: the "
            "choice has to be frozen and committed by a separate --tune run first, "
            "which is what stops the winner being picked by the same measurements it "
            "is then published with." % path)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise FrozenChoiceMissing(
            "%s cannot be read as JSON (%s), so there is no usable frozen choice. "
            "Re-run --tune." % (path, exc))
    if not isinstance(doc, dict):
        raise FrozenChoiceMissing(
            "%s does not hold a JSON object; it cannot be a frozen choice." % path)
    return doc


def load_tuning(directory):
    """The frozen cipher -> backend mapping from `directory`/tuning.json."""
    doc = load_tuning_document(directory)
    choice = doc.get("choice")
    if not isinstance(choice, dict) or not choice:
        raise FrozenChoiceMissing(
            "%s has no non-empty `choice` object, so it freezes nothing."
            % os.path.join(directory, TUNING_FILENAME))
    bad = sorted(k for k, v in choice.items() if not isinstance(v, str) or not v)
    if bad:
        raise FrozenChoiceMissing(
            "%s names no backend for: %s"
            % (os.path.join(directory, TUNING_FILENAME), ", ".join(bad)))
    return dict(choice)


# --- run bookkeeping ------------------------------------------------------------------

def make_run_index(campaign_uid, seq, total):
    """`<campaign uid>#07`: unique within a campaign and across campaigns.

    Namespacing the run index with the campaign's uid is what makes two campaigns'
    runs.csv files refuse to merge quietly. Concatenated, their rows keep distinct
    keys per campaign, so `summarize` pairs within each and a reader can see two
    sources in the raw column -- where a bare 0..24 would have silently paired run 3
    of one campaign against run 3 of another, on a host where that comparison can be a
    factor of two of nothing.
    """
    width = max(2, len(str(max(total - 1, 0))))
    return "%s#%0*d" % (campaign_uid, width, seq)


def cipher_orders(ciphers, runs, seed):
    """One measurement order per run, deterministic given `seed`.

    The order is varied between runs because position in a process is not neutral: the
    first cipher measured pays for a cold cache and a clock still ramping, and the last
    runs on a hotter core. Holding the order fixed turns that into a constant bias in
    one direction for one cipher; varying it turns it into spread that the interval
    then shows. Deterministic, so the campaign is a rerunnable command and not a
    different experiment each time.
    """
    rng = random.Random(seed)
    orders = []
    for _ in range(runs):
        order = list(ciphers)
        rng.shuffle(order)
        orders.append(order)
    return orders


def select_args(order, choice):
    """`--select cipher=impl` arguments for one run, in measurement order."""
    args = []
    for cipher in order:
        args += ["--select", "%s=%s" % (cipher, choice[cipher])]
    return args


# --- provenance probes: every one records what it saw, none of them raise --------------

def _read(root, path):
    """Contents of `path` under `root`, stripped, or None if it cannot be read."""
    try:
        with open(os.path.join(root, path.lstrip("/")), encoding="utf-8",
                  errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def _as_int(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def parse_cpu_list(text):
    """`"0-3,8,10"` -> [0, 1, 2, 3, 8, 10]. Unparseable input gives []."""
    if not text:
        return []
    out = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            lo, hi = _as_int(lo), _as_int(hi)
            if lo is None or hi is None or hi < lo:
                continue
            out.extend(range(lo, hi + 1))
        else:
            one = _as_int(part)
            if one is not None:
                out.append(one)
    return sorted(set(out))


def cmdline_flags(text):
    """The kernel command line, plus whatever `isolcpus=` and `nohz_full=` say.

    Both are recorded as None when absent, which on this machine is the honest answer
    and is not the same as "the campaign disabled them".
    """
    found = {"raw": text, "isolcpus": None, "nohz_full": None}
    for token in (text or "").split():
        for key in ("isolcpus", "nohz_full"):
            if token.startswith(key + "="):
                found[key] = token.split("=", 1)[1]
    return found


def cpu_busy_fraction(before, after, cpu):
    """Busy fraction of `cpu` between two `/proc/stat` snapshots, or None.

    This is how "was the hyperthread sibling left idle?" gets answered with a number
    instead of an intention. /proc/stat's per-cpu line is
    `cpuN user nice system idle iowait irq softirq steal ...`; idle and iowait are the
    not-busy fields.
    """
    if cpu is None:      # --no-pin: there is no one CPU whose busy fraction means anything
        return None

    def fields(text):
        for line in (text or "").splitlines():
            parts = line.split()
            if parts and parts[0] == "cpu%d" % cpu:
                values = [_as_int(p) for p in parts[1:]]
                if any(v is None for v in values) or len(values) < 5:
                    return None
                return values
        return None

    first, second = fields(before), fields(after)
    if first is None or second is None:
        return None
    width = min(len(first), len(second))
    delta = [second[i] - first[i] for i in range(width)]
    total = sum(delta)
    if total <= 0:
        return None
    idle = delta[3] + delta[4]
    return (total - idle) / float(total)


def read_thermal_zones(root="/"):
    """Every thermal zone the platform exposes, as degrees C. [] where there are none."""
    base = os.path.join(root, "sys/class/thermal")
    zones = []
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return zones
    for name in names:
        if not name.startswith("thermal_zone"):
            continue
        raw = _as_int(_read(root, "sys/class/thermal/%s/temp" % name))
        zones.append({
            "zone": name,
            "type": _read(root, "sys/class/thermal/%s/type" % name),
            "temp_c": None if raw is None else raw / 1000.0,
        })
    return zones


def hottest_zone(zones):
    """The zone a per-run `temp_c` column should carry, or None.

    The package sensor when the platform has one, because that is the one that tracks
    what the measured core is doing; otherwise the hottest reading, which at least
    cannot understate. Deterministic either way -- picking "the first zone" would make
    the column depend on sysfs enumeration order.
    """
    usable = [z for z in zones if z.get("temp_c") is not None]
    if not usable:
        return None
    for zone in usable:
        if zone.get("type") == "x86_pkg_temp":
            return zone
    return max(usable, key=lambda z: (z["temp_c"], z["zone"]))


def probe_cpu(cpu, root="/"):
    """The pinned CPU's frequency policy and topology, as found.

    `cpu is None` means --no-pin, and then there is no policy to report: reporting cpu0's
    governor for an unpinned run would be an assertion about a CPU the work may never
    have touched, in a file whose whole contract is that everything in it was observed.
    """
    if cpu is None:
        return {"pinned_cpu": None, "model_name": None, "governor": None,
                "scaling_driver": None, "scaling_min_khz": None,
                "scaling_max_khz": None, "cur_freq_khz": None,
                "thread_siblings_list": None, "hyperthread_siblings": [],
                "smt_active": _read(root, "sys/devices/system/cpu/smt/active"),
                "intel_pstate_no_turbo":
                    _read(root, "sys/devices/system/cpu/intel_pstate/no_turbo")}
    prefix = "sys/devices/system/cpu/cpu%d" % cpu
    siblings_text = _read(root, prefix + "/topology/thread_siblings_list")
    siblings = [c for c in parse_cpu_list(siblings_text) if c != cpu]
    model = None
    cpuinfo = _read(root, "proc/cpuinfo")
    for line in (cpuinfo or "").splitlines():
        if line.lower().startswith("model name"):
            model = line.split(":", 1)[1].strip()
            break
    return {
        "pinned_cpu": cpu,
        "model_name": model,
        "governor": _read(root, prefix + "/cpufreq/scaling_governor"),
        "scaling_driver": _read(root, prefix + "/cpufreq/scaling_driver"),
        "scaling_min_khz": _as_int(_read(root, prefix + "/cpufreq/scaling_min_freq")),
        "scaling_max_khz": _as_int(_read(root, prefix + "/cpufreq/scaling_max_freq")),
        "cur_freq_khz": _as_int(_read(root, prefix + "/cpufreq/scaling_cur_freq")),
        "thread_siblings_list": siblings_text,
        "hyperthread_siblings": siblings,
        "smt_active": _read(root, "sys/devices/system/cpu/smt/active"),
        "intel_pstate_no_turbo": _read(root, "sys/devices/system/cpu/intel_pstate/no_turbo"),
    }


def sha256_of(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def git(*args, root=None):
    """git's stdout, or "" when it fails. Provenance capture never aborts a campaign.

    Trailing newlines go; leading whitespace stays. `git status --porcelain` puts the
    index status in column 1 and leaves it blank for a working-tree-only change, so
    `.strip()` here silently deletes the first line's first character -- see
    PORCELAIN_LINE.
    """
    proc = subprocess.run(["git"] + list(args), cwd=root or ROOT,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.stdout.rstrip("\n")


def git_bytes(*args, root=None):
    """git's stdout as bytes, or None when the command failed.

    Separate from `git` because a blob's bytes must not be decoded, re-encoded or
    newline-translated before being hashed: the whole point of hashing them is that the
    result matches what the repository stores.
    """
    proc = subprocess.run(["git"] + list(args), cwd=root or ROOT,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.stdout if proc.returncode == 0 else None


def freeze_state(head_blob, working_blob):
    """(in_head, modified) from two git object ids. Pure, so it can be tested exactly.

    **Why blob ids and not `git status`.** `git status --porcelain -- tuning.json` asks
    the index whether it is willing to report a difference, and the index can be told
    not to: `git update-index --assume-unchanged`, `--skip-worktree`, or a
    `.gitattributes` clean filter all make an edited file report clean. The freeze check
    would then pass for a tuning.json edited after its commit -- which is exactly
    "the winner was chosen after the numbers", the one thing the two-phase split exists
    to rule out -- and the sha256 stamped beside it would be of the altered file.
    `assume-unchanged` on a generated results file is a common habit, so this is not
    only an adversarial case.

    Comparing the committed blob id against `git hash-object` of the working file is a
    content comparison that no index setting can fake.
    """
    if not head_blob:
        return False, True
    return True, working_blob != head_blob


def tuning_freeze_record(directory, root=None):
    """What the history says about tuning.json: is it committed, and is it unchanged.

    Records both object ids and both hashes. `sha256_committed` is the hash of the
    bytes that were actually frozen -- read out of the commit, not off the disk -- so a
    reader with the repository can reproduce it with
    `git show <freeze_commit>:<path> | sha256sum` and check the published record
    against the history rather than against the working tree it was written from.
    """
    path = os.path.join(directory, TUNING_FILENAME)
    relative = os.path.relpath(os.path.abspath(path), root or ROOT)
    head_blob = git("rev-parse", "--verify", "--quiet", "HEAD:%s" % relative,
                    root=root) or None
    working_blob = git("hash-object", "--", path, root=root) or None
    in_head, modified = freeze_state(head_blob, working_blob)
    committed = git_bytes("show", "HEAD:%s" % relative, root=root) if in_head else None
    return {
        "path": relative,
        "sha256": sha256_of(path),
        "sha256_committed": (None if committed is None
                             else hashlib.sha256(committed).hexdigest()),
        "head_blob": head_blob,
        "working_blob": working_blob,
        "in_head": in_head,
        "modified_in_worktree": modified,
        "freeze_commit": git("log", "-1", "--format=%H", "--", relative, root=root)
                         or None,
        "freeze_commit_utc": git("log", "-1", "--format=%cI", "--", relative,
                                 root=root) or None,
    }


def freeze_note(freeze):
    """The runs.csv header line describing the freeze behind these numbers.

    A file produced with --allow-unfrozen must say so in the same place a reader looks
    for the freeze commit. Printing `frozen in commit None` there would read as a
    formatting glitch rather than as the missing guarantee it is.
    """
    if not freeze.get("in_head"):
        return ("kernel choice NOT FROZEN IN THE HISTORY: %s is not committed, so "
                "nothing here shows the choice predates these numbers "
                "(working tuning.json sha256 %s)"
                % (freeze.get("path"), freeze.get("sha256")))
    if freeze.get("modified_in_worktree"):
        return ("kernel choice frozen in commit %s (%s) but %s was edited afterwards, "
                "so the measured choice is not the committed one (tuning.json sha256 "
                "%s)" % (freeze.get("freeze_commit"), freeze.get("freeze_commit_utc"),
                         freeze.get("path"), freeze.get("sha256")))
    # The committed hash, not the working one. They are equal here -- that is what the
    # branch above checked -- but quoting the one read out of the commit is what makes
    # the line reproducible with `git show <commit>:<path> | sha256sum` by a reader who
    # has the repository and not the machine.
    return ("kernel choice frozen in commit %s (%s), tuning.json sha256 %s "
            "(git blob %s)"
            % (freeze.get("freeze_commit"), freeze.get("freeze_commit_utc"),
               freeze.get("sha256_committed"), freeze.get("head_blob")))


def dirty_note(allow_dirty, watched_dirty):
    """The runs.csv header line for a run measured against modified build inputs, or None.

    `--allow-unfrozen` at least reached runs.csv through freeze_note; `--allow-dirty`
    marked nothing at all, leaving the header's bare `commit: <sha>` line standing --
    which is word for word the sentence DirtyTree's own message calls a lie, that the
    commit stamped here does not describe the binary that was measured. stderr is not
    the artefact.
    """
    if not (allow_dirty and watched_dirty):
        return None
    return ("MEASURED AGAINST A MODIFIED TREE (--allow-dirty): the commit above does "
            "NOT describe the binary these numbers came from. Modified build input(s): "
            + ", ".join(watched_dirty))


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Hex characters of the campaign uid. Twelve is 48 bits: two campaigns colliding would
# have to be a deliberate act, and the uid namespaces `run_index` so that two campaigns'
# rows cannot pair across campaigns. Shorten it and that separation stops holding.
CAMPAIGN_UID_CHARS = 12


def make_campaign_uid(parts):
    """A short stable id for one campaign, derived from what makes it that campaign."""
    text = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:CAMPAIGN_UID_CHARS]


# --- driving the harness ---------------------------------------------------------------

def harness_command(binary, csv_path, size, cpu=None, trials=None, selects=(),
                    kat_json=None, extra=()):
    """The exact argv for one ctr_bench invocation, taskset prefix included."""
    cmd = []
    if cpu is not None:
        cmd += ["taskset", "-c", str(cpu)]
    cmd += [binary, "--csv", csv_path, "--size", str(size)]
    if trials is not None:
        cmd += ["--trials", str(trials)]
    if kat_json is not None:
        cmd += ["--kat-json", kat_json]
    cmd += list(selects) + list(extra)
    return cmd


def run_harness(cmd, quiet=True):
    proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise HarnessFailed(
            "%s exited %d\n%s%s"
            % (" ".join(cmd), proc.returncode, proc.stdout, proc.stderr))
    if not quiet and proc.stdout:
        sys.stdout.write(proc.stdout)
    return proc


def read_harness_csv(path):
    with open(path, encoding="utf-8") as fh:
        return [dict(row) for row in csv.DictReader(fh)
                if not (row.get("cipher") or "").startswith("#")]


def registered_backends(binary, cpu=None):
    """cipher -> {backend names available on this machine}, from the harness itself.

    Asked of the binary rather than reconstructed here, so that `check_tuning` compares
    the frozen choice against what will actually be measured.
    """
    cmd = ([] if cpu is None else ["taskset", "-c", str(cpu)]) \
        + [binary, "--list-backends"]
    proc = run_harness(cmd)
    available = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0].startswith("#"):
            continue
        cipher, impl, state = parts
        if state != "available":
            continue
        available.setdefault(cipher, set()).add(impl)
    return available


# --- writing the outputs ---------------------------------------------------------------

def _write_atomic(path, text):
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    os.replace(tmp, path)


def write_json(path, doc):
    _write_atomic(path, json.dumps(doc, indent=2, sort_keys=True) + "\n")


def provenance_marker(campaign, allow_dirty=False, allow_unfrozen=False):
    """The marker this run's data carries.

    `--campaign` decides it, and an open escape hatch takes it away. The second half is
    unreachable while `require_no_escape_hatch` runs first -- and it is here anyway,
    because these are two independent ways to reach the same wrong file and the cost of
    the second defence is one boolean. A caller that acquires a new path into this
    function does not also get to publish a waived campaign.
    """
    if campaign and not (allow_dirty or allow_unfrozen):
        return PROVENANCE_CAMPAIGN
    return PROVENANCE_SMOKE


def runs_csv_text(rows, campaign, notes=(), allow_dirty=False, allow_unfrozen=False):
    """runs.csv as text: the provenance marker first, then prose, then the data.

    The smoke-run prose is chosen from the marker rather than from `campaign`, so the two
    can never disagree: a file that says SMOKE-RUN always carries the paragraph saying
    what that means.
    """
    marker = provenance_marker(campaign, allow_dirty, allow_unfrozen)
    lines = ["# provenance: %s" % marker]
    if marker != PROVENANCE_CAMPAIGN:
        lines += ["# " + line for line in SMOKE_HEADER]
    lines.append("#")
    for note in notes:
        lines.append("# " + note if note else "#")
    lines.append("#")
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(RUNS_COLUMNS)
    for row in rows:
        writer.writerow(["" if row.get(c) is None else row.get(c)
                         for c in RUNS_COLUMNS])
    return "\n".join(lines) + "\n" + buf.getvalue()


def write_runs_csv(path, rows, campaign, notes=(), allow_dirty=False,
                   allow_unfrozen=False):
    refuse_downgrade(path, campaign)
    _write_atomic(path, runs_csv_text(rows, campaign, notes, allow_dirty, allow_unfrozen))
    return path


# --- phase 1: tuning --------------------------------------------------------------------

def rank_candidates(samples):
    """[{impl, median, min, max, runs, samples}], best median first.

    `samples` maps backend name -> the per-run throughputs it was measured at. Ties
    break on the name so that two identical backends do not swap the freeze between
    tuning runs.
    """
    ranked = []
    for impl in sorted(samples):
        values = sorted(samples[impl])
        ranked.append({
            "impl": impl,
            "median_mbit_per_sec": statistics.median(values),
            "min_mbit_per_sec": values[0],
            "max_mbit_per_sec": values[-1],
            "runs": len(values),
            "samples_mbit_per_sec": values,
        })
    ranked.sort(key=lambda c: (-c["median_mbit_per_sec"], c["impl"]))
    return ranked


def winner_is_separated(ranked):
    """Whether the winner beat the runner-up on every tuning run it was measured on.

    Reported in tuning.json rather than used to abort. Five runs on a host with two
    performance states 2.15x apart cannot always tell two backends apart, and the
    freeze happens anyway -- so the file has to say when the choice it records was not
    actually decided by the evidence behind it. A single candidate is not "separated"
    from anything; it is unopposed, and saying `true` there would overstate it.
    Neither is a candidate measured once: one observation has no range, so "the ranges
    do not overlap" collapses to "one number was bigger", which on a host with two
    performance states is a coin toss dressed as evidence. Both cases return None --
    not judged -- rather than the reassuring answer.
    """
    if len(ranked) < 2:
        return None
    if any(candidate["runs"] < 2 for candidate in ranked[:2]):
        return None
    return ranked[0]["min_mbit_per_sec"] > ranked[1]["max_mbit_per_sec"]


def tuning_document(samples_by_cipher, meta):
    """tuning.json: the choice, and the evidence that produced it, in one file."""
    choice = {}
    evidence = {}
    for cipher in sorted(samples_by_cipher):
        ranked = rank_candidates(samples_by_cipher[cipher])
        if not ranked:
            continue
        choice[cipher] = ranked[0]["impl"]
        evidence[cipher] = {
            "winner": ranked[0]["impl"],
            "separated": winner_is_separated(ranked),
            "candidates": ranked,
        }
    doc = dict(meta)
    doc["choice"] = choice
    doc["evidence"] = evidence
    return doc


# --- the phases -------------------------------------------------------------------------

def _cipher_names():
    return [name for _path, name, _rounds in cipher_set.resolve()]


def _sample_environment(cpu, root="/"):
    return {
        "cpu": probe_cpu(cpu, root=root),
        "thermal_zones": read_thermal_zones(root=root),
        "loadavg": _read(root, "proc/loadavg"),
    }


def _toolchain(binary, build):
    dry = subprocess.run(["make", "--always-make", "--dry-run", binary],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    lines = [ln for ln in dry.stdout.splitlines() if ln.strip()]
    compile_command = next((ln for ln in reversed(lines) if "-o " + binary in ln), None)
    cc = os.environ.get("CC", "cc")
    version = subprocess.run([cc, "--version"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
    return {
        "cc": cc,
        "cc_version": version.stdout.strip().splitlines()[0] if version.stdout else None,
        "compile_command": compile_command,
        "make_dry_run": lines,
        "rebuilt_by_campaign": build,
        "python": sys.version.split()[0],
    }


def build_environment(args, phase, campaign, binary, out_dir, extra):
    """env.json's contents. Everything here is observed; nothing here is required."""
    dirty = dirty_paths_from_porcelain(git("status", "--porcelain"))
    watched_dirty = sorted(p for p in dirty if p.startswith(WATCHED_BUILD_INPUTS))
    doc = {
        "schema": 1,
        "target": args.target,
        "phase": phase,
        "provenance": provenance_marker(campaign, args.allow_dirty,
                                        args.allow_unfrozen),
        "generated_utc": utc_now(),
        "host": _read("/", "proc/sys/kernel/hostname"),
        "commit": {
            "sha": git("rev-parse", "HEAD") or None,
            "describe": git("describe", "--always", "--dirty") or None,
            "dirty": bool(dirty),
            "dirty_paths": sorted(dirty),
            "watched_build_inputs": list(WATCHED_BUILD_INPUTS),
            "watched_dirty": watched_dirty,
        },
        "toolchain": _toolchain(binary, not args.no_build),
        "kernel": {
            "uname": _read("/", "proc/version"),
            "cmdline": cmdline_flags(_read("/", "proc/cmdline")),
        },
        "binary": {
            "path": binary,
            "sha256": sha256_of(os.path.join(ROOT, binary)),
            "size_bytes": (os.path.getsize(os.path.join(ROOT, binary))
                           if os.path.exists(os.path.join(ROOT, binary)) else None),
        },
        "nproc": os.cpu_count(),
        "at_start": _sample_environment(args.cpu),
        "protocol": {
            "sizes_bytes": list(args.sizes),
            "published_size_bytes": summarize.PUBLISHED_SIZE_BYTES,
            "trials_per_run": args.trials,
            "order_seed": args.seed,
            "cipher_order_varied_between_runs": True,
            "min_publishable_runs": MIN_PUBLISHABLE_RUNS,
            "comparison_rule":
                "Paired within one process only. This host has two discrete "
                "performance states about 2.15x apart and which one a process lands in "
                "is not controllable, so an absolute figure from this file compared "
                "against an absolute figure from any other file can show a factor of "
                "two that does not exist. Every published comparison is a per-run "
                "ratio against a baseline measured in the same process.",
        },
        "out_dir": os.path.relpath(os.path.abspath(out_dir), ROOT),
    }
    doc.update(extra)
    return doc


def _measure_once(binary, args, size, selects, tmp_csv, run_index, seq, order):
    """One ctr_bench process: all of `order`'s ciphers, one working-set size."""
    started = utc_now()
    cmd = harness_command(binary, tmp_csv, size, cpu=args.cpu, trials=args.trials,
                          selects=selects)
    run_harness(cmd)
    zone = hottest_zone(read_thermal_zones())
    freq = probe_cpu(args.cpu)["cur_freq_khz"]
    position = {cipher: i for i, cipher in enumerate(order)}
    rows = []
    for row in read_harness_csv(tmp_csv):
        rows.append({
            "target": args.target,
            "campaign_uid": args.campaign_uid,
            "run_index": run_index,
            "run_seq": seq,
            "order_position": position.get(row["cipher"], ""),
            "size_bytes": row["size_bytes"],
            "cipher": row["cipher"],
            "impl": row["impl"],
            "rounds": row["rounds"],
            "block_bytes": row["block_bytes"],
            "mbit_per_sec": row["mbit_per_sec"],
            "ns_median": row["ns_median"],
            "ns_min": row["ns_min"],
            "prepare_ns": row["prepare_ns"],
            "tsc_per_byte": row["tsc_per_byte"],
            "temp_c": "NA" if zone is None else "%.1f" % zone["temp_c"],
            "freq_khz": "NA" if freq is None else freq,
            "started_utc": started,
        })
    return rows


def phase_tune(args, binary, out_dir):
    """Measure every backend TUNING_RUNS times and freeze a winner per cipher."""
    samples = {}
    tmp_csv = os.path.join(out_dir, ".tune.csv")
    kat_path = os.path.join(out_dir, KAT_FILENAME)
    print("tuning: %d runs over every registered backend at %d bytes"
          % (args.tuning_runs, summarize.PUBLISHED_SIZE_BYTES))
    for run in range(args.tuning_runs):
        cmd = harness_command(binary, tmp_csv, summarize.PUBLISHED_SIZE_BYTES,
                              cpu=args.cpu, trials=args.trials,
                              kat_json=kat_path if run == 0 else None)
        run_harness(cmd)
        if run == 0:
            with open(kat_path, encoding="utf-8") as fh:
                entries = json.load(fh)
            print("  correctness gate: %d backends, all passing"
                  % check_kat(entries))
        for row in read_harness_csv(tmp_csv):
            samples.setdefault(row["cipher"], {}).setdefault(row["impl"], []) \
                .append(float(row["mbit_per_sec"]))
        print("  run %d/%d" % (run + 1, args.tuning_runs))
    if os.path.exists(tmp_csv):
        os.remove(tmp_csv)

    doc = tuning_document(samples, {
        "schema": 1,
        "target": args.target,
        "generated_utc": utc_now(),
        "provenance": provenance_marker(args.campaign, args.allow_dirty,
                                        args.allow_unfrozen),
        "commit": git("rev-parse", "HEAD") or None,
        "binary_sha256": sha256_of(os.path.join(ROOT, binary)),
        "size_bytes": summarize.PUBLISHED_SIZE_BYTES,
        "runs": args.tuning_runs,
        "note": "The winner per cipher, and every candidate's median, spread and raw "
                "samples. `separated` says whether the winner beat the runner-up on "
                "every tuning run; false means the freeze records a choice this "
                "evidence did not actually decide.",
    })
    path = os.path.join(out_dir, TUNING_FILENAME)
    write_json(path, doc)
    print("\nwrote %s" % path)
    for cipher in sorted(doc["choice"]):
        separated = doc["evidence"][cipher]["separated"]
        note = {True: "", False: "*** not separated from the runner-up",
                None: "(separation not judged: one candidate, or one run each)"
                }[separated]
        print("  %-30s %-18s %s" % (cipher, doc["choice"][cipher], note))
    print("\nCommit this file on its own before measuring:\n"
          "  git add %s && git commit -m 'Freeze the %s kernel choice before measuring'"
          % (os.path.relpath(path, ROOT), args.target))
    return doc


def phase_measure(args, binary, out_dir):
    """Measure the frozen winners, `--runs` times, at every working-set size."""
    choice = load_tuning(out_dir)
    freeze = tuning_freeze_record(out_dir)
    if args.allow_unfrozen:
        print("WARNING: --allow-unfrozen: the freeze is not being checked against the "
              "history, so these numbers do not carry the guarantee that the kernel "
              "choice predates them.")
    else:
        require_frozen(freeze["path"], freeze["in_head"],
                       freeze["modified_in_worktree"])
    ciphers = _cipher_names()
    check_tuning_covers(choice, ciphers)
    check_tuning(choice, registered_backends(binary, cpu=args.cpu))

    orders = cipher_orders(ciphers, args.runs, args.seed)

    # The gate first, on exactly the backends about to be measured, and its verdict on
    # disk before any timing row exists.
    kat_path = os.path.join(out_dir, KAT_FILENAME)
    tmp_csv = os.path.join(out_dir, ".measure.csv")
    run_harness(harness_command(binary, tmp_csv, summarize.PUBLISHED_SIZE_BYTES,
                                cpu=args.cpu, trials=1,
                                selects=select_args(orders[0], choice),
                                kat_json=kat_path))
    with open(kat_path, encoding="utf-8") as fh:
        entries = json.load(fh)
    check_kat(entries, expected={(c, choice[c]) for c in ciphers})
    print("correctness gate: %d backends, all passing -> %s"
          % (len(entries), kat_path))

    rows = []
    for seq, order in enumerate(orders):
        run_index = make_run_index(args.campaign_uid, seq, args.runs)
        for size in args.sizes:
            rows += _measure_once(binary, args, size, select_args(order, choice),
                                  tmp_csv, run_index, seq, order)
        print("  run %d/%d (%s) %s" % (seq + 1, args.runs, run_index,
                                       " ".join(order)))
    if os.path.exists(tmp_csv):
        os.remove(tmp_csv)

    watched_dirty = sorted(p for p in dirty_paths_from_porcelain(
        git("status", "--porcelain")) if p.startswith(WATCHED_BUILD_INPUTS))
    notes = [
        "target: %s" % args.target,
        "produced_by: tools/campaign.py --measure (see %s for the machine it ran on)"
        % ENV_FILENAME,
        "commit: %s" % (git("rev-parse", "HEAD") or "unknown"),
        "binary sha256: %s" % sha256_of(os.path.join(ROOT, binary)),
        freeze_note(freeze),
        "",
    ]
    # Immediately under the commit line it qualifies, because a reader who takes the
    # commit at face value has already been misled by the time a footnote arrives.
    note = dirty_note(args.allow_dirty, watched_dirty)
    if note:
        notes[3:3] = [note, ""]
    notes += [
        "Comparisons from this file are paired within a run. Each run_index is one",
        "ctr_bench process that measured every cipher at one working-set size, and the",
        "ratios tools/summarize.py publishes are formed inside those processes. This",
        "host has two discrete performance states about 2.15x apart and which one a",
        "process lands in is luck, so an absolute number here divided by an absolute",
        "number from any other file is not a measurement of anything.",
        "",
        "run_index carries the campaign uid for that reason: two campaigns' rows",
        "concatenated keep distinct keys instead of pairing across campaigns.",
    ]
    runs_path = os.path.join(out_dir, RUNS_FILENAME)
    write_runs_csv(runs_path, rows, args.campaign, notes,
                   args.allow_dirty, args.allow_unfrozen)
    print("\nwrote %s (%d rows, %d runs, sizes %s)"
          % (runs_path, len(rows), args.runs,
             ", ".join(str(s) for s in args.sizes)))
    return runs_path


# --- CLI ----------------------------------------------------------------------------------

def _summarize(runs_path):
    """Form the summary from the raw runs, so no number reaches a table by hand."""
    try:
        summarize.main([runs_path])
    except (ValueError, OSError) as exc:
        print("summary NOT written: %s" % exc, file=sys.stderr)
        return False
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run a measurement campaign in two frozen phases, with provenance.")
    parser.add_argument("target", help="hardware target; names the results/v2/ directory")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--tune", action="store_true",
                      help="phase 1: measure every backend and freeze a winner per cipher")
    mode.add_argument("--measure", action="store_true",
                      help="phase 2: measure the frozen winners")
    parser.add_argument("--campaign", action="store_true",
                        help="this is the publication campaign: mark the output "
                             "CAMPAIGN and enforce the run-count floor")
    parser.add_argument("--runs", type=int, default=DEFAULT_MEASURE_RUNS,
                        help="whole-program runs in --measure (default: %(default)s)")
    parser.add_argument("--tuning-runs", type=int, default=TUNING_RUNS,
                        help="runs per backend in --tune (default: %(default)s)")
    parser.add_argument("--cpu", type=int, default=DEFAULT_CPU,
                        help="CPU to pin to with taskset (default: %(default)s)")
    parser.add_argument("--sizes", type=int, nargs="+", default=list(SIZES),
                        help="working-set sizes in bytes (default: %(default)s)")
    parser.add_argument("--trials", type=int, default=None,
                        help="ctr_bench --trials; its own default when unset")
    parser.add_argument("--seed", type=int, default=0,
                        help="seed for the per-run cipher order (default: %(default)s)")
    parser.add_argument("--out-dir", default=None,
                        help="where to write; default results/v2/<target>. For trials: "
                             "summarize.py takes the target from the directory's name, "
                             "so a summary written elsewhere is labelled after that "
                             "directory, not after this argument")
    parser.add_argument("--binary", default=DEFAULT_BINARY,
                        help="the harness (default: %(default)s)")
    parser.add_argument("--allow-dirty", action="store_true",
                        help="trials only: measure with modified build inputs, "
                             "recording in the file that it was done. Cannot be "
                             "combined with --campaign")
    parser.add_argument("--allow-unfrozen", action="store_true",
                        help="trials only: measure against an uncommitted tuning.json; "
                             "the result cannot support the freeze-before-measure "
                             "claim. Cannot be combined with --campaign")
    parser.add_argument("--no-build", action="store_true",
                        help="do not run make before measuring")
    parser.add_argument("--no-pin", action="store_true",
                        help="do not pin with taskset; the run records no CPU policy")
    args = parser.parse_args(argv)
    if args.no_pin:
        args.cpu = None

    # Everything that can reject the invocation happens before any directory is
    # created, so a mistyped command does not leave an empty results/v2/<target>
    # behind that looks like a campaign nobody can find the data for.
    if os.sep in args.target or args.target in (".", ".."):
        parser.error("target %r is not a plain name" % args.target)
    if summarize.PUBLISHED_SIZE_BYTES not in args.sizes:
        parser.error(
            "--sizes must include the published working-set size %d; without it the "
            "campaign measures nothing that may be published."
            % summarize.PUBLISHED_SIZE_BYTES)
    if any(size <= 0 for size in args.sizes):
        parser.error("--sizes must be positive byte counts, got %s" % (args.sizes,))
    # A repeated size would put two ctr_bench processes in one (run_index, size_bytes)
    # bucket, and summarize.paired_ratios keys on exactly that pair: the duplicate is not
    # a second sample, it is two different processes' numbers silently paired against
    # each other on this bimodal host. Collapse it rather than measure it.
    deduplicated = sorted(set(args.sizes))
    if len(deduplicated) != len(args.sizes):
        print("note: --sizes had repeated values; measuring %s once each"
              % ", ".join(str(s) for s in deduplicated), file=sys.stderr)
    args.sizes = deduplicated
    # argparse's type=int accepts 0 and negatives happily, and both reach the phases as a
    # loop that runs no times: --runs 0 wrote an empty runs.csv and --tuning-runs 0 froze
    # a choice from no evidence at all.
    if args.measure and args.runs < 1:
        parser.error("--runs must be at least 1, got %d" % args.runs)
    if args.tune and args.tuning_runs < 1:
        parser.error("--tuning-runs must be at least 1, got %d" % args.tuning_runs)

    out_dir = args.out_dir or os.path.join(ROOT, RESULTS_ROOT, args.target)
    phase = "tune" if args.tune else "measure"
    try:
        require_no_escape_hatch(args.campaign, args.allow_dirty, args.allow_unfrozen)
        require_no_downgrade(out_dir, args.campaign)
        if args.allow_dirty:
            dirty = dirty_paths_from_porcelain(git("status", "--porcelain"))
            watched = sorted(p for p in dirty if p.startswith(WATCHED_BUILD_INPUTS))
            if watched:
                print("WARNING: --allow-dirty with %d modified build input(s); the "
                      "commit recorded in %s does not describe the binary measured:\n  %s"
                      % (len(watched), ENV_FILENAME, "\n  ".join(watched)),
                      file=sys.stderr)
        else:
            require_clean(WATCHED_BUILD_INPUTS)

        # The floor is about the sample a *summary* is computed from, so it applies to
        # the measurement phase only. --tune's five runs pick a winner and publish
        # nothing; holding them to a bimodality detector's minimum would be a warning
        # on every tuning run for a rule that does not apply to it.
        if args.measure:
            for warning in require_run_count(args.runs, args.campaign):
                print("WARNING: %s" % warning, file=sys.stderr)

        os.makedirs(out_dir, exist_ok=True)
        if not args.no_build:
            subprocess.run(["make", args.binary], cwd=ROOT, check=True)
        if not os.path.exists(os.path.join(ROOT, args.binary)):
            raise CampaignError("%s does not exist; build it or pass --binary"
                                % args.binary)

        args.campaign_uid = make_campaign_uid([
            phase, args.target, utc_now(), args.seed,
            sha256_of(os.path.join(ROOT, args.binary)), git("rev-parse", "HEAD"),
        ])
        before = _read("/", "proc/stat")

        env_path = os.path.join(out_dir, ENV_FILENAME)
        extra = {"campaign_uid": args.campaign_uid}
        if args.measure:
            extra["tuning_freeze"] = tuning_freeze_record(out_dir)
        env = build_environment(args, phase, args.campaign,
                                args.binary, out_dir, extra)
        write_json(env_path, env)

        if args.tune:
            phase_tune(args, args.binary, out_dir)
            runs_path = None
        else:
            runs_path = phase_measure(args, args.binary, out_dir)

        # Rewritten with what the machine did *while* the campaign ran, which is the
        # only way "was the sibling idle?" gets an answer rather than an intention.
        siblings = env["at_start"]["cpu"]["hyperthread_siblings"]
        env["at_end"] = _sample_environment(args.cpu)
        env["observed_during_run"] = {
            "finished_utc": utc_now(),
            "pinned_cpu_busy_fraction":
                cpu_busy_fraction(before, _read("/", "proc/stat"), args.cpu),
            "hyperthread_sibling_busy_fraction": {
                str(s): cpu_busy_fraction(before, _read("/", "proc/stat"), s)
                for s in siblings},
        }
        write_json(env_path, env)
        print("wrote %s" % env_path)

        # "no number reaches a paper table by hand" is not satisfied by a summary that
        # was attempted: if the summary did not form, the campaign did not finish, and
        # exit 0 would tell a script otherwise.
        if runs_path and not _summarize(runs_path):
            return 1
    except CampaignError as exc:
        print("campaign: %s" % exc, file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print("campaign: %s failed (%d)" % (exc.cmd, exc.returncode), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
