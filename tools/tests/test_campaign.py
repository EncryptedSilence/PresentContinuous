"""The campaign driver's guards, with no hardware in the loop.

Every test here runs on fabricated inputs -- a string of `git status` output, a
temporary directory holding a JSON file, a fake `/sys` tree, a runs.csv built by hand
-- because the guards exist precisely for the case where the machine is not
cooperating, and a test that needed the machine to cooperate could not check them.

Expected values are derived rather than observed. Where a constant is a judgement
call, the test asserts the *reason* for it (that `MIN_PUBLISHABLE_RUNS` is exactly the
sample size below which `summarize.modality` returns no verdict) rather than the
number, so that moving the number in one file and not the other fails here.

The exception is the EndToEnd suite at the bottom, which drives campaign.main against a
stub harness inside a throwaway git repository. It is still hardware-independent -- the
stub does arithmetic, not cryptography -- but it exists for the one thing the pure
guards cannot cover: whether the driver actually *calls* them.
"""
import contextlib
import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import campaign, cipher_set, make_tables, summarize


# --- the brief's five guards ------------------------------------------------------

class TestGuards(unittest.TestCase):
    def test_measure_refuses_without_tuning(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(campaign.FrozenChoiceMissing):
                campaign.load_tuning(d)

    def test_measure_refuses_an_impl_that_no_longer_exists(self):
        tuning = {"present-80-r16": "ctr-bitslice-avx512"}
        with self.assertRaises(campaign.FrozenChoiceStale):
            campaign.check_tuning(tuning, available={"ctr-table", "ctr-bitslice-avx2"})

    def test_a_frozen_choice_that_still_exists_is_accepted(self):
        tuning = {"present-80-r16": "ctr-bitslice-avx2"}
        campaign.check_tuning(tuning, available={"ctr-table", "ctr-bitslice-avx2"})

    def test_dirty_tree_aborts(self):
        with self.assertRaises(campaign.DirtyTree):
            campaign.require_clean(["Makefile", "src/"], dirty=["Makefile"])

    def test_a_dirty_file_outside_the_watched_set_is_fine(self):
        campaign.require_clean(["Makefile", "src/"], dirty=["README.md"])


class TestExceptionsAreDistinguishable(unittest.TestCase):
    """Tasks 9 and 10 reuse these unchanged, so their relationships are contract."""

    def test_the_three_frozen_choice_failures_share_a_base_but_not_each_other(self):
        for cls in (campaign.FrozenChoiceMissing, campaign.FrozenChoiceStale,
                    campaign.FrozenChoiceUnfrozen):
            self.assertTrue(issubclass(cls, campaign.FrozenChoiceError))
            self.assertTrue(issubclass(cls, campaign.CampaignError))
        # A caller distinguishing "run --tune" from "re-run --tune" from "commit it"
        # needs these three to be siblings, not a chain.
        self.assertFalse(issubclass(campaign.FrozenChoiceStale,
                                    campaign.FrozenChoiceMissing))
        self.assertFalse(issubclass(campaign.FrozenChoiceMissing,
                                    campaign.FrozenChoiceStale))
        self.assertFalse(issubclass(campaign.FrozenChoiceUnfrozen,
                                    campaign.FrozenChoiceStale))

    def test_dirty_tree_is_not_a_frozen_choice_failure(self):
        self.assertFalse(issubclass(campaign.DirtyTree, campaign.FrozenChoiceError))
        self.assertTrue(issubclass(campaign.DirtyTree, campaign.CampaignError))


# --- require_clean, and what counts as a watched path -----------------------------

class TestRequireClean(unittest.TestCase):
    def test_a_file_inside_a_watched_directory_aborts(self):
        with self.assertRaises(campaign.DirtyTree):
            campaign.require_clean(["src/"], dirty=["src/present_ctr_avx2.c"])

    def test_a_file_nested_deeper_in_a_watched_directory_aborts(self):
        with self.assertRaises(campaign.DirtyTree):
            campaign.require_clean(["fw/"], dirty=["fw/m4/gen/cipher_set.h"])

    def test_a_sibling_directory_with_a_shared_prefix_is_not_watched(self):
        """`src/` must not match `src-notes/`. The trailing slash is what does it."""
        campaign.require_clean(["src/"], dirty=["src-notes/todo.md"])

    def test_the_message_names_the_offending_path_and_not_the_innocent_one(self):
        with self.assertRaises(campaign.DirtyTree) as caught:
            campaign.require_clean(["bench/"],
                                   dirty=["bench/ctr_bench.c", "paper/main.tex"])
        self.assertIn("bench/ctr_bench.c", str(caught.exception))
        self.assertNotIn("paper/main.tex", str(caught.exception))

    def test_an_empty_watch_list_watches_nothing(self):
        campaign.require_clean([], dirty=["Makefile", "src/present.c"])

    def test_a_clean_tree_returns_the_paths_it_was_given(self):
        self.assertEqual(campaign.require_clean(["src/"], dirty=["docs/x.md"]),
                         ["docs/x.md"])

    def test_the_watched_set_is_the_five_build_inputs(self):
        """Named in the brief; the same allowlist tools/run_m4_bench.py follows."""
        self.assertEqual(set(campaign.WATCHED_BUILD_INPUTS),
                         {"Makefile", "bench/", "src/", "include/", "fw/"})
        for entry in campaign.WATCHED_BUILD_INPUTS:
            if entry != "Makefile":
                self.assertTrue(entry.endswith("/"),
                                "%r must end in / or it matches by bare prefix" % entry)


class TestDirtyPathParsing(unittest.TestCase):
    """`git status --porcelain` is the only place this module touches the machine, so
    its output is parsed here from strings rather than produced by a real repository."""

    def test_status_codes_are_stripped_from_every_form(self):
        text = " M src/present.c\n?? bench/new.c\nA  include/x.h\n"
        self.assertEqual(campaign.dirty_paths_from_porcelain(text),
                         ["src/present.c", "bench/new.c", "include/x.h"])

    def test_both_halves_of_a_rename_are_reported(self):
        """Moving a file out of a watched directory changes the build too. Keeping
        only the destination would report `notes/present.c`, which no watched prefix
        matches, and the campaign would call a tree with a source file missing clean."""
        text = 'R  src/present.c -> notes/present.c\n'
        self.assertEqual(campaign.dirty_paths_from_porcelain(text),
                         ["src/present.c", "notes/present.c"])
        with self.assertRaises(campaign.DirtyTree):
            campaign.require_clean(["src/"],
                                   dirty=campaign.dirty_paths_from_porcelain(text))

    def test_quoted_paths_are_unquoted(self):
        text = ' M "src/odd name.c"\n'
        self.assertEqual(campaign.dirty_paths_from_porcelain(text),
                         ["src/odd name.c"])

    def test_blank_lines_produce_no_paths(self):
        self.assertEqual(campaign.dirty_paths_from_porcelain("\n\n"), [])

    def test_a_leading_space_eaten_by_a_stripping_caller_still_parses(self):
        """The bug this parser was rewritten for. A working-tree-only change leads
        with a blank index column, so `git status --porcelain` output beginning with
        " M bench/ctr_bench.c" becomes "M bench/ctr_bench.c" the moment anything calls
        .strip() on the command's stdout -- and a fixed `line[3:]` then yields
        "ench/ctr_bench.c", which matches no watched prefix. The tree is dirty and the
        campaign calls it clean, which is the one thing require_clean exists to stop."""
        self.assertEqual(
            campaign.dirty_paths_from_porcelain("M bench/ctr_bench.c\n"),
            ["bench/ctr_bench.c"])
        with self.assertRaises(campaign.DirtyTree):
            campaign.require_clean(
                campaign.WATCHED_BUILD_INPUTS,
                dirty=campaign.dirty_paths_from_porcelain("M bench/ctr_bench.c\n"))

    def test_a_path_beginning_with_a_status_letter_is_not_eaten(self):
        self.assertEqual(campaign.dirty_paths_from_porcelain(" M Makefile\n"),
                         ["Makefile"])
        self.assertEqual(campaign.dirty_paths_from_porcelain("?? src/M.c\n"),
                         ["src/M.c"])

    def test_the_real_git_output_is_not_stripped_of_its_leading_column(self):
        """`git()` is the only thing here that runs a command, and the whole parser
        above depends on it not eating column 1. Checked against this repository,
        which always has at least the campaign's own working state in it, and skipped
        rather than asserted when the tree happens to be clean."""
        text = campaign.git("status", "--porcelain")
        if not text.strip():
            self.skipTest("working tree is clean; nothing to parse")
        # Porcelain v1 is `XY<space>PATH`, so column index 2 is a space on every line.
        # A caller that stripped the output shifts the first line left and breaks that.
        for line in text.splitlines():
            self.assertEqual(line[2], " ",
                             "%r is not porcelain v1; column 1 was eaten" % line)


# --- the frozen choice ------------------------------------------------------------

class TestCheckTuning(unittest.TestCase):
    def test_a_mapping_checks_availability_per_cipher(self):
        """ctr-bitslice-avx2 exists, but not for aes-r5. A flat set of every backend
        name in the build cannot see that, and the campaign would fail inside the
        harness partway through instead of at the guard."""
        available = {"present-80-r16": {"ctr-bitslice-avx2", "ctr-table"},
                     "aes-r5": {"ctr-table-x8", "ctr-ref"}}
        campaign.check_tuning({"present-80-r16": "ctr-bitslice-avx2"}, available)
        with self.assertRaises(campaign.FrozenChoiceStale):
            campaign.check_tuning({"aes-r5": "ctr-bitslice-avx2"}, available)

    def test_a_cipher_absent_from_the_registry_is_stale(self):
        with self.assertRaises(campaign.FrozenChoiceStale) as caught:
            campaign.check_tuning({"cipher-Z": "ctr-ref"},
                                  {"present-80-r16": {"ctr-ref"}})
        self.assertIn("cipher-Z", str(caught.exception))

    def test_every_stale_entry_is_reported_not_just_the_first(self):
        with self.assertRaises(campaign.FrozenChoiceStale) as caught:
            campaign.check_tuning({"a": "gone-1", "b": "gone-2", "c": "here"},
                                  available={"here"})
        message = str(caught.exception)
        self.assertIn("gone-1", message)
        self.assertIn("gone-2", message)
        self.assertIn("2 backend(s)", message)

    def test_an_empty_available_set_is_stale_rather_than_vacuously_fine(self):
        with self.assertRaises(campaign.FrozenChoiceStale):
            campaign.check_tuning({"present-80-r16": "ctr-ref"}, available=set())

    def test_an_empty_choice_checks_vacuously(self):
        """Nothing frozen is not a *stale* choice; check_tuning_covers is what
        catches it, and conflating the two would give the wrong fix."""
        campaign.check_tuning({}, available=set())


class TestTuningCoverage(unittest.TestCase):
    CIPHERS = [name for _p, name, _r in cipher_set.resolve()]

    def test_the_seven_ciphers_are_covered_by_a_full_choice(self):
        campaign.check_tuning_covers({c: "ctr-ref" for c in self.CIPHERS},
                                     self.CIPHERS)

    def test_a_missing_cipher_is_named(self):
        choice = {c: "ctr-ref" for c in self.CIPHERS}
        dropped = self.CIPHERS[2]
        del choice[dropped]
        with self.assertRaises(campaign.FrozenChoiceMissing) as caught:
            campaign.check_tuning_covers(choice, self.CIPHERS)
        self.assertIn(dropped, str(caught.exception))

    def test_a_cipher_the_set_no_longer_resolves_is_stale(self):
        choice = {c: "ctr-ref" for c in self.CIPHERS}
        choice["present-80-retired"] = "ctr-ref"
        with self.assertRaises(campaign.FrozenChoiceStale) as caught:
            campaign.check_tuning_covers(choice, self.CIPHERS)
        self.assertIn("present-80-retired", str(caught.exception))


class TestLoadTuning(unittest.TestCase):
    def _write(self, directory, doc):
        path = os.path.join(directory, campaign.TUNING_FILENAME)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return path

    def test_the_choice_is_returned_exactly_as_written(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, {"choice": {"present-80-r16": "ctr-bitslice-avx2",
                                       "cipher-D": "ctr-bitslice-u64"},
                            "evidence": {}})
            self.assertEqual(campaign.load_tuning(d),
                             {"present-80-r16": "ctr-bitslice-avx2",
                              "cipher-D": "ctr-bitslice-u64"})

    def test_a_document_with_no_choice_freezes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, {"evidence": {}})
            with self.assertRaises(campaign.FrozenChoiceMissing):
                campaign.load_tuning(d)

    def test_an_empty_choice_freezes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, {"choice": {}})
            with self.assertRaises(campaign.FrozenChoiceMissing):
                campaign.load_tuning(d)

    def test_a_choice_naming_no_backend_for_a_cipher_is_missing(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, {"choice": {"present-80-r16": ""}})
            with self.assertRaises(campaign.FrozenChoiceMissing) as caught:
                campaign.load_tuning(d)
            self.assertIn("present-80-r16", str(caught.exception))

    def test_unreadable_json_is_not_silently_an_empty_choice(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, campaign.TUNING_FILENAME), "w") as fh:
                fh.write("{not json")
            with self.assertRaises(campaign.FrozenChoiceMissing):
                campaign.load_tuning(d)

    def test_a_json_list_is_not_a_frozen_choice(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, ["present-80-r16"])
            with self.assertRaises(campaign.FrozenChoiceMissing):
                campaign.load_tuning(d)


class TestFreezeCheck(unittest.TestCase):
    """The freeze is only worth something if it is in the history before the run."""

    def test_an_uncommitted_tuning_file_is_refused(self):
        with self.assertRaises(campaign.FrozenChoiceUnfrozen) as caught:
            campaign.require_frozen("results/v2/x86/tuning.json",
                                    in_head=False, modified=True)
        self.assertIn("not committed", str(caught.exception))

    def test_a_committed_but_edited_tuning_file_is_refused(self):
        """The choice about to be measured is then not the choice the history
        records, so the freeze commit proves nothing about these numbers."""
        with self.assertRaises(campaign.FrozenChoiceUnfrozen) as caught:
            campaign.require_frozen("results/v2/x86/tuning.json",
                                    in_head=True, modified=True)
        self.assertIn("differs from the committed copy", str(caught.exception))

    def test_a_committed_unmodified_tuning_file_is_accepted(self):
        self.assertTrue(campaign.require_frozen("results/v2/x86/tuning.json",
                                                in_head=True, modified=False))


class TestFreezeNote(unittest.TestCase):
    """What runs.csv's header says about the freeze, in each of the three states."""

    FROZEN = {"path": "results/v2/x86/tuning.json", "sha256": "abc",
              "sha256_committed": "abc", "head_blob": "b10b", "working_blob": "b10b",
              "in_head": True, "modified_in_worktree": False,
              "freeze_commit": "c0ffee", "freeze_commit_utc": "2026-01-01T00:00:00Z"}

    def test_a_real_freeze_names_the_commit_the_hash_and_the_blob(self):
        note = campaign.freeze_note(self.FROZEN)
        self.assertIn("c0ffee", note)
        self.assertIn("abc", note)
        self.assertIn("b10b", note)
        self.assertNotIn("NOT FROZEN", note)

    def test_the_hash_quoted_is_the_committed_one_not_the_working_one(self):
        """So a reader with the repository and not the machine can reproduce the line
        with `git show <commit>:<path> | sha256sum`. The two are equal on this branch;
        quoting the working copy's would make the line unreproducible the moment they
        ever were not."""
        note = campaign.freeze_note(
            dict(self.FROZEN, sha256="from-the-disk", sha256_committed="from-the-commit"))
        self.assertIn("from-the-commit", note)
        self.assertNotIn("from-the-disk", note)

    def test_an_uncommitted_freeze_says_so_where_the_commit_would_go(self):
        """`--allow-unfrozen` must not produce a header reading `frozen in commit
        None`, which reads as a formatting glitch rather than a missing guarantee."""
        unfrozen = dict(self.FROZEN, in_head=False, freeze_commit=None,
                        freeze_commit_utc=None)
        note = campaign.freeze_note(unfrozen)
        self.assertIn("NOT FROZEN IN THE HISTORY", note)
        self.assertNotIn("None", note)

    def test_an_edited_freeze_says_the_measured_choice_is_not_the_committed_one(self):
        note = campaign.freeze_note(dict(self.FROZEN, modified_in_worktree=True))
        self.assertIn("edited afterwards", note)


class TestFreezeStateFromBlobs(unittest.TestCase):
    """The freeze is a content comparison, because `git status` is not one.

    `git update-index --assume-unchanged`, `--skip-worktree` and a .gitattributes clean
    filter each make an edited file report clean, and the previous check asked git
    status. Comparing the committed blob id against `git hash-object` of the working
    file is what no index setting can fake.
    """

    def test_no_committed_blob_means_unfrozen(self):
        self.assertEqual(campaign.freeze_state(None, "b10b"), (False, True))
        self.assertEqual(campaign.freeze_state("", "b10b"), (False, True))

    def test_equal_blobs_mean_frozen_and_unmodified(self):
        self.assertEqual(campaign.freeze_state("b10b", "b10b"), (True, False))

    def test_different_blobs_mean_frozen_but_edited(self):
        self.assertEqual(campaign.freeze_state("b10b", "other"), (True, True))

    def test_a_working_file_git_cannot_hash_counts_as_edited(self):
        """`git hash-object` returning nothing means the file is gone or unreadable;
        that is not evidence it matches the commit."""
        self.assertEqual(campaign.freeze_state("b10b", None), (True, True))


class TestDirtyNote(unittest.TestCase):
    """--allow-dirty used to mark nothing, leaving runs.csv's bare `commit: <sha>`
    line standing -- the exact sentence DirtyTree's own message calls a lie."""

    def test_a_dirty_allowed_run_says_so_and_names_the_files(self):
        note = campaign.dirty_note(True, ["bench/ctr_bench.c", "src/aes.c"])
        self.assertIn("MEASURED AGAINST A MODIFIED TREE", note)
        self.assertIn("bench/ctr_bench.c", note)
        self.assertIn("src/aes.c", note)

    def test_a_clean_run_gets_no_note_at_all(self):
        self.assertIsNone(campaign.dirty_note(True, []))
        self.assertIsNone(campaign.dirty_note(False, []))

    def test_the_flag_alone_is_not_the_condition(self):
        """--allow-dirty on a tree that turned out clean has nothing to disclose, and a
        caveat that appears when nothing is wrong teaches readers to skip it."""
        self.assertIsNone(campaign.dirty_note(True, []))
        self.assertIsNotNone(campaign.dirty_note(True, ["Makefile"]))
        self.assertIsNone(campaign.dirty_note(False, ["Makefile"]))


# --- the run-count floor ----------------------------------------------------------

class TestRunCountFloor(unittest.TestCase):
    def test_the_floor_is_the_sample_size_summarize_will_judge(self):
        """Derived, not restated. `MIN_PUBLISHABLE_RUNS` has to be exactly the sample
        size at which summarize.modality starts returning a verdict -- one below and
        every published row reads `not-judged`."""
        self.assertIs(campaign.MIN_PUBLISHABLE_RUNS, summarize.MODALITY_MIN_N)
        below = [100.0 + i for i in range(campaign.MIN_PUBLISHABLE_RUNS - 1)]
        at = [100.0 + i for i in range(campaign.MIN_PUBLISHABLE_RUNS)]
        self.assertFalse(summarize.modality(below)["judged"])
        self.assertTrue(summarize.modality(at)["judged"])

    def test_a_campaign_below_the_floor_is_refused(self):
        with self.assertRaises(campaign.RunCountTooLow):
            campaign.require_run_count(campaign.MIN_PUBLISHABLE_RUNS - 1,
                                       campaign=True)

    def test_a_campaign_at_the_floor_is_allowed_with_a_warning(self):
        warnings = campaign.require_run_count(campaign.MIN_PUBLISHABLE_RUNS,
                                              campaign=True)
        self.assertEqual(len(warnings), 1)
        self.assertIn("outside the protocol", warnings[0])

    def test_a_trial_below_the_floor_warns_twice_and_does_not_raise(self):
        warnings = campaign.require_run_count(3, campaign=False)
        self.assertEqual(len(warnings), 2)
        self.assertTrue(any("not-judged" in w for w in warnings))
        self.assertTrue(any("outside the protocol" in w for w in warnings))

    def test_the_default_run_count_is_inside_the_protocol_band_and_needs_no_warning(self):
        self.assertLessEqual(campaign.PROTOCOL_RUNS_MIN, campaign.DEFAULT_MEASURE_RUNS)
        self.assertLessEqual(campaign.DEFAULT_MEASURE_RUNS, campaign.PROTOCOL_RUNS_MAX)
        self.assertEqual(
            campaign.require_run_count(campaign.DEFAULT_MEASURE_RUNS, campaign=True),
            [])

    def test_above_the_protocol_band_also_warns(self):
        warnings = campaign.require_run_count(campaign.PROTOCOL_RUNS_MAX + 1,
                                              campaign=True)
        self.assertEqual(len(warnings), 1)
        self.assertIn("outside the protocol", warnings[0])

    def test_zero_runs_is_a_programming_error_not_a_campaign(self):
        with self.assertRaises(ValueError):
            campaign.require_run_count(0, campaign=False)


# --- the correctness-gate verdict -------------------------------------------------

def kat_entry(cipher, impl, passed=True, check="matches-ctr-ref", offset=None):
    return {"cipher": cipher, "impl": impl, "pass": passed, "check": check,
            "offset": offset}


class TestKatVerdict(unittest.TestCase):
    def test_all_passing_returns_the_count(self):
        entries = [kat_entry("a", "ctr-ref"), kat_entry("b", "ctr-table")]
        self.assertEqual(campaign.check_kat(entries), 2)

    def test_an_empty_verdict_list_is_a_failure_not_a_vacuous_pass(self):
        """`all([])` is True, and a gate that checked nothing is exactly where that
        reading is most wrong: no timing number from such a run is authorised."""
        with self.assertRaises(campaign.KatFailed):
            campaign.check_kat([])

    def test_a_failing_entry_names_the_backend_and_the_offset(self):
        entries = [kat_entry("a", "ctr-ref"),
                   kat_entry("b", "ctr-table", passed=False, offset=1024)]
        with self.assertRaises(campaign.KatFailed) as caught:
            campaign.check_kat(entries)
        message = str(caught.exception)
        self.assertIn("ctr-table", message)
        self.assertIn("1024", message)
        self.assertIn("1 of 2", message)

    def test_a_backend_with_no_verdict_is_refused(self):
        """A gate verdict that does not cover a backend authorises a number it never
        checked, which is indistinguishable in the output from one it did."""
        entries = [kat_entry("a", "ctr-ref")]
        with self.assertRaises(campaign.KatFailed) as caught:
            campaign.check_kat(entries, expected={("a", "ctr-ref"), ("b", "ctr-table")})
        self.assertIn("b/ctr-table", str(caught.exception))

    def test_extra_verdicts_beyond_the_expected_set_are_fine(self):
        entries = [kat_entry("a", "ctr-ref"), kat_entry("b", "ctr-table")]
        self.assertEqual(campaign.check_kat(entries, expected={("a", "ctr-ref")}), 2)

    def test_a_missing_pass_field_counts_as_a_failure(self):
        with self.assertRaises(campaign.KatFailed):
            campaign.check_kat([{"cipher": "a", "impl": "ctr-ref"}])


# --- the provenance marker --------------------------------------------------------

def fabricated_rows(runs, ciphers, sizes, uid="deadbeefcafe", rate=None):
    """runs.csv rows with no measurement in them.

    `rate(cipher, size, seq)` decides each number, so a test can force the answer it
    expects instead of asserting whatever a machine produced.
    """
    rate = rate or (lambda cipher, size, seq: 1000.0)
    rows = []
    for seq in range(runs):
        run_index = campaign.make_run_index(uid, seq, runs)
        for size in sizes:
            for position, cipher in enumerate(ciphers):
                rows.append({
                    "target": "x86", "campaign_uid": uid, "run_index": run_index,
                    "run_seq": seq, "order_position": position, "size_bytes": size,
                    "cipher": cipher, "impl": "ctr-ref", "rounds": 16,
                    "block_bytes": 8, "mbit_per_sec": rate(cipher, size, seq),
                    "ns_median": 1.0, "ns_min": 1.0, "prepare_ns": 1.0,
                    "tsc_per_byte": "NA", "temp_c": "NA", "freq_khz": "NA",
                    "started_utc": "2026-01-01T00:00:00Z",
                })
    return rows


class TestProvenanceMarker(unittest.TestCase):
    def test_the_campaign_marker_is_the_exact_first_line(self):
        text = campaign.runs_csv_text(fabricated_rows(1, ["a"], [65536]),
                                      campaign=True)
        self.assertEqual(text.splitlines()[0], "# provenance: CAMPAIGN")

    def test_the_smoke_marker_is_the_exact_first_line(self):
        text = campaign.runs_csv_text(fabricated_rows(1, ["a"], [65536]),
                                      campaign=False)
        self.assertEqual(text.splitlines()[0], "# provenance: SMOKE-RUN")

    def test_a_trial_says_so_in_prose_as_well_as_in_the_marker(self):
        text = campaign.runs_csv_text(fabricated_rows(1, ["a"], [65536]),
                                      campaign=False)
        self.assertIn("NOT A MEASUREMENT RESULT", text)
        campaign_text = campaign.runs_csv_text(fabricated_rows(1, ["a"], [65536]),
                                               campaign=True)
        self.assertNotIn("NOT A MEASUREMENT RESULT", campaign_text)

    def test_summarize_reads_back_the_marker_this_module_writes(self):
        """The consumer's parser, not a second copy of the grammar here."""
        for flag, expected in ((True, "CAMPAIGN"), (False, "SMOKE-RUN")):
            text = campaign.runs_csv_text(fabricated_rows(1, ["a"], [65536]),
                                          campaign=flag)
            comments = [ln for ln in text.splitlines() if ln.startswith("#")]
            self.assertEqual(summarize.provenance_of(comments), expected)

    def test_only_the_campaign_marker_survives_require_campaign(self):
        self.assertTrue(summarize.is_publishable_provenance(
            campaign.provenance_marker(True), require_campaign=True))
        self.assertFalse(summarize.is_publishable_provenance(
            campaign.provenance_marker(False), require_campaign=True))

    def test_the_marker_comes_from_the_flag_and_from_nothing_else(self):
        """A campaign's file and a trial's file differ in the first line and in the
        prose that explains it -- never in a number, and never in an edit made
        afterwards."""
        rows = fabricated_rows(2, ["a", "b"], [65536])
        as_campaign = campaign.runs_csv_text(rows, campaign=True).splitlines()
        as_trial = campaign.runs_csv_text(rows, campaign=False).splitlines()
        data_of = lambda lines: [ln for ln in lines if not ln.startswith("#")]
        self.assertEqual(data_of(as_campaign), data_of(as_trial))
        self.assertNotEqual(as_campaign[0], as_trial[0])

    def test_an_open_escape_hatch_takes_the_campaign_marker_away(self):
        """The second of two independent defences: `require_no_escape_hatch` refuses
        the combination at the CLI, and this makes any other route into the writer
        produce SMOKE-RUN anyway. A campaign measured against an unfrozen choice or a
        modified tree is not a campaign whatever the flag says."""
        for dirty, unfrozen in ((True, False), (False, True), (True, True)):
            with self.subTest(allow_dirty=dirty, allow_unfrozen=unfrozen):
                self.assertEqual(campaign.provenance_marker(True, dirty, unfrozen),
                                 campaign.PROVENANCE_SMOKE)
        self.assertEqual(campaign.provenance_marker(True, False, False),
                         campaign.PROVENANCE_CAMPAIGN)

    def test_the_smoke_prose_follows_the_marker_not_the_flag(self):
        """A file that says SMOKE-RUN always carries the paragraph saying what that
        means, including when the marker was taken away rather than not asked for."""
        text = campaign.runs_csv_text(fabricated_rows(1, ["a"], [65536]),
                                      campaign=True, allow_unfrozen=True)
        self.assertEqual(text.splitlines()[0], "# provenance: SMOKE-RUN")
        self.assertIn("NOT A MEASUREMENT RESULT", text)


class TestEscapeHatchRefusal(unittest.TestCase):
    def test_a_campaign_with_a_hatch_open_is_refused(self):
        for dirty, unfrozen in ((True, False), (False, True), (True, True)):
            with self.subTest(allow_dirty=dirty, allow_unfrozen=unfrozen):
                with self.assertRaises(campaign.EscapeHatchInCampaign):
                    campaign.require_no_escape_hatch(True, dirty, unfrozen)

    def test_the_message_names_every_hatch_that_was_open(self):
        with self.assertRaises(campaign.EscapeHatchInCampaign) as caught:
            campaign.require_no_escape_hatch(True, True, True)
        self.assertIn("--allow-dirty", str(caught.exception))
        self.assertIn("--allow-unfrozen", str(caught.exception))

    def test_a_trial_may_open_every_hatch(self):
        """The hatches exist for trials; refusing them there would leave no way to
        measure a work-in-progress at all."""
        self.assertTrue(campaign.require_no_escape_hatch(False, True, True))
        self.assertTrue(campaign.require_no_escape_hatch(True, False, False))


class TestOutputDirectoryDowngrade(unittest.TestCase):
    """`require_no_downgrade` looks at the whole directory before the phase starts."""

    def _campaign_dir(self, directory, name):
        if name.endswith(".json"):
            campaign.write_json(os.path.join(directory, name),
                                {"provenance": campaign.PROVENANCE_CAMPAIGN})
        else:
            with open(os.path.join(directory, name), "w", encoding="utf-8") as fh:
                fh.write("# provenance: %s\nrun_index\n" % campaign.PROVENANCE_CAMPAIGN)

    def test_every_file_a_phase_writes_is_checked_not_only_the_rows(self):
        """env.json and kat.json are written before runs.csv, so guarding runs.csv
        alone let a trial destroy them and only then refuse."""
        for name in campaign.CAMPAIGN_OUTPUTS:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                self._campaign_dir(d, name)
                with self.assertRaises(campaign.CampaignError):
                    campaign.require_no_downgrade(d, campaign=False)

    def test_a_campaign_may_write_over_a_campaign(self):
        with tempfile.TemporaryDirectory() as d:
            self._campaign_dir(d, campaign.RUNS_FILENAME)
            self.assertTrue(campaign.require_no_downgrade(d, campaign=True))

    def test_a_trial_may_write_over_a_trial(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, campaign.RUNS_FILENAME), "w",
                      encoding="utf-8") as fh:
                fh.write("# provenance: %s\n" % campaign.PROVENANCE_SMOKE)
            campaign.write_json(os.path.join(d, campaign.ENV_FILENAME),
                                {"provenance": campaign.PROVENANCE_SMOKE})
            self.assertTrue(campaign.require_no_downgrade(d, campaign=False))

    def test_an_empty_or_absent_directory_is_fine(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(campaign.require_no_downgrade(d, campaign=False))
            self.assertTrue(campaign.require_no_downgrade(
                os.path.join(d, "nothing-here"), campaign=False))

    def test_the_marker_is_read_from_both_shapes_a_campaign_writes(self):
        with tempfile.TemporaryDirectory() as d:
            csv_path = os.path.join(d, "runs.csv")
            json_path = os.path.join(d, "env.json")
            with open(csv_path, "w", encoding="utf-8") as fh:
                fh.write("# provenance: CAMPAIGN\n# more\nrun_index\n")
            campaign.write_json(json_path, {"provenance": "SMOKE-RUN"})
            self.assertEqual(campaign.provenance_of_file(csv_path), "CAMPAIGN")
            self.assertEqual(campaign.provenance_of_file(json_path), "SMOKE-RUN")
            self.assertIsNone(campaign.provenance_of_file(
                os.path.join(d, "absent.csv")))

    def test_a_file_without_a_marker_reads_as_no_marker_not_as_a_campaign(self):
        with tempfile.TemporaryDirectory() as d:
            plain = os.path.join(d, "runs.csv")
            with open(plain, "w", encoding="utf-8") as fh:
                fh.write("run_index,cipher\n1,a\n")
            self.assertIsNone(campaign.provenance_of_file(plain))
            campaign.write_json(os.path.join(d, "env.json"), {"schema": 1})
            self.assertIsNone(campaign.provenance_of_file(
                os.path.join(d, "env.json")))
            self.assertTrue(campaign.require_no_downgrade(d, campaign=False))


class TestRefuseDowngrade(unittest.TestCase):
    def test_a_trial_will_not_overwrite_a_campaign(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            with open(path, "w") as fh:
                fh.write("# provenance: CAMPAIGN\ncipher\na\n")
            with self.assertRaises(campaign.CampaignError):
                campaign.refuse_downgrade(path, campaign=False)

    def test_a_campaign_may_overwrite_anything(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            with open(path, "w") as fh:
                fh.write("# provenance: CAMPAIGN\ncipher\na\n")
            self.assertTrue(campaign.refuse_downgrade(path, campaign=True))

    def test_a_trial_may_overwrite_a_trial(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "runs.csv")
            with open(path, "w") as fh:
                fh.write("# provenance: SMOKE-RUN\ncipher\na\n")
            self.assertTrue(campaign.refuse_downgrade(path, campaign=False))

    def test_a_path_that_does_not_exist_yet_is_fine(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(campaign.refuse_downgrade(
                os.path.join(d, "runs.csv"), campaign=False))


# --- the shape of runs.csv, against its actual consumer ---------------------------

class TestRunsCsvContract(unittest.TestCase):
    def test_every_column_summarize_requires_is_written(self):
        """Derived from summarize's own list, so adding a required column there
        fails here rather than at the end of a campaign."""
        for column in summarize.REQUIRED_RUN_COLUMNS:
            self.assertIn(column, campaign.RUNS_COLUMNS)

    def test_the_optional_sensor_columns_are_written_too(self):
        """summarize parses temp_c and freq_khz when present; a campaign that has
        them and does not record them throws away the only evidence that the machine
        was not throttling."""
        self.assertIn("temp_c", campaign.RUNS_COLUMNS)
        self.assertIn("freq_khz", campaign.RUNS_COLUMNS)

    def test_run_index_carries_the_campaign_uid_and_sorts_in_run_order(self):
        indices = [campaign.make_run_index("abc123", seq, 25) for seq in range(25)]
        self.assertEqual(len(set(indices)), 25)
        for index in indices:
            self.assertTrue(index.startswith("abc123#"))
        # Zero-padded, so lexicographic order is run order -- run 2 before run 10.
        self.assertEqual(indices, sorted(indices))

    def test_the_pad_width_grows_with_the_run_count(self):
        self.assertEqual(campaign.make_run_index("u", 7, 25), "u#07")
        self.assertEqual(campaign.make_run_index("u", 7, 300), "u#007")
        self.assertEqual(sorted(campaign.make_run_index("u", s, 300)
                                for s in range(300)),
                         [campaign.make_run_index("u", s, 300) for s in range(300)])

    def test_two_campaigns_rows_do_not_pair_across_campaigns(self):
        """Concatenated, they must collide in summarize's duplicate check rather than
        quietly forming a ratio between two different machines' states."""
        one = campaign.make_run_index("aaaaaaaaaaaa", 0, 25)
        two = campaign.make_run_index("bbbbbbbbbbbb", 0, 25)
        self.assertNotEqual(one, two)

    def _write_runs(self, directory, rows, campaign_flag=True):
        path = os.path.join(directory, "runs.csv")
        campaign.write_runs_csv(path, rows, campaign_flag)
        return path

    def test_a_fabricated_campaign_summarises_to_the_ratio_it_was_built_with(self):
        """The whole consumer contract in one test, on numbers chosen so the answer
        is known: the baseline is 1000 everywhere and the challenger 1500, so every
        per-run paired ratio is exactly 1.5 and so is its median."""
        ciphers = ["present-80-r16", "faster"]
        rows = fabricated_rows(
            summarize.MODALITY_MIN_N, ciphers, list(campaign.SIZES),
            rate=lambda cipher, size, seq: 1500.0 if cipher == "faster" else 1000.0)
        with tempfile.TemporaryDirectory() as d:
            path = self._write_runs(d, rows)
            out = summarize.summarize(path, baseline="present-80-r16", resamples=50)
            published = [r for r in out
                         if r["published"] == "yes" and r["cipher"] == "faster"]
            self.assertEqual(len(published), 1)
            self.assertAlmostEqual(published[0]["ratio_median"], 1.5, places=9)
            self.assertAlmostEqual(published[0]["median_mbit_per_sec"], 1500.0,
                                   places=9)
            self.assertEqual(published[0]["n_runs"], summarize.MODALITY_MIN_N)
            self.assertEqual(published[0]["size_bytes"],
                             summarize.PUBLISHED_SIZE_BYTES)

    def test_a_campaign_at_the_floor_is_judged_rather_than_not_judged(self):
        """The reason the floor exists, checked end to end: at MIN_PUBLISHABLE_RUNS
        the summary carries a modality verdict; one run fewer and it does not."""
        ciphers = ["present-80-r16", "other"]
        for runs, expect_judged in ((campaign.MIN_PUBLISHABLE_RUNS, True),
                                    (campaign.MIN_PUBLISHABLE_RUNS - 1, False)):
            rows = fabricated_rows(
                runs, ciphers, list(campaign.SIZES),
                rate=lambda c, s, seq: 1000.0 + seq + (100.0 if c == "other" else 0.0))
            with tempfile.TemporaryDirectory() as d:
                out = summarize.summarize(self._write_runs(d, rows),
                                          baseline="present-80-r16", resamples=50)
                verdicts = {r["modality"] for r in out}
                if expect_judged:
                    self.assertNotIn(summarize.MODALITY_NOT_JUDGED, verdicts)
                else:
                    self.assertEqual(verdicts, {summarize.MODALITY_NOT_JUDGED})

    def test_make_tables_accepts_the_campaign_marker_under_require_campaign(self):
        """The switch make_tables could not turn on until a driver wrote the marker.
        This is that switch, exercised against a file this module produced."""
        ciphers = ["present-80-r16", "other"]
        rows = fabricated_rows(
            summarize.MODALITY_MIN_N, ciphers, list(campaign.SIZES),
            rate=lambda c, s, seq: 1000.0 + seq + (100.0 if c == "other" else 0.0))
        with tempfile.TemporaryDirectory() as d:
            path = self._write_runs(d, rows, campaign_flag=True)
            summarize.summarize(path, baseline="present-80-r16", resamples=50)
            summary = os.path.join(d, "summary.csv")
            provenance, _comments, published = make_tables.load_summary(
                summary, require_campaign=True)
            self.assertEqual(provenance, "CAMPAIGN")
            self.assertTrue(published)

    def test_make_tables_still_refuses_a_trial_under_require_campaign(self):
        ciphers = ["present-80-r16", "other"]
        rows = fabricated_rows(
            summarize.MODALITY_MIN_N, ciphers, list(campaign.SIZES),
            rate=lambda c, s, seq: 1000.0 + seq + (100.0 if c == "other" else 0.0))
        with tempfile.TemporaryDirectory() as d:
            path = self._write_runs(d, rows, campaign_flag=False)
            summarize.summarize(path, baseline="present-80-r16", resamples=50)
            with self.assertRaises(make_tables.SmokeRunRefused):
                make_tables.load_summary(os.path.join(d, "summary.csv"),
                                         require_campaign=True)

    def test_the_published_size_is_measured_and_two_others_are_too(self):
        """summarize.ranking_stable needs more than one size to compare, and the
        published one has to be among them or nothing publishable is measured."""
        self.assertIn(summarize.PUBLISHED_SIZE_BYTES, campaign.SIZES)
        self.assertEqual(len(campaign.SIZES), 3)
        self.assertEqual(list(campaign.SIZES), sorted(set(campaign.SIZES)))


# --- the measurement order --------------------------------------------------------

class TestCipherOrder(unittest.TestCase):
    CIPHERS = [name for _p, name, _r in cipher_set.resolve()]

    def test_each_run_measures_every_cipher_exactly_once(self):
        for order in campaign.cipher_orders(self.CIPHERS, 25, seed=0):
            self.assertEqual(sorted(order), sorted(self.CIPHERS))

    def test_the_order_actually_varies_between_runs(self):
        """Fixed order makes position bias -- cold cache on the first cipher, a hotter
        core on the last -- a constant offset for one cipher instead of spread."""
        orders = campaign.cipher_orders(self.CIPHERS, 25, seed=0)
        self.assertGreater(len({tuple(o) for o in orders}), 1)

    def test_the_same_seed_gives_the_same_orders(self):
        self.assertEqual(campaign.cipher_orders(self.CIPHERS, 25, seed=7),
                         campaign.cipher_orders(self.CIPHERS, 25, seed=7))

    def test_the_input_list_is_not_mutated(self):
        original = list(self.CIPHERS)
        campaign.cipher_orders(self.CIPHERS, 5, seed=0)
        self.assertEqual(self.CIPHERS, original)

    def test_one_order_per_run(self):
        self.assertEqual(len(campaign.cipher_orders(self.CIPHERS, 13, seed=0)), 13)


class TestSelectArgs(unittest.TestCase):
    def test_the_arguments_follow_the_measurement_order(self):
        choice = {"a": "ctr-ref", "b": "ctr-table", "c": "ctr-bitslice-u64"}
        self.assertEqual(campaign.select_args(["c", "a", "b"], choice),
                         ["--select", "c=ctr-bitslice-u64",
                          "--select", "a=ctr-ref",
                          "--select", "b=ctr-table"])

    def test_one_process_holds_the_whole_cipher_set(self):
        """This is the pairing guarantee in argv form: every cipher a comparison
        touches is measured by the same ctr_bench process as the baseline."""
        ciphers = [name for _p, name, _r in cipher_set.resolve()]
        args = campaign.select_args(ciphers, {c: "ctr-ref" for c in ciphers})
        self.assertEqual(args.count("--select"), len(ciphers))


class TestHarnessCommand(unittest.TestCase):
    def test_the_pin_is_a_taskset_prefix(self):
        cmd = campaign.harness_command("build/ctr_bench", "/tmp/x.csv", 65536, cpu=8)
        self.assertEqual(cmd[:3], ["taskset", "-c", "8"])
        self.assertEqual(cmd[3], "build/ctr_bench")

    def test_no_cpu_means_no_taskset(self):
        cmd = campaign.harness_command("build/ctr_bench", "/tmp/x.csv", 65536)
        self.assertEqual(cmd[0], "build/ctr_bench")
        self.assertNotIn("taskset", cmd)

    def test_the_size_reaches_the_harness(self):
        cmd = campaign.harness_command("b", "/tmp/x.csv", 4096)
        self.assertEqual(cmd[cmd.index("--size") + 1], "4096")

    def test_trials_are_left_to_the_harness_default_when_unset(self):
        self.assertNotIn("--trials",
                         campaign.harness_command("b", "/tmp/x.csv", 4096))
        self.assertIn("--trials",
                      campaign.harness_command("b", "/tmp/x.csv", 4096, trials=3))

    def test_the_kat_path_is_passed_only_when_asked_for(self):
        self.assertNotIn("--kat-json",
                         campaign.harness_command("b", "/tmp/x.csv", 4096))
        cmd = campaign.harness_command("b", "/tmp/x.csv", 4096, kat_json="/tmp/k.json")
        self.assertEqual(cmd[cmd.index("--kat-json") + 1], "/tmp/k.json")


# --- provenance probes, on a fabricated /sys and /proc ----------------------------

class TestCpuListParsing(unittest.TestCase):
    def test_ranges_and_singletons(self):
        self.assertEqual(campaign.parse_cpu_list("0-3,8,10-11"),
                         [0, 1, 2, 3, 8, 10, 11])

    def test_the_form_this_machine_produces(self):
        self.assertEqual(campaign.parse_cpu_list("8-9"), [8, 9])

    def test_duplicates_collapse_and_the_result_is_sorted(self):
        self.assertEqual(campaign.parse_cpu_list("5,1,5,0-1"), [0, 1, 5])

    def test_nothing_is_not_an_error(self):
        self.assertEqual(campaign.parse_cpu_list(""), [])
        self.assertEqual(campaign.parse_cpu_list(None), [])

    def test_a_malformed_range_is_dropped_rather_than_raising(self):
        """A probe that raises turns an unreadable sysfs file into a failed campaign."""
        self.assertEqual(campaign.parse_cpu_list("9-8,3"), [3])
        self.assertEqual(campaign.parse_cpu_list("x-y,4"), [4])


class TestCmdlineFlags(unittest.TestCase):
    def test_both_flags_are_extracted(self):
        got = campaign.cmdline_flags("ro quiet isolcpus=8,9 nohz_full=8-9 splash")
        self.assertEqual(got["isolcpus"], "8,9")
        self.assertEqual(got["nohz_full"], "8-9")

    def test_absent_flags_are_none_not_false(self):
        """`None` says the kernel was not given the option. `False` would read as a
        finding about the campaign's own preparation, which this file never asserts."""
        got = campaign.cmdline_flags("ro quiet splash")
        self.assertIsNone(got["isolcpus"])
        self.assertIsNone(got["nohz_full"])
        self.assertEqual(got["raw"], "ro quiet splash")

    def test_a_similarly_named_option_is_not_mistaken_for_it(self):
        self.assertIsNone(campaign.cmdline_flags("my_isolcpus_note=1")["isolcpus"])

    def test_an_unreadable_cmdline_still_produces_the_keys(self):
        got = campaign.cmdline_flags(None)
        self.assertEqual(set(got), {"raw", "isolcpus", "nohz_full"})


class TestCpuBusyFraction(unittest.TestCase):
    """`/proc/stat`: cpuN user nice system idle iowait irq softirq steal ..."""

    def test_a_fully_idle_cpu_reads_zero(self):
        before = "cpu9 0 0 0 0 0 0 0 0\n"
        after = "cpu9 0 0 0 100 0 0 0 0\n"
        self.assertEqual(campaign.cpu_busy_fraction(before, after, 9), 0.0)

    def test_a_fully_busy_cpu_reads_one(self):
        before = "cpu9 0 0 0 0 0 0 0 0\n"
        after = "cpu9 100 0 0 0 0 0 0 0\n"
        self.assertEqual(campaign.cpu_busy_fraction(before, after, 9), 1.0)

    def test_a_quarter_busy_cpu_reads_a_quarter(self):
        before = "cpu8 0 0 0 0 0 0 0 0\ncpu9 0 0 0 0 0 0 0 0\n"
        after = "cpu8 0 0 0 0 0 0 0 0\ncpu9 20 0 5 75 0 0 0 0\n"
        self.assertAlmostEqual(campaign.cpu_busy_fraction(before, after, 9), 0.25)

    def test_iowait_counts_as_idle(self):
        before = "cpu9 0 0 0 0 0 0 0 0\n"
        after = "cpu9 0 0 0 50 50 0 0 0\n"
        self.assertEqual(campaign.cpu_busy_fraction(before, after, 9), 0.0)

    def test_the_right_cpu_is_read(self):
        before = "cpu8 0 0 0 0 0 0 0 0\ncpu9 0 0 0 0 0 0 0 0\n"
        after = "cpu8 100 0 0 0 0 0 0 0\ncpu9 0 0 0 100 0 0 0 0\n"
        self.assertEqual(campaign.cpu_busy_fraction(before, after, 8), 1.0)
        self.assertEqual(campaign.cpu_busy_fraction(before, after, 9), 0.0)

    def test_a_cpu_that_is_not_there_is_none_rather_than_zero(self):
        """Zero would read as `the sibling was idle`, which is the one claim this
        number exists to support and must never be invented."""
        self.assertIsNone(campaign.cpu_busy_fraction("cpu0 1 1 1 1 1\n",
                                                     "cpu0 2 2 2 2 2\n", 9))

    def test_no_elapsed_time_is_none_rather_than_zero(self):
        same = "cpu9 1 1 1 1 1 1 1 1\n"
        self.assertIsNone(campaign.cpu_busy_fraction(same, same, 9))

    def test_a_cpu_prefix_is_not_matched_loosely(self):
        """`cpu9` must not be answered by the line for `cpu90`, nor by the aggregate
        `cpu` line."""
        before = "cpu 0 0 0 0 0 0 0 0\ncpu90 0 0 0 0 0 0 0 0\n"
        after = "cpu 100 0 0 0 0 0 0 0\ncpu90 100 0 0 0 0 0 0 0\n"
        self.assertIsNone(campaign.cpu_busy_fraction(before, after, 9))


class FakeRoot:
    """A /sys and /proc tree with only the files a test puts in it."""

    def __init__(self, directory):
        self.root = directory

    def write(self, relative, text):
        path = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path


class TestProbeCpu(unittest.TestCase):
    def test_the_machine_is_reported_as_it_is(self):
        with tempfile.TemporaryDirectory() as d:
            fake = FakeRoot(d)
            prefix = "sys/devices/system/cpu/cpu8"
            fake.write(prefix + "/cpufreq/scaling_governor", "powersave\n")
            fake.write(prefix + "/cpufreq/scaling_cur_freq", "1234567\n")
            fake.write(prefix + "/topology/thread_siblings_list", "8-9\n")
            fake.write("proc/cpuinfo",
                       "processor\t: 0\nmodel name\t: Fictional CPU 9000\nflags\t: x\n")
            got = campaign.probe_cpu(8, root=d)
        self.assertEqual(got["governor"], "powersave")
        self.assertEqual(got["cur_freq_khz"], 1234567)
        self.assertEqual(got["hyperthread_siblings"], [9])
        self.assertEqual(got["model_name"], "Fictional CPU 9000")
        self.assertEqual(got["pinned_cpu"], 8)

    def test_the_pinned_cpu_is_not_listed_as_its_own_sibling(self):
        with tempfile.TemporaryDirectory() as d:
            FakeRoot(d).write("sys/devices/system/cpu/cpu8/topology/"
                              "thread_siblings_list", "8-9\n")
            self.assertEqual(campaign.probe_cpu(8, root=d)["hyperthread_siblings"], [9])

    def test_a_machine_exposing_nothing_yields_nulls_rather_than_an_exception(self):
        """Recorded as observed, never asserted: a target with no cpufreq at all must
        still produce an env.json."""
        with tempfile.TemporaryDirectory() as d:
            got = campaign.probe_cpu(8, root=d)
        self.assertIsNone(got["governor"])
        self.assertIsNone(got["cur_freq_khz"])
        self.assertIsNone(got["model_name"])
        self.assertEqual(got["hyperthread_siblings"], [])

    def test_a_governor_that_is_not_performance_is_reported_not_corrected(self):
        with tempfile.TemporaryDirectory() as d:
            FakeRoot(d).write("sys/devices/system/cpu/cpu8/cpufreq/scaling_governor",
                              "powersave\n")
            self.assertEqual(campaign.probe_cpu(8, root=d)["governor"], "powersave")


class TestThermal(unittest.TestCase):
    def test_zones_are_read_in_millidegrees_and_reported_in_degrees(self):
        with tempfile.TemporaryDirectory() as d:
            fake = FakeRoot(d)
            fake.write("sys/class/thermal/thermal_zone0/temp", "45000\n")
            fake.write("sys/class/thermal/thermal_zone0/type", "acpitz\n")
            fake.write("sys/class/thermal/thermal_zone1/temp", "61000\n")
            fake.write("sys/class/thermal/thermal_zone1/type", "x86_pkg_temp\n")
            zones = campaign.read_thermal_zones(root=d)
        self.assertEqual([z["temp_c"] for z in zones], [45.0, 61.0])

    def test_a_platform_with_no_sensors_reports_none_rather_than_failing(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(campaign.read_thermal_zones(root=d), [])
        self.assertIsNone(campaign.hottest_zone([]))

    def test_the_package_sensor_wins_even_when_it_is_not_the_hottest(self):
        """The package sensor tracks what the measured core is doing; picking the
        hottest zone would let a GPU or a disk decide the column."""
        zones = [{"zone": "thermal_zone0", "type": "acpitz", "temp_c": 90.0},
                 {"zone": "thermal_zone1", "type": "x86_pkg_temp", "temp_c": 55.0}]
        self.assertEqual(campaign.hottest_zone(zones)["type"], "x86_pkg_temp")

    def test_without_a_package_sensor_the_hottest_zone_wins(self):
        zones = [{"zone": "thermal_zone0", "type": "acpitz", "temp_c": 40.0},
                 {"zone": "thermal_zone1", "type": "iwlwifi", "temp_c": 51.0}]
        self.assertEqual(campaign.hottest_zone(zones)["temp_c"], 51.0)

    def test_a_zone_with_no_reading_is_skipped_rather_than_chosen(self):
        zones = [{"zone": "thermal_zone0", "type": "acpitz", "temp_c": None},
                 {"zone": "thermal_zone1", "type": "iwlwifi", "temp_c": 33.0}]
        self.assertEqual(campaign.hottest_zone(zones)["temp_c"], 33.0)


# --- tuning: the choice, and the evidence for it ----------------------------------

class TestTuningEvidence(unittest.TestCase):
    def test_the_winner_is_the_highest_median_not_the_highest_single_run(self):
        """A lucky run must not decide a freeze that cannot be appealed. `slow` peaks
        higher than `fast` ever reaches, and still loses on the median."""
        ranked = campaign.rank_candidates({
            "fast": [100.0, 101.0, 102.0, 103.0, 104.0],
            "slow": [1.0, 2.0, 3.0, 4.0, 500.0],
        })
        self.assertEqual(ranked[0]["impl"], "fast")
        self.assertEqual(ranked[0]["median_mbit_per_sec"], 102.0)
        self.assertEqual(ranked[1]["median_mbit_per_sec"], 3.0)

    def test_the_medians_that_justified_the_choice_are_recorded(self):
        doc = campaign.tuning_document(
            {"c": {"a": [10.0, 12.0, 11.0], "b": [1.0, 2.0, 3.0]}}, {})
        candidates = doc["evidence"]["c"]["candidates"]
        self.assertEqual([c["impl"] for c in candidates], ["a", "b"])
        self.assertEqual(candidates[0]["median_mbit_per_sec"], 11.0)
        self.assertEqual(candidates[0]["samples_mbit_per_sec"], [10.0, 11.0, 12.0])
        self.assertEqual(doc["choice"], {"c": "a"})

    def test_a_tie_breaks_on_the_name_so_the_freeze_is_reproducible(self):
        ranked = campaign.rank_candidates({"zzz": [5.0], "aaa": [5.0]})
        self.assertEqual([c["impl"] for c in ranked], ["aaa", "zzz"])

    def test_a_clear_winner_is_separated(self):
        self.assertTrue(campaign.winner_is_separated(
            campaign.rank_candidates({"fast": [100.0, 101.0], "slow": [10.0, 11.0]})))

    def test_overlapping_candidates_are_not_separated(self):
        """Five runs on a host with two performance states cannot always tell two
        backends apart. The freeze happens anyway, so the file has to say when the
        evidence did not decide it."""
        self.assertFalse(campaign.winner_is_separated(
            campaign.rank_candidates({"a": [100.0, 80.0], "b": [99.0, 95.0]})))

    def test_a_single_candidate_is_unopposed_rather_than_separated(self):
        """`True` would claim a comparison that never happened."""
        self.assertIsNone(campaign.winner_is_separated(
            campaign.rank_candidates({"only": [1.0, 2.0]})))

    def test_one_run_each_is_not_judged_rather_than_separated(self):
        """With one observation per candidate there is no range to be separated, so
        the comparison collapses to "one number was bigger" -- which on a host with
        two performance states 2.15x apart is a coin toss, not evidence."""
        self.assertIsNone(campaign.winner_is_separated(
            campaign.rank_candidates({"a": [100.0], "b": [10.0]})))

    def test_two_runs_each_can_be_judged(self):
        self.assertTrue(campaign.winner_is_separated(
            campaign.rank_candidates({"a": [100.0, 99.0], "b": [10.0, 11.0]})))

    def test_a_third_candidate_measured_once_does_not_block_the_verdict(self):
        """Only the two being compared have to have been measured more than once."""
        self.assertTrue(campaign.winner_is_separated(campaign.rank_candidates(
            {"a": [100.0, 99.0], "b": [10.0, 11.0], "c": [1.0]})))

    def test_touching_ranges_do_not_count_as_separated(self):
        self.assertFalse(campaign.winner_is_separated(
            campaign.rank_candidates({"a": [10.0, 12.0], "b": [8.0, 10.0]})))

    def test_the_document_carries_the_metadata_it_was_given(self):
        doc = campaign.tuning_document({"c": {"a": [1.0]}},
                                       {"commit": "abc", "runs": 5})
        self.assertEqual(doc["commit"], "abc")
        self.assertEqual(doc["runs"], 5)

    def test_a_written_document_round_trips_through_load_tuning(self):
        doc = campaign.tuning_document(
            {"present-80-r16": {"ctr-bitslice-avx2": [2.0], "ctr-ref": [1.0]}}, {})
        with tempfile.TemporaryDirectory() as d:
            campaign.write_json(os.path.join(d, campaign.TUNING_FILENAME), doc)
            self.assertEqual(campaign.load_tuning(d),
                             {"present-80-r16": "ctr-bitslice-avx2"})


# --- the harness's own new flags, exercised if it happens to be built -------------

BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "..", "build", "ctr_bench")


@unittest.skipUnless(os.path.exists(BINARY), "build/ctr_bench is not built")
class TestHarnessFlags(unittest.TestCase):
    """Not a measurement: these check the flags campaign.py depends on, at the
    smallest working-set size and one trial, and assert nothing about speed."""

    def _run(self, *args):
        return subprocess.run([BINARY] + list(args), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)

    def test_list_backends_names_the_cipher_set(self):
        proc = self._run("--list-backends")
        self.assertEqual(proc.returncode, 0)
        listed = {line.split()[0] for line in proc.stdout.splitlines() if line.strip()}
        self.assertEqual(listed, {name for _p, name, _r in cipher_set.resolve()})

    def test_registered_backends_parses_into_a_per_cipher_mapping(self):
        available = campaign.registered_backends(BINARY)
        self.assertEqual(set(available),
                         {name for _p, name, _r in cipher_set.resolve()})
        for impls in available.values():
            self.assertIn("ctr-ref", impls)

    def test_a_frozen_choice_of_ctr_ref_everywhere_passes_the_real_guard(self):
        ciphers = [name for _p, name, _r in cipher_set.resolve()]
        choice = {c: "ctr-ref" for c in ciphers}
        campaign.check_tuning_covers(choice, ciphers)
        campaign.check_tuning(choice, campaign.registered_backends(BINARY))

    def test_select_measures_the_named_backends_in_the_named_order(self):
        with tempfile.TemporaryDirectory() as d:
            csv_path = os.path.join(d, "out.csv")
            proc = self._run("--csv", csv_path, "--size", "4096", "--trials", "1",
                             "--select", "aes-r5=ctr-table-x8",
                             "--select", "present-80-r16=ctr-ref")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = campaign.read_harness_csv(csv_path)
        self.assertEqual([(r["cipher"], r["impl"]) for r in rows],
                         [("aes-r5", "ctr-table-x8"), ("present-80-r16", "ctr-ref")])

    def test_two_backends_for_one_cipher_in_one_run_is_refused(self):
        """summarize cannot pair a run holding two impls of the same cipher, so the
        harness refuses to produce one rather than leaving it to be noticed."""
        with tempfile.TemporaryDirectory() as d:
            csv_path = os.path.join(d, "out.csv")
            proc = self._run("--csv", csv_path, "--size", "4096", "--trials", "1",
                             "--select", "present-80-r16=ctr-ref",
                             "--select", "present-80-r16=ctr-table")
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(os.path.exists(csv_path))

    def test_an_unknown_backend_is_refused_and_writes_no_csv(self):
        with tempfile.TemporaryDirectory() as d:
            csv_path = os.path.join(d, "out.csv")
            proc = self._run("--csv", csv_path, "--size", "4096", "--trials", "1",
                             "--select", "present-80-r16=ctr-bitslice-avx512")
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(os.path.exists(csv_path))

    def test_kat_json_holds_one_passing_entry_per_measured_backend(self):
        with tempfile.TemporaryDirectory() as d:
            csv_path = os.path.join(d, "out.csv")
            kat_path = os.path.join(d, "kat.json")
            proc = self._run("--csv", csv_path, "--size", "4096", "--trials", "1",
                             "--kat-json", kat_path,
                             "--select", "present-80-r16=ctr-ref",
                             "--select", "cipher-D=ctr-bitslice-u64")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(kat_path, encoding="utf-8") as fh:
                entries = json.load(fh)
        self.assertEqual(len(entries), 2)
        self.assertEqual(campaign.check_kat(
            entries, expected={("present-80-r16", "ctr-ref"),
                               ("cipher-D", "ctr-bitslice-u64")}), 2)
        for entry in entries:
            self.assertIsNone(entry["offset"])

    def test_the_gate_verdict_is_written_before_the_csv_exists(self):
        """A kat.json can never describe a different run from the rows beside it."""
        with tempfile.TemporaryDirectory() as d:
            csv_path = os.path.join(d, "out.csv")
            kat_path = os.path.join(d, "kat.json")
            self._run("--csv", csv_path, "--size", "4096", "--trials", "1",
                      "--kat-json", kat_path,
                      "--select", "present-80-r16=ctr-ref")
            self.assertLessEqual(os.path.getmtime(kat_path),
                                 os.path.getmtime(csv_path))


class TestCliRejectsBadInvocations(unittest.TestCase):
    """Rejected before any directory is created, so a mistyped command leaves no
    empty results/v2/<target> behind looking like a campaign whose data went missing.
    Each of these exits during argument checking and never reaches the harness."""

    def _listing(self):
        """What results/v2 holds, tolerating its absence on a fresh checkout."""
        root = os.path.join(campaign.ROOT, "results", "v2")
        return set(os.listdir(root)) if os.path.isdir(root) else set()

    def setUp(self):
        self.before = self._listing()

    def tearDown(self):
        self.assertEqual(self._listing(), self.before,
                         "a rejected invocation created a results/v2 directory")

    def _rejects(self, argv):
        with open(os.devnull, "w") as devnull:
            stderr, sys.stderr = sys.stderr, devnull
            try:
                with self.assertRaises(SystemExit) as caught:
                    campaign.main(argv)
            finally:
                sys.stderr = stderr
        self.assertNotEqual(caught.exception.code, 0)

    def test_a_target_that_is_a_path_is_refused(self):
        self._rejects(["../elsewhere", "--tune"])
        self._rejects(["..", "--tune"])

    def test_omitting_the_published_size_is_refused(self):
        """Measuring only 4 KiB and 16 KiB would produce a campaign with nothing
        publishable in it, and the flip check would compare two unpublished sizes."""
        self._rejects(["x86", "--measure", "--sizes", "4096", "16384"])

    def test_a_nonsense_size_is_refused(self):
        self._rejects(["x86", "--measure", "--sizes", "0",
                       str(summarize.PUBLISHED_SIZE_BYTES)])

    def test_the_two_phases_cannot_be_run_by_one_command(self):
        """A commit has to sit between them, so one command that did both would
        destroy the property the split exists for."""
        self._rejects(["x86", "--tune", "--measure"])

    def test_a_phase_must_be_named(self):
        self._rejects(["x86"])

    def test_zero_measurement_runs_is_refused_rather_than_writing_no_rows(self):
        """argparse's type=int is happy with 0 and the run loop then runs no times,
        which produced a runs.csv with a header, no rows and no complaint."""
        self._rejects(["x86", "--measure", "--runs", "0"])
        self._rejects(["x86", "--measure", "--runs", "-3"])

    def test_zero_tuning_runs_is_refused_rather_than_freezing_nothing(self):
        """A tuning.json built from no evidence at all still says `choice`."""
        self._rejects(["x86", "--tune", "--tuning-runs", "0"])


# --- end to end: the entry points, against a stub harness in a throwaway repository ---
#
# Everything above this line tests a guard's body. Nothing above it tests whether the
# guard is *called*, and a guard nobody calls is not a guard: deleting `require_frozen(
# ...)` from phase_measure left the whole suite green. These tests drive campaign.main
# itself -- argument parsing, both phases, the writers, the summary -- so that each
# refusal is provoked through the same path a person would take.
#
# Two things make that possible without depending on this machine:
#   * a stub binary with ctr_bench's command-line surface and arithmetic instead of
#     cryptography, so the numbers are the same on every host and in every mood; and
#   * a throwaway git repository as campaign.ROOT, so `git status`, the freeze commit
#     and the output directory are all fixture state rather than the real worktree's.
# Consequently these tests can and do commit, dirty the tree, and write results/v2 --
# in a directory that is deleted afterwards, never in the repository under test.

STUB_SOURCE = '''#!/usr/bin/env python3
"""A stand-in for build/ctr_bench: the same flags campaign.py uses, deterministic
numbers, no cryptography. What is under test is whether the driver calls its guards,
and a stub is what makes that answer independent of what this machine is doing."""
import json
import os
import sys

CIPHERS = @CIPHERS@
IMPLS = ["ctr-ref", "ctr-fast"]


def rate(cipher, impl, nth):
    """Deterministic, ctr-fast always ahead, and enough spread that a summary of it is
    not a column of identical numbers."""
    base = 100.0 * (CIPHERS.index(cipher) + 1)
    if impl == "ctr-fast":
        base *= 2.0
    return base * (1.0 + ((nth * 7919) % 13) / 1000.0)


def main(argv):
    csv_path = None
    size = 0
    kat_path = None
    selects = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--list-backends":
            for cipher in CIPHERS:
                for impl in IMPLS:
                    sys.stdout.write(cipher + " " + impl + " available\\n")
            return 0
        if arg in ("--csv", "--size", "--trials", "--kat-json", "--select"):
            value = argv[i + 1]
            i += 2
            if arg == "--csv":
                csv_path = value
            elif arg == "--size":
                size = int(value)
            elif arg == "--kat-json":
                kat_path = value
            elif arg == "--select":
                selects.append(value)
            continue
        sys.stderr.write("stub: unknown argument " + arg + "\\n")
        return 2

    pairs = []
    for spec in selects:
        cipher, _, impl = spec.partition("=")
        if cipher not in CIPHERS or impl not in IMPLS:
            sys.stderr.write("stub: no such backend " + spec + "\\n")
            return 1
        pairs.append((cipher, impl))
    if not pairs:
        pairs = [(c, m) for c in CIPHERS for m in IMPLS]

    log = os.environ.get("STUB_LOG")
    if log:
        with open(log, "a") as fh:
            fh.write(" ".join(argv) + "\\n")

    failing = os.environ.get("STUB_KAT_FAIL")
    omitted = os.environ.get("STUB_KAT_OMIT")
    if kat_path:
        entries = []
        for cipher, impl in pairs:
            if cipher == omitted:
                continue
            entries.append({"cipher": cipher, "impl": impl, "rounds": 1,
                            "pass": cipher != failing,
                            "check": "matches-ctr-ref", "ctr0": 0,
                            "offset": 0 if cipher == failing else None})
        with open(kat_path, "w") as fh:
            json.dump(entries, fh)
        # ctr_bench writes the verdict and then exits non-zero, in that order. STUB_KAT
        # _QUIET suppresses only the exit status, which is the one case the driver's own
        # check_kat exists for: a harness whose exit status and verdict file disagree.
        if failing and not os.environ.get("STUB_KAT_QUIET"):
            return 1

    counter = csv_path + ".n"
    nth = 0
    if os.path.exists(counter):
        with open(counter) as fh:
            nth = int(fh.read().strip() or "0")
    with open(counter, "w") as fh:
        fh.write(str(nth + 1))

    with open(csv_path, "w") as fh:
        fh.write("cipher,impl,rounds,block_bytes,size_bytes,mbit_per_sec,"
                 "ns_median,ns_min,prepare_ns,tsc_per_byte\\n")
        for cipher, impl in pairs:
            fh.write("%s,%s,1,8,%d,%.6f,1000,900,10,1.5\\n"
                     % (cipher, impl, size, rate(cipher, impl, nth)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''


class EndToEnd(unittest.TestCase):
    """A throwaway repository with a stub harness in it, and campaign.main driving it."""

    CIPHERS = [name for _p, name, _r in cipher_set.resolve()]
    BASE = ["x86", "--no-build", "--no-pin", "--binary", "build/ctr_bench"]

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="campaign-e2e-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.git("init", "-q", ".")
        self.git("config", "user.email", "campaign-test@example.invalid")
        self.git("config", "user.name", "Campaign Test")
        os.makedirs(os.path.join(self.root, "build"))
        os.makedirs(os.path.join(self.root, "bench"))
        stub = os.path.join(self.root, "build", "ctr_bench")
        self.write(stub, STUB_SOURCE.replace("@CIPHERS@", repr(self.CIPHERS)))
        os.chmod(stub, 0o755)
        # A watched build input to dirty, and one that is not, so the dirty tests
        # distinguish "any change" from "a change that could alter the binary".
        self.write(os.path.join(self.root, "Makefile"), "build/ctr_bench:\n\t@true\n")
        self.write(os.path.join(self.root, "bench", "ctr_bench.c"), "/* stub */\n")
        self.write(os.path.join(self.root, "README.md"), "not a build input\n")
        self.write(os.path.join(self.root, ".gitignore"), "build/\n")
        self.git("add", "Makefile", "bench/ctr_bench.c", "README.md", ".gitignore")
        self.git("commit", "-q", "-m", "base")
        patcher = mock.patch.object(campaign, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.out_dir = os.path.join(self.root, campaign.RESULTS_ROOT, "x86")

    # -- fixture plumbing --

    def git(self, *args):
        proc = subprocess.run(["git"] + list(args), cwd=self.root,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    @staticmethod
    def write(path, text):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def run_main(self, *extra):
        """campaign.main with output captured; returns (exit code, stdout+stderr)."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = campaign.main(self.BASE + list(extra))
        return code, buf.getvalue()

    def tune(self, *extra):
        code, out = self.run_main("--tune", "--tuning-runs", "2", *extra)
        self.assertEqual(code, 0, out)
        return out

    def freeze(self):
        """Commit the tuning.json, which is what --measure demands have happened."""
        self.git("add", os.path.join(campaign.RESULTS_ROOT, "x86",
                                     campaign.TUNING_FILENAME))
        self.git("commit", "-q", "-m", "Freeze the x86 kernel choice")

    def measure(self, *extra):
        return self.run_main("--measure", "--runs", "2", "--sizes",
                             str(summarize.PUBLISHED_SIZE_BYTES), *extra)

    def tuned_and_frozen(self):
        self.tune()
        self.freeze()

    def out(self, name):
        return os.path.join(self.out_dir, name)

    def read(self, name):
        with open(self.out(name), encoding="utf-8") as fh:
            return fh.read()

    def load(self, name):
        with open(self.out(name), encoding="utf-8") as fh:
            return json.load(fh)

    def rows(self):
        with open(self.out(campaign.RUNS_FILENAME), encoding="utf-8") as fh:
            lines = [ln for ln in fh if not ln.startswith("#")]
        return list(csv.DictReader(lines))

    def edit_tuning(self, mutate):
        """Change the frozen choice and re-commit it, so the freeze itself stays valid
        and only its contents are wrong -- otherwise require_frozen fires first and the
        test proves nothing about the guard it aimed at."""
        doc = self.load(campaign.TUNING_FILENAME)
        mutate(doc)
        campaign.write_json(self.out(campaign.TUNING_FILENAME), doc)
        self.git("add", os.path.join(campaign.RESULTS_ROOT, "x86",
                                     campaign.TUNING_FILENAME))
        self.git("commit", "-q", "-m", "Edit the frozen choice")

    # -- the happy path, which is also what every refusal test is a deviation from --

    def test_tune_freezes_a_winner_per_cipher_with_its_evidence(self):
        self.tune()
        doc = self.load(campaign.TUNING_FILENAME)
        self.assertEqual(sorted(doc["choice"]), sorted(self.CIPHERS))
        # ctr-fast is exactly twice ctr-ref in the stub, on every run, so the winner is
        # decided and separated -- an implementation that picked the loser, or called a
        # coin-flip separated, disagrees here.
        self.assertEqual(set(doc["choice"].values()), {"ctr-fast"})
        for cipher in self.CIPHERS:
            self.assertIs(doc["evidence"][cipher]["separated"], True)
            self.assertEqual([c["runs"] for c in doc["evidence"][cipher]["candidates"]],
                             [2, 2])

    def test_tune_runs_the_correctness_gate_and_keeps_its_verdict(self):
        self.tune()
        entries = self.load(campaign.KAT_FILENAME)
        # Every cipher and every backend: tuning measures them all, so the gate has to
        # cover them all.
        self.assertEqual({(e["cipher"], e["impl"]) for e in entries},
                         {(c, i) for c in self.CIPHERS
                          for i in ("ctr-ref", "ctr-fast")})
        self.assertEqual(campaign.check_kat(entries), len(entries))

    def test_the_default_tuning_run_count_is_the_documented_five(self):
        """Not --tuning-runs 2: this is the default a real freeze would use, and one
        run per candidate cannot separate a winner from a runner-up at all."""
        code, out = self.run_main("--tune")
        self.assertEqual(code, 0, out)
        doc = self.load(campaign.TUNING_FILENAME)
        self.assertEqual(doc["runs"], campaign.TUNING_RUNS)
        self.assertEqual(doc["evidence"][self.CIPHERS[0]]["candidates"][0]["runs"], 5)

    def test_measure_writes_rows_a_summary_and_an_environment(self):
        self.tuned_and_frozen()
        code, out = self.measure()
        self.assertEqual(code, 0, out)
        rows = self.rows()
        self.assertEqual(len(rows), 2 * len(self.CIPHERS))
        self.assertEqual({r["impl"] for r in rows}, {"ctr-fast"})
        self.assertTrue(os.path.exists(self.out("summary.csv")),
                        "the summary is formed by the driver, not by hand")
        self.assertTrue(os.path.exists(self.out(campaign.ENV_FILENAME)))

    # -- the refusals, each provoked through main --

    def test_an_uncommitted_freeze_stops_the_measurement(self):
        """The freeze-before-measure claim is the reason the phases are separate
        commands; measuring against a tuning.json that is not in the history would make
        it unprovable, so this is a refusal and not a warning."""
        self.tune()                       # deliberately not committed
        code, out = self.measure()
        self.assertEqual(code, 1)
        self.assertIn("is not committed", out)
        self.assertFalse(os.path.exists(self.out(campaign.RUNS_FILENAME)))

    def test_an_edited_freeze_stops_the_measurement(self):
        """git status is not the question -- `--assume-unchanged` makes an edited file
        report clean -- so the check is against the committed blob's bytes."""
        self.tuned_and_frozen()
        doc = self.load(campaign.TUNING_FILENAME)
        doc["choice"][self.CIPHERS[0]] = "ctr-ref"
        campaign.write_json(self.out(campaign.TUNING_FILENAME), doc)
        self.git("update-index", "--assume-unchanged",
                 os.path.join(campaign.RESULTS_ROOT, "x86", campaign.TUNING_FILENAME))
        self.assertEqual(self.git("status", "--porcelain",
                                  os.path.join(campaign.RESULTS_ROOT, "x86",
                                               campaign.TUNING_FILENAME)), "",
                         "the fixture must be one git status calls clean")
        code, out = self.measure()
        self.assertEqual(code, 1)
        self.assertIn("differs from the committed copy", out)

    def test_allow_unfrozen_measures_anyway_and_says_so(self):
        self.tune()
        code, out = self.measure("--allow-unfrozen")
        self.assertEqual(code, 0, out)
        self.assertIn("--allow-unfrozen", out)
        self.assertTrue(self.read(campaign.RUNS_FILENAME)
                        .startswith("# provenance: " + campaign.PROVENANCE_SMOKE))

    def test_a_dirty_watched_build_input_stops_the_measurement(self):
        self.tuned_and_frozen()
        self.write(os.path.join(self.root, "bench", "ctr_bench.c"), "/* edited */\n")
        code, out = self.measure()
        self.assertEqual(code, 1)
        self.assertIn("bench/ctr_bench.c", out)
        self.assertFalse(os.path.exists(self.out(campaign.RUNS_FILENAME)))

    def test_a_dirty_file_that_is_not_a_build_input_does_not_stop_anything(self):
        """The refusal is about the binary the commit describes, so widening it to any
        modified file would make it a nuisance rather than a guarantee."""
        self.tuned_and_frozen()
        self.write(os.path.join(self.root, "README.md"), "edited prose\n")
        code, out = self.measure()
        self.assertEqual(code, 0, out)

    def test_allow_dirty_measures_and_marks_the_file_where_the_commit_is(self):
        self.tuned_and_frozen()
        self.write(os.path.join(self.root, "Makefile"), "build/ctr_bench:\n\t@echo\n")
        code, out = self.measure("--allow-dirty")
        self.assertEqual(code, 0, out)
        text = self.read(campaign.RUNS_FILENAME)
        self.assertIn("MEASURED AGAINST A MODIFIED TREE", text)
        # Beside the commit line it qualifies: a caveat further down the file is a
        # caveat a reader has already passed the misleading line to reach.
        header = [ln for ln in text.splitlines() if ln.startswith("#")]
        commit_at = next(i for i, ln in enumerate(header) if ln.startswith("# commit:"))
        self.assertTrue(header[commit_at + 1].startswith("# MEASURED AGAINST"))
        self.assertEqual(self.load(campaign.ENV_FILENAME)["commit"]["watched_dirty"],
                         ["Makefile"])

    def test_a_campaign_cannot_be_asked_for_with_an_escape_hatch_open(self):
        """summarize copies the provenance marker onto summary.csv and nothing else,
        and summary.csv is all make_tables --require-campaign reads: a caveat in
        runs.csv would be invisible exactly where it matters."""
        for hatch in ("--allow-unfrozen", "--allow-dirty"):
            with self.subTest(hatch=hatch):
                code, out = self.measure("--campaign", "--runs", "12", hatch)
                self.assertEqual(code, 1)
                self.assertIn("--campaign cannot be combined with", out)
                self.assertFalse(os.path.exists(self.out_dir),
                                 "the refusal must come before anything is written")

    def test_a_campaign_below_the_bimodality_floor_is_refused(self):
        self.tuned_and_frozen()
        code, out = self.measure("--campaign")
        self.assertEqual(code, 1)
        self.assertIn("below the %d" % summarize.MODALITY_MIN_N, out)
        self.assertFalse(os.path.exists(self.out(campaign.RUNS_FILENAME)))

    def test_a_campaign_at_the_floor_is_marked_campaign_and_publishes(self):
        self.tuned_and_frozen()
        code, out = self.run_main("--measure", "--campaign", "--runs",
                                  str(summarize.MODALITY_MIN_N), "--sizes",
                                  str(summarize.PUBLISHED_SIZE_BYTES))
        self.assertEqual(code, 0, out)
        self.assertTrue(self.read(campaign.RUNS_FILENAME)
                        .startswith("# provenance: " + campaign.PROVENANCE_CAMPAIGN))
        # The point of the whole exercise: make_tables --require-campaign accepts it.
        provenance, _comments, published = make_tables.load_summary(
            self.out("summary.csv"), require_campaign=True)
        self.assertEqual(provenance, summarize.PROVENANCE_CAMPAIGN)
        self.assertTrue(published)

    def test_a_trial_refuses_to_run_into_a_campaigns_directory(self):
        """env.json and kat.json are written before the rows are, so a guard that only
        protected runs.csv let the trial destroy the campaign's machine record and then
        abort, leaving published numbers beside a record of a different run."""
        self.tuned_and_frozen()
        code, out = self.run_main("--measure", "--campaign", "--runs",
                                  str(summarize.MODALITY_MIN_N), "--sizes",
                                  str(summarize.PUBLISHED_SIZE_BYTES))
        self.assertEqual(code, 0, out)
        before = {name: self.read(name) for name in
                  (campaign.RUNS_FILENAME, campaign.ENV_FILENAME,
                   campaign.KAT_FILENAME, "summary.csv")}
        code, out = self.measure()
        self.assertEqual(code, 1)
        self.assertIn("refusing to run a trial into it", out)
        for name, text in before.items():
            self.assertEqual(self.read(name), text, "%s was overwritten" % name)

    def test_a_trial_refuses_to_retune_over_a_campaigns_freeze(self):
        """--tune had no downgrade guard at all and would replace the frozen file."""
        self.tuned_and_frozen()
        code, _ = self.run_main("--measure", "--campaign", "--runs",
                                str(summarize.MODALITY_MIN_N), "--sizes",
                                str(summarize.PUBLISHED_SIZE_BYTES))
        self.assertEqual(code, 0)
        frozen = self.read(campaign.TUNING_FILENAME)
        code, out = self.run_main("--tune", "--tuning-runs", "2")
        self.assertEqual(code, 1)
        self.assertIn("refusing to run a trial into it", out)
        self.assertEqual(self.read(campaign.TUNING_FILENAME), frozen)

    def test_a_frozen_choice_missing_a_cipher_stops_the_measurement(self):
        self.tuned_and_frozen()
        self.edit_tuning(lambda doc: doc["choice"].pop(self.CIPHERS[0]))
        code, out = self.measure()
        self.assertEqual(code, 1)
        self.assertIn("covers no backend for", out)
        self.assertFalse(os.path.exists(self.out(campaign.RUNS_FILENAME)))

    def test_a_frozen_choice_naming_an_absent_backend_stops_the_measurement(self):
        """Refused by the driver against what the binary registers, before the harness
        runs -- not discovered partway through by the harness failing."""
        self.tuned_and_frozen()
        self.edit_tuning(
            lambda doc: doc["choice"].update({self.CIPHERS[0]: "ctr-bitslice-avx512"}))
        code, out = self.measure()
        self.assertEqual(code, 1)
        self.assertIn("The choice was frozen against a different build", out)

    def test_a_failing_correctness_gate_stops_the_measurement(self):
        self.tuned_and_frozen()
        with mock.patch.dict(os.environ, {"STUB_KAT_FAIL": self.CIPHERS[1]}):
            code, out = self.measure()
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.out(campaign.RUNS_FILENAME)))

    def test_a_gate_verdict_missing_a_measured_backend_stops_the_measurement(self):
        """A verdict file that does not cover a backend authorises a number nothing
        checked; the harness exiting 0 is not the same claim."""
        self.tuned_and_frozen()
        with mock.patch.dict(os.environ, {"STUB_KAT_OMIT": self.CIPHERS[1]}):
            code, out = self.measure()
        self.assertEqual(code, 1)
        self.assertIn("has no verdict for", out)
        self.assertFalse(os.path.exists(self.out(campaign.RUNS_FILENAME)))

    def test_a_failing_gate_stops_the_tuning_phase_too(self):
        with mock.patch.dict(os.environ, {"STUB_KAT_FAIL": self.CIPHERS[0]}):
            code, out = self.run_main("--tune", "--tuning-runs", "2")
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.out(campaign.TUNING_FILENAME)))

    def test_a_verdict_file_saying_fail_stops_a_tuning_that_exited_zero(self):
        """The harness's exit status is not the only thing standing between a broken
        backend and a published number. This is the case the driver's own check_kat
        exists for and the only one in which it is reachable: a gate that recorded a
        failure while the process that recorded it returned success."""
        with mock.patch.dict(os.environ, {"STUB_KAT_FAIL": self.CIPHERS[0],
                                          "STUB_KAT_QUIET": "1"}):
            code, out = self.run_main("--tune", "--tuning-runs", "2")
        self.assertEqual(code, 1)
        self.assertIn("correctness gate failed", out)
        self.assertFalse(os.path.exists(self.out(campaign.TUNING_FILENAME)))

    def test_a_verdict_file_saying_fail_stops_a_measurement_that_exited_zero(self):
        self.tuned_and_frozen()
        with mock.patch.dict(os.environ, {"STUB_KAT_FAIL": self.CIPHERS[0],
                                          "STUB_KAT_QUIET": "1"}):
            code, out = self.measure()
        self.assertEqual(code, 1)
        self.assertIn("correctness gate failed", out)
        self.assertFalse(os.path.exists(self.out(campaign.RUNS_FILENAME)))

    def test_a_summary_that_will_not_form_fails_the_command(self):
        """`no number reaches a paper table by hand` is not satisfied by a summary that
        was attempted: exiting 0 would tell a script the campaign finished."""
        self.tuned_and_frozen()
        with mock.patch.object(campaign.summarize, "main",
                               side_effect=ValueError("no")):
            code, out = self.measure()
        self.assertEqual(code, 1)
        self.assertIn("summary NOT written", out)

    # -- what the written files have to say --

    def test_every_run_gets_its_own_run_index_carrying_the_campaign_uid(self):
        """summarize.paired_ratios buckets on (run_index, size_bytes). One index for
        every run would pool 25 processes into one bucket on a host whose processes
        differ by a factor of two."""
        self.tuned_and_frozen()
        code, out = self.run_main("--measure", "--runs", "3", "--sizes",
                                  str(summarize.PUBLISHED_SIZE_BYTES))
        self.assertEqual(code, 0, out)
        rows = self.rows()
        indices = [r["run_index"] for r in rows]
        self.assertEqual(len(set(indices)), 3)
        uid = rows[0]["campaign_uid"]
        self.assertEqual({r["campaign_uid"] for r in rows}, {uid})
        self.assertTrue(all(i.startswith(uid + "#") for i in indices))
        # 12 hex characters. Short enough to read in a filename, long enough that two
        # campaigns colliding -- and so pairing across each other -- is not a thing that
        # happens; a handful of characters would make it one.
        self.assertEqual(len(uid), 12)
        # Zero-padded and fixed width, so `sort` on the column is run order and not
        # 10 < 2. Three runs is enough to show the padding is there at all.
        self.assertEqual(sorted(set(indices)),
                         [uid + "#0" + str(i) for i in range(3)])

    def test_two_sizes_in_one_run_stay_in_separate_buckets(self):
        self.tuned_and_frozen()
        code, out = self.run_main("--measure", "--runs", "2", "--sizes", "4096",
                                  str(summarize.PUBLISHED_SIZE_BYTES))
        self.assertEqual(code, 0, out)
        rows = self.rows()
        self.assertEqual(len(rows), 2 * 2 * len(self.CIPHERS))
        buckets = {(r["run_index"], r["size_bytes"]) for r in rows}
        self.assertEqual(len(buckets), 4)

    def test_a_repeated_size_is_collapsed_rather_than_measured_twice(self):
        """Two processes in one (run_index, size_bytes) bucket are not two samples --
        paired_ratios would pair one process's numerator with another's denominator."""
        self.tuned_and_frozen()
        published = str(summarize.PUBLISHED_SIZE_BYTES)
        code, out = self.run_main("--measure", "--runs", "1", "--sizes",
                                  published, published)
        self.assertEqual(code, 0, out)
        self.assertEqual(len(self.rows()), len(self.CIPHERS))
        self.assertIn("repeated values", out)

    def test_the_cipher_order_varies_between_runs_and_follows_the_seed(self):
        self.tuned_and_frozen()
        orders = {}
        for seed in ("0", "7"):
            code, out = self.run_main("--measure", "--runs", "4", "--sizes",
                                      str(summarize.PUBLISHED_SIZE_BYTES),
                                      "--seed", seed)
            self.assertEqual(code, 0, out)
            # run_seq rather than run_index: the index carries a per-invocation uid, so
            # comparing on it would differ between the two runs whatever the seed did.
            orders[seed] = [(r["run_seq"], r["cipher"], r["order_position"])
                            for r in self.rows()]
        self.assertNotEqual(orders["0"], orders["7"],
                            "the order seed reached nothing")
        # And within one seed the runs are not all the same order, which is the
        # protocol's actual requirement.
        by_run = {}
        for seq, cipher, position in orders["0"]:
            by_run.setdefault(seq, {})[cipher] = position
        self.assertGreater(len({tuple(sorted(d.items())) for d in by_run.values()}), 1)

    def test_the_runs_file_names_the_commit_that_froze_the_choice(self):
        """This is the whole freeze-before-measure claim, reduced to something a reader
        can check with `git show <commit>:<path> | sha256sum`."""
        self.tuned_and_frozen()
        freeze_commit = self.git("log", "-1", "--format=%H").strip()
        blob = self.git("rev-parse", "HEAD:%s"
                        % os.path.join(campaign.RESULTS_ROOT, "x86",
                                       campaign.TUNING_FILENAME)).strip()
        digest = hashlib.sha256(
            self.read(campaign.TUNING_FILENAME).encode("utf-8")).hexdigest()
        code, out = self.measure()
        self.assertEqual(code, 0, out)
        text = self.read(campaign.RUNS_FILENAME)
        self.assertIn(freeze_commit, text)
        self.assertIn(blob, text)
        self.assertIn(digest, text)

    def test_the_environment_file_records_the_freeze_and_the_tree(self):
        self.tuned_and_frozen()
        code, out = self.measure()
        self.assertEqual(code, 0, out)
        env = self.load(campaign.ENV_FILENAME)
        freeze = env["tuning_freeze"]
        self.assertTrue(freeze["in_head"])
        self.assertFalse(freeze["modified_in_worktree"])
        self.assertEqual(freeze["head_blob"], freeze["working_blob"])
        self.assertEqual(freeze["sha256"], freeze["sha256_committed"])
        self.assertEqual(freeze["freeze_commit"],
                         self.git("log", "-1", "--format=%H").strip())
        self.assertEqual(env["commit"]["watched_dirty"], [])
        self.assertEqual(env["commit"]["sha"], self.git("rev-parse", "HEAD").strip())

    def test_git_status_output_is_not_stripped_of_its_first_column(self):
        """`git status --porcelain` leaves column 1 blank for a working-tree-only
        change, so a caller that strips its stdout deletes the first line's first
        character and turns ` M bench/ctr_bench.c` into `ench/ctr_bench.c` -- a path
        that matches no watched prefix, so a dirty tree reports clean. Needs a repo with
        exactly one modified file to show it, which is why it lives here."""
        self.write(os.path.join(self.root, "bench", "ctr_bench.c"), "/* edited */\n")
        raw = campaign.git("status", "--porcelain")
        self.assertTrue(raw.startswith(" M "), repr(raw))
        self.assertEqual(campaign.dirty_paths_from_porcelain(raw),
                         ["bench/ctr_bench.c"])
        with self.assertRaises(campaign.DirtyTree):
            campaign.require_clean(campaign.WATCHED_BUILD_INPUTS)

    def test_the_default_pinned_cpu_is_not_the_kernels_busiest(self):
        """CPU 0 is where the kernel puts timers and unbound IRQs by default, so it is
        the one CPU a measurement should not pick; --no-pin is how a run opts out of
        pinning entirely rather than by naming a different core."""
        self.assertIsNotNone(campaign.DEFAULT_CPU)
        self.assertNotEqual(campaign.DEFAULT_CPU, 0)
        self.assertIn("taskset",
                      campaign.harness_command("b", "c", 1, cpu=campaign.DEFAULT_CPU))
        self.assertNotIn("taskset", campaign.harness_command("b", "c", 1, cpu=None))

    def test_an_unpinned_run_reports_no_cpu_policy_rather_than_someone_elses(self):
        self.tuned_and_frozen()
        code, out = self.measure()
        self.assertEqual(code, 0, out)
        cpu = self.load(campaign.ENV_FILENAME)["at_start"]["cpu"]
        self.assertIsNone(cpu["pinned_cpu"])
        self.assertIsNone(cpu["governor"])
        self.assertEqual({r["freq_khz"] for r in self.rows()}, {"NA"})


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
