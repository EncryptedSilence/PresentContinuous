"""The campaign driver's guards, with no hardware in the loop.

Every test here runs on fabricated inputs -- a string of `git status` output, a
temporary directory holding a JSON file, a fake `/sys` tree, a runs.csv built by hand
-- because the guards exist precisely for the case where the machine is not
cooperating, and a test that needed the machine to cooperate could not check them.

Expected values are derived rather than observed. Where a constant is a judgement
call, the test asserts the *reason* for it (that `MIN_PUBLISHABLE_RUNS` is exactly the
sample size below which `summarize.modality` returns no verdict) rather than the
number, so that moving the number in one file and not the other fails here.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

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
              "in_head": True, "modified_in_worktree": False,
              "freeze_commit": "c0ffee", "freeze_commit_utc": "2026-01-01T00:00:00Z"}

    def test_a_real_freeze_names_the_commit_and_the_hash(self):
        note = campaign.freeze_note(self.FROZEN)
        self.assertIn("c0ffee", note)
        self.assertIn("abc", note)
        self.assertNotIn("NOT FROZEN", note)

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

    def setUp(self):
        self.before = set(os.listdir(os.path.join(campaign.ROOT, "results", "v2")))

    def tearDown(self):
        self.assertEqual(
            set(os.listdir(os.path.join(campaign.ROOT, "results", "v2"))), self.before,
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


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
