"""The mutation harness's own tests.

The harness exists to answer "would the suite notice if this constant were wrong?".
That answer is worthless unless the harness is loud when it cannot apply a mutation --
which is exactly how an earlier version of it reported fourteen consecutive kills
against code that was no longer there. The patterns had stopped matching, nothing said
so, and every no-op edit was scored as a pass.

So the property under test here is not "the mutations kill things" (that is what
running the harness tells you) but "the harness fails rather than shrugs when its
patterns rot". A refactor that moves the statistics code must break this file, not
quietly reduce the harness to a no-op that congratulates whoever runs it.
"""
import os
import unittest

from tools.tests import mutate


class TestApplyMutation(unittest.TestCase):
    ONE = mutate.Mutation("t", "tools/summarize.py", "ALPHA", "BETA", "a constant")

    def test_a_single_match_is_applied(self):
        self.assertEqual(mutate.apply_mutation("x = ALPHA\n", self.ONE), "x = BETA\n")

    def test_a_missing_pattern_raises_rather_than_skipping(self):
        """The failure that produced a false clean sweep. A mutation that cannot be
        applied must stop the run; returning the text unchanged makes the suite pass
        and the harness call that a kill."""
        with self.assertRaises(mutate.PatternNotFound) as caught:
            mutate.apply_mutation("x = GAMMA\n", self.ONE)
        self.assertIn("appears 0 times", str(caught.exception))
        self.assertIn("tools/summarize.py", str(caught.exception))

    def test_an_ambiguous_pattern_raises_too(self):
        """Two matches means the pattern has stopped identifying the one line it was
        written for, so the edit is no longer the edit it claims to be."""
        with self.assertRaises(mutate.PatternNotFound) as caught:
            mutate.apply_mutation("ALPHA\nALPHA\n", self.ONE)
        self.assertIn("appears 2 times", str(caught.exception))

    def test_the_message_names_the_mutation_and_its_pattern(self):
        """A rotted pattern has to be fixable from the message alone."""
        with self.assertRaises(mutate.PatternNotFound) as caught:
            mutate.apply_mutation("", self.ONE)
        self.assertIn("'t'", str(caught.exception))
        self.assertIn("ALPHA", str(caught.exception))


class TestMutationsStillApply(unittest.TestCase):
    """Every mutation must still match the tree exactly once.

    This is the check that keeps the harness honest between runs of it: a rename or a
    reflow that leaves a mutation unmatched silently drops whatever that mutation was
    defending, and the next `mutate.py` run would otherwise report a smaller sweep as
    though it were a complete one. Here it fails in `make test` instead.
    """

    def test_each_pattern_appears_exactly_once_in_its_file(self):
        for mutation in mutate.MUTATIONS + mutate.CONTROLS:
            with self.subTest(mutation=mutation.name):
                path = os.path.join(mutate.REPO_ROOT, mutation.path)
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                self.assertEqual(
                    1, text.count(mutation.old),
                    "mutation %r no longer identifies one line of %s; the constant "
                    "it defends (%s) is unchecked until the pattern is updated"
                    % (mutation.name, mutation.path, mutation.defends))

    def test_each_mutation_actually_changes_the_text(self):
        for mutation in mutate.MUTATIONS + mutate.CONTROLS:
            with self.subTest(mutation=mutation.name):
                self.assertNotEqual(mutation.old, mutation.new)

    def test_mutation_names_are_unique(self):
        names = [m.name for m in mutate.MUTATIONS + mutate.CONTROLS]
        self.assertEqual(len(names), len(set(names)))


class TestNegativeControls(unittest.TestCase):
    """The instrument's calibration.

    Without these the harness had no way to notice that it was killing everything.
    It ran `unittest discover` over `tools/tests` inside the mutated copy, which
    collected this very file, whose pattern check then failed against the file that
    had just been mutated -- for every mutation, regardless of what the mutation did.
    Every mutation self-killed, the sweep reported 25 killed and 0 survived, and no
    survivor was reportable under any circumstances. A control that must survive is
    what turns that from an invisible defect into a failed run.
    """

    def test_controls_exist(self):
        self.assertTrue(mutate.CONTROLS)
        for control in mutate.CONTROLS:
            self.assertTrue(control.control)

    def test_a_control_only_ever_edits_a_comment(self):
        """A control that touched real code would be a mutation, and its survival
        would be a finding rather than a calibration."""
        for control in mutate.CONTROLS:
            with self.subTest(control=control.name):
                self.assertTrue(control.old.lstrip().startswith("#"))
                self.assertTrue(control.new.lstrip().startswith("#"))

    def test_controls_cover_both_subject_files(self):
        """A control in only one file would leave the other uncalibrated."""
        self.assertEqual({c.path for c in mutate.CONTROLS},
                         {m.path for m in mutate.MUTATIONS})

    def test_real_mutations_are_not_marked_as_controls(self):
        for mutation in mutate.MUTATIONS:
            self.assertFalse(mutation.control, mutation.name)


class TestSubjectExclusion(unittest.TestCase):
    """This file asserts over the *source text* of the subject, so under any mutation
    it fails for a reason that has nothing to do with the mutation. It must therefore
    not be part of what the sweep runs. Its real job -- catching pattern rot -- is
    done in `make test`, where the tree is unmutated and the assertion means
    something."""

    def test_this_file_is_excluded_from_the_subject(self):
        self.assertIn("tools/tests/test_mutate.py", mutate.EXCLUDED_FROM_SUBJECT)

    def test_the_excluded_paths_exist_in_the_tree(self):
        """An exclusion for a file that has been renamed silently stops excluding."""
        for relative in mutate.EXCLUDED_FROM_SUBJECT:
            self.assertTrue(
                os.path.exists(os.path.join(mutate.REPO_ROOT, relative)), relative)


class TestFailureParsing(unittest.TestCase):
    """A mutation is killed when the suite names tests that were not already failing.
    Miscounting here turns a survivor into a kill, which is the direction that
    matters."""

    OUTPUT = (
        "FAIL: test_one (tools.tests.test_summarize.TestA.test_one)\n"
        "ERROR: test_two (tools.tests.test_make_tables.TestB.test_two)\n"
        "Ran 150 tests in 3.2s\n"
        "FAILED (failures=1, errors=1)\n")

    def test_both_failures_and_errors_are_counted(self):
        self.assertEqual(
            mutate.failing_tests(self.OUTPUT),
            {"tools.tests.test_summarize.TestA.test_one",
             "tools.tests.test_make_tables.TestB.test_two"})

    def test_a_clean_run_names_nothing(self):
        self.assertEqual(mutate.failing_tests("Ran 150 tests\n\nOK\n"), set())

    def test_the_word_failed_alone_is_not_a_test_id(self):
        self.assertEqual(mutate.failing_tests("FAILED (failures=1)\n"), set())


if __name__ == "__main__":
    unittest.main()
