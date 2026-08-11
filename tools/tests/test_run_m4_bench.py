"""The M4 driver's git-provenance parse: a dirty build input must be seen as dirty.

`tools/run_m4_bench.py` stamps every results/m4-speed.csv with the commit at HEAD and
refuses to run when a build input is modified in the working tree, so that the commit
always describes the firmware bytes measured. The refusal is only as good as its parse
of `git status --porcelain`, and that parse has one adversarial case: git leaves the
index column blank for a working-tree-only change (`" M path"`), so a caller that
`.strip()`s the command's stdout deletes the first line's leading space and a parser
that then slices a fixed `line[3:]` reads the path one character short -- it matches no
watched prefix, the tree is called clean, and the CSV is stamped with a commit that
does not describe its binaries. These tests pin both halves of the fix: git() keeps the
leading column, and build_state_paths() recovers the path even if some future caller
does not.
"""
import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import run_m4_bench  # noqa: E402


class TestGitPreservesLeadingColumn(unittest.TestCase):
    def test_git_keeps_the_blank_index_column(self):
        """git() must not strip the leading blank the status field carries.

        A working-tree-only modification prints `" M path"`; stripping stdout turns
        that into `"M path"`, which is not porcelain v1 any more.
        """
        completed = types.SimpleNamespace(stdout=" M fw/m4/ctr_m4_main.c\n")
        with mock.patch("run_m4_bench.subprocess.run", return_value=completed):
            out = run_m4_bench.git("status", "--porcelain")
        self.assertEqual(out, " M fw/m4/ctr_m4_main.c")

    def test_git_still_drops_the_trailing_newline(self):
        completed = types.SimpleNamespace(stdout="abc123\n")
        with mock.patch("run_m4_bench.subprocess.run", return_value=completed):
            self.assertEqual(run_m4_bench.git("rev-parse", "HEAD"), "abc123")


class TestBuildStatePaths(unittest.TestCase):
    """build_state_paths() with git() monkeypatched, so the parse is tested in
    isolation from the machine's actual tree state."""

    def _paths(self, porcelain):
        with mock.patch.object(run_m4_bench, "git", lambda *a: porcelain):
            # An out_path that is not one of the dirty files, so nothing is excluded
            # for being the CSV being written.
            return run_m4_bench.build_state_paths(os.path.join(run_m4_bench.ROOT,
                                                               "results/does-not-exist.csv"))

    def test_a_single_modified_build_input_is_detected_as_dirty(self):
        """The case the whole fix is for: exactly one modified build input, so its
        porcelain line is the first (and only) line and carries the blank column."""
        self.assertEqual(self._paths(" M fw/m4/ctr_m4_main.c\n"),
                         [" M fw/m4/ctr_m4_main.c"])

    def test_a_leading_column_eaten_by_a_stripping_caller_still_parses(self):
        """Defence in depth: even handed `"M path"` (the column already eaten), the
        status-field-aware parse recovers the path, where a fixed `line[3:]` would
        yield `"/m4/ctr_m4_main.c"` and miss the watched prefix."""
        self.assertEqual(self._paths("M fw/m4/ctr_m4_main.c\n"),
                         ["M fw/m4/ctr_m4_main.c"])

    def test_a_dirty_file_outside_the_watched_set_is_ignored(self):
        self.assertEqual(self._paths(" M README.md\n"), [])

    def test_a_renames_destination_is_matched(self):
        # A rename out of src/ into an unwatched dir changes the build; the parser must
        # look at the destination, not the source.
        self.assertEqual(self._paths('R  notes/x.c -> src/present_ctr_bitslice.c\n'),
                         ['R  notes/x.c -> src/present_ctr_bitslice.c'])

    def test_a_clean_tree_is_not_dirty(self):
        self.assertEqual(self._paths(""), [])


if __name__ == "__main__":
    unittest.main()
