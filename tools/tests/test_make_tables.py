"""The table generator, checked on the two things that make a table wrong in a way
a reader cannot see: publishing from a file that says it is not a measurement, and
turning a group of statistically indistinguishable ciphers back into a ranking.

The numeric content is checked as "the number in the TeX is the number in the CSV,
formatted", because the whole point of this file existing is that no figure is
retyped by hand.
"""
import os
import tempfile
import unittest

from tools import make_tables, summarize


HEADER = ",".join(summarize.SUMMARY_COLUMNS)

# The modality block, twice per row: absolute then ratio. Spelled out as a helper so
# a fixture row reads as its measurement rather than as sixteen commas.
UNIMODAL = "unimodal,1,,,0.4,not flagged"
# The third state, and the one this file previously typeset identically to the
# second. `mode_count` is blank rather than 1 and `gap_over_spread` is `n/a`,
# because nothing was measured to count or to divide.
NOT_JUDGED = "not-judged,,,,n/a,sample of 9 is too small to judge modality"


def row(cipher, impl, median, lo, hi, ratio, r_lo, r_hi, top, r_top,
        size=65536, published="yes", n_runs=25,
        modality=UNIMODAL, ratio_modality=UNIMODAL):
    return ",".join(str(f) for f in (
        "x86", size, cipher, impl, n_runs, median, lo, hi, "present-80-r16",
        ratio, r_lo, r_hi, modality, ratio_modality, top, r_top, published))


# Two ciphers whose absolute intervals overlap (a top group of two) and one that is
# clearly behind. The ratio column is exact by construction.
ROWS = [
    row("present-80-r16", "ctr-table", 416.0, 400.0, 430.0, 1.0, 1.0, 1.0,
        "yes", "yes"),
    row("cipher-D", "ctr-bitslice-avx2", 366.0, 350.0, 410.0, 0.88, 0.86, 0.90,
        "yes", "no"),
    row("aes-r5", "ctr-table", 120.0, 118.0, 122.0, 0.288, 0.285, 0.291,
        "no", "no"),
    row("present-80-r16", "ctr-table", 900.0, 890.0, 910.0, 1.0, 1.0, 1.0,
        "yes", "yes", size=4096, published="no"),
]


def write_summary(directory, provenance="CAMPAIGN", rows=ROWS, header=HEADER,
                  extra_headers=("# ranking_stability: STABLE",)):
    path = os.path.join(directory, "summary.csv")
    with open(path, "w", encoding="ascii") as fh:
        if provenance is not None:
            fh.write("# provenance: %s\n" % provenance)
        for line in extra_headers:
            fh.write(line + "\n")
        fh.write(header + "\n")
        for line in rows:
            fh.write(line + "\n")
    return path


class TestProvenanceRefusal(unittest.TestCase):
    def test_a_smoke_run_is_refused(self):
        """The marker exists precisely to stop a trial run reaching the paper, so
        the generator must not merely warn."""
        with tempfile.TemporaryDirectory() as d:
            path = write_summary(d, provenance="SMOKE-RUN")
            with self.assertRaises(make_tables.SmokeRunRefused):
                make_tables.render(path)

    def test_a_smoke_run_leaves_no_partial_table_behind(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_summary(d, provenance="SMOKE-RUN")
            out = os.path.join(d, "out")
            with self.assertRaises(make_tables.SmokeRunRefused):
                make_tables.write_table(path, out)
            self.assertFalse(os.path.isdir(out) and os.listdir(out))

    def test_a_decorated_smoke_run_marker_is_also_refused(self):
        """Exact equality against `SMOKE-RUN` walks straight past these. Task 8's
        campaign.py, which writes the markers, has not been written, so the grammar
        is not fixed anywhere yet."""
        for marker in ("SMOKE-RUN (3 runs, do not publish)",
                       "SMOKE RUN",
                       "smoke-run, preliminary",
                       "TRIAL"):
            with tempfile.TemporaryDirectory() as d:
                path = write_summary(d, provenance=marker)
                with self.assertRaises(make_tables.SmokeRunRefused, msg=marker):
                    make_tables.render(path)

    def test_a_campaign_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn("tabular", make_tables.render(write_summary(d)))

    def test_an_unknown_marker_is_rendered_but_says_so_in_the_output(self):
        with tempfile.TemporaryDirectory() as d:
            tex = make_tables.render(write_summary(d, provenance=None))
            self.assertIn("UNKNOWN", tex)

    def test_require_campaign_upgrades_unknown_to_a_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_summary(d, provenance=None)
            with self.assertRaises(make_tables.SmokeRunRefused):
                make_tables.render(path, require_campaign=True)


class TestContent(unittest.TestCase):
    def render(self, **kw):
        with tempfile.TemporaryDirectory() as d:
            return make_tables.render(write_summary(d, **kw))

    def test_only_the_published_size_reaches_the_table(self):
        tex = self.render()
        self.assertIn("65536", tex)
        self.assertNotIn("900.0", tex)

    def test_every_published_cipher_appears_once(self):
        tex = self.render()
        for cipher in ("present-80-r16", "cipher-D", "aes-r5"):
            self.assertEqual(tex.count(cipher + "}"), 1, cipher)

    def test_the_figures_are_the_csv_figures_formatted(self):
        tex = self.render()
        self.assertIn("416.0", tex)
        self.assertIn("400.0", tex)
        self.assertIn("430.0", tex)
        self.assertIn("0.880", tex)

    def test_the_top_group_is_marked_and_the_laggard_is_not(self):
        tex = self.render()
        rows = {ln.split("&")[0]: ln for ln in tex.splitlines() if "&" in ln}
        leader = [ln for k, ln in rows.items() if "present-80-r16" in k][0]
        laggard = [ln for k, ln in rows.items() if "aes-r5" in k][0]
        self.assertIn(make_tables.TOP_GROUP_MARK, leader)
        self.assertNotIn(make_tables.TOP_GROUP_MARK, laggard)

    def test_a_group_of_one_is_a_clear_leader_and_is_not_marked(self):
        """Only the leader is in the ratio group in ROWS. Marking it and then saying
        marked rows are not ranked against each other would assert the opposite of
        what the measurement found."""
        tex = self.render()
        self.assertNotIn(make_tables.RATIO_GROUP_MARK, tex)
        # ... while the two-member absolute group is still marked and explained.
        self.assertIn(make_tables.TOP_GROUP_MARK, tex)

    def test_the_group_is_explained_in_a_note_not_only_by_a_symbol(self):
        tex = self.render()
        self.assertIn("not ranked", tex.lower())

    def test_a_multimodal_row_reports_its_modes_instead_of_an_interval(self):
        """An interval around the median of a two-state sample describes neither
        state. The table must show the states."""
        rows = list(ROWS)
        rows[1] = row("cipher-D", "ctr-bitslice-avx2", 304.0, 193.0, 416.0,
                      0.73, 0.46, 1.0, "yes", "no", n_runs=24,
                      modality="multimodal,2,193.0;415.3,0.5;0.5,252.8,two states")
        tex = self.render(rows=rows)
        line = [ln for ln in tex.splitlines() if "cipher-D" in ln][0]
        # 415.3 is a mode median and appears nowhere in the interval, so finding it
        # proves the modes were rendered rather than the bracket.
        self.assertIn("415.3", line)
        self.assertIn("193.0", line)
        self.assertNotIn("[193.0, 416.0]", tex)
        self.assertNotIn("304.0", tex)
        self.assertIn(make_tables.MULTIMODAL_MARK, line)
        self.assertIn("50", line)  # the share of runs in each state
        self.assertIn("multimodal", tex.lower())

    def test_underscores_in_names_are_escaped(self):
        rows = [row("odd_name", "ctr_table", 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
                    "yes", "yes")]
        tex = self.render(rows=rows)
        self.assertNotIn("odd_name", tex)
        self.assertIn(r"odd\_name", tex)

    def test_the_baseline_is_named_in_the_ratio_column(self):
        self.assertIn("present-80-r16", self.render())

    def test_the_stability_verdict_is_carried_into_the_table(self):
        self.assertIn("STABLE", self.render())

    def test_the_run_count_is_a_range_when_the_rows_disagree(self):
        """`n_runs` is per (cipher, size) and a discarded run lowers it for one
        cipher only. Printing rows[0]'s count as the count states a number that is
        false for every other row."""
        rows = [ROWS[0],
                row("cipher-D", "ctr", 366.0, 350.0, 410.0, 0.88, 0.86, 0.90,
                    "yes", "no", n_runs=22)]
        with tempfile.TemporaryDirectory() as d:
            tex = make_tables.render(write_summary(d, rows=rows))
        self.assertIn("22 to 25 runs", tex)
        self.assertIn("varying by cipher", tex)

    def test_a_single_run_count_is_stated_plainly(self):
        self.assertIn("25 runs per cipher", self.render())

    def test_the_measured_coverage_is_carried_into_the_caption(self):
        with tempfile.TemporaryDirectory() as d:
            tex = make_tables.render(write_summary(
                d, extra_headers=("# ranking_stability: STABLE",
                                  "# ci_coverage: nominal 95%; measured 0.86-0.91")))
        self.assertIn("Interval coverage", tex)
        self.assertIn("0.86-0.91", tex)


class TestRatioModality(unittest.TestCase):
    """The critical finding. The ratio is the declared primary quantity, and it was
    the one column that could never refuse to print a bracket."""

    # The reviewer's reproduction: per-run ratios of 0.526 once, 1.132 sixteen times
    # and 2.433 eight times, from runs that straddle a host state transition.
    STRADDLED = row("cipher-D", "ctr", 215.0, 210.0, 220.0,
                    1.132, 1.132, 2.433, "no", "no",
                    ratio_modality="multimodal,2,1.132;2.433,0.68;0.32,inf,two states")

    def render(self, rows):
        with tempfile.TemporaryDirectory() as d:
            return make_tables.render(write_summary(d, rows=rows))

    def test_a_bimodal_ratio_prints_its_states_not_a_bracket(self):
        tex = self.render([ROWS[0], self.STRADDLED])
        line = [ln for ln in tex.splitlines() if "cipher-D" in ln][0]
        self.assertIn("2.433", line)
        self.assertIn("1.132", line)
        self.assertNotIn("[1.132, 2.433]", tex)
        self.assertIn(make_tables.MULTIMODAL_MARK, line)
        self.assertIn("68", line)  # the share of runs in the lower state

    def test_the_drift_cancels_claim_is_withdrawn_when_it_did_not(self):
        """`so drift common to a run cancels` is the sentence the finding singled
        out: asserted unconditionally under a table where it demonstrably had not."""
        tex = self.render([ROWS[0], self.STRADDLED])
        self.assertNotIn("drift common to a run cancels", tex)
        self.assertIn("did not cancel", tex)
        self.assertIn("straddling", tex)

    def test_the_claim_is_made_when_the_check_supports_it(self):
        tex = self.render(list(ROWS))
        self.assertIn("checked for a second mode and none was found", tex)
        self.assertNotIn("did not cancel", tex)

    def test_an_absolute_bracket_is_still_printed_for_a_bimodal_ratio_row(self):
        """Only the column whose sample is bimodal loses its interval."""
        line = [ln for ln in self.render([ROWS[0], self.STRADDLED]).splitlines()
                if "cipher-D" in ln][0]
        self.assertIn("[210.0, 220.0]", line)


class TestNotJudged(unittest.TestCase):
    """The third modality state. `summary.csv` learned to say `not-judged` in round 1;
    the table went on rendering it as an ordinary bracket with no mark, and the caption
    went on claiming the check had run and come back clean. Raising MODALITY_MIN_N from
    8 to 12 is what put a realistic 8-to-11-run campaign into this band.
    """

    UNJUDGED = row("cipher-D", "ctr", 418.4, 416.7, 420.1,
                   1.137, 1.137, 1.137, "no", "no", n_runs=9,
                   modality=NOT_JUDGED, ratio_modality=NOT_JUDGED)

    def render(self, rows):
        with tempfile.TemporaryDirectory() as d:
            return make_tables.render(write_summary(d, rows=rows))

    def test_the_drift_cancelled_claim_is_not_made_for_an_unjudged_ratio(self):
        """The exact finding: `if ratio_multimodal:` sent `not-judged` down the else
        branch, which asserts the check ran and found nothing. It did not run."""
        tex = self.render([ROWS[0], self.UNJUDGED])
        self.assertNotIn("checked for a second mode and none was found", tex)
        self.assertNotIn("so drift common to a run cancelled", tex)
        self.assertIn("not established", tex)

    def test_the_three_states_produce_three_different_captions(self):
        """Checked-and-clean, checked-and-flagged, and not-judged must not collapse
        into two. A pair of branches over three outcomes is what caused this."""
        clean = self.render(list(ROWS))
        flagged = self.render([ROWS[0], TestRatioModality.STRADDLED])
        unjudged = self.render([ROWS[0], self.UNJUDGED])
        self.assertIn("none was found", clean)
        self.assertNotIn("not established", clean)
        self.assertIn("did not cancel", flagged)
        self.assertNotIn("none was found", flagged)
        self.assertIn("not established", unjudged)
        self.assertNotIn("did not cancel", unjudged)

    def test_an_unjudged_cell_is_marked_in_the_body(self):
        """A row nobody could judge must not be typeset identically to a row that
        passed. The interval is still printed -- the spread is real -- but the mark is
        what stops it reading as having cleared a check that never ran."""
        line = [ln for ln in self.render([ROWS[0], self.UNJUDGED]).splitlines()
                if "cipher-D" in ln][0]
        self.assertIn("418.4 [416.7, 420.1]", line)
        self.assertIn(make_tables.NOT_JUDGED_MARK, line)
        self.assertEqual(2, line.count(make_tables.NOT_JUDGED_MARK))

    def test_a_judged_row_carries_no_such_mark(self):
        for line in self.render(list(ROWS)).splitlines():
            self.assertNotIn(make_tables.NOT_JUDGED_MARK, line)

    def test_the_mark_is_explained_only_when_it_is_used(self):
        self.assertIn("could not judge", self.render([ROWS[0], self.UNJUDGED]))
        self.assertNotIn("could not judge", self.render(list(ROWS)))

    def test_the_unjudged_mark_is_distinct_from_the_multimodal_one(self):
        """Sharing a symbol would put "we looked and found two states" and "we never
        looked" behind the same footnote."""
        self.assertNotEqual(make_tables.NOT_JUDGED_MARK,
                            make_tables.MULTIMODAL_MARK)
        self.assertNotEqual(make_tables.NOT_JUDGED_MARK, make_tables.TOP_GROUP_MARK)
        self.assertNotEqual(make_tables.NOT_JUDGED_MARK, make_tables.RATIO_GROUP_MARK)

    def test_only_the_unjudged_side_of_a_row_is_marked(self):
        """A campaign can have enough runs for the absolute sample and not for the
        ratio, or the reverse, when a run was discarded for one cipher."""
        half = row("cipher-E", "ctr", 300.0, 295.0, 305.0, 0.9, 0.88, 0.92,
                   "no", "no", ratio_modality=NOT_JUDGED)
        line = [ln for ln in self.render([ROWS[0], half]).splitlines()
                if "cipher-E" in ln][0]
        throughput, ratio = line.split("&")[2], line.split("&")[3]
        self.assertNotIn(make_tables.NOT_JUDGED_MARK, throughput)
        self.assertIn(make_tables.NOT_JUDGED_MARK, ratio)


class TestStabilityCaption(unittest.TestCase):
    """A verdict that is right about half the time is tolerable in a log and not in a
    caption. summarize.py decides publishability because only it sees every size."""

    def render(self, headers):
        with tempfile.TemporaryDirectory() as d:
            return make_tables.render(write_summary(d, extra_headers=headers))

    def test_an_unpublishable_unstable_verdict_stays_out_of_the_caption(self):
        tex = self.render((
            "# ranking_stability: UNSTABLE -- ranking differs between size 4096 and "
            "size 65536: a, b vs b, a",
            "# ranking_stability_publishable: no -- only among ciphers whose "
            "intervals overlap",
        ))
        self.assertNotIn("UNSTABLE", tex)
        self.assertNotIn("Ranking stability", tex)

    def test_a_publishable_unstable_verdict_is_carried_in_full(self):
        tex = self.render((
            "# ranking_stability: UNSTABLE -- ranking differs between size 4096 and "
            "size 65536: a, b vs b, a",
            "# ranking_stability_publishable: yes -- a/b changed places with "
            "non-overlapping intervals at both",
        ))
        self.assertIn("UNSTABLE", tex)
        self.assertIn("4096", tex)

    def test_a_stable_verdict_is_carried(self):
        tex = self.render(("# ranking_stability: STABLE -- identical at all 3 sizes",
                           "# ranking_stability_publishable: yes"))
        self.assertIn("STABLE", tex)

    def test_an_unstable_verdict_without_the_field_is_not_carried(self):
        """A summary written before the publishability field existed. The spurious
        direction is UNSTABLE, so only a STABLE verdict travels."""
        tex = self.render(("# ranking_stability: UNSTABLE -- 4096 vs 65536",))
        self.assertNotIn("Ranking stability", tex)


class TestRowFiltering(unittest.TestCase):
    def test_rows_that_are_not_measurements_are_dropped_when_status_exists(self):
        header = HEADER + ",status"
        rows = [ROWS[0] + ",measured",
                ROWS[2] + ",unwritten"]
        with tempfile.TemporaryDirectory() as d:
            tex = make_tables.render(write_summary(d, rows=rows, header=header))
        self.assertIn("present-80-r16", tex)
        self.assertNotIn("aes-r5", tex)

    def test_a_summary_without_a_status_column_is_not_a_key_error(self):
        with tempfile.TemporaryDirectory() as d:
            make_tables.render(write_summary(d))

    def test_a_summary_with_no_published_rows_is_refused(self):
        rows = [ROWS[3]]  # published=no
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                make_tables.render(write_summary(d, rows=rows))


class TestOutputPath(unittest.TestCase):
    def test_the_target_comes_from_the_directory_not_from_a_flag(self):
        with tempfile.TemporaryDirectory() as d:
            target_dir = os.path.join(d, "results", "v2", "a7")
            os.makedirs(target_dir)
            path = write_summary(target_dir)
            out = os.path.join(d, "tables")
            written = make_tables.write_table(path, out)
            self.assertEqual(os.path.basename(written), "a7-ctr.tex")
            self.assertTrue(os.path.exists(written))

    def test_the_file_is_reproducible(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_summary(d)
            out = os.path.join(d, "tables")
            with open(make_tables.write_table(path, out), "rb") as fh:
                first = fh.read()
            with open(make_tables.write_table(path, out), "rb") as fh:
                second = fh.read()
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
