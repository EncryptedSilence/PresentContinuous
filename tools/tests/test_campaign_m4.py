"""The Cortex-M4 counter-mode campaign's pure guards.

tools/campaign_m4.py flashes firmware and reads it back, which needs a board; these tests
cover the parts that decide something without one -- the pass/fail threshold, the winner
selection, and the freeze check -- because those are where a wrong constant or a flipped
comparison would publish a plausible-looking but wrong verdict. tools/tests/mutate.py
mutates exactly these and expects this file to notice.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import campaign_m4  # noqa: E402


class TestThreshold(unittest.TestCase):
    def test_twelve_mbit_is_one_and_a_half_megabytes_per_second(self):
        # 12 Mbit/s of video / 8 bits = 1.5e6 bytes/s = 1.5 MB/s. The firmware's mb_per_sec
        # column is MB/s, so this is the number the verdict compares against.
        self.assertEqual(campaign_m4.VIDEO_BITS_PER_S, 12_000_000)
        self.assertAlmostEqual(campaign_m4.THRESHOLD_MB_S, 1.5)

    def test_at_the_threshold_the_device_sustains_the_stream(self):
        # The boundary matters: exactly 1.5 MB/s is a pass, not a fail. A `>` instead of
        # `>=` would call the marginal cipher a failure.
        self.assertEqual(campaign_m4._verdict(1.5), "PASS")

    def test_just_below_the_threshold_fails(self):
        self.assertEqual(campaign_m4._verdict(1.4999), "FAIL")

    def test_comfortably_above_passes(self):
        self.assertEqual(campaign_m4._verdict(1.57), "PASS")


class TestPickWinner(unittest.TestCase):
    def _row(self, impl, cyc, status="ok"):
        return {"impl": impl, "cyc_per_byte": cyc, "status": status,
                "mb_per_sec": None, "cyc_per_byte_min": cyc, "ns_per_op": 0.0,
                "cipher": "c", "rounds": 1, "config": "product"}

    def test_the_fastest_backend_wins(self):
        rows = [self._row("ctr-table", 162.0),
                self._row("ctr-bitslice-u64", 125.8),
                self._row("ctr-bitslice-u32", 106.8)]
        self.assertEqual(campaign_m4.pick_winner(rows)["impl"], "ctr-bitslice-u32")

    def test_fastest_is_the_minimum_not_the_maximum(self):
        # The mutation this kills is min -> max. State it as its own case so the intent is
        # unmistakable: the winner is the LOWEST cycles/byte.
        rows = [self._row("slow", 200.0), self._row("fast", 100.0)]
        self.assertEqual(campaign_m4.pick_winner(rows)["impl"], "fast")

    def test_a_failing_backend_is_never_the_winner(self):
        rows = [self._row("kat-failer", 1.0, status="KAT_FAIL"),
                self._row("real", 150.0)]
        self.assertEqual(campaign_m4.pick_winner(rows)["impl"], "real")

    def test_no_ok_backend_is_no_winner(self):
        rows = [self._row("a", 1.0, status="KAT_FAIL")]
        self.assertIsNone(campaign_m4.pick_winner(rows))


class TestFreezeVerdict(unittest.TestCase):
    def test_uncommitted_is_not_frozen(self):
        in_head, modified = campaign_m4.freeze_verdict(None, "abc")
        self.assertFalse(in_head)
        self.assertTrue(modified)

    def test_committed_and_unchanged_is_frozen(self):
        in_head, modified = campaign_m4.freeze_verdict("abc", "abc")
        self.assertTrue(in_head)
        self.assertFalse(modified)

    def test_committed_but_edited_after_is_modified(self):
        # The case the freeze exists for: a winners file changed after its commit. Equal
        # blobs mean unchanged; different blobs must read as modified.
        in_head, modified = campaign_m4.freeze_verdict("abc", "def")
        self.assertTrue(in_head)
        self.assertTrue(modified)


class TestWinnerFnMap(unittest.TestCase):
    def test_every_backend_name_maps_to_a_c_function(self):
        # A winner the firmware can report but that WINNER_FN does not know would make
        # write_winners_mk raise KeyError at freeze time. The eight names here are the
        # portfolio fw/m4/ctr_m4_main.c's IMPLS[] can emit.
        expected = {"ctr-ref", "ctr-table", "ctr-table-x2", "ctr-table-x4",
                    "ctr-table-x8", "ctr-table-x16", "ctr-bitslice-u64",
                    "ctr-bitslice-u32"}
        self.assertEqual(set(campaign_m4.WINNER_FN), expected)


if __name__ == "__main__":
    unittest.main()
