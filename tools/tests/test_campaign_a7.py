"""Tests for the Cortex-A7 campaign driver (tools/campaign_a7.py).

Everything here runs on the x86 host with no board: the board is behind
`campaign_a7.Board`, and these tests inject a FakeBoard with scripted temperatures,
clocks and canned ctr_bench output. The pure guard/gate/randomisation logic is tested
directly; the EndToEnd suite at the bottom drives campaign_a7.main against a throwaway
git repository, exactly as tools/tests/test_campaign.py does for the x86 flow.
"""

import contextlib
import csv
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import campaign, campaign_a7, cipher_set, summarize

CIPHERS = [name for _p, name, _r in cipher_set.resolve()]


class FakeBoard:
    """A Cortex-A7 stand-in with scripted sysfs and canned ctr_bench output."""

    def __init__(self, temp_millic=60000, cur_khz=campaign_a7.PINNED_KHZ,
                 pin_on_performance=True):
        # temp_millic may be a list consumed one reading at a time (clamping at the end),
        # so a scenario can be "hot, hot, then cool".
        self._temp_seq = list(temp_millic) if isinstance(temp_millic, list) else None
        self._temp_fixed = None if self._temp_seq is not None else temp_millic
        self._temp_i = 0
        self.cur_khz = cur_khz
        self.pin_on_performance = pin_on_performance
        self.governors = {"/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor" % c:
                          "ondemand" for c in range(4)}
        self.set_governor_calls = []
        self.rsynced = False
        self.built = False
        self.run_count = 0

    # -- sysfs --
    def read_temp_millic(self):
        if self._temp_seq is not None:
            value = self._temp_seq[min(self._temp_i, len(self._temp_seq) - 1)]
            self._temp_i += 1
            return value
        return self._temp_fixed

    def read_cur_khz(self, cpu):
        return self.cur_khz

    def read_governors(self):
        return dict(self.governors)

    def set_governor(self, name):
        self.set_governor_calls.append(name)
        for key in self.governors:
            self.governors[key] = name
        if name == "performance" and self.pin_on_performance:
            self.cur_khz = campaign_a7.PINNED_KHZ
        if name == "ondemand":
            self.cur_khz = 816000

    # -- build/transport --
    def rsync_tree(self):
        self.rsynced = True

    def build(self):
        self.built = True

    def put_script(self, *args):
        pass

    def binary_sha256(self):
        return "fakesha256"

    def probe_env(self):
        return {"hostname": "fake-a7", "uname": "Linux fake-a7 armv7l",
                "gcc": "gcc 14.2.0", "governors": self.read_governors(),
                "scaling_cur_khz": self.read_cur_khz(campaign_a7.BOARD_CPU),
                "scaling_max_khz": campaign_a7.PINNED_KHZ,
                "thermal_zone0_millic": self.read_temp_millic()}

    # -- harness --
    def list_backends(self):
        return {c: {"ctr-ref", "ctr-fast"} for c in CIPHERS}

    def run_ctr_bench(self, selects, size, trials=None, kat=False):
        self.run_count += 1
        chosen = {}
        tokens = iter(selects)
        for tok in tokens:
            if tok == "--select":
                cipher, impl = next(tokens).split("=", 1)
                chosen[cipher] = impl
        rows, entries = [], []
        pairs = (list(chosen.items()) if chosen
                 else [(c, i) for c in CIPHERS for i in ("ctr-ref", "ctr-fast")])
        for cipher, impl in pairs:
            rows.append(self._row(cipher, impl, size))
            entries.append({"cipher": cipher, "impl": impl, "rounds": 16,
                            "size_bytes": size, "pass": True,
                            "check": "matches-ctr-ref", "offset": None})
        return rows, (entries if kat else None)

    def _row(self, cipher, impl, size):
        base = 200.0 if impl == "ctr-fast" else 100.0
        # A per-cipher factor so ratios against the baseline are not all 1.0, plus a
        # small per-run jitter so the bootstrap sees a real spread.
        factor = 1.0 + (CIPHERS.index(cipher) * 0.1)
        jitter = float(self.run_count % 4)
        return {"cipher": cipher, "impl": impl, "size_bytes": str(size),
                "block_bytes": "8", "rounds": "16",
                "mbit_per_sec": "%.4f" % (base * factor + jitter),
                "ns_median": "1000.0", "ns_min": "1000.0",
                "prepare_ns": "10.0", "tsc_per_byte": "1.0"}


# --- pure logic ----------------------------------------------------------------------

class TestCipherOrders(unittest.TestCase):
    def test_each_run_uses_random_seeded_by_seed_plus_index(self):
        import random
        orders = campaign_a7.cipher_orders(CIPHERS, 5, seed=7)
        for i, order in enumerate(orders):
            expected = list(CIPHERS)
            random.Random(7 + i).shuffle(expected)
            self.assertEqual(order, expected)

    def test_orders_are_reproducible_for_a_seed(self):
        a = campaign_a7.cipher_orders(CIPHERS, 25, seed=0)
        b = campaign_a7.cipher_orders(CIPHERS, 25, seed=0)
        self.assertEqual(a, b)

    def test_a_different_seed_gives_different_orders(self):
        a = campaign_a7.cipher_orders(CIPHERS, 25, seed=0)
        b = campaign_a7.cipher_orders(CIPHERS, 25, seed=1)
        self.assertNotEqual(a, b)

    def test_every_order_is_a_permutation_of_the_cipher_set(self):
        for order in campaign_a7.cipher_orders(CIPHERS, 10, seed=3):
            self.assertEqual(sorted(order), sorted(CIPHERS))


class TestThermalViolation(unittest.TestCase):
    def test_a_clean_reading_has_no_reasons(self):
        self.assertEqual(campaign_a7.thermal_violation(60.0, 1296000, 72.0), [])

    def test_temperature_over_the_ceiling_is_named(self):
        reasons = campaign_a7.thermal_violation(80.0, 1296000, 72.0)
        self.assertEqual(len(reasons), 1)
        self.assertIn("80.0", reasons[0])
        self.assertIn("72.0", reasons[0])

    def test_a_clock_off_the_pin_is_named(self):
        reasons = campaign_a7.thermal_violation(60.0, 960000, 72.0)
        self.assertTrue(any("960000" in r and "left pinned" in r for r in reasons))

    def test_both_faults_are_reported(self):
        reasons = campaign_a7.thermal_violation(90.0, 480000, 72.0)
        self.assertEqual(len(reasons), 2)

    def test_unreadable_sensors_are_a_violation_not_a_pass(self):
        self.assertTrue(campaign_a7.thermal_violation(None, None, 72.0))


class TestThermalGuard(unittest.TestCase):
    def _guard(self, ceiling=72.0, cap=4):
        return {"ceiling_c": ceiling, "pinned_khz": campaign_a7.PINNED_KHZ,
                "retake_cap": cap}

    def test_a_clean_board_takes_the_run_on_the_first_attempt(self):
        board = FakeBoard(temp_millic=60000)
        log = []
        result = campaign_a7.measure_run_guarded(
            board, lambda: [{"cipher": "x"}], "run0", log=log.append, **self._guard())
        self.assertEqual(result["retakes"], 0)
        self.assertEqual(log, [])
        self.assertEqual(result["rows"], [{"cipher": "x"}])

    def test_a_hot_take_is_discarded_and_the_log_names_the_temperature(self):
        # 80 C on the first pre-read, then 60 C: one discard, then a clean take.
        board = FakeBoard(temp_millic=[80000, 60000, 60000])
        log = []
        result = campaign_a7.measure_run_guarded(
            board, lambda: [{"cipher": "x"}], "run0", log=log.append, **self._guard())
        self.assertEqual(result["retakes"], 1)
        self.assertEqual(len(log), 1)
        self.assertIn("80.0", log[0])
        self.assertIn("DISCARD", log[0])

    def test_a_persistently_hot_board_hits_the_cap_and_raises(self):
        board = FakeBoard(temp_millic=56000)      # below idle-ceiling scenarios
        log = []
        with self.assertRaises(campaign_a7.ThermalCapExceeded) as ctx:
            campaign_a7.measure_run_guarded(
                board, lambda: [{"cipher": "x"}], "run0",
                log=log.append, **self._guard(ceiling=40.0, cap=3))
        self.assertEqual(len(ctx.exception.discards), 3)
        self.assertEqual(len(log), 3)
        for line in log:
            self.assertIn("56.0", line)

    def test_a_discard_waits_the_cooldown_before_retaking(self):
        board = FakeBoard(temp_millic=[80000, 60000, 60000])
        slept = []
        with mock.patch.object(campaign_a7, "_sleep", slept.append):
            result = campaign_a7.measure_run_guarded(
                board, lambda: [{"cipher": "x"}], "run0",
                cooldown_s=30.0, **self._guard())
        self.assertEqual(result["retakes"], 1)
        self.assertIn(30.0, slept)          # the one discard paused before the retake

    def test_a_clean_run_never_sleeps(self):
        board = FakeBoard(temp_millic=60000)
        slept = []
        with mock.patch.object(campaign_a7, "_sleep", slept.append):
            campaign_a7.measure_run_guarded(
                board, lambda: [{"cipher": "x"}], "run0",
                cooldown_s=30.0, **self._guard())
        self.assertEqual(slept, [])

    def test_a_clock_that_left_the_pin_after_the_run_discards_it(self):
        class Throttler(FakeBoard):
            def __init__(self):
                super().__init__(temp_millic=60000)
                self._reads = 0

            def read_cur_khz(self, cpu):
                # 1296 before the run, 960 after it (post-read discards), then 1296.
                self._reads += 1
                return 960000 if self._reads == 2 else campaign_a7.PINNED_KHZ

        board = Throttler()
        log = []
        result = campaign_a7.measure_run_guarded(
            board, lambda: [{"cipher": "x"}], "run0", log=log.append, **self._guard())
        self.assertEqual(result["retakes"], 1)
        self.assertIn("after run", log[0])
        self.assertIn("960000", log[0])


class TestClockGate(unittest.TestCase):
    def test_a_pinned_board_passes_and_reports_the_reading(self):
        board = FakeBoard()
        reading = campaign_a7.gate_performance_clock(board)
        self.assertTrue(reading["ok"])
        self.assertEqual(reading["cur_khz"], campaign_a7.PINNED_KHZ)
        self.assertIn("performance", board.set_governor_calls)

    def test_a_board_that_will_not_pin_is_refused(self):
        board = FakeBoard(cur_khz=960000, pin_on_performance=False)
        with self.assertRaises(campaign_a7.ClockGateFailed) as ctx:
            campaign_a7.gate_performance_clock(board)
        self.assertIn("960000", str(ctx.exception))
        self.assertFalse(ctx.exception.reading["ok"])


class TestDriftCheck(unittest.TestCase):
    @staticmethod
    def _row(cipher, med, ci, r_med, r_ci, ratio_modality="unimodal"):
        return {"cipher": cipher, "published": "yes",
                "median_mbit_per_sec": med, "ci_lo": ci[0], "ci_hi": ci[1],
                "ratio_median": r_med, "ratio_lo": r_ci[0], "ratio_hi": r_ci[1],
                "modality": "unimodal", "ratio_modality": ratio_modality}

    def test_tight_ratios_report_the_claim_held(self):
        rows = [
            self._row("present-80-r16", 100, (100, 100), 1.0, (1.0, 1.0)),
            self._row("cipher-D", 50, (40, 60), 0.5, (0.495, 0.505)),
            self._row("aes-r5", 80, (64, 96), 0.8, (0.792, 0.808)),
        ]
        result = campaign_a7.drift_check(rows)
        self.assertTrue(result["claim_held"])
        self.assertGreater(result["tighter_factor"], 1.5)
        self.assertEqual(result["n_ciphers"], 2)      # baseline excluded

    def test_ratios_no_tighter_than_absolute_report_the_claim_did_not_hold(self):
        rows = [
            self._row("present-80-r16", 100, (100, 100), 1.0, (1.0, 1.0)),
            self._row("cipher-D", 50, (48, 52), 0.5, (0.46, 0.54)),
            self._row("aes-r5", 80, (77, 83), 0.8, (0.73, 0.87)),
        ]
        result = campaign_a7.drift_check(rows)
        self.assertFalse(result["claim_held"])

    def test_a_multimodal_ratio_defeats_the_claim_even_if_intervals_look_tight(self):
        rows = [
            self._row("present-80-r16", 100, (100, 100), 1.0, (1.0, 1.0)),
            self._row("cipher-D", 50, (40, 60), 0.5, (0.499, 0.501),
                      ratio_modality=summarize.MODALITY_MULTIMODAL),
        ]
        result = campaign_a7.drift_check(rows)
        self.assertFalse(result["claim_held"])
        self.assertEqual(result["multimodal_ratio_ciphers"], ["cipher-D"])

    def test_the_lines_state_the_verdict_plainly(self):
        held = campaign_a7.drift_check_lines(campaign_a7.drift_check([
            self._row("present-80-r16", 100, (100, 100), 1.0, (1.0, 1.0)),
            self._row("cipher-D", 50, (40, 60), 0.5, (0.495, 0.505)),
            self._row("aes-r5", 80, (64, 96), 0.8, (0.792, 0.808)),
        ]))
        self.assertTrue(held[0].startswith(campaign_a7.DRIFT_CHECK_PREFIX))
        self.assertIn("HELD", held[0])


class TestShippedSummaryCarriesVerdict(unittest.TestCase):
    """The regression for the bug the reviewer caught: the DID-NOT-HOLD verdict must be
    in the summary.csv that the *documented Step 6 command* writes, not only in a driver
    annotate step that command overwrites. So we assert the verdict via the shipped path
    -- summarize.summarize on an a7/runs.csv -- and that re-running it (the exact
    clobber scenario) keeps the verdict rather than replacing it with the optimistic
    boilerplate."""

    def _write_did_not_hold_runs(self, directory):
        # Absolutes are tight and the two ciphers do NOT co-drift, so the per-run ratio
        # is no tighter than the absolute -- the A7's real shape. The pairing has nothing
        # to cancel and the verdict must say so.
        a7_dir = os.path.join(directory, "a7")
        os.makedirs(a7_dir)
        path = os.path.join(a7_dir, "runs.csv")
        header = "run_index,order_index,cipher,impl,size_bytes,mbit_per_sec"
        state = 1234567
        rows = []
        for run in range(16):
            state = (1103515245 * state + 12345) & 0x7FFFFFFF
            base = 188.0 + (state % 7) * 0.05          # tiny, independent jitter
            state = (1103515245 * state + 12345) & 0x7FFFFFFF
            other = 170.0 + (state % 11) * 0.05         # uncorrelated with base
            rows.append("%d,0,present-80-r16,ctr-bitslice-neon,65536,%.6f" % (run, base))
            rows.append("%d,0,cipher-D,ctr-table-x2,65536,%.6f" % (run, other))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# provenance: CAMPAIGN\n")
            fh.write(header + "\n")
            fh.write("\n".join(rows) + "\n")
        return path

    def test_the_documented_step6_command_writes_the_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = self._write_did_not_hold_runs(tmp)
            # The exact documented Step 6 invocation.
            summarize.main([runs, "--baseline", "present-80-r16"])
            summary = os.path.join(os.path.dirname(runs), "summary.csv")
            with open(summary, encoding="utf-8") as fh:
                text = fh.read()
        self.assertIn(campaign_a7.DRIFT_CHECK_PREFIX, text)
        self.assertIn("DID NOT HOLD", text)

    def test_re_running_the_command_does_not_clobber_the_verdict(self):
        # This is the shipped bug: run summarize twice (driver, then the bare Step 6
        # command) and the second write must still carry the verdict, with exactly one
        # block.
        with tempfile.TemporaryDirectory() as tmp:
            runs = self._write_did_not_hold_runs(tmp)
            summarize.main([runs, "--baseline", "present-80-r16"])
            summarize.main([runs, "--baseline", "present-80-r16"])
            summary = os.path.join(os.path.dirname(runs), "summary.csv")
            with open(summary, encoding="utf-8") as fh:
                text = fh.read()
        self.assertEqual(text.count(campaign_a7.DRIFT_CHECK_PREFIX), 1)
        self.assertEqual(text.count("Median absolute-throughput CI"), 1)
        self.assertIn("DID NOT HOLD", text)


# --- end to end, campaign_a7.main against a throwaway repo and a FakeBoard ------------

class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="a7-e2e-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.git("init", "-q", ".")
        self.git("config", "user.email", "a7-test@example.invalid")
        self.git("config", "user.name", "A7 Test")
        os.makedirs(os.path.join(self.root, "bench"))
        self.write(os.path.join(self.root, "Makefile"), "build/ctr_bench:\n\t@true\n")
        self.write(os.path.join(self.root, "bench", "ctr_bench.c"), "/* stub */\n")
        self.write(os.path.join(self.root, ".gitignore"), "results/\n")
        self.git("add", "Makefile", "bench/ctr_bench.c", ".gitignore")
        self.git("commit", "-q", "-m", "base")
        # campaign_a7 does a bare `import campaign`, so the module it uses is
        # campaign_a7.campaign -- a different object than this test's `tools.campaign`.
        # Patch the ROOT on the modules campaign_a7 actually references.
        for target in (campaign_a7, campaign_a7.campaign):
            patcher = mock.patch.object(target, "ROOT", self.root)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.out_dir = os.path.join(self.root, campaign_a7.campaign.RESULTS_ROOT,
                                    campaign_a7.TARGET)

    def git(self, *args):
        proc = subprocess.run(["git"] + list(args), cwd=self.root,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    @staticmethod
    def write(path, text):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def run_main(self, board, *args):
        buf = io.StringIO()
        with mock.patch.object(campaign_a7, "Board", lambda host: board), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = campaign_a7.main(["--host", "fake", "--no-build", *args])
        return code, buf.getvalue()

    def out(self, name):
        return os.path.join(self.out_dir, name)

    def load(self, name):
        with open(self.out(name), encoding="utf-8") as fh:
            return json.load(fh)

    def rows(self):
        with open(self.out(campaign_a7.RUNS_FILENAME), encoding="utf-8") as fh:
            lines = [ln for ln in fh if not ln.startswith("#")]
        return list(csv.DictReader(lines))

    def tune(self, board, *args):
        code, out = self.run_main(board, "--tune", "--tuning-runs", "2", *args)
        self.assertEqual(code, 0, out)
        return out

    def freeze(self):
        self.git("add", "-f", os.path.join(campaign.RESULTS_ROOT, campaign_a7.TARGET,
                                           campaign_a7.TUNING_FILENAME))
        self.git("commit", "-q", "-m", "Freeze the A7 kernel choice")

    # -- happy path --
    def test_tune_freezes_the_fast_winner_with_its_evidence(self):
        self.tune(FakeBoard())
        doc = self.load(campaign_a7.TUNING_FILENAME)
        self.assertEqual(sorted(doc["choice"]), sorted(CIPHERS))
        self.assertEqual(set(doc["choice"].values()), {"ctr-fast"})
        self.assertEqual(doc["pinned_khz"], campaign_a7.PINNED_KHZ)

    def test_tune_records_the_governor_and_clock_in_env(self):
        self.tune(FakeBoard())
        env = self.load(campaign_a7.ENV_FILENAME)
        self.assertTrue(env["clock_gate"]["ok"])
        self.assertEqual(env["clock_gate"]["cur_khz"], campaign_a7.PINNED_KHZ)
        self.assertEqual(env["protocol"]["pinned_khz"], campaign_a7.PINNED_KHZ)

    def test_measure_writes_rows_env_and_an_annotated_summary(self):
        self.tune(FakeBoard())
        self.freeze()
        code, out = self.run_main(FakeBoard(), "--measure", "--runs", "4")
        self.assertEqual(code, 0, out)
        rows = self.rows()
        self.assertEqual(len(rows), 4 * len(CIPHERS))
        self.assertEqual({r["impl"] for r in rows}, {"ctr-fast"})
        # seed and order_index are present and reproduce the order.
        self.assertEqual({r["seed"] for r in rows}, {"0"})
        positions = {int(r["order_index"]) for r in rows}
        self.assertEqual(positions, set(range(len(CIPHERS))))
        with open(self.out("summary.csv"), encoding="utf-8") as fh:
            summary = fh.read()
        self.assertIn(campaign_a7.DRIFT_CHECK_PREFIX, summary)

    def test_measure_refuses_an_uncommitted_freeze(self):
        self.tune(FakeBoard())                        # not committed
        code, out = self.run_main(FakeBoard(), "--measure", "--runs", "3")
        self.assertEqual(code, 1)
        self.assertIn("is not committed", out)
        self.assertFalse(os.path.exists(self.out(campaign_a7.RUNS_FILENAME)))

    def test_the_governor_is_restored_to_ondemand_after_a_run(self):
        board = FakeBoard()
        self.tune(board)
        self.assertEqual(board.set_governor_calls[-1], "ondemand")

    # -- the gates fire through main --
    def test_a_board_that_will_not_pin_refuses_and_records_the_refusal(self):
        board = FakeBoard(cur_khz=960000, pin_on_performance=False)
        code, out = self.run_main(board, "--tune", "--tuning-runs", "2")
        self.assertEqual(code, 1)
        self.assertIn("not pinned", out)
        env = self.load(campaign_a7.ENV_FILENAME)
        self.assertFalse(env["clock_gate"]["ok"])
        self.assertFalse(os.path.exists(self.out(campaign_a7.TUNING_FILENAME)))

    def test_the_thermal_guard_fires_and_exits_non_zero_at_the_cap(self):
        # Idle board at 56 C, ceiling 40 C: every take trips, the cap is hit, non-zero.
        board = FakeBoard(temp_millic=56000)
        code, out = self.run_main(board, "--tune", "--tuning-runs", "2",
                                  "--thermal-ceiling", "40", "--retake-cap", "3")
        self.assertEqual(code, 1)
        self.assertIn("retake cap", out)
        # Three distinct guarded takes were discarded before the cap fired; the raised
        # message then echoes the last one, so at least three DISCARD lines appear.
        for take in range(3):
            self.assertIn("take %d" % take, out)
        self.assertGreaterEqual(out.count("DISCARD"), 3)
        self.assertIn("56.0", out)
        # The governor is still restored even though the campaign failed.
        self.assertEqual(board.set_governor_calls[-1], "ondemand")


if __name__ == "__main__":
    unittest.main()
