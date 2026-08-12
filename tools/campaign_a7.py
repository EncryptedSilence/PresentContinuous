#!/usr/bin/env python3
"""The Cortex-A7 counter-mode campaign: `tools/campaign.py a7`.

The A7 is the third measurement target after the x86 host (the main flow in
`campaign.py`) and the Cortex-M4 (`campaign_m4.py`). Unlike the M4's deterministic
DWT cycle counts, the A7 is a running Linux box measured by a wall clock: noisy, and
liable to drift as it warms. So this driver reuses the *ctr_bench* machinery and the
freeze/provenance discipline of the x86 flow, and adds the three things the board
needs that the x86 host does not:

  1. an SSH driver -- the board has no checkout, so the tree is rsynced over and built
     natively there each run (the Makefile's ctr_bench links src/keyschedule.c, whose
     __int128 gcc rejects on armv7, so the build is done by hand with the recipe Tasks
     5 and 6 validated: keyschedule_portable.c in its place, the large S-box circuits
     at -O2 to fit the board's 512 MB, the rest at -O3);

  2. a governor/clock gate -- the board is pinned to `performance` at 1296 MHz and the
     campaign REFUSES to start unless it verifies that; the governor is restored to
     `ondemand` when the campaign ends, because leaving a passively-cooled board at max
     clock is bad hygiene;

  3. a thermal guard -- the board's temperature and clock are read before and after
     every measured run, and a run taken while the clock left 1296 MHz or the
     temperature crossed the ceiling is DISCARDED and retaken, with a cap so a
     persistently hot board fails loudly (non-zero exit) instead of looping forever.

The paired-within-one-process comparison is the same as the x86 flow's, and for the
same reason turned to the A7's failure mode: an absolute A7 speed wanders as the board
drifts, so every published comparison is a per-run ratio against a baseline measured in
the *same* ctr_bench process. tools/summarize.py forms those ratios. Whether the
pairing actually cancels the drift on this board -- the protocol's own central claim --
is checked at the end and recorded honestly in summary.csv's header, held or not.

Standard library only, like the rest of tools/.
"""

import argparse
import csv
import io
import json
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import campaign  # noqa: E402  (reuses its freeze/clean/provenance/tuning helpers)
import cipher_set  # noqa: E402
import summarize  # noqa: E402

ROOT = campaign.ROOT

TARGET = "a7"
DEFAULT_HOST = "a7"
REMOTE_DIR = "PRESENT_mod"          # under the board's login home
BOARD_CPU = 3                       # the core taskset pins to, and whose clock is gated
PINNED_KHZ = 1296000                # the only clock a published A7 number may be taken at

# The throttle-relevant ceiling, set from measurement rather than guessed. On this
# board the clock holds at 1296 MHz through a sustained single-core NEON load: the
# temperature plateaus at ~72-73 C at full clock and does not drop it, and the clock was
# observed pinned even at 76.8 C. trip_point_0 (75 C) is a passive trip with no observed
# clock effect; trip_point_1 is 80 C. So the hard guarantee is the clock gate (freq must
# equal PINNED_KHZ, which catches any real throttle directly); the temperature ceiling
# is a secondary guard set at 80 C -- above the ~73 C operating plateau and its ~77 C
# transients, at the first trip where throttle management could begin. A lower value
# (an earlier guess of 72 C) sits inside the board's own normal operating band and
# discards runs whose clock is perfectly pinned, which is not what the guard is for.
DEFAULT_CEILING_C = 80.0

# A run that cannot be taken cleanly in this many attempts fails the campaign rather
# than retaking forever. Small on purpose: a board that trips four takes in a row is not
# going to settle within a campaign, and a loud stop is the honest outcome.
DEFAULT_RETAKE_CAP = 4

DEFAULT_RUNS = 25
TUNING_RUNS = 5
BASELINE = "present-80-r16"

# One published working-set size. The A7 campaign's unit is "one run = all seven ciphers
# in one ctr_bench process", so a run maps cleanly to one thermally-guarded take; the
# pairing the drift-cancellation claim rests on is fully exercised at this size, which is
# the one Step 6 examines. (The x86 flow measures three sizes for a cache-ranking check;
# that is a separate question and would triple this passively-cooled board's thermal
# exposure for a claim this campaign does not make.)
SIZE_BYTES = summarize.PUBLISHED_SIZE_BYTES

# Compiled at -O2 to fit the board's memory (the large retyped S-box circuits); the rest
# at -O3. This is the split Tasks 5 and 6 validated on this exact board.
BOARD_COLD_SRCS = (
    "src/present_bitslice.c", "src/present_bitslice32.c",
    "src/present_neon.c", "src/gen/variants_gen.c",
)
BOARD_HOT_SRCS = (
    "src/variant.c", "src/keyschedule_portable.c", "src/present_core.c",
    "src/present_ref.c", "src/present_table.c", "src/present_table_x.c",
    "src/present_avx2.c",
    "src/present_ctr_bitslice.c", "src/present_ctr_avx2.c", "src/present_ctr_neon.c",
    "bench/ctr_registry.c", "bench/ctr_narrow.c", "bench/ctr_wide.c",
    "bench/ctr_wide_neon.c", "bench/ctr_cipher_set.c",
)
BOARD_MAIN_SRC = "bench/ctr_bench.c"
BOARD_FLAGS = ("-mcpu=native -mfpu=neon-vfpv4 -mfloat-abi=hard -std=gnu11 "
               "-Wall -Wextra -Iinclude -Isrc -Ibench")
BOARD_BINARY = "build/ctr_bench"

# A single take is seconds (measure) to tens of seconds (tune, all backends); this cap
# only exists to stop a take orphaned by a dead driver from running away on the board.
REMOTE_TAKE_TIMEOUT_S = 300

RUNS_FILENAME = campaign.RUNS_FILENAME
ENV_FILENAME = campaign.ENV_FILENAME
KAT_FILENAME = campaign.KAT_FILENAME
TUNING_FILENAME = campaign.TUNING_FILENAME

A7_RUNS_COLUMNS = (
    "target", "campaign_uid", "run_index", "run_seq", "seed", "order_index",
    "size_bytes", "cipher", "impl", "rounds", "block_bytes",
    "mbit_per_sec", "ns_median", "ns_min", "prepare_ns", "tsc_per_byte",
    "temp_before_c", "temp_after_c", "freq_before_khz", "freq_after_khz",
    "retakes", "started_utc",
)

DRIFT_CHECK_PREFIX = "# a7_drift_check:"

# The build script pushed to the board and run there. Cold sources to -O2 objects, then
# everything else compiled and linked at -O3 against those objects.
BOARD_BUILD_SCRIPT = """\
set -e
cd "$HOME/{remote_dir}"
FLAGS="{flags}"
mkdir -p build/cold
COLDOBJ=""
for f in {cold}; do
  o="build/cold/$(echo "$f" | tr / _).o"
  gcc $FLAGS -O2 -c -o "$o" "$f"
  COLDOBJ="$COLDOBJ $o"
done
gcc $FLAGS -O3 -o {binary} {main} {hot} $COLDOBJ
test -x {binary} && echo BUILD_OK
"""


class A7Error(campaign.CampaignError):
    """Anything that stops the A7 campaign before it produces a number."""


class ClockGateFailed(A7Error):
    """The board is not pinned to `performance` at 1296 MHz, so no run may start."""


class ThermalCapExceeded(A7Error):
    """A run could not be taken within the retake cap; the board will not settle."""

    def __init__(self, message, discards):
        super().__init__(message)
        self.discards = discards


# --- the board, behind an interface a test can replace -------------------------------

class Board:
    """The real Cortex-A7, reached over SSH. Every method a test needs to fake is here.

    Nothing above this class runs a subprocess against the board directly; the campaign
    logic talks to a `Board`, so a FakeBoard with scripted temperatures and canned
    ctr_bench output drives the whole flow on the x86 host with no hardware.
    """

    def __init__(self, host, remote_dir=REMOTE_DIR, ssh_timeout=900):
        self.host = host
        self.remote_dir = remote_dir
        self.ssh_timeout = ssh_timeout

    # -- raw transport --
    def ssh(self, command, check=True, timeout=None):
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", self.host, command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=timeout or self.ssh_timeout)
        if check and proc.returncode != 0:
            raise A7Error("ssh %s: `%s` exited %d\n%s%s"
                          % (self.host, command, proc.returncode,
                             proc.stdout, proc.stderr))
        return proc.returncode, proc.stdout, proc.stderr

    def rsync_tree(self):
        local = ROOT.rstrip("/") + "/"
        remote = "%s:%s/" % (self.host, self.remote_dir)
        proc = subprocess.run(
            ["rsync", "-az", "--delete", "--exclude=.git", "--exclude=build",
             local, remote],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=self.ssh_timeout)
        if proc.returncode != 0:
            raise A7Error("rsync to %s failed (%d)\n%s%s"
                          % (remote, proc.returncode, proc.stdout, proc.stderr))

    def put_script(self, remote_name, text):
        # Write via stdin so no quoting of the script body reaches the remote shell.
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", self.host,
             "cat > %s/%s" % (self.remote_dir, remote_name)],
            input=text, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=self.ssh_timeout)
        if proc.returncode != 0:
            raise A7Error("writing %s to the board failed (%d)\n%s"
                          % (remote_name, proc.returncode, proc.stderr))

    # -- sysfs reads --
    def _read(self, path):
        rc, out, _ = self.ssh("cat %s 2>/dev/null" % path, check=False)
        text = out.strip()
        return text if (rc == 0 and text) else None

    def read_temp_millic(self):
        return _as_int(self._read("/sys/class/thermal/thermal_zone0/temp"))

    def read_cur_khz(self, cpu):
        return _as_int(self._read(
            "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq" % cpu))

    def read_governors(self):
        rc, out, _ = self.ssh(
            "for c in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; "
            "do echo \"$c $(cat $c)\"; done", check=False)
        governors = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:
                governors[parts[0]] = parts[1]
        return governors

    def set_governor(self, name):
        self.ssh("echo %s | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor "
                 "> /dev/null" % name)

    # -- building and running the harness --
    def build(self):
        script = BOARD_BUILD_SCRIPT.format(
            remote_dir=self.remote_dir, flags=BOARD_FLAGS, binary=BOARD_BINARY,
            main=BOARD_MAIN_SRC, cold=" ".join(BOARD_COLD_SRCS),
            hot=" ".join(BOARD_HOT_SRCS))
        self.put_script("build_a7_ctr.sh", script)
        rc, out, err = self.ssh("cd %s && sh build_a7_ctr.sh" % self.remote_dir,
                                check=False)
        if rc != 0 or "BUILD_OK" not in out:
            raise A7Error("board build failed (%d):\n%s%s" % (rc, out, err))

    def binary_sha256(self):
        rc, out, _ = self.ssh("sha256sum %s/%s" % (self.remote_dir, BOARD_BINARY),
                              check=False)
        return out.split()[0] if rc == 0 and out.split() else None

    def list_backends(self):
        rc, out, _ = self.ssh("cd %s && ./%s --list-backends"
                              % (self.remote_dir, BOARD_BINARY), check=False)
        available = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] == "available":
                available.setdefault(parts[0], set()).add(parts[1])
        return available

    def run_ctr_bench(self, selects, size, trials=None, kat=False):
        """One ctr_bench process on the board; returns (rows, kat_or_None)."""
        remote_csv = "/tmp/a7_take.csv"
        remote_kat = "/tmp/a7_kat.json"
        # `timeout` wraps the harness so that if this driver dies mid-take, the remote
        # process self-terminates instead of orphaning into a runaway that reheats the
        # board (a hazard learned the hard way during bring-up).
        cmd = ["cd %s &&" % self.remote_dir, "timeout %d" % REMOTE_TAKE_TIMEOUT_S,
               "taskset -c %d" % BOARD_CPU,
               "./%s" % BOARD_BINARY, "--csv", remote_csv, "--size", str(size)]
        if trials is not None:
            cmd += ["--trials", str(trials)]
        if kat:
            cmd += ["--kat-json", remote_kat]
        cmd += list(selects)
        cmd += ["&& echo ---CSV--- && cat", remote_csv]
        if kat:
            cmd += ["&& echo ---KAT--- && cat", remote_kat]
        rc, out, err = self.ssh(" ".join(cmd), check=False)
        if rc != 0:
            raise campaign.HarnessFailed(
                "ctr_bench on %s exited %d\n%s%s" % (self.host, rc, out, err))
        return _split_take_output(out, want_kat=kat)

    def probe_env(self):
        rc, uname, _ = self.ssh("uname -a", check=False)
        rc, host, _ = self.ssh("cat /proc/sys/kernel/hostname", check=False)
        rc, gcc, _ = self.ssh("gcc --version | head -1", check=False)
        rc, avail, _ = self.ssh(
            "cat /sys/devices/system/cpu/cpu%d/cpufreq/scaling_available_frequencies"
            % BOARD_CPU, check=False)
        rc, maxk, _ = self.ssh(
            "cat /sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq" % BOARD_CPU,
            check=False)
        rc, trips, _ = self.ssh(
            "for t in /sys/class/thermal/thermal_zone0/trip_point_*_temp; "
            "do cat $t; done", check=False)
        return {
            "uname": uname.strip() or None,
            "hostname": host.strip() or None,
            "gcc": gcc.strip() or None,
            "governors": self.read_governors(),
            "scaling_cur_khz": self.read_cur_khz(BOARD_CPU),
            "scaling_max_khz": _as_int(maxk.strip()),
            "scaling_available_khz": [int(x) for x in avail.split()] if avail else [],
            "thermal_zone0_millic": self.read_temp_millic(),
            "thermal_trip_points_millic": [int(x) for x in trips.split()]
                                          if trips.strip() else [],
        }


def _as_int(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _split_take_output(out, want_kat):
    """Parse the concatenated `<csv> ---KAT--- <json>` a take prints back."""
    kat = None
    csv_text = out
    if want_kat and "---KAT---" in out:
        csv_text, _, kat_text = out.partition("---KAT---")
        try:
            kat = json.loads(kat_text.strip())
        except json.JSONDecodeError:
            kat = None
    if "---CSV---" in csv_text:
        csv_text = csv_text.split("---CSV---", 1)[1]
    rows = [dict(r) for r in csv.DictReader(io.StringIO(csv_text.strip()))
            if r.get("cipher") and not r["cipher"].startswith("#")]
    return rows, kat


# --- the gates: clock and temperature ------------------------------------------------

def gate_performance_clock(board, pinned_khz=PINNED_KHZ, cpu=BOARD_CPU):
    """Set `performance`, verify the clock is pinned, and return what was read.

    Raises ClockGateFailed unless every core reports `performance` and the pinned core's
    current clock is exactly `pinned_khz`. The reading is returned either way so env.json
    can record what the board actually was, refusal or not.
    """
    board.set_governor("performance")
    governors = board.read_governors()
    cur_khz = board.read_cur_khz(cpu)
    reading = {"governors": governors, "cur_khz": cur_khz, "pinned_khz": pinned_khz}
    not_perf = sorted(c for c, g in governors.items() if g != "performance")
    problems = []
    if not governors:
        problems.append("no cpufreq governor could be read from the board")
    if not_perf:
        problems.append("these cores are not `performance`: %s" % ", ".join(not_perf))
    if cur_khz != pinned_khz:
        problems.append("cpu%d clock is %s kHz, not the required %d kHz"
                        % (cpu, cur_khz, pinned_khz))
    reading["ok"] = not problems
    if problems:
        exc = ClockGateFailed(
            "the A7 is not pinned for measurement, so no run may start:\n  %s\n"
            "The board must be `performance` at %d kHz; it can be pinned there "
            "(scaling_max_freq lists 1296000) but was not."
            % ("\n  ".join(problems), pinned_khz))
        exc.reading = reading
        raise exc
    return reading


def thermal_violation(temp_c, cur_khz, ceiling_c, pinned_khz=PINNED_KHZ):
    """The reasons this reading fails the guard, as a list ([] means clean)."""
    reasons = []
    if temp_c is None:
        reasons.append("temperature unreadable")
    elif temp_c > ceiling_c:
        reasons.append("temp %.1fC over ceiling %.1fC" % (temp_c, ceiling_c))
    if cur_khz is None:
        reasons.append("clock unreadable")
    elif cur_khz != pinned_khz:
        reasons.append("clock %d kHz left pinned %d kHz" % (cur_khz, pinned_khz))
    return reasons


def _sleep(seconds):
    """time.sleep, but a no-op for non-positive durations (and cheap to patch in tests)."""
    if seconds and seconds > 0:
        time.sleep(seconds)


def sample_thermal(board, cpu=BOARD_CPU):
    millic = board.read_temp_millic()
    return {
        "temp_c": None if millic is None else millic / 1000.0,
        "cur_khz": board.read_cur_khz(cpu),
    }


def measure_run_guarded(board, take, run_label, ceiling_c, pinned_khz=PINNED_KHZ,
                        retake_cap=DEFAULT_RETAKE_CAP, cpu=BOARD_CPU, log=None,
                        cooldown_s=0.0):
    """Take one run under the thermal guard, retaking on a violation up to the cap.

    `take` is a zero-argument callable that performs one ctr_bench process and returns
    its rows. The guard reads temperature and clock immediately before and after that
    process; a violation on either side discards the take and retries. Every discard is
    logged with the reading that caused it. A discard sleeps `cooldown_s` before the
    retake, so a board that ran hot has a chance to shed heat rather than the retake
    burning the cap at the same temperature. Exceeding `retake_cap` raises
    ThermalCapExceeded rather than looping, so a board that will not settle stops the
    campaign loudly.
    """
    log = log or (lambda msg: print(msg))
    discards = []
    for attempt in range(retake_cap):
        pre = sample_thermal(board, cpu)
        reasons = thermal_violation(pre["temp_c"], pre["cur_khz"], ceiling_c, pinned_khz)
        if reasons:
            record = _discard_record(run_label, attempt, "before", pre, reasons)
            discards.append(record)
            log(_discard_line(record))
            _sleep(cooldown_s)
            continue
        rows = take()
        post = sample_thermal(board, cpu)
        reasons = thermal_violation(post["temp_c"], post["cur_khz"], ceiling_c,
                                    pinned_khz)
        if reasons:
            record = _discard_record(run_label, attempt, "after", post, reasons)
            discards.append(record)
            log(_discard_line(record))
            _sleep(cooldown_s)
            continue
        return {"rows": rows, "pre": pre, "post": post,
                "retakes": len(discards), "discards": discards}
    raise ThermalCapExceeded(
        "%s: discarded %d consecutive takes at the thermal guard (ceiling %.1fC, "
        "pinned %d kHz) and hit the retake cap; the board is not settling. "
        "Last discard: %s"
        % (run_label, retake_cap, ceiling_c, pinned_khz,
           _discard_line(discards[-1]) if discards else "(none)"),
        discards)


def _discard_record(run_label, attempt, when, reading, reasons):
    return {
        "run": run_label, "attempt": attempt, "when": when,
        "temp_c": reading["temp_c"], "cur_khz": reading["cur_khz"],
        "reasons": reasons,
    }


def _discard_line(record):
    return ("DISCARD %s take %d (%s run): temp=%s C clock=%s kHz -- %s"
            % (record["run"], record["attempt"], record["when"],
               "NA" if record["temp_c"] is None else "%.1f" % record["temp_c"],
               "NA" if record["cur_khz"] is None else record["cur_khz"],
               "; ".join(record["reasons"])))


# --- per-run cipher order ------------------------------------------------------------

def cipher_orders(ciphers, runs, seed):
    """One fresh permutation per run, from random.Random(seed + run_index).

    A separate stream per run (not one stream advanced across runs) so that the order of
    run k depends only on `seed + k`: rerunning a single run, or the whole campaign,
    reproduces the same orders, and `order_index` in runs.csv lets a reader check whether
    position in the process correlates with the result.
    """
    orders = []
    for i in range(runs):
        rng = random.Random(seed + i)
        order = list(ciphers)
        rng.shuffle(order)
        orders.append(order)
    return orders


def select_args(order, choice):
    args = []
    for cipher in order:
        args += ["--select", "%s=%s" % (cipher, choice[cipher])]
    return args


# --- writing runs.csv ----------------------------------------------------------------

def runs_csv_text(rows, campaign_marker, notes):
    lines = ["# provenance: %s" % campaign_marker]
    if campaign_marker != campaign.PROVENANCE_CAMPAIGN:
        lines += ["# " + line for line in campaign.SMOKE_HEADER]
    lines.append("#")
    for note in notes:
        lines.append("# " + note if note else "#")
    lines.append("#")
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(A7_RUNS_COLUMNS)
    for row in rows:
        writer.writerow(["" if row.get(c) is None else row.get(c)
                         for c in A7_RUNS_COLUMNS])
    return "\n".join(lines) + "\n" + buf.getvalue()


def _fmt_c(value):
    return "NA" if value is None else "%.1f" % value


def _measure_rows(raw_rows, meta, order, pre, post, retakes, started):
    position = {cipher: i for i, cipher in enumerate(order)}
    out = []
    for row in raw_rows:
        out.append({
            "target": TARGET,
            "campaign_uid": meta["campaign_uid"],
            "run_index": meta["run_index"],
            "run_seq": meta["run_seq"],
            "seed": meta["seed"],
            "order_index": position.get(row["cipher"], ""),
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
            "temp_before_c": _fmt_c(pre["temp_c"]),
            "temp_after_c": _fmt_c(post["temp_c"]),
            "freq_before_khz": "NA" if pre["cur_khz"] is None else pre["cur_khz"],
            "freq_after_khz": "NA" if post["cur_khz"] is None else post["cur_khz"],
            "retakes": retakes,
            "started_utc": started,
        })
    return out


# --- the Step 6 drift check ----------------------------------------------------------

# The drift verdict is computed and emitted by tools/summarize.py itself, so the
# documented Step 6 command -- `summarize.py runs.csv --baseline present-80-r16` --
# writes the honest verdict into summary.csv's header directly. These thin wrappers
# keep the a7-flavoured prefix and give the driver's console print and its tests one
# name to call; the logic has a single home in summarize, with no second writer to
# clobber the block.

def drift_check(summary_rows, baseline=BASELINE):
    return summarize.drift_verdict(summary_rows, baseline)


def drift_check_lines(result):
    return summarize.drift_verdict_lines(result, DRIFT_CHECK_PREFIX)

# --- env.json ------------------------------------------------------------------------

def build_env(args, phase, board_env, board_sha, clock_reading, campaign_uid,
              extra=None):
    dirty = campaign.dirty_paths_from_porcelain(campaign.git("status", "--porcelain"))
    watched_dirty = sorted(p for p in dirty
                           if p.startswith(campaign.WATCHED_BUILD_INPUTS))
    doc = {
        "schema": 1,
        "target": TARGET,
        "phase": phase,
        "provenance": campaign.provenance_marker(args.campaign),
        "generated_utc": campaign.utc_now(),
        "driver_host": campaign._read("/", "proc/sys/kernel/hostname"),
        "board_host": args.host,
        "commit": {
            "sha": campaign.git("rev-parse", "HEAD") or None,
            "describe": campaign.git("describe", "--always", "--dirty") or None,
            "dirty": bool(dirty),
            "dirty_paths": sorted(dirty),
            "watched_build_inputs": list(campaign.WATCHED_BUILD_INPUTS),
            "watched_dirty": watched_dirty,
        },
        "board": board_env,
        "board_binary": {"path": BOARD_BINARY, "sha256": board_sha},
        "clock_gate": clock_reading,
        "campaign_uid": campaign_uid,
        "protocol": {
            "pinned_khz": PINNED_KHZ,
            "pinned_cpu": BOARD_CPU,
            "thermal_ceiling_c": args.thermal_ceiling,
            "retake_cap": args.retake_cap,
            "retake_cooldown_s": args.cooldown,
            "inter_take_settle_s": args.settle,
            "size_bytes": SIZE_BYTES,
            "runs": args.runs if phase == "measure" else args.tuning_runs,
            "order_seed": args.seed,
            "baseline": BASELINE,
            "cipher_order_from": "random.Random(seed + run_index)",
            "comparison_rule":
                "Paired within one ctr_bench process. Absolute A7 speeds drift as the "
                "board warms, so a figure from this file divided by a figure from any "
                "other file is not a measurement; every published comparison is a "
                "per-run ratio against %s measured in the same process." % BASELINE,
        },
    }
    if extra:
        doc.update(extra)
    return doc


# --- the two phases ------------------------------------------------------------------

def _guard_args(args):
    return {"ceiling_c": args.thermal_ceiling, "pinned_khz": PINNED_KHZ,
            "retake_cap": args.retake_cap, "cpu": BOARD_CPU,
            "cooldown_s": args.cooldown}


def phase_tune(args, board, out_dir):
    """Measure every backend TUNING_RUNS times on the board and freeze a winner."""
    guard = _guard_args(args)
    samples = {}
    kat_saved = False
    print("tuning: %d guarded runs over every backend at %d bytes on %s"
          % (args.tuning_runs, SIZE_BYTES, args.host))
    for i in range(args.tuning_runs):
        if i > 0:
            _sleep(args.settle)     # shed the heat of the previous heavy take
        want_kat = not kat_saved

        def take():
            rows, kat = board.run_ctr_bench([], SIZE_BYTES, trials=args.trials,
                                            kat=want_kat)
            take.kat = kat
            return rows
        take.kat = None
        result = measure_run_guarded(board, take, "tune#%d" % i, **guard)
        if want_kat and take.kat is not None:
            passed = campaign.check_kat(take.kat)
            print("  correctness gate: %d backends, all passing" % passed)
            campaign.write_json(os.path.join(out_dir, KAT_FILENAME), take.kat)
            kat_saved = True
        for row in result["rows"]:
            samples.setdefault(row["cipher"], {}).setdefault(row["impl"], []) \
                .append(float(row["mbit_per_sec"]))
        print("  run %d/%d (retakes: %d)" % (i + 1, args.tuning_runs,
                                             result["retakes"]))

    doc = campaign.tuning_document(samples, {
        "schema": 1,
        "target": TARGET,
        "generated_utc": campaign.utc_now(),
        "provenance": campaign.provenance_marker(args.campaign),
        "commit": campaign.git("rev-parse", "HEAD") or None,
        "board_binary_sha256": board.binary_sha256(),
        "size_bytes": SIZE_BYTES,
        "runs": args.tuning_runs,
        "pinned_khz": PINNED_KHZ,
        "note": "The winner per cipher on the A7, and every candidate's median, spread "
                "and raw samples. `separated` says whether the winner beat the "
                "runner-up on every tuning run.",
    })
    path = os.path.join(out_dir, TUNING_FILENAME)
    campaign.write_json(path, doc)
    print("\nwrote %s" % path)
    for cipher in sorted(doc["choice"]):
        sep = doc["evidence"][cipher]["separated"]
        note = {True: "", False: "*** not separated from the runner-up",
                None: "(separation not judged)"}[sep]
        print("  %-30s %-20s %s" % (cipher, doc["choice"][cipher], note))
    print("\nFreeze it before measuring:\n"
          "  git add %s && git commit -m 'Freeze the A7 kernel choice'"
          % os.path.relpath(path, ROOT))
    return doc


def phase_measure(args, board, out_dir):
    """Measure the frozen winners, `--runs` guarded runs, at the published size."""
    choice = campaign.load_tuning(out_dir)
    freeze = campaign.tuning_freeze_record(out_dir)
    campaign.require_frozen(freeze["path"], freeze["in_head"],
                            freeze["modified_in_worktree"])
    ciphers = [name for _p, name, _r in cipher_set.resolve()]
    campaign.check_tuning_covers(choice, ciphers)
    campaign.check_tuning(choice, board.list_backends())

    orders = cipher_orders(ciphers, args.runs, args.seed)
    guard = _guard_args(args)
    campaign_uid = args.campaign_uid

    # The gate first, on exactly the backends about to be measured, its verdict on disk
    # before any timing row exists. Taken under the guard like every other run.
    def kat_take():
        take_rows, kat = board.run_ctr_bench(select_args(orders[0], choice), SIZE_BYTES,
                                             trials=1, kat=True)
        kat_take.kat = kat
        return take_rows
    kat_take.kat = None
    measure_run_guarded(board, kat_take, "kat", **guard)
    kat = kat_take.kat
    campaign.check_kat(kat, expected={(c, choice[c]) for c in ciphers})
    campaign.write_json(os.path.join(out_dir, KAT_FILENAME), kat)
    print("correctness gate: %d backends, all passing" % len(kat))

    rows = []
    for seq, order in enumerate(orders):
        if seq > 0:
            _sleep(args.settle)     # keep the board from accumulating heat across runs
        run_index = campaign.make_run_index(campaign_uid, seq, args.runs)
        started = campaign.utc_now()

        def take():
            take_rows, _ = board.run_ctr_bench(select_args(order, choice), SIZE_BYTES,
                                               trials=args.trials)
            return take_rows
        result = measure_run_guarded(board, take, run_index, **guard)
        meta = {"campaign_uid": campaign_uid, "run_index": run_index,
                "run_seq": seq, "seed": args.seed}
        rows += _measure_rows(result["rows"], meta, order, result["pre"],
                              result["post"], result["retakes"], started)
        print("  run %d/%d (%s) retakes=%d temp %s->%s C  %s"
              % (seq + 1, args.runs, run_index, result["retakes"],
                 _fmt_c(result["pre"]["temp_c"]), _fmt_c(result["post"]["temp_c"]),
                 " ".join(order)))

    marker = campaign.provenance_marker(args.campaign)
    notes = [
        "target: a7 (Cortex-A7, %s)" % args.host,
        "produced_by: tools/campaign.py a7 --measure (see %s for the board)"
        % ENV_FILENAME,
        "commit: %s" % (campaign.git("rev-parse", "HEAD") or "unknown"),
        "board binary sha256: %s" % board.binary_sha256(),
        campaign.freeze_note(freeze),
        "",
        "Comparisons from this file are paired within a run. Each run_index is one",
        "ctr_bench process on the board that measured every cipher at %d bytes; the"
        % SIZE_BYTES,
        "ratios tools/summarize.py publishes are formed inside those processes, so the",
        "board's drift as it warms is common to the pair and cancels. An absolute number",
        "here divided by an absolute number from any other file is not a measurement.",
        "",
        "seed and order_index reproduce each run's cipher order (random.Random(seed +",
        "run_index)); temp_before/after and freq_before/after are the thermal guard's",
        "readings; retakes counts discards before the take that stands.",
    ]
    runs_path = os.path.join(out_dir, RUNS_FILENAME)
    campaign.refuse_downgrade(runs_path, args.campaign)
    campaign._write_atomic(runs_path, runs_csv_text(rows, marker, notes))
    print("\nwrote %s (%d rows, %d runs)" % (runs_path, len(rows), args.runs))
    return runs_path


# --- summary + Step 6 ----------------------------------------------------------------

def summarize_and_check(runs_path):
    # summarize writes summary.csv with the drift verdict already in its header (the
    # shipped path). We recompute the verdict only to echo it to the console and to
    # return it to the caller; we do NOT rewrite the file.
    rows = summarize.summarize(runs_path, baseline=BASELINE)
    result = drift_check(rows, baseline=BASELINE)
    print("\n" + "\n".join(drift_check_lines(result)))
    return result


# --- CLI -----------------------------------------------------------------------------

def main(argv):
    parser = argparse.ArgumentParser(
        prog="campaign.py a7",
        description="Cortex-A7 counter-mode campaign over SSH, with a thermal guard.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--tune", action="store_true",
                      help="measure every backend and freeze a winner per cipher")
    mode.add_argument("--measure", action="store_true",
                      help="measure the frozen winners under the thermal guard")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help="ssh host for the board (default: %(default)s)")
    parser.add_argument("--campaign", action="store_true",
                        help="publication campaign: mark CAMPAIGN, enforce the run floor")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS,
                        help="whole-program runs in --measure (default: %(default)s)")
    parser.add_argument("--tuning-runs", type=int, default=TUNING_RUNS,
                        help="runs per backend in --tune (default: %(default)s)")
    parser.add_argument("--seed", type=int, default=0,
                        help="seed for the per-run cipher order (default: %(default)s)")
    parser.add_argument("--thermal-ceiling", type=float, default=DEFAULT_CEILING_C,
                        help="discard a run taken above this temperature "
                             "(default: %(default)s C)")
    parser.add_argument("--retake-cap", type=int, default=DEFAULT_RETAKE_CAP,
                        help="fail after this many discards of one run "
                             "(default: %(default)s)")
    parser.add_argument("--cooldown", type=float, default=0.0,
                        help="seconds to wait after a thermal discard before retaking, "
                             "so a hot board can shed heat instead of burning the cap "
                             "at the same temperature (default: %(default)s)")
    parser.add_argument("--settle", type=float, default=0.0,
                        help="seconds to wait between takes to keep the board from "
                             "accumulating heat across runs (default: %(default)s)")
    parser.add_argument("--trials", type=int, default=None,
                        help="ctr_bench --trials; its own default when unset")
    parser.add_argument("--out-dir", default=None,
                        help="where to write; default results/v2/a7")
    parser.add_argument("--no-build", action="store_true",
                        help="do not rsync/build on the board (reuse what is there)")
    parser.add_argument("--no-restore-governor", action="store_true",
                        help="leave the board on `performance` (default restores "
                             "`ondemand`)")
    args = parser.parse_args(argv)

    if args.measure and args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.tune and args.tuning_runs < 1:
        parser.error("--tuning-runs must be at least 1")
    if args.retake_cap < 1:
        parser.error("--retake-cap must be at least 1")

    out_dir = args.out_dir or os.path.join(ROOT, campaign.RESULTS_ROOT, TARGET)
    phase = "tune" if args.tune else "measure"
    board = Board(args.host)
    governor_restored = False
    try:
        campaign.require_clean(campaign.WATCHED_BUILD_INPUTS)
        if args.measure and args.campaign:
            for warning in campaign.require_run_count(args.runs, args.campaign):
                print("WARNING: %s" % warning, file=sys.stderr)

        os.makedirs(out_dir, exist_ok=True)
        if not args.no_build:
            print("rsync tree to %s and build ctr_bench on the board..." % args.host)
            board.rsync_tree()
            board.build()

        # The gate: pin the clock, and refuse if it will not pin. Recorded either way.
        clock_reading = None
        try:
            clock_reading = gate_performance_clock(board)
            print("clock gate: performance @ %d kHz -- ok" % PINNED_KHZ)
        except ClockGateFailed as exc:
            # Record what was seen before refusing, so env.json shows the refusal.
            board_env = _safe_probe(board)
            env = build_env(args, phase, board_env, board.binary_sha256(),
                            getattr(exc, "reading", {"ok": False}), "gate-refused")
            campaign.write_json(os.path.join(out_dir, ENV_FILENAME), env)
            raise

        campaign_uid = campaign.make_campaign_uid([
            phase, TARGET, campaign.utc_now(), args.seed,
            board.binary_sha256(), campaign.git("rev-parse", "HEAD")])
        args.campaign_uid = campaign_uid

        board_env = board.probe_env()
        extra = {}
        if args.measure:
            extra["tuning_freeze"] = campaign.tuning_freeze_record(out_dir)
        env = build_env(args, phase, board_env, board.binary_sha256(),
                        clock_reading, campaign_uid, extra)
        campaign.write_json(os.path.join(out_dir, ENV_FILENAME), env)

        if args.tune:
            phase_tune(args, board, out_dir)
            runs_path = None
        else:
            runs_path = phase_measure(args, board, out_dir)

        # Rewrite env with the board's end state, so "did it drift or throttle during
        # the run?" is answerable from a reading, not an intention.
        env["board_at_end"] = _safe_probe(board)
        env["finished_utc"] = campaign.utc_now()
        campaign.write_json(os.path.join(out_dir, ENV_FILENAME), env)

        if runs_path:
            summarize_and_check(runs_path)
    except campaign.CampaignError as exc:
        print("a7 campaign: %s" % exc, file=sys.stderr)
        return 1
    except (subprocess.SubprocessError, OSError) as exc:
        print("a7 campaign: %s" % exc, file=sys.stderr)
        return 1
    finally:
        if not args.no_restore_governor:
            try:
                board.set_governor("ondemand")
                governor_restored = True
            except Exception as exc:  # noqa: BLE001 -- best-effort hygiene
                print("WARNING: could not restore the board governor to ondemand: %s"
                      % exc, file=sys.stderr)
        if governor_restored:
            print("restored the board governor to ondemand")
    return 0


def _safe_probe(board):
    try:
        return board.probe_env()
    except Exception as exc:  # noqa: BLE001
        return {"probe_error": str(exc)}


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
