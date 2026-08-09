#!/usr/bin/env python3
"""Produce results/m4-speed.csv: this project's authoritative Cortex-M4 result.

`make m4-bench` runs this. It builds all three memory configurations from a
removed build/m4, flashes and runs each one on the board, and writes a single CSV
carrying every row plus the provenance needed to check it.

Why one command rather than three runs stitched together
--------------------------------------------------------
On this part a per-row figure moves by up to 7.5% purely from where the code
lands. The governing variable is a code address's offset **mod 16**: with the ART
off the only instruction-fetch granularity is the 128-bit flash word, so a +16 B
shift is invisible (0 of 39 rows move) and a +4 B shift is close to worst case
(39 of 39 move). Any edit anywhere in the image -- even to a string literal --
reshuffles those offsets. So rows built at different commits are not comparable
columns, and assembling this file by hand from three separate sessions produces a
table that looks fine and is not one. This script is what makes that impossible:
one build, one commit, one session, all three configurations, or it fails.

The three configurations, and what each answers:

  product      code in flash, ART on   -- how the cipher actually runs, and the
                                          fastest placement this part offers
  flash-noart  code in flash, ART off  -- the accelerator's own contribution
  sram-noart   code in SRAM,  ART off  -- instruction fetch moved off the
                                          dedicated ICode bus onto the system bus

Nothing here computes, adjusts or infers a timing figure. Every number in the
output came off the board in this run, copied verbatim from the firmware's own
CSV; the script's whole job is to make sure the three sets belong together and to
say where they came from. The two derived lines it does emit (the aggregate
ratios) are labelled as derived, quoted to two significant figures, and
recomputable from the rows below them.

Hardware notes that cost an afternoon each if ignored:

  * st-util holds the USB device. It is terminated in a `finally` on every path,
    including exceptions and Ctrl-C, or the next run fails with a misleading
    "cannot open device".
  * The semihosted output appears on **st-util's** stdout, not gdb's.
  * st-util 1.8.0 does not implement SYS_EXIT, so fw/m4/run.gdb breaks at sh_exit
    to end a scripted run.
  * NRST is not wired on this board: `st-flash --reset` only, never
    --connect-under-reset for writes.
"""

import argparse
import atexit
import datetime
import hashlib
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import cipher_set  # noqa: E402  (needs HERE on the path)

# (config label as the firmware reports it, Makefile binary name). The label is
# not a second source of truth -- it comes from M4_DEFS_<name> in the Makefile and
# is *checked* against what the firmware prints in every row, so a build whose
# label and linker script disagree fails here rather than being published.
CONFIGS = [
    ("product", "bench_m4"),
    ("flash-noart", "flash_noart"),
    ("sram-noart", "sram_noart"),
]

# Cipher pairs whose identical rows have been checked against their variant JSONs
# and are explained by the note the emitter prints. Detection is derived from the
# rows, so a pair that appears later is still *found*; this list only controls
# whether it is described as expected. A new pair therefore shows up labelled
# unexplained rather than silently inheriting an explanation that may not fit.
EXPLAINED_IDENTICAL = {
    ("cipher-D-lin444-297-aes-r5", "cipher-D-lin444-297-r5"),
}

# Bitsliced S-box gate counts quoted in the IDENTICAL ROWS note. An index into
# present_circuit_gates_u64[] would be machinery (the order is generated), so
# these are literals -- but sbox_gates_still_current() checks them against the
# generated table so a regenerated circuit makes the note wrong loudly instead of
# leaving it silently stale.
AES_SBOX_GATES = 132
CIPHER_D_SBOX_GATES = 1107
SBOX_CIRCUITS_H = "src/gen/sbox_circuits.h"

FLASH_ORIGIN = "0x08000000"
GDB_SCRIPT = "fw/m4/run.gdb"

START_MARKER = "# m4-bench: on-device speed benchmark"
COLUMN_HEADER = ("cipher,rounds,impl,config,cycles_per_byte,cycles_per_byte_min,"
                 "mb_per_sec,ns_per_op,status")
END_PREFIX = "# stack peak:"

# An st-util log line, which must never be mistaken for benchmark output.
STUTIL_LOG = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\s+(INFO|WARN|ERROR|DEBUG)\b")
# A data row: nine fields, the four timing ones either a number or empty (a
# KAT_FAIL row carries no timings and must still reach the CSV).
NUM = r"(?:\d+\.\d+|)"
ROW_RE = re.compile(
    rf"^([A-Za-z0-9._-]+),(\d+),([A-Za-z0-9._-]+),([A-Za-z0-9._-]+),"
    rf"({NUM}),({NUM}),({NUM}),({NUM}),([A-Za-z_]+)$")


class Failure(Exception):
    """A condition that must stop the run rather than be worked around."""


# --------------------------------------------------------------------------- #
# process helpers
# --------------------------------------------------------------------------- #

def run(cmd, timeout=None, cwd=ROOT, check=True):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise Failure("command failed (exit %d): %s\n--- stdout ---\n%s\n--- stderr ---\n%s"
                      % (p.returncode, " ".join(cmd), p.stdout, p.stderr))
    return p


def tool_version(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return "unavailable (%s)" % exc
    text = (p.stdout or "") + (p.stderr or "")
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return "unknown"


def kill_stray_st_util():
    """A leftover server owns the USB device; the next st-flash fails obscurely."""
    p = subprocess.run(["pgrep", "-x", "st-util"], capture_output=True, text=True)
    pids = [int(x) for x in p.stdout.split()]
    if not pids:
        return
    print("WARNING: st-util already running (pid %s); it holds the USB device. "
          "Terminating it." % ", ".join(str(x) for x in pids), file=sys.stderr)
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    for _ in range(50):
        if not subprocess.run(["pgrep", "-x", "st-util"],
                              capture_output=True).stdout.strip():
            return
        time.sleep(0.1)
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    time.sleep(0.5)


def probe():
    """Fail loudly with st-info's own output if there is no programmer."""
    if shutil.which("st-info") is None:
        raise Failure("st-info not on PATH; install stlink-tools")
    p = subprocess.run(["st-info", "--probe"], capture_output=True, text=True, timeout=60)
    text = (p.stdout or "") + (p.stderr or "")
    m = re.search(r"Found (\d+) stlink programmers", text)
    if p.returncode != 0 or not m or int(m.group(1)) == 0:
        raise Failure(
            "no ST-LINK programmer found -- st-info --probe said:\n" + text.rstrip()
            + "\n\nLikely causes, in order:\n"
              "  * another process already owns the device. Anything holding it --\n"
              "    st-util, openocd, a debugger in an IDE -- makes the probe report\n"
              "    zero programmers, not a busy device. This script kills stray\n"
              "    st-util before probing; check for the others with\n"
              "    `fuser -v /dev/bus/usb/*/*` or `lsof | grep -i stlink`.\n"
              "  * the board is unplugged, or the USB cable is power-only.\n"
              "  * udev rules are missing, so the device is there but not writable.")
    return text.strip()


# --------------------------------------------------------------------------- #
# one configuration on the board
# --------------------------------------------------------------------------- #

def flash_and_run(binary, log_dir, gdb_timeout, flash_timeout):
    """Flash build/m4/<binary>.bin, run it under st-util, return st-util's stream.

    st-util is started here and terminated in the `finally`, on every path
    including an exception and Ctrl-C. Nothing between the two lines may return
    early.
    """
    elf = os.path.join(ROOT, "build", "m4", binary + ".elf")
    bin_ = os.path.join(ROOT, "build", "m4", binary + ".bin")
    for path in (elf, bin_):
        if not os.path.exists(path):
            raise Failure("missing %s -- the build did not produce it" % path)

    # NRST is not wired: software reset only, never --connect-under-reset.
    run(["st-flash", "--reset", "write", bin_, FLASH_ORIGIN], timeout=flash_timeout)

    server_log = os.path.join(log_dir, binary + ".st-util.log")
    gdb_log = os.path.join(log_dir, binary + ".gdb.log")
    proc = None
    fh = open(server_log, "w+")
    try:
        proc = subprocess.Popen(["st-util"], cwd=ROOT, stdout=fh,
                                stderr=subprocess.STDOUT, text=True)
        _kill_on_exit.append(proc)

        deadline = time.time() + 30
        while time.time() < deadline:
            if proc.poll() is not None:
                fh.flush()
                raise Failure("st-util exited immediately (%d):\n%s"
                              % (proc.returncode, open(server_log).read()))
            fh.flush()
            if "Listening at" in open(server_log).read():
                break
            time.sleep(0.2)
        else:
            raise Failure("st-util never reported 'Listening at':\n" + open(server_log).read())

        gp = subprocess.run(["gdb-multiarch", "-batch", "-x", GDB_SCRIPT, elf],
                            cwd=ROOT, capture_output=True, text=True, timeout=gdb_timeout)
        with open(gdb_log, "w") as g:
            g.write(gp.stdout + gp.stderr)
        if gp.returncode != 0:
            raise Failure("gdb-multiarch failed (exit %d):\n%s\n%s"
                          % (gp.returncode, gp.stdout, gp.stderr))
    finally:
        if proc is not None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
            except OSError:
                pass
            if proc in _kill_on_exit:
                _kill_on_exit.remove(proc)
        fh.flush()
        fh.close()

    return open(server_log).read()


_kill_on_exit = []


@atexit.register
def _reap():
    for proc in list(_kill_on_exit):
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# parsing what the firmware said
# --------------------------------------------------------------------------- #

class Emission:
    def __init__(self, header, rows, trailer):
        self.header = header      # comment lines before the column header
        self.rows = rows          # data rows, verbatim
        self.trailer = trailer    # comment lines after the last data row

    def field(self, prefix):
        for line in self.header + self.trailer:
            if line.startswith(prefix):
                return line
        return None


def extract(stream, config, binary):
    """Pull the firmware's CSV out of st-util's stream, or fail saying why.

    st-util interleaves its own log lines with the semihosted stream while it is
    writing flash. Those are dropped by pattern and counted; anything else that
    is neither a comment nor a well-formed row is an error, because a mangled row
    is exactly the kind of damage that would otherwise be published as a number.
    """
    lines = stream.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == START_MARKER)
    except StopIteration:
        raise Failure("%s: the firmware never printed its start marker %r. "
                      "st-util's stream was:\n%s" % (binary, START_MARKER, stream[-4000:]))
    try:
        end = next(i for i in range(start, len(lines))
                   if lines[i].startswith(END_PREFIX))
    except StopIteration:
        raise Failure("%s: the firmware started but never reached %r -- it did not "
                      "run to completion. Stream tail:\n%s"
                      % (binary, END_PREFIX, stream[-4000:]))

    block, dropped = [], 0
    for line in lines[start:end + 1]:
        if STUTIL_LOG.match(line.strip()):
            dropped += 1
            continue
        block.append(line.rstrip("\r"))

    if COLUMN_HEADER not in block:
        raise Failure("%s: the column header line is missing or mangled; refusing "
                      "to guess the column order.\n%s" % (binary, "\n".join(block)))
    ci = block.index(COLUMN_HEADER)

    # The start marker is framing, not provenance; everything else before the
    # column header is the firmware's own account of what it measured.
    header = [l for l in block[:ci] if l.strip() and l.strip() != START_MARKER]
    rows, trailer = [], []
    for line in block[ci + 1:]:
        if not line.strip():
            continue
        if line.startswith("#"):
            trailer.append(line)
            continue
        if trailer:
            raise Failure("%s: a data row appears after the trailing comments; the "
                          "stream is out of order:\n%r" % (binary, line))
        m = ROW_RE.match(line)
        if not m:
            raise Failure("%s: unparseable line between the column header and the "
                          "trailer -- not a comment and not a well-formed row:\n%r"
                          % (binary, line))
        if m.group(4) != config:
            raise Failure("%s: row says config=%r but this build is labelled %r. "
                          "The binary and its label disagree; nothing from this "
                          "build can be published.\n%r"
                          % (binary, m.group(4), config, line))
        rows.append(line)

    if not rows:
        raise Failure("%s: no data rows at all" % binary)
    if dropped:
        print("  note: dropped %d interleaved st-util log line(s) from %s's stream"
              % (dropped, binary), file=sys.stderr)
    return Emission(header, rows, trailer)


def check_cipher_set(emissions):
    """The seven ciphers and their round counts come from tools/cipher_set.py.

    Nothing here restates them; this checks that what the board reported is
    exactly what that file defines, so a cipher silently dropped from the
    firmware's KAT table shows up as a failure and not as a shorter table.
    """
    want = {(name, rounds) for _, name, rounds in cipher_set.resolve()}
    for config, em in emissions.items():
        got = {(ROW_RE.match(r).group(1), int(ROW_RE.match(r).group(2))) for r in em.rows}
        if got != want:
            raise Failure(
                "%s: the ciphers on the board do not match tools/cipher_set.py.\n"
                "  missing: %s\n  unexpected: %s"
                % (config, sorted(want - got) or "none", sorted(got - want) or "none"))
    return sorted(want)


# --------------------------------------------------------------------------- #
# the output file
# --------------------------------------------------------------------------- #

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def git(*args):
    return subprocess.run(["git"] + list(args), cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()


# Everything that can change a firmware image. An allowlist rather than an
# exclusion list: a path nobody thought of is then treated as build-affecting only
# if it lives somewhere the build actually reads, and the failure mode of getting
# it wrong is a spurious refusal rather than a CSV stamped with a commit that does
# not describe its binaries. The wildcard directories matter as directories --
# `$(wildcard fw/m4/*.h)` and `$(wildcard variants/*.json)` mean a new *untracked*
# file there changes the build too.
BUILD_INPUTS = ("Makefile", "fw/", "src/", "include/", "bench/", "variants/",
                "tools/cipher_set.py", "tools/gen_m4_kats.py", "tools/gen_c.py",
                "tools/gen_retyped_circuits.py", "tools/m4_kat_oracle.c",
                "tools/sbox_synth.c", "tools/run_m4_bench.py")


def build_state_paths(out_path):
    """Working-tree changes that would make the stamped commit a lie."""
    dirty = []
    for line in git("status", "--porcelain").splitlines():
        path = line[3:].strip().strip('"')
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        if not path.startswith(BUILD_INPUTS):
            continue
        if os.path.abspath(os.path.join(ROOT, path)) == os.path.abspath(out_path):
            continue
        dirty.append(line)
    return dirty


def ratio_summary(emissions):
    """Aggregate cycles_per_byte ratios against `product`, derived from the rows.

    Emitted as a comment so the file's headline is recomputable from the file
    itself. Two significant figures, because the layout noise floor is 7.5% and a
    third digit would not be a measurement.
    """
    def table(config):
        out = {}
        for r in emissions[config].rows:
            m = ROW_RE.match(r)
            if m.group(9) == "ok" and m.group(5):
                out[(m.group(1), m.group(3))] = float(m.group(5))
        return out

    base = table("product")
    lines = []
    for config, _ in CONFIGS:
        if config == "product":
            continue
        other = table(config)
        keys = sorted(set(base) & set(other))
        if not keys:
            continue
        vals = [other[k] / base[k] for k in keys]
        slower = sum(1 for v in vals if v > 1.0)
        lines.append("#   %-12s %.2g / %.2g / %.2g   (min / median / max over %d rows; "
                     "%d of %d slower than product)"
                     % (config, min(vals), statistics.median(vals), max(vals),
                        len(vals), slower, len(vals)))
    return lines


def sbox_gates_still_current():
    """Do the two gate counts quoted in the IDENTICAL ROWS note still appear in
    the generated gate table? If not, the note says so rather than asserting a
    number the sources no longer support."""
    try:
        with open(os.path.join(ROOT, SBOX_CIRCUITS_H)) as f:
            text = f.read()
    except OSError:
        return False
    m = re.search(r"present_circuit_gates_u64\[[^\]]*\]\s*=\s*\{([^}]*)\}", text)
    if not m:
        return False
    vals = set(v.strip() for v in m.group(1).split(","))
    return str(AES_SBOX_GATES) in vals and str(CIPHER_D_SBOX_GATES) in vals


def variant_path(reported_name):
    """The JSON a reported cipher name came from, per tools/cipher_set.py.

    Not derivable from the name: two of the seven are benchmarked at a round
    count their JSON does not declare, so `aes-r5` lives in variants/wide/aes.json
    and a path built by string-concatenating the reported name would be a
    citation to a file that does not exist.
    """
    for path, name, _ in cipher_set.resolve():
        if name == reported_name:
            return path
    return "(not in tools/cipher_set.py: %s)" % reported_name


def ok_values(emissions):
    """(cipher, impl) -> {config: cycles_per_byte} over rows that carry a figure."""
    vals = {}
    for config, em in emissions.items():
        for r in em.rows:
            m = ROW_RE.match(r)
            if m.group(9) != "ok" or not m.group(5):
                continue
            vals.setdefault((m.group(1), m.group(3)), {})[config] = m.group(5)
    return vals


def min_column_note(emissions):
    """How often cycles_per_byte and cycles_per_byte_min coincide, and over what.

    Derived, not asserted: if a future board or a future protocol ever produces
    spread between the two columns, this stops claiming they agree and reports
    the count that actually differs.
    """
    same = total = 0
    for em in emissions.values():
        for r in em.rows:
            m = ROW_RE.match(r)
            if m.group(9) != "ok" or not m.group(5):
                continue
            total += 1
            same += (m.group(5) == m.group(6))
    return same, total


def identical_pairs(emissions):
    """Ciphers whose rows for some implementation are bit-identical, and the
    implementation that separates them most.

    Derived from the rows for the same reason: six identical row pairs in a
    published file read as a copy-paste fault unless something says otherwise,
    and a note hard-coded to today's six would still say "expected" on the day
    the set changes. Returns [(cipher_a, cipher_b, [impls], n_pairs, contrast)]
    where contrast is the sharpest disagreeing implementation, or None if no
    implementation disagrees at all -- which would not be reassuring and is
    reported as such.
    """
    vals = ok_values(emissions)
    ciphers = sorted({c for c, _ in vals})
    impls = sorted({i for _, i in vals})
    out = []
    for i in range(len(ciphers)):
        for j in range(i + 1, len(ciphers)):
            ca, cb = ciphers[i], ciphers[j]
            same, differ, pairs = [], [], 0
            for im in impls:
                va, vb = vals.get((ca, im)), vals.get((cb, im))
                if not va or not vb:
                    continue
                shared = sorted(set(va) & set(vb))
                if not shared:
                    continue
                if all(va[c] == vb[c] for c in shared):
                    same.append(im)
                    pairs += len(shared)
                else:
                    for c in shared:
                        x, y = float(va[c]), float(vb[c])
                        differ.append((max(x, y) / min(x, y), im, c, va[c], vb[c]))
            if same:
                # Quote the contrast from the primary configuration when there is
                # one: it is the column a reader is looking at, and a contrast
                # drawn from sram-noart would invite the thought that the
                # separation is a memory-placement effect rather than the cipher.
                primary = [d for d in differ if d[2] == CONFIGS[0][0]]
                pick = max(primary) if primary else (max(differ) if differ else None)
                out.append((ca, cb, same, pairs, pick))
    return out


def partition(emissions):
    """Split the firmware's provenance into what is shared and what is per-config.

    Decided by comparing the three streams rather than by a hardcoded list, so a
    line that starts varying between configurations moves into the per-config
    block on its own instead of being published once and silently attributed to
    all three.
    """
    per = {c: em.header + em.trailer for c, em in emissions.items()}
    first = per[CONFIGS[0][0]]
    common = set(first)
    for c, _ in CONFIGS[1:]:
        common &= set(per[c])
    shared = [l for l in first if l in common]
    unique = {c: [l for l in per[c] if l not in common] for c, _ in CONFIGS}
    return shared, unique


def compose(emissions, meta, out_path):
    shared, unique = partition(emissions)
    ciphers = check_cipher_set(emissions)
    n_rows = sum(len(em.rows) for em in emissions.values())
    n_ok = sum(1 for em in emissions.values() for r in em.rows
               if ROW_RE.match(r).group(9) == "ok")

    L = []
    a = L.append
    # No nominal frequency here. The part is specified for 168 MHz and the PLL is
    # configured for it, but the only clock figure this file may state is the one
    # that was measured, which is per configuration below -- printing "168 MHz" in
    # the title is how a nominal number becomes the one a reader quotes.
    a("# results/m4-speed.csv -- Cortex-M4 speed, on an STM32F407. The core clock")
    a("# was measured for each configuration; see the per-configuration block below.")
    a("# The authoritative M4 measurement for this project: it supersedes every")
    a("# per-task CSV quoted in the phase-4 task reports, which were built at")
    a("# different commits and whose columns are therefore not comparable with each")
    a("# other. (results/speed.csv is x86-64 and results/speed-arm.csv is 32-bit")
    a("# ARMv7-A/NEON on a Cortex-A7, not aarch64; neither is superseded by this,")
    a("# and neither is measured the same way.)")
    a("#")
    a("# Produced by `make m4-bench` (tools/run_m4_bench.py): one command, one")
    a("# session, one commit, all three configurations built from a removed")
    a("# build/m4 and measured one after another on the same board without")
    a("# rebuilding in between. That is a requirement, not a convenience -- see")
    a("# RESOLUTION below.")
    a("#")
    a("# Each configuration is flashed twice before it runs, which is worth stating")
    a("# because it is not what a reader would assume: `st-flash --reset write` puts")
    a("# the image on the part and software-resets it (NRST is not wired on this")
    a("# board), and gdb's `load` over the st-util session then writes the same image")
    a("# again before running it. The second write is what the run actually executes.")
    a("# Both write the same bytes from the same build, so this affects nothing in")
    a("# the rows below; it is recorded because the procedure should be checkable")
    a("# against the file rather than reconstructed from the script.")
    a("#")
    a("# reproduce:  git checkout %s && make m4-bench" % meta["commit"][:12])
    a("#             This file is committed on top of that commit, so it is not in")
    a("#             the tree the command checks out. The build inputs that can")
    a("#             change a firmware byte -- and which the driver refuses to run")
    a("#             with modified -- are:")
    for i in range(0, len(BUILD_INPUTS), 4):
        a("#               " + "  ".join(BUILD_INPUTS[i:i + 4]))
    a("#             Checked separately, not by this run, which cannot check")
    a("#             itself. The command was run repeatedly at commits differing")
    a("#             only in this script's comment text, which cannot reach a")
    a("#             firmware byte. All three sha256 below reproduced every time,")
    a("#             and columns 1-7 of all %d rows -- through mb_per_sec -- were"
      % n_rows)
    a("#             byte-identical every time. ns_per_op is the only column that")
    a("#             moved, in its low-order digits, tracking the LSE-referenced")
    a("#             sysclk measurement.")
    a("#")
    a("#             These three sha256 are NOT the ones this file carried at")
    a("#             05fad44 and before, and were not expected to be. Every")
    a("#             published revision up to that point changed this script and")
    a("#             the build's relocation audit only, so the images reproduced")
    a("#             byte for byte across all of them; the revision that added the")
    a("#             bitslice64 rows is a firmware change, and a firmware change")
    a("#             moves code addresses. `git diff 05fad44..%s -- fw src include"
      % meta["commit"][:7])
    a("#             bench variants` is what shows which kind of change this was --")
    a("#             not anyone's word, including mine.")
    a("#")
    a("#             The consequence for a reader holding an older copy: the %d"
      % n_rows)
    a("#             rows below were all measured in the run described here, so")
    a("#             they are comparable with each other, and that is the only")
    a("#             comparison this file supports. Rows carried over from an")
    a("#             older copy are not a column to difference against these.")
    a("#             RESOLUTION's 7.5% does not bound the difference either: it")
    a("#             was measured by relinking one set of object files, and a")
    a("#             firmware change recompiles them. A cipher whose timed kernel")
    a("#             is inlined into the harness translation unit moves furthest,")
    a("#             because editing any function in that unit lets the compiler")
    a("#             re-schedule the whole of it.")
    a("#")
    a("# commit:     %s%s" % (meta["commit"], "" if meta["clean"] else "  *** DIRTY ***"))
    a("# tree:       %s" % ("clean (no modified build input)" if meta["clean"]
                            else "MODIFIED -- the commit above does NOT describe these binaries: "
                                 + "; ".join(meta["dirty"])))
    a("# measured:   %s" % meta["when"])
    a("# host:       %s" % meta["host"])
    a("# toolchain:  %s" % meta["cc"])
    a("#             %s" % meta["stlink"])
    a("#             %s" % meta["gdb"])
    a("# programmer: %s" % meta["probe"])
    a("#")
    a("# CONFIGURATIONS -- the `config` column")
    a("#   product      code in flash, ART on   how the cipher actually runs, and the")
    a("#                                        fastest placement this part offers")
    a("#   flash-noart  code in flash, ART off  the accelerator's own contribution")
    a("#   sram-noart   code in SRAM,  ART off  instruction fetch moved off the")
    a("#                                        dedicated ICode bus onto the system")
    a("#                                        bus that carries every data access.")
    a("#                                        NOT a lower bound and NOT 'the cipher")
    a("#                                        without the flash': this part has no")
    a("#                                        zero-wait-state executable memory.")
    a("#")
    a("# RESOLUTION -- read this before comparing any two rows")
    a("#   A per-row figure here moves by up to 7.5% from code placement alone. The")
    a("#   governing variable is a code address's offset mod 16: with the ART off the")
    a("#   only instruction-fetch granularity is the 128-bit flash word, so a +16 B")
    a("#   shift of the image is invisible (0 of 39 rows move) while a +4 B shift is")
    a("#   close to worst case (39 of 39 move, up to 7.5%). Measured directly, on one")
    a("#   set of object files relinked against scripts differing only by padding")
    a("#   ahead of .text, with a zero-pad control that was byte-identical to the")
    a("#   shipped image. Turning the ART bits off is itself a 4-byte shift (`movs")
    a("#   r2,#5` is two bytes where `movw r2,#0x705` is four), so the harmful case is")
    a("#   the one this file's own comparison sits on, and no care removes it.")
    a("#")
    a("#   Stated honestly: 7.5% was measured on flash-noart, the configuration most")
    a("#   exposed to it, and is applied to all three here as the conservative")
    a("#   choice rather than as a measured value for each. product has the D-cache")
    a("#   absorbing part of it and is probably better; sram-noart fetches over the")
    a("#   system bus and has no word to straddle. The two pad points (+16 and +4)")
    a("#   bracket the effect and establish the mechanism; they are not a")
    a("#   distribution, so 7.5% is a bound, not a typical value.")
    a("#")
    a("#   Stated honestly, second part -- AND THIS PARAGRAPH CORRECTS THE FIRMWARE'S")
    a("#   OWN LINE BELOW, it is not a second independent statement of the same")
    a("#   thing. Under SHARED further down, the line beginning `cross-config layout")
    a("#   noise:` is fw/m4/bench_m4_main.c's text, reproduced verbatim and never")
    a("#   edited by this script (see the note at the head of that block). It states")
    a("#   the same relink experiment WITHOUT the qualification that follows. Where")
    a("#   the two differ, this paragraph is the one to believe; the relayed line is")
    a("#   kept unedited because its value is being the firmware's own words, not")
    a("#   because it is the more complete statement.")
    a("#")
    a("#   The qualification: the relink experiment was run on a 39-row image, before")
    a("#   the ten bitslice64 rows existed -- which is why the relayed line says `0 of")
    a("#   39` and `39 of 39` while this file publishes 49 pairs per configuration.")
    a("#   It has NOT been re-measured on the image that produced this file, and by")
    a("#   the argument three paragraphs up -- a firmware change recompiles the")
    a("#   objects, so the 7.5% does not bound the difference across one -- carrying")
    a("#   it here is an assumption, not a measurement. The mechanism (offset mod 16")
    a("#   against a 128-bit flash word) is a property of the part and does not depend")
    a("#   on the row set, so the figure is expected to be about right; it is quoted")
    a("#   as the working floor rather than as a value measured on this image.")
    a("#   Anything that turns on the third significant figure of a cross-config ratio")
    a("#   should re-run the relink on the current objects first.")
    a("#")
    a("#   Therefore: quote ratios between configurations to TWO SIGNIFICANT FIGURES,")
    a("#   prefer the aggregate over any individual row, and never difference two")
    a("#   individual rows across configurations -- at a 7.5% floor a 1.05x per-row")
    a("#   difference is not a measurement. Within one config the board is")
    a("#   deterministic and cycles_per_byte repeats to the last digit; the floor is a")
    a("#   property of comparing configurations, not of the counter.")
    a("#")
    a("#   THIS PARAGRAPH ALSO CORRECTS A RELAYED LINE, on the same terms as above.")
    a("#   Under SHARED below, the line beginning `tables:` is again the firmware's")
    a("#   verbatim text, and it quotes per-row percentages (+6.99% / +6.73%) for the")
    a("#   T-table CCM-vs-SRAM A/B without saying what they are worth. They are")
    a("#   single-row differences between two separate builds -- the case the")
    a("#   paragraph above forbids, and worse than a relink, since a different table")
    a("#   placement recompiles. Read them for their SIGN, which is the whole of the")
    a("#   conclusion (CCM is slower for those tables); the magnitude is inside the")
    a("#   floor and means nothing. The relayed line does not say that; this does.")
    a("#")
    a("# AGGREGATE RATIOS -- derived from the rows below, not measured separately;")
    a("# cycles_per_byte of the named config over product, per (cipher, impl) pair:")
    for line in ratio_summary(emissions):
        a(line)
    a("#   The MEDIAN is the figure to quote: it is an aggregate over exactly the")
    a("#   pairs counted on each line above -- those with status=ok in both that")
    a("#   configuration and product, which is the only set for which a ratio")
    a("#   exists -- and an aggregate is what survives the 7.5% floor. That count")
    a("#   is not necessarily the total pair count: a KAT_FAIL row anywhere drops")
    a("#   its pair from the ratio while leaving it in the rows below.")
    a("#   min and max are single rows and each carries that floor in full --")
    a("#   read them as the spread, not as")
    a("#   measurements of a best and worst case. The count of rows slower than")
    a("#   product is a sign test and needs no error bar at all.")
    a("#")
    a("# IMAGES -- all three from the one build described above (sha256):")
    for config, binary in CONFIGS:
        a("#   %-12s %s  build/m4/%s.elf" % (config, meta["sha"][binary], binary))
    a("#   build/m4 was removed before the build, and `make m4-configs` built all")
    a("#   three in a single invocation. The build refuses to link sram-noart unless")
    a("#   an nm audit finds every .text symbol of every relocated object inside")
    a("#   .ramtext, so a run whose timed code silently stayed in flash cannot be")
    a("#   published. This build: %s" % meta["audit"])
    a("#")
    a("# PER CONFIGURATION -- reported by the firmware itself, not by this script.")
    a("# `observed` is read off the running part (main's linked address, and")
    a("# FLASH_ACR read back from the peripheral), so no build label can lie about")
    a("# what was measured:")
    for config, _ in CONFIGS:
        a("#   [%s]" % config)
        for line in unique[config]:
            a("#     " + line.lstrip("# ").rstrip())
    a("#")
    a("# SHARED -- reported identically by all three configurations, so it is stated")
    a("# once here rather than three times above. Method, limits and memory use,")
    a("# emitted by fw/m4/bench_m4_main.c. Any line that starts differing between")
    a("# configurations moves into the per-configuration block above on its own; the")
    a("# split is decided by comparing the three streams, not by a fixed list.")
    a("#")
    a("# Every line below is the firmware's own text, reproduced byte for byte. This")
    a("# script does not edit, reword or drop any of them, which is the whole reason")
    a("# the block is worth having: it can be diffed against the firmware source. The")
    a("# cost of that is that a relayed line cannot be updated when something later")
    a("# supersedes it, so TWO OF THEM ARE CORRECTED IN RESOLUTION ABOVE and must be")
    a("# read together with it rather than as standalone claims --")
    a("#   `cross-config layout noise:`  the 7.5% floor and its `39 of 39` were")
    a("#                                 measured on a 39-row image; this file")
    a("#                                 publishes 49 pairs per configuration and the")
    a("#                                 relink was not re-run. RESOLUTION says so.")
    a("#   `tables:`                     the +6.99% / +6.73% are single-row")
    a("#                                 differences between two builds, good for")
    a("#                                 their sign only. RESOLUTION says so.")
    a("# No other line below is qualified or superseded elsewhere in this file. The")
    a("# list is exhaustive so that a reader who lands in this block first cannot")
    a("# mistake either of those two for the last word on its subject:")
    for line in shared:
        a("#   " + line.lstrip("# ").rstrip())
    a("#")
    a("# ROWS: %d = %d (cipher, impl) pairs x %d configurations, from %d ciphers."
      % (n_rows, n_rows // len(CONFIGS), len(CONFIGS), len(ciphers)))
    a("# %d are status=ok. Not every cipher has every implementation (aes-r5 has no"
      % n_ok)
    a("# `ref` row and aes-lin444 no fused-table row), so the pair count is not a")
    a("# product of two round numbers. The cipher list and round counts are checked against")
    a("# tools/cipher_set.py, which is the single definition shared with the FPGA and")
    a("# x86 targets. A (cipher, impl) pair the on-device known-answer gate does not")
    a("# clear is emitted as status=KAT_FAIL with all four timing fields EMPTY -- it")
    a("# is never dropped, because a missing row and a failing row mean different")
    a("# things. keysetup rows use bytes_per_op = 1, as results/speed.csv does, so")
    a("# their cycles_per_byte reads as cycles per setup.")
    a("#")
    # --- the two columns a reader will otherwise misread ---------------------
    same, total = min_column_note(emissions)
    a("# THE TWO CYCLE COLUMNS")
    if same == total:
        a("#   cycles_per_byte and cycles_per_byte_min are equal in all %d timed rows."
          % total)
        a("#   They are not one number printed twice. fw/m4/bench_m4_main.c sorts the")
        a("#   trial array and then reads samples[TRIALS/2] and samples[0] from it --")
        a("#   two different elements, the median and the minimum, computed separately")
        a("#   over the trials counted in the protocol line above.")
        a("#   They coincide because every trial returns the identical cycle count:")
        a("#   interrupts are masked, SysTick is off, the working set is in CCM and each")
        a("#   table is in the memory chosen for it, so nothing is left to vary. Read it")
        a("#   as: on this part, under this protocol, the measurement has no run-to-run")
        a("#   spread to report.")
        a("#   So the min column is confirmation, not information, and the trial count")
        a("#   should not be read as implying a variance that does not exist. This says")
        a("#   nothing about spread BETWEEN configurations, which is real and is the")
        a("#   subject of RESOLUTION above.")
    else:
        a("#   cycles_per_byte and cycles_per_byte_min differ in %d of %d timed rows,"
          % (total - same, total))
        a("#   so the trials are NOT all returning the same count and the min column")
        a("#   carries real information. This is a change from previous runs of this")
        a("#   benchmark, in which all trials agreed; something is perturbing the")
        a("#   measurement and the spread should be explained before the rows are used.")
    a("#")
    # --- rows that are identical on purpose ---------------------------------
    dupes = identical_pairs(emissions)
    a("# IDENTICAL ROWS BETWEEN CIPHERS")
    if not dupes:
        a("#   None: no two ciphers share a bit-identical row for any implementation.")
    for ca, cb, impls, pairs, contrast in dupes:
        a("#   %s and %s are bit-identical" % (ca, cb))
        a("#   in %s (%d row pairs across the %d configurations)."
          % ("/".join(impls), pairs, len(CONFIGS)))
        if contrast and (ca, cb) in EXPLAINED_IDENTICAL:
            ratio, im, cfg, va, vb = contrast
            a("#   Expected, and not a copy-paste fault. The two differ in exactly one")
            a("#   field that affects computation: the 8-bit S-box. Compare")
            a("#     %s" % variant_path(ca))
            a("#     %s" % variant_path(cb))
            a("#   -- key_bits, key_schedule, linear, rounds and sbox_bits are all equal")
            a("#   and only sbox differs. A table implementation does the same number of")
            a("#   lookups into a table of the same size with the same access pattern")
            a("#   whatever the S-box holds, so its cycle count cannot tell them apart.")
            a("#   That they ARE different ciphers is visible in the rows themselves,")
            a("#   wherever an implementation depends on S-box structure rather than")
            a("#   just its size. Under %s, %s costs" % (cfg, im))
            a("#     %-28s %s cyc/B" % (ca, va))
            a("#     %-28s %s cyc/B" % (cb, vb))
            a("#   a factor of %.1f." % ratio)
            if sbox_gates_still_current():
                a("#   Bitsliced, the AES S-box costs %d gates where cipher-D's costs %d"
                  % (AES_SBOX_GATES, CIPHER_D_SBOX_GATES))
                a("#   -- see %s, of which the M4 links the u32 retype" % SBOX_CIRCUITS_H)
                a("#   of the same circuits. The %.1fx in gates exceeds the %.1fx in"
                  % (CIPHER_D_SBOX_GATES / float(AES_SBOX_GATES), ratio))
                a("#   cycles, which is what should happen: only the S-box layer differs,")
                a("#   so the linear layer, the round-key addition and the bitslice")
                a("#   transpose are identical work in both and dilute the ratio. The gate")
                a("#   counts set the direction and the order of magnitude of the gap;")
                a("#   they do not account for the whole of it on their own.")
            else:
                a("#   The bitsliced S-box gate counts this note quotes (%d and %d) are"
                  % (AES_SBOX_GATES, CIPHER_D_SBOX_GATES))
                a("#   no longer both present in %s, so they are"
                  % SBOX_CIRCUITS_H)
                a("#   withheld here rather than published stale. The measured factor")
                a("#   above stands; only the circuit-size explanation for it is")
                a("#   unverified against the sources of this build.")
            a("#   Both figures come from the same image in the same run, so the")
            a("#   layout floor in RESOLUTION does not apply here: this is a")
            a("#   within-configuration ratio, not a cross-configuration one.")
        elif contrast:
            ratio, im, cfg, va, vb = contrast
            a("#   This pair was NOT among the ones explained when this file's emitter")
            a("#   was written, so treat the identical rows as unexplained rather than")
            a("#   as expected, and check them. They do separate elsewhere: %s under" % im)
            a("#   %s is %s vs %s cyc/B, a factor of %.1f." % (cfg, va, vb, ratio))
        else:
            a("#   NO implementation distinguishes these two ciphers anywhere in this")
            a("#   file. That is not expected and should be investigated before the rows")
            a("#   are used: two entries of the cipher set may have collapsed onto one.")
    a("#")
    a(COLUMN_HEADER)
    for config, _ in CONFIGS:
        L.extend(emissions[config].rows)

    text = "\n".join(L) + "\n"
    tmp = out_path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, out_path)
    return n_rows, n_ok


# --------------------------------------------------------------------------- #

def run_only(args):
    """--run-only: one image onto the board, its own output back, nothing else.

    Deliberately does not build, check the tree, verify the cipher set or write a
    file. It is a way to look at a board, not a way to produce a result -- the
    moment it could write results/m4-speed.csv it would become a second way to
    produce that file, and the whole point of this script is that there is one.
    """
    log_dir = args.log_dir or os.path.join(ROOT, "results", "logs", "m4")
    os.makedirs(log_dir, exist_ok=True)
    binary = args.run_only
    if not os.path.exists(os.path.join(ROOT, "build", "m4", binary + ".bin")):
        raise Failure("no build/m4/%s.bin -- build it first (`make m4-one` builds "
                      "the per-cipher images, `make m4-configs` the three combined "
                      "ones)" % binary)
    kill_stray_st_util()
    probe()
    print("[%s] flashing and running ..." % binary, file=sys.stderr)
    stream = flash_and_run(binary, log_dir, args.gdb_timeout, args.flash_timeout)

    # Printed from the start marker on, with st-util's own log lines dropped -- the
    # same framing extract() uses, but without its checks, because an image that
    # stopped early is exactly what someone runs this to look at.
    started = False
    for line in stream.splitlines():
        if line.strip() == START_MARKER:
            started = True
        if started and not STUTIL_LOG.match(line.strip()):
            print(line.rstrip())
    if not started:
        raise Failure("%s never printed its start marker %r; the raw stream is in "
                      "%s" % (binary, START_MARKER,
                              os.path.join(log_dir, binary + ".st-util.log")))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "m4-speed.csv"))
    ap.add_argument("--log-dir", default=None,
                    help="where to keep the raw st-util and gdb streams "
                         "(default: results/logs/m4)")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="run with modified build inputs. The stamped commit then "
                         "does not describe the binaries, and the CSV says so.")
    ap.add_argument("--gdb-timeout", type=float, default=600.0)
    ap.add_argument("--flash-timeout", type=float, default=300.0)
    ap.add_argument("--run-only", metavar="BINARY",
                    help="flash build/m4/BINARY.bin, run it, print its output and "
                         "stop. Nothing is composed, checked or published. This is "
                         "for the per-cipher images (build/m4/one_<cipher>_<config>, "
                         "`make m4-one`) and for iterating on a kernel: it is the "
                         "one place the board is driven from, so a development run "
                         "and a published run flash, reset and read the part the "
                         "same way.")
    args = ap.parse_args()

    if args.run_only:
        return run_only(args)

    out_path = os.path.abspath(args.out)
    log_dir = args.log_dir or os.path.join(ROOT, "results", "logs", "m4")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    commit = git("rev-parse", "HEAD")
    if not commit:
        raise Failure("not a git checkout -- the CSV cannot be stamped with a commit")
    dirty = build_state_paths(out_path)
    if dirty and not args.allow_dirty:
        raise Failure(
            "build inputs are modified, so a commit stamp would be a lie:\n  "
            + "\n  ".join(dirty)
            + "\nCommit them first, or pass --allow-dirty to publish a CSV that says "
              "its commit does not describe its binaries.")

    # Order matters, and the obvious order is wrong. A stray st-util owns the USB
    # device, and st-info --probe then reports "Found 0 stlink programmers" -- so
    # probing first aborts the run in exactly the situation the killer exists to
    # recover from, and the killer never runs.
    kill_stray_st_util()
    probe_text = probe()
    probe_line = " / ".join(x.strip() for x in probe_text.splitlines()[:4])

    # Unconditional, and there is deliberately no flag to skip it. The three
    # configurations must come from one build or their columns are not comparable,
    # and the audit line the CSV stamps has to come from the build that produced
    # the binaries being measured -- a cached build emits no audit line at all.
    shutil.rmtree(os.path.join(ROOT, "build", "m4"), ignore_errors=True)
    print("building all three configurations at %s ..." % commit[:12])
    build = run(["make", "m4-configs"], timeout=1800)
    # The audit line is stamped into the CSV as evidence the relocation held, so
    # this script must not accept a line that is not evidence of anything. The
    # Makefile already refuses to emit a zero or below-floor count; re-checking
    # here means a future regression there cannot quietly become a published
    # claim, which is the failure this whole audit exists to prevent.
    audit = None
    for line in (build.stdout + build.stderr).splitlines():
        if "relocation audit ok" in line:
            audit = line.split(":", 1)[1].strip()
    if audit is None:
        raise Failure(
            "the sram-noart relocation audit produced no line in this build, so "
            "there is nothing to stamp into the CSV; refusing to measure a "
            "configuration whose code placement is unverified.\n"
            "Expected `relocation audit ok` in the output of `make m4-configs`; "
            "build/m4 was removed first, so the link -- and with it the audit -- "
            "should have run.")
    m = re.search(r"(\d+) symbols in \.ramtext", audit)
    if not m or int(m.group(1)) < 1:
        raise Failure("the relocation audit reported %r -- it examined no symbols, "
                      "so it is not evidence that anything was relocated. Refusing "
                      "to stamp it into the CSV as if it were." % audit)

    emissions = {}
    streams = {}
    for config, binary in CONFIGS:
        print("[%s] flashing and running build/m4/%s.bin ..." % (config, binary))
        stream = flash_and_run(binary, log_dir, args.gdb_timeout, args.flash_timeout)
        streams[config] = stream
        emissions[config] = extract(stream, config, binary)
        print("  %d rows" % len(emissions[config].rows))

    meta = {
        "commit": commit,
        "clean": not dirty,
        "dirty": dirty,
        "when": datetime.datetime.now(datetime.timezone.utc)
                        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": "%s %s" % (os.uname().sysname, os.uname().release),
        "cc": tool_version(["arm-none-eabi-gcc", "--version"]),
        "stlink": "st-flash/st-util " + tool_version(["st-flash", "--version"]),
        "gdb": tool_version(["gdb-multiarch", "--version"]),
        "probe": probe_line,
        "audit": audit,
        "sha": {b: sha256(os.path.join(ROOT, "build", "m4", b + ".elf"))
                for _, b in CONFIGS},
    }

    n_rows, n_ok = compose(emissions, meta, out_path)
    print("wrote %s: %d rows, %d ok, %d not ok" % (out_path, n_rows, n_ok, n_rows - n_ok))

    # The per-kernel footprint, from the same run and the same build. Produced here
    # rather than by a separate command so it cannot end up describing a different
    # image than the speed rows do -- the failure the whole one-command discipline
    # in this script exists to prevent.
    #
    # The RAM figures are identical in all three configurations (they are sizeof
    # arithmetic over the round count, and no configuration changes either), so the
    # product stream is the one used. The Flash figures come from bench_m4.elf for
    # the same reason: product is the configuration a deployment would ship.
    footprint_out = os.path.join(os.path.dirname(out_path), "m4-footprint.csv")
    stream_path = os.path.join(log_dir, "product.footprint-stream.log")
    with open(stream_path, "w", encoding="utf-8") as fh:
        fh.write(streams["product"])
    fp = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", "m4_footprint.py"),
         "--elf", os.path.join(ROOT, "build", "m4", "bench_m4.elf"),
         "--stream", stream_path, "--out", footprint_out],
        cwd=ROOT, capture_output=True, text=True)
    if fp.returncode != 0:
        # Not fatal to the speed CSV, which is already written and valid. Say so
        # loudly rather than leaving a stale footprint file next to a fresh one.
        print("WARNING: the per-kernel footprint was NOT regenerated:\n%s%s"
              % (fp.stdout, fp.stderr), file=sys.stderr)
        print("  %s may now be stale with respect to %s"
              % (footprint_out, out_path), file=sys.stderr)
    else:
        print(fp.stdout.strip())
    if n_ok != n_rows:
        print("NOTE: %d row(s) are not status=ok -- they are in the file with empty "
              "timing fields, as they must be." % (n_rows - n_ok), file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as exc:
        print("run_m4_bench: %s" % exc, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("run_m4_bench: interrupted", file=sys.stderr)
        sys.exit(130)
