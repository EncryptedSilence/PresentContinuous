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
    a("# other. (results/speed.csv is x86 and results/speed-arm.csv is aarch64/NEON;")
    a("# neither is superseded by this, and neither is measured the same way.)")
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
    a("#             moved, in its eighth significant figure, tracking the")
    a("#             LSE-referenced sysclk measurement.")
    a("#             The three sha256 below are also unchanged from the version of")
    a("#             this file published at fe9d1fb, which someone other than its")
    a("#             author reproduced on their own hardware runs. Everything")
    a("#             committed since then changed this script and the build's")
    a("#             relocation audit only, and `git diff fe9d1fb..%s`" % meta["commit"][:7])
    a("#             touching no firmware source is the check for that -- not")
    a("#             anyone's word, including mine.")
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
    a("#   Therefore: quote ratios between configurations to TWO SIGNIFICANT FIGURES,")
    a("#   prefer the aggregate over any individual row, and never difference two")
    a("#   individual rows across configurations -- at a 7.5% floor a 1.05x per-row")
    a("#   difference is not a measurement. Within one config the board is")
    a("#   deterministic and cycles_per_byte repeats to the last digit; the floor is a")
    a("#   property of comparing configurations, not of the counter.")
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
    a("# split is decided by comparing the three streams, not by a fixed list:")
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
        a("#   They are not the same number printed twice: fw/m4/bench_m4_main.c sorts")
        a("#   the trial array and takes samples[TRIALS/2] and samples[0] from it as two")
        a("#   separate reads (the trial count is in the protocol line above, and the")
        a("#   median and the minimum of a sorted array are different elements of it).")
        a("#   They coincide because every trial returns the identical")
        a("#   cycle count -- interrupts masked, SysTick off, the working set in CCM and")
        a("#   the tables in the memory chosen for them, so there is nothing left to")
        a("#   vary. Read it as: on this part, under this protocol, the measurement has")
        a("#   no run-to-run spread to report. The min column is therefore confirmation,")
        a("#   not information, and '15 trials' should not be read as implying a")
        a("#   variance that does not exist. Spread between configurations is a")
        a("#   different matter entirely -- see RESOLUTION above.")
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
            a("#   Expected, and not a copy-paste fault: these two differ in exactly one")
            a("#   field that affects computation -- the 8-bit S-box. Compare")
            a("#   variants/%s.json and variants/%s.json: key_bits," % (ca, cb))
            a("#   key_schedule, linear, rounds and sbox_bits are all equal, and only")
            a("#   sbox differs. A table implementation does the same number of lookups")
            a("#   into a table of the same size with the same access pattern whatever")
            a("#   the S-box holds, so the cycle counts have to agree.")
            a("#   The check that they are nevertheless different ciphers is in the rows")
            a("#   themselves: where an implementation depends on S-box *structure* they")
            a("#   separate sharply. %s under %s is %s vs %s cyc/B, a factor of %.1f --"
              % (im, cfg, va, vb, ratio))
            a("#   a ~1107-gate bitsliced circuit against the AES circuit. Both figures")
            a("#   come from the same image in the same run, so no layout floor applies")
            a("#   to that comparison; it is a within-configuration ratio, not a")
            a("#   cross-configuration one.")
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
    args = ap.parse_args()

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
    for config, binary in CONFIGS:
        print("[%s] flashing and running build/m4/%s.bin ..." % (config, binary))
        stream = flash_and_run(binary, log_dir, args.gdb_timeout, args.flash_timeout)
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
