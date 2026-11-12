#!/usr/bin/env python3
"""Flash the ChaCha20/Ascon measurement firmware onto the STM32F407 board, run it
under st-util semihosting, and write the measured CSV.

The procedure is the project's PRESENT one (tools/run_m4_bench.py, flash_and_run):
st-flash --reset (NRST is not wired, never connect-under-reset), then st-util as
the gdb server, then gdb-multiarch with fw/m4/run.gdb, which loads the ELF and
breaks at sh_exit. The semihosted output arrives on st-util's stdout.

A CSV is written only if the firmware's own KAT run reported status 0 (both
tests/test_ca.c and tests/test_bc.c ran on the board, each with its summary line
reporting 0 failures, and the MPU bounds gate for the block-cipher CTR kernels
reported ok), the clock line is present with meas_status=1,
CSV_BEGIN/CSV_END are both present and every expected row (every KAT-passed
ChaCha20 / Ascon / block-cipher CTR implementation x 64/1536/4096 B, exactly
once, numeric) is present. Anything else is an error and no new file is written: the
output goes to .tmp and is renamed only on success, so a failed run leaves the
previous CSV, with its own date and firmware hash, untouched."""
import argparse
import hashlib
import os
import re
import subprocess
import sys
import time

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(TOP)
GDB_SCRIPT = os.path.join(ROOT, "fw", "m4", "run.gdb")
FLASH_ORIGIN = "0x08000000"


class Failure(Exception):
    pass


def run(cmd, timeout):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise Failure("%s failed (%d):\n%s%s" % (cmd[0], p.returncode, p.stdout, p.stderr))
    return p.stdout + p.stderr


def flash_and_run(elf, bin_, log_dir, gdb_timeout):
    run(["st-flash", "--reset", "write", bin_, FLASH_ORIGIN], timeout=120)
    server_log = os.path.join(log_dir, "ca_fw.st-util.log")
    gdb_log = os.path.join(log_dir, "ca_fw.gdb.log")
    proc = None
    fh = open(server_log, "w+")
    try:
        proc = subprocess.Popen(["st-util"], cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 30
        while time.time() < deadline:
            fh.flush()
            if proc.poll() is not None:
                raise Failure("st-util exited immediately (%d):\n%s" % (proc.returncode, open(server_log).read()))
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
            raise Failure("gdb-multiarch failed (%d):\n%s\n%s" % (gp.returncode, gp.stdout, gp.stderr))
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        fh.flush()
        fh.close()
    return open(server_log).read()


HEADER = ("cipher,impl,lanes,msg_bytes,payload_bytes,cycles_median,cycles_min,cycles_per_byte,"
          "cycles_per_byte_min,cycles_per_bit,mbit_per_sec")
SIZES = ("64", "1536", "4096")


def parse(stream):
    # st-util interleaves its own log lines, so firmware lines are matched by
    # content; each marker must occur exactly once and in order.
    lines = stream.splitlines()

    def one(pred, what):
        idx = [i for i, l in enumerate(lines) if pred(l)]
        if len(idx) != 1:
            raise Failure("expected exactly one %s line, got %d" % (what, len(idx)))
        return idx[0]

    i_clock = one(lambda l: l.startswith("# clock:"), "clock")
    i_kb = one(lambda l: l == "KAT_BEGIN", "KAT_BEGIN")
    i_ke = one(lambda l: l.startswith("KAT_END "), "KAT_END")
    i_cb = one(lambda l: l == "CSV_BEGIN", "CSV_BEGIN")
    i_ce = one(lambda l: l.startswith("CSV_END checksum="), "CSV_END")
    if not i_clock < i_kb < i_ke < i_cb < i_ce:
        raise Failure("markers out of order")
    if lines[i_ke] != "KAT_END status=0":
        raise Failure("on-board KAT run failed: " + lines[i_ke])
    m = re.fullmatch(r"# clock: source=(\w+) pll=(-?\d+) measured_hz=(\d+) meas_status=(-?\d+) \(1=ok\)",
                     lines[i_clock])
    if not m or m.group(4) != "1":
        raise Failure("clock line malformed or measurement not in tolerance: " + lines[i_clock])
    hz = int(m.group(3))
    if not re.fullmatch(r"CSV_END checksum=[0-9a-f]{8}", lines[i_ce]):
        raise Failure("malformed CSV_END: " + lines[i_ce])

    katlines = lines[i_kb + 1:i_ke]
    # tests/test_ca.c: "chacha20 <impl> ok" / "ascon <impl> ok"
    impl_re = re.compile(r"^(chacha20|ascon) +(\S+) +(ok|FAILED|SKIPPED.*)$")
    # tests/test_bc.c: "aes128-ctr|aes256-ctr|qalqan-ctr <impl> L=<n> ok (<k> CTR runs vs reference)"
    bc_re = re.compile(r"^(aes128-ctr|aes256-ctr|qalqan-ctr) +(\S+) +(?:L=\d+ +(ok|FAILED)\b.*|(SKIPPED.*))$")
    impls = []
    for l in katlines:
        mm = impl_re.match(l)
        if mm:
            if mm.group(3) != "ok":
                raise Failure("implementation not ok: " + l)
            impls.append(("chacha20" if mm.group(1) == "chacha20" else "ascon128", mm.group(2)))
            continue
        mm = bc_re.match(l)
        if mm:
            if mm.group(3) != "ok":
                raise Failure("implementation not ok: " + l)
            impls.append((mm.group(1), mm.group(2)))
    if len(set(impls)) != len(impls):
        raise Failure("an implementation is reported twice in the KAT run")
    ca_sum = [l for l in katlines if re.fullmatch(r"\d+ implementations tested, \d+ skipped, \d+ failures", l)]
    bc_sum = [l for l in katlines
              if re.fullmatch(r"\d+ block-cipher CTR implementations tested, \d+ skipped, \d+ failures", l)]
    if len(ca_sum) != 1 or len(bc_sum) != 1:
        raise Failure("KAT summary missing (test_ca %d, test_bc %d summary lines)" % (len(ca_sum), len(bc_sum)))
    for summ, cips in ((ca_sum[0], ("chacha20", "ascon128")), (bc_sum[0], ("aes128-ctr", "aes256-ctr", "qalqan-ctr"))):
        tested, skipped, failed = map(int, re.findall(r"\d+", summ))
        n = sum(1 for c, _ in impls if c in cips)
        if failed != 0 or skipped != 0 or tested != n or n == 0:
            raise Failure("KAT summary %r does not match %d ok implementation lines" % (summ, n))
    if "reference block functions: ok (" not in "\n".join(katlines):
        raise Failure("test_bc reference block KAT line missing or not ok")
    guard = [l for l in katlines if l.startswith("bc MPU guard: ")]
    if len(guard) != 1 or not re.match(r"bc MPU guard: ok \(\d+ runs", guard[0]):
        raise Failure("MPU bounds gate missing or not ok: %r" % guard)
    if any(l.startswith("MPU_GUARD_FAULT") for l in lines):
        raise Failure("MPU bounds gate fault")

    if lines[i_cb + 1] != HEADER:
        raise Failure("unexpected CSV header: " + lines[i_cb + 1])
    rows = lines[i_cb + 2:i_ce]
    seen = set()
    for r in rows:
        f = r.split(",")
        if len(f) != HEADER.count(",") + 1:
            raise Failure("malformed row: %r" % r)
        try:
            ints = [int(x) for x in f[2:7]]
            floats = [float(x) for x in f[7:11]]
        except ValueError:
            raise Failure("non-numeric field: %r" % r)
        if min(ints) <= 0 or min(floats) <= 0 or ints[4] > ints[3]:
            raise Failure("implausible values: %r" % r)
        key = (f[0], f[1], f[3])
        if key in seen:
            raise Failure("duplicate row: %r" % r)
        seen.add(key)
    want = {(c, i, s) for c, i in impls for s in SIZES}
    if seen != want:
        raise Failure("rows do not cover exactly the KAT-passed implementations x sizes; missing %s, extra %s"
                      % (sorted(want - seen), sorted(seen - want)))
    comments = [l for l in lines[:i_cb] if l.startswith("# ")]
    katlines = [l for l in katlines if impl_re.match(l) or bc_re.match(l) or "implementations tested" in l
                or l.startswith("KAT_MAX_LEN=") or l.startswith("reference block functions:")
                or l.startswith("bc MPU guard: ")]
    return hz, HEADER, rows, comments, katlines, lines[i_ce]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--log-dir", required=True)
    ap.add_argument("--gdb-timeout", type=int, default=3600)
    ap.add_argument("--expect-guard-fault", action="store_true",
                    help="GUARD_SELFTEST firmware: succeed only if the MPU gate caught its deliberate read")
    a = ap.parse_args()
    a.elf, a.bin, a.csv, a.log_dir = map(os.path.abspath, (a.elf, a.bin, a.csv, a.log_dir))
    for p in (a.elf, a.bin):
        if not os.path.exists(p):
            raise Failure("missing " + p)
    t0 = time.time()
    stream = flash_and_run(a.elf, a.bin, a.log_dir, a.gdb_timeout)
    if a.expect_guard_fault:
        if "MPU_GUARD_FAULT impl=selftest-read-past-end" not in stream or "NOT CAUGHT" in stream:
            raise Failure("guard selftest: the deliberate out-of-range read was NOT caught")
        print("guard selftest: deliberate read one byte past the buffer raised MemManage (gate works)")
        return
    hz, header, rows, comments, katlines, csv_end = parse(stream)
    elf_sha = hashlib.sha256(open(a.elf, "rb").read()).hexdigest()
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True,
                            text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "chacha_ascon"], cwd=ROOT,
                           capture_output=True, text=True).stdout.strip()
    cc = subprocess.run(["arm-none-eabi-gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    tmp = a.csv + ".tmp"
    with open(tmp, "w") as f:
        f.write("# Measured on the board (not a model). tools/m4_board.py, %s\n" % time.strftime("%Y-%m-%d"))
        for c in comments:
            f.write(c + "\n")
        f.write("# firmware: %s sha256=%s\n" % (os.path.basename(a.elf), elf_sha))
        f.write("# source: commit %s%s; %s; -O2 -mcpu=cortex-m4 -mthumb\n"
                % (commit, " +uncommitted changes" if dirty else "", cc))
        for k in katlines:
            f.write("# KAT on board: %s\n" % k)
        f.write("# %s; run time %.0f s\n" % (csv_end, time.time() - t0))
        f.write(header + "\n")
        for r in rows:
            f.write(r + "\n")
    os.replace(tmp, a.csv)
    print("wrote %s: %d rows, SYSCLK %.3f MHz" % (a.csv, len(rows), hz / 1e6))
    for r in rows:
        print(r)


if __name__ == "__main__":
    try:
        main()
    except Failure as e:
        print("m4_board: " + str(e), file=sys.stderr)
        sys.exit(1)
