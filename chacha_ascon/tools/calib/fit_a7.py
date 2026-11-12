#!/usr/bin/env python3
"""Fit the Cortex-A7 model on MEASURED PRESENT kernels and show how much the
study's own estimates move across every parameter set the fit cannot reject.

  fit_a7.py CAL_ELF CAL_TRACE CAL_REGIONS name=measured_c/B ... \
            [--targets ELF TRACE REGIONS [msg_bytes]]

Calibration: tools/calib/a7_present_calib.c (build line in its header), traced
under qemu-arm -cpu cortex-a7; measured values are results/speed-arm.csv at
1296 MHz (c/B = 1296 / MB/s). Each parameter set replays the same instruction
streams. Prints every candidate's per-kernel errors (sorted by worst |error|),
then, for candidates whose worst error is within --keep of the best, the range
of each target estimate -- the model's sensitivity to what PRESENT does not pin
down."""
import argparse
import itertools
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import arm_cycles as A


def load(elf, trace, regions, want=lambda lab: True):
    ins, mark = A.disassemble(elf)
    pcs = [int(m.group(1), 16) for m in (A.TRACE_RE.match(l) for l in open(trace, "rb")) if m]
    labels = [l.split() for l in open(regions) if l.startswith("REGION")]
    marks = [i for i, p in enumerate(pcs) if p == mark]
    iv = [(marks[i], marks[i + 1]) for i in range(0, len(marks) - 1, 2)]
    out = []
    for lab, (a, b) in zip(labels, iv):
        if lab[1] != "0" and not want(lab):
            continue
        seq = [(*ins[pcs[i]], pcs[i + 1] != pcs[i] + ins[pcs[i]][2], pcs[i]) for i in range(a, b)]
        out.append((lab, seq))
    return out


def price(p, seq):
    m = A.A7(p)
    t = 0
    for x in seq:
        t = m.step(*x)
    return t


def cpb(p, streams):
    base = price(p, streams[0][1])
    return {(lab[2], lab[3], lab[5]): (price(p, seq) - base) / int(lab[6]) for lab, seq in streams[1:]}


ap = argparse.ArgumentParser()
ap.add_argument("elf"); ap.add_argument("trace"); ap.add_argument("regions")
ap.add_argument("meas", nargs="+")
ap.add_argument("--targets", nargs="+")
ap.add_argument("--keep", type=float, default=0.03)
a = ap.parse_args()
meas = {k: float(v) for k, v in (kv.split("=") for kv in a.meas)}
cal = load(a.elf, a.trace, a.regions)
tgt = None
if a.targets:
    size = a.targets[3] if len(a.targets) > 3 else "4096"
    tgt = load(*a.targets[:3], want=lambda lab: lab[5] == size)

grid = dict(
    dual=["gcc", "gcc+ndisp", "gcc+regreg"],
    load_lat=[2, 3],
    neon_lat=[3, 4],
    nqueue=[4, 16],
    shift_fwd=[0, 1],
)
keys = list(grid)
res = []
for vals in itertools.product(*(grid[k] for k in keys)):
    kw = dict(zip(keys, vals))
    p = A.a7_params(**kw)
    got = cpb(p, cal)
    errs = {k[1]: (v, v / meas[k[1]] - 1) for k, v in got.items() if k[1] in meas}
    worst = max(abs(e) for _, e in errs.values())
    res.append((worst, kw, errs))
    print("%.3f %s %s" % (worst, kw, " ".join("%s=%.1f(%+.1f%%)" % (n, v, 100 * e) for n, (v, e) in errs.items())),
          flush=True)
res.sort(key=lambda r: r[0])
print("\nBEST", res[0][1], "worst %.1f%%" % (100 * res[0][0]))
if tgt:
    keep = [r for r in res if r[0] <= res[0][0] + a.keep]
    print("\n%d parameter sets within %.0f%% of the best fit; target estimates (c/B):" % (len(keep), 100 * a.keep))
    rows = {}
    for worst, kw, _ in keep:
        for k, v in cpb(A.a7_params(**kw), tgt).items():
            rows.setdefault(k, []).append(v)
    best = cpb(A.a7_params(**res[0][1]), tgt)
    for k, vs in rows.items():
        print("  %-9s %-24s best-fit %6.1f   range %6.1f .. %6.1f" % (k[0], k[1], best[k], min(vs), max(vs)))
