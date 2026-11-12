#!/usr/bin/env python3
"""Clock-constraint sweep of the Gowin IDE projects in chacha_ascon/fpga/gen (make gowin-projects).

Gowin place-and-route is timing-driven: a core that meets a loose constraint can usually go
faster with a tighter one, and a constraint far above what the core can do yields the core's
real limit in the timing report. Per project:
  build at the start constraint; while the build meets timing, retry at 1.15 x its Fmax
  (at least +10 % over the constraint); once a build fails, retry once at its own reported
  Fmax; stop when a step does not raise the best met Fmax, or after --max-iter builds.
The project is then rebuilt at the constraint of the best met build, so its impl/ directory
(read by tools/gowin_collect.py, `make gowin-report`) holds the reported result. Every step is
logged to results/fpga/gowin-sweep.csv.

Usage (repository root): python3 chacha_ascon/fpga/tools/gowin_sweep.py [--only a,b] [--max-iter N]"""
from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
import time
from pathlib import Path

FPGA = Path(__file__).resolve().parents[1]
ROOT = FPGA.parents[1]
GEN = FPGA / "gen" / "gowin"
LOG = FPGA.parent / "results" / "fpga" / "gowin-sweep.csv"
sys.path.insert(0, str(ROOT / "tools"))
from gowin_collect import timing_metrics, xml_metrics  # noqa: E402


def build(name: str, mhz: float) -> dict:
    d = GEN / name
    (d / "cipher_core.sdc").write_text(f"create_clock -name clk -period {1000.0 / mhz:.3f} [get_ports {{clk}}]\n")
    env = dict(os.environ, LOG_FILE=str(d / "gowin_build.log"))
    t0 = time.time()
    rc = subprocess.run([str(ROOT / "fpga" / "run_gowin_build.sh"), str(d)], env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT).returncode
    r = {"core": name, "constraint_mhz": round(mhz, 3), "rc": rc, "seconds": round(time.time() - t0)}
    t, x = timing_metrics(d), xml_metrics(d)
    r.update(fmax_mhz=t.get("fmax_mhz"), wns_ns=t.get("wns_ns"), met=t.get("timing_met"),
             luts=x.get("luts"), registers=x.get("registers"), alus=x.get("alus"), bsram=x.get("bsram"))
    return r


def current_constraint(name: str) -> float:
    txt = (GEN / name / "cipher_core.sdc").read_text()
    return 1000.0 / float(txt.split("-period")[1].split()[0])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--max-iter", type=int, default=6)
    a = ap.parse_args()
    names = [l.strip() for l in (FPGA / "gen" / "modules.txt").read_text().splitlines() if l.strip()]
    if a.only:
        names = [n for n in names if n in a.only.split(",")]
    new = not LOG.is_file()
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["date", "core", "step", "constraint_mhz", "rc", "fmax_mhz", "wns_ns",
                                           "met", "luts", "registers", "alus", "bsram", "seconds"],
                           lineterminator="\n", extrasaction="ignore")
        if new:
            w.writeheader()
        for name in names:
            f = current_constraint(name)
            best = None          # (fmax, constraint) of the best met build
            retried_fail = False
            for step in range(a.max_iter):
                r = build(name, f)
                w.writerow({"date": time.strftime("%Y-%m-%d %H:%M"), "step": step, **r})
                fh.flush()
                fm = float(r["fmax_mhz"]) if r["fmax_mhz"] else 0.0
                print(f"{name:<10} step {step} constraint {f:7.2f}  Fmax {fm:7.2f}  met {r['met']}  "
                      f"LUT {r['luts']}  {r['seconds']} s", flush=True)
                if r["met"] == "yes":
                    if best and fm <= best[0] * 1.005:
                        break
                    best = max(best or (0, 0), (fm, f))
                    f = max(fm * 1.15, f * 1.10)
                else:
                    if retried_fail or (best and fm <= best[0]):
                        break
                    retried_fail = True
                    f = fm
            if best is None:
                print(f"{name}: no build met timing", flush=True)
                continue
            if abs(current_constraint(name) - best[1]) > 1e-3 or r["met"] != "yes":
                r = build(name, best[1])
                w.writerow({"date": time.strftime("%Y-%m-%d %H:%M"), "step": "final", **r})
                fh.flush()
                print(f"{name:<10} final constraint {best[1]:7.2f}  Fmax {r['fmax_mhz']}  met {r['met']}", flush=True)


if __name__ == "__main__":
    main()
