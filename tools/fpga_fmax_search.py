#!/usr/bin/env python3
"""Search each generated Gowin core for the tightest clock constraint it still meets.

The candidate rate an attacker gets from a core is ``cores * Fmax / II``, so Fmax is
a first-class result, not a byproduct. A place-and-route tool stops optimising once
the constraint is met, which makes a hand-picked constraint a *lower bound* on the
achievable clock: ``present-80-lin444-297-r7-speed`` was constrained at 200 MHz and
closed at 215 MHz with 0.349 ns still in hand, so 200 MHz was simply the number
somebody typed.

This walks the constraint down instead. From a passing build with slack ``S`` at
period ``P``, the next candidate is ``P - S`` -- the period the design actually
achieved. When one fails, the search bisects back toward the last passing period.
The best passing period per core is written to a JSON file that tools/gen_fpga.py
reads, so the searched constraints survive regeneration and stay reviewable.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from gowin_collect import timing_metrics  # noqa: E402

DEFAULT_CONSTRAINTS = ROOT / "fpga" / "clock_constraints.json"

# Below this the remaining gain is inside the tool's own run-to-run variation.
MIN_STEP_NS = 0.02
# Gowin stops optimising the moment it meets the constraint, so a build that closes
# with exactly zero slack reports fmax == constraint and tells us nothing about the
# real ceiling. Probe this much tighter instead of concluding the search is done.
PROBE_FRACTION = 0.97
# Never propose a period the fabric cannot plausibly reach; keeps a failed parse
# from driving the search into a wall of hopeless builds.
MIN_PERIOD_NS = 1.0


def write_sdc(project_dir: Path, period_ns: float) -> None:
    (project_dir / "cipher_core.sdc").write_text(
        f"create_clock -name clk -period {period_ns:.3f} [get_ports {{clk}}]\n",
        encoding="ascii",
    )


def build(project_dir: Path, log_name: str) -> None:
    impl = project_dir / "impl"
    if impl.exists():
        shutil.rmtree(impl)
    env = dict(os.environ)
    env["LOG_FILE"] = str(project_dir / log_name)
    subprocess.run(
        [str(ROOT / "fpga" / "run_gowin_build.sh"), str(project_dir)],
        check=True,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def measure(project_dir: Path) -> tuple[bool, float | None, float | None]:
    """Returns (timing_met, fmax_mhz, wns_ns) for the build sitting in project_dir."""
    m = timing_metrics(project_dir)
    met = m.get("timing_met") == "yes"
    try:
        fmax = float(m["fmax_mhz"]) if m.get("fmax_mhz") else None
    except ValueError:
        fmax = None
    try:
        wns = float(m["wns_ns"]) if m.get("wns_ns") else None
    except ValueError:
        wns = None
    return met, fmax, wns


def confirm_one(project_dir: Path, period: float, max_builds: int,
                guard: float) -> dict:
    """Relax ``period`` until a from-scratch build meets timing.

    Gowin place-and-route is not deterministic run to run: the same RTL at the same
    constraint has closed at +0.047 ns and missed at -0.065 ns. Because the search
    drives slack to roughly zero by construction, its best period is one sample of a
    noisy process, and a constraint sitting on the edge is not reproducible. A
    recorded constraint has to survive an independent rebuild, so back off by
    ``guard`` per miss until one does.
    """
    history = []
    for _ in range(max_builds):
        write_sdc(project_dir, period)
        t0 = time.time()
        build(project_dir, "gowin_build.log")
        met, fmax, wns = measure(project_dir)
        history.append(
            {"period_ns": round(period, 3), "timing_met": met, "fmax_mhz": fmax,
             "wns_ns": wns, "seconds": round(time.time() - t0, 1), "confirm": True}
        )
        print(f"    confirm {period:6.3f} ns -> met={met} fmax={fmax} wns={wns}", flush=True)
        if met:
            return {"period_ns": period, "fmax_mhz": fmax, "confirmed": True,
                    "history": history}
        period *= guard
    return {"period_ns": period / guard, "fmax_mhz": None, "confirmed": False,
            "history": history}


def search_one(project_dir: Path, start_period: float, max_builds: int,
               known_failed: float | None = None) -> dict:
    best: dict | None = None
    failed_period: float | None = known_failed
    period = start_period
    history = []

    for attempt in range(max_builds):
        write_sdc(project_dir, period)
        t0 = time.time()
        build(project_dir, f"gowin_build_p{period:.3f}.log")
        met, fmax, wns = measure(project_dir)
        history.append(
            {"period_ns": round(period, 3), "timing_met": met, "fmax_mhz": fmax,
             "wns_ns": wns, "seconds": round(time.time() - t0, 1)}
        )
        print(f"    period {period:6.3f} ns -> met={met} fmax={fmax} wns={wns}", flush=True)

        if met:
            if best is None or period < best["period_ns"]:
                best = {"period_ns": period, "fmax_mhz": fmax, "wns_ns": wns}
            if wns is None:
                break
            if failed_period is not None:
                nxt = (period + failed_period) / 2.0
            elif wns > MIN_STEP_NS:
                nxt = period - wns
            else:
                nxt = period * PROBE_FRACTION
            if nxt < MIN_PERIOD_NS or period - nxt < MIN_STEP_NS:
                break
            period = nxt
        else:
            failed_period = period
            if best is None:
                # Even the starting constraint failed: relax until something passes.
                period = period * 1.15
                continue
            nxt = (period + best["period_ns"]) / 2.0
            if best["period_ns"] - nxt < MIN_STEP_NS:
                break
            period = nxt

    return {"best": best, "history": history}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gen-dir", type=Path, default=ROOT / "fpga/generated")
    ap.add_argument("--constraints", type=Path, default=DEFAULT_CONSTRAINTS)
    ap.add_argument("--max-builds", type=int, default=5,
                    help="place-and-route runs per core")
    ap.add_argument("--only", action="append", default=None,
                    help="restrict to these core names (repeatable)")
    ap.add_argument("--confirm", action="store_true",
                    help="rebuild each core at its recorded constraint and relax "
                         "until an independent build meets timing")
    ap.add_argument("--guard", type=float, default=1.02,
                    help="period back-off applied per failed confirmation build")
    args = ap.parse_args()

    modules = [m.strip() for m in (args.gen_dir / "modules.txt").read_text().splitlines()
               if m.strip()]
    if args.only:
        modules = [m for m in modules if m in set(args.only)]

    existing = {}
    if args.constraints.is_file():
        existing = json.loads(args.constraints.read_text())

    results = dict(existing)
    for mod in modules:
        project_dir = args.gen_dir / "gowin" / mod
        sdc = project_dir / "cipher_core.sdc"
        start = float(sdc.read_text().split("-period")[1].split("[")[0].strip())
        prior = existing.get(mod, {}).get("history", [])
        if args.confirm:
            entry = existing.get(mod, {})
            period = float(entry.get("period_ns") or start)
            if not entry.get("confirmed"):
                # An unconfirmed period is a single sample of a noisy placer, and the
                # search always lands on it with near-zero slack. Open a guard band
                # before spending a build on a constraint we already know is marginal.
                period *= args.guard
            print(f"== {mod} confirming {period:.3f} ns", flush=True)
            out = confirm_one(project_dir, period, args.max_builds, args.guard)
            results[mod] = {
                "period_ns": round(out["period_ns"], 3),
                "searched": entry.get("searched", False),
                "confirmed": out["confirmed"],
                "fmax_mhz": out["fmax_mhz"] or entry.get("fmax_mhz"),
                "history": prior + out["history"],
            }
            if not out["confirmed"]:
                print(f"   {mod} never met timing in {args.max_builds} builds",
                      flush=True)
            continue
        # A place-and-route run costs minutes, so never re-derive a failure a previous
        # pass already paid for: resume the bisection from the tightest known failure.
        failures = [h["period_ns"] for h in prior
                    if not h.get("timing_met") and h["period_ns"] < start]
        known_failed = max(failures) if failures else None
        if known_failed is not None and start - known_failed < 2 * MIN_STEP_NS:
            print(f"== {mod} converged at {start:.3f} ns "
                  f"({known_failed:.3f} ns fails); skipping", flush=True)
            continue
        seed = f" (resuming, {known_failed:.3f} ns known to fail)" if known_failed else ""
        print(f"== {mod} (start {start:.3f} ns){seed}", flush=True)
        out = search_one(project_dir, start, args.max_builds, known_failed)
        if out["best"] is None:
            print(f"   no passing constraint found for {mod}; leaving {start:.3f} ns",
                  flush=True)
            write_sdc(project_dir, start)
            build(project_dir, "gowin_build.log")
            results[mod] = {"period_ns": round(start, 3), "searched": False}
            continue
        best = out["best"]
        print(f"   best {best['period_ns']:.3f} ns "
              f"({1000.0 / best['period_ns']:.2f} MHz constraint, "
              f"fmax {best['fmax_mhz']} MHz)", flush=True)
        results[mod] = {
            "period_ns": round(best["period_ns"], 3),
            "searched": True,
            "fmax_mhz": best["fmax_mhz"],
            # Keep every pass's builds: the record of what failed is what makes a
            # later run resumable, and it shows how the constraint was arrived at.
            "history": prior + out["history"],
        }
        # Leave the project in its best passing state so the report reflects it.
        write_sdc(project_dir, best["period_ns"])
        build(project_dir, "gowin_build.log")

    args.constraints.parent.mkdir(parents=True, exist_ok=True)
    args.constraints.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n",
                                encoding="ascii")
    print(f"wrote {args.constraints}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
