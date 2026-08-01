#!/usr/bin/env python3
"""Differential cryptanalysis driver for PRESENT_mod.

    python3 analysis/cli.py sboxes
    python3 analysis/cli.py analyze --variant present-80 --max-rounds 8
    python3 analysis/cli.py analyze --all --max-rounds 7 --timeout 120
    python3 analysis/cli.py trail --variant present-80 --rounds 5
    python3 analysis/cli.py cluster --variant present-80 --rounds 5
    python3 analysis/cli.py report
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from present_sat import report as report_mod
from present_sat import search, solver, variants
from present_sat.model import MODE_WEIGHT
from present_sat.report import RoundRow


def _pick(args) -> list:
    if args.all:
        return variants.load_all()
    if not args.variant:
        raise SystemExit("give --variant NAME or --all")
    return [variants.get(name) for name in args.variant]


def cmd_sboxes(args) -> int:
    print(f"{'variant':28s} {'du':>3s} {'lin':>4s} {'deg':>4s} {'bn':>3s} {'fix':>4s} "
          f"{'weights':>12s} {'exact':>6s}")
    for v in variants.load_all():
        p = v.weights.summary()
        print(f"{v.name:28s} {p['differential_uniformity']:3d} {p['linearity']:4d} "
              f"{p['algebraic_degree']:4d} {p['branch_number']:3d} {p['fixed_points']:4d} "
              f"{str(p['weights_used']):>12s} {str(p['exact_weights']):>6s}")
    return 0


def cmd_analyze(args) -> int:
    solver_name = solver.solver_version(args.solver)
    print(f"solver: {solver_name}")

    for v in _pick(args):
        print(f"\n=== {v.name} ({v.rounds} rounds, {v.key_bits}-bit key)")
        rows = []
        started = time.monotonic()
        for r in range(1, args.max_rounds + 1):
            act = search.min_active_sboxes(v, r, timeout=args.timeout,
                                           solver=args.solver,
                                           total_budget=args.budget)
            wgt = search.min_trail_weight_from_active(
                v, r, act, timeout=args.timeout, solver=args.solver,
                total_budget=args.budget)

            rows.append(RoundRow(
                rounds=r, min_active=act.value if act.value is not None else act.lower_bound,
                active_status=act.status,
                min_weight=wgt.value if wgt.value is not None else wgt.lower_bound,
                weight_status=wgt.status,
                seconds=act.seconds + wgt.seconds, calls=act.calls + wgt.calls,
                n_vars=wgt.n_vars, n_clauses=wgt.n_clauses,
            ))

            exact = wgt.status == search.EXACT
            act_s = str(act.value) if act.status == search.EXACT else f">={act.lower_bound}"
            wgt_s = str(wgt.value) if exact else f">={wgt.lower_bound}"
            prob = f"2^-{wgt.value}" if exact else f"<=2^-{wgt.lower_bound}"
            print(f"  r={r:2d}  active={act_s:>5s}  weight={wgt_s:>6s}  "
                  f"prob={prob:>10s}  ({act.seconds + wgt.seconds:6.2f}s, "
                  f"{wgt.n_clauses} clauses)")

            if args.stop_at_weight and wgt.status == search.EXACT and \
                    wgt.value is not None and wgt.value >= args.stop_at_weight:
                print(f"  reached weight {wgt.value} >= {args.stop_at_weight}, stopping")
                break
            if args.budget and time.monotonic() - started > args.budget:
                print("  per-variant time budget exhausted, stopping")
                break

        path = report_mod.write_rows(v.name, rows)
        bound = report_mod.weight_lower_bound(rows, v.rounds)
        need = report_mod.rounds_for_weight(rows, report_mod.SECURITY_TARGET)
        print(f"  -> {os.path.relpath(path)}")
        print(f"  provable: any characteristic over {v.rounds} rounds has "
              f"probability <= 2^-{bound}")
        if need:
            print(f"  rounds needed to prove 2^-64: {need} "
                  f"(margin {v.rounds / need:.2f}x)")
        else:
            print("  not enough data to prove a 2^-64 bound")
    return 0


def cmd_trail(args) -> int:
    v = variants.get(args.variant[0])
    act = search.min_active_sboxes(v, args.rounds, timeout=args.timeout, solver=args.solver)
    res = search.min_trail_weight_from_active(v, args.rounds, act, timeout=args.timeout,
                                              solver=args.solver)
    print(act.describe())
    print(res.describe())
    if res.trail:
        print()
        print(res.trail.format())
    return 0 if res.status == search.EXACT else 1


def cmd_cluster(args) -> int:
    v = variants.get(args.variant[0])
    act = search.min_active_sboxes(v, args.rounds, timeout=args.timeout, solver=args.solver)
    best = search.min_trail_weight_from_active(v, args.rounds, act, timeout=args.timeout,
                                               solver=args.solver)
    if best.status != search.EXACT or best.trail is None:
        print("could not find an optimal trail to cluster around")
        return 1

    t = best.trail
    print(t.format())
    print()
    for extra in range(0, args.extra_weight + 1):
        w = (best.value or 0) + extra
        c = search.count_trails(v, args.rounds, w, t.diff_in, t.diff_out,
                                limit=args.limit, timeout=args.timeout, solver=args.solver)
        note = "" if c.exhausted else f" (stopped at limit {args.limit})"
        print(f"  weight {w}: {c.trails} characteristics{note}  [{c.seconds:.1f}s]")
    print("\nCharacteristics sharing the input and output difference add up, so the "
          "differential is more probable than the single best characteristic.")
    return 0


def cmd_report(args) -> int:
    vs = variants.load_all()
    try:
        name = solver.solver_version(args.solver)
    except Exception:
        name = ""
    text = report_mod.build_report(vs, name)
    path = report_mod.write_report(text)
    print(f"wrote {os.path.relpath(path)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--variant", action="append", help="variant name (repeatable)")
        p.add_argument("--all", action="store_true", help="every registered variant")
        p.add_argument("--timeout", type=float, default=300,
                       help="per solver call, seconds (default 300)")
        p.add_argument("--budget", type=float, default=None,
                       help="per-variant wall-clock budget, seconds")
        p.add_argument("--solver", default=None, help="path or name of a SAT solver")

    p = sub.add_parser("analyze", help="minimum active S-boxes and trail weight per round")
    common(p)
    p.add_argument("--max-rounds", type=int, default=8)
    p.add_argument("--stop-at-weight", type=int, default=None,
                   help="stop once the optimal weight reaches this value")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("trail", help="print the best characteristic for one round count")
    common(p)
    p.add_argument("--rounds", type=int, required=True)
    p.set_defaults(func=cmd_trail)

    p = sub.add_parser("cluster", help="count characteristics sharing the best in/out pair")
    common(p)
    p.add_argument("--rounds", type=int, required=True)
    p.add_argument("--extra-weight", type=int, default=2)
    p.add_argument("--limit", type=int, default=500)
    p.set_defaults(func=cmd_cluster)

    p = sub.add_parser("sboxes", help="S-box properties of every variant")
    p.set_defaults(func=cmd_sboxes)

    p = sub.add_parser("report", help="join speed and differential results into report.md")
    p.add_argument("--solver", default=None)
    p.set_defaults(func=cmd_report)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
