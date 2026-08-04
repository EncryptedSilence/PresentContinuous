#!/usr/bin/env python3
"""Prove a differential weight bound without finding the exact optimum.

analysis/cli.py `analyze` reports the *optimal* trail weight per round count, which
costs a ladder of solver calls: every k below the optimum is an UNSAT call, and those
are the expensive ones. For the comparison in docs/speed-at-equal-security.md that is
more than is needed. The question there is only ever "is every characteristic over r
rounds at least weight W?", and that is one call:

    add `sum(objective) <= W - 1` to the model and ask for satisfiability.
    UNSAT  -> proven: every r-round characteristic has weight >= W.
    SAT    -> not proven, and the witness is a counterexample trail.

For the 128-bit ciphers the difference is decisive -- the exact optimum at four rounds
did not finish, while the bound it would have implied takes one call.

    python3 analysis/prove_bound.py --variants-dir variants/wide \
            --variant aes-lin444-1-10-15 --rounds 4 --weight 64
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from present_sat import model as model_mod
from present_sat import solver as solver_mod
from present_sat import variants as variants_mod
from present_sat.trail import decode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--variant", required=True)
    ap.add_argument("--variants-dir", default=None)
    ap.add_argument("--rounds", type=int, required=True)
    ap.add_argument("--weight", type=int, required=True,
                    help="the bound to prove: every characteristic costs at least this")
    ap.add_argument("--mode", choices=(model_mod.MODE_WEIGHT, model_mod.MODE_ACTIVE),
                    default=model_mod.MODE_WEIGHT,
                    help="weight bounds the trail directly; active bounds the number of "
                         "active S-boxes and converts via the S-box's minimum nonzero "
                         "weight, which is weaker but often a far easier search")
    ap.add_argument("--timeout", type=float, default=None)
    ap.add_argument("--solver", default=None)
    ap.add_argument("--csv", default=None,
                    help="append one row per call, so a sweep leaves an artefact")
    args = ap.parse_args()

    v = variants_mod.get(args.variant, args.variants_dir)
    print(f"solver: {solver_mod.solver_version(args.solver)}")
    print(f"{v.name}: proving every {args.rounds}-round characteristic has "
          f"weight >= {args.weight}")

    # In active mode the objective counts active S-boxes, not weight. Every active
    # S-box costs at least w_min, so `active >= ceil(target / w_min)` implies
    # `weight >= target`. The implication only goes one way -- failing to prove the
    # active bound says nothing about the weight bound -- but when it succeeds the
    # weight statement is just as sound, and the CNF has no weight encoding in it at
    # all, which is a different and often much easier search.
    if args.mode == model_mod.MODE_ACTIVE:
        w_min = min(w for (a, _b), w in v.weights.transitions.items() if a != 0)
        target = -(-args.weight // w_min)          # ceil
        print(f"  via active S-boxes: >= {target} active, each costing >= {w_min}")
    else:
        target = args.weight

    started = time.monotonic()
    m = model_mod.build(v, args.rounds, args.mode)
    model_mod.bound(m, target - 1)
    res = solver_mod.solve(m.cnf, timeout=args.timeout, solver=args.solver)
    secs = time.monotonic() - started

    print(f"  {m.cnf.nv} vars, {len(m.cnf.clauses)} clauses, {secs:.1f}s")

    witness = None
    if res.status == solver_mod.SAT:
        model_mod.verify_solution(m, res.value)
        witness = decode(m, res).total_weight
    if args.csv:
        new = not os.path.exists(args.csv)
        with open(args.csv, "a", encoding="utf-8") as fh:
            if new:
                fh.write("variant,rounds,target_weight,mode,status,witness_weight,"
                         "seconds,n_vars,n_clauses\n")
            fh.write(f"{v.name},{args.rounds},{args.weight},{args.mode},{res.status},"
                     f"{'' if witness is None else witness},{secs:.1f},"
                     f"{m.cnf.nv},{len(m.cnf.clauses)}\n")

    if res.status == solver_mod.UNSAT:
        print(f"  UNSAT -> PROVEN: no {args.rounds}-round characteristic reaches "
              f"weight <= {args.weight - 1}, so the bound is 2^-{args.weight} or better")
        return 0
    if res.status == solver_mod.SAT:
        # The witness was already replayed against the cipher above, so a
        # counterexample is never an artefact of the encoding -- the same check
        # cli.py applies to every trail it accepts.
        t = decode(m, res)
        if args.mode == model_mod.MODE_ACTIVE:
            print(f"  SAT -> NOT proven this way: a characteristic with only "
                  f"{t.total_active} active S-boxes exists, which is too few to force "
                  f"weight {args.weight}. Its true weight may still be high enough -- "
                  f"only --mode weight can settle that.")
        else:
            print(f"  SAT -> NOT proven. Counterexample of weight {witness}:")
        print(t.format())
        return 1
    print(f"  {res.status}: no answer within the timeout; nothing proven either way")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
