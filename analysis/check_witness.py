#!/usr/bin/env python3
"""Replay a solver's SAT model against the cipher and print the trail.

dump_cnf.py hands a formula to an external solver, which answers with a bare
assignment. That assignment is only evidence if it survives the same check
prove_bound applies to its own witnesses: model.verify_solution walks the trail
through the real S-box and linear layer and confirms every difference and every
weight. This closes that loop for a model that came back from a file.

The model must be rebuilt with exactly the arguments dump_cnf.py was given, since
variable numbering depends on them.

    python3 analysis/check_witness.py --variant present-80-lin444-297 --rounds 5 \
            --weight 64 --model TARGET-r5.kissat.3008.out
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from present_sat import model as model_mod
from present_sat import solver as solver_mod
from present_sat import variants as variants_mod
from present_sat.trail import decode


def read_model(path: str) -> tuple:
    """Parse competition-format output into (status, assignment set)."""
    status, lits = None, []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("s "):
                word = line.split()[1].upper()
                status = {"SATISFIABLE": solver_mod.SAT,
                          "UNSATISFIABLE": solver_mod.UNSAT}.get(word, solver_mod.UNKNOWN)
            elif line.startswith("v "):
                lits.extend(int(t) for t in line.split()[1:])
    return status, [v for v in lits if v != 0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--variant", required=True)
    ap.add_argument("--variants-dir", default=None)
    ap.add_argument("--rounds", type=int, required=True)
    ap.add_argument("--weight", type=int, required=True)
    ap.add_argument("--mode", choices=(model_mod.MODE_WEIGHT, model_mod.MODE_ACTIVE),
                    default=model_mod.MODE_WEIGHT)
    ap.add_argument("--model", required=True, help="solver output file")
    args = ap.parse_args()

    status, lits = read_model(args.model)
    if status != solver_mod.SAT:
        print(f"{args.model}: status is {status}, nothing to replay")
        return 2

    v = variants_mod.get(args.variant, args.variants_dir)
    target = args.weight
    if args.mode == model_mod.MODE_ACTIVE:
        w_min = min(w for (a, _b), w in v.weights.transitions.items() if a != 0)
        target = -(-args.weight // w_min)

    m = model_mod.build(v, args.rounds, args.mode)
    model_mod.bound(m, target - 1)

    true_lits = {abs(x) for x in lits if x > 0}
    if len(lits) < m.cnf.nv:
        print(f"warning: model has {len(lits)} literals for {m.cnf.nv} variables")

    def value(lit: int) -> bool:
        return (abs(lit) in true_lits) if lit > 0 else (abs(lit) not in true_lits)

    # Every clause must hold: this catches a model built with different arguments
    # from the one the solver actually saw, which would otherwise decode to nonsense.
    for i, clause in enumerate(m.cnf.clauses):
        if not any(value(lit) for lit in clause):
            print(f"FAIL: clause {i} is unsatisfied by this model -- the formula and "
                  f"the assignment do not match")
            return 1
    print(f"all {len(m.cnf.clauses)} clauses satisfied")

    # And the trail must replay through the real cipher. verify_solution and decode
    # both want the Result contract -- value(var) over variable numbers, and a model
    # list of signed literals indexed by var - 1 -- not the literal-level lookup the
    # clause check above uses.
    res = solver_mod.Result(
        status=solver_mod.SAT,
        model=[(v if v in true_lits else -v) for v in range(1, m.cnf.nv + 1)],
        seconds=0.0, n_vars=m.cnf.nv, n_clauses=len(m.cnf.clauses),
    )
    model_mod.verify_solution(m, res.value)
    t = decode(m, res)
    print(f"replayed against {v.name}: OK\n")
    print(t.format())
    print(f"\ntotal weight {t.total_weight} <= {args.weight - 1}, so W({args.rounds}) "
          f"<= {t.total_weight}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
