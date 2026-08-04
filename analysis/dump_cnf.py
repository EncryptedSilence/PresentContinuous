#!/usr/bin/env python3
"""Write the bound-probe CNF to a DIMACS file instead of solving it.

prove_bound.py builds a formula and hands it straight to whichever solver the
solver module picks. When the question is which solver to pick, that is the wrong
shape: the formula has to be built once and fed to several. This writes exactly the
formula prove_bound would have solved -- same model, same cardinality bound -- so a
solver comparison measures the solvers and not the encoder.

    python3 analysis/dump_cnf.py --variant present-80 --rounds 15 --weight 64 \
            --out /tmp/p80-r15.cnf
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from present_sat import model as model_mod
from present_sat import variants as variants_mod


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--variant", required=True)
    ap.add_argument("--variants-dir", default=None)
    ap.add_argument("--rounds", type=int, required=True)
    ap.add_argument("--weight", type=int, required=True)
    ap.add_argument("--mode", choices=(model_mod.MODE_WEIGHT, model_mod.MODE_ACTIVE),
                    default=model_mod.MODE_WEIGHT)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    v = variants_mod.get(args.variant, args.variants_dir)
    target = args.weight
    if args.mode == model_mod.MODE_ACTIVE:
        w_min = min(w for (a, _b), w in v.weights.transitions.items() if a != 0)
        target = -(-args.weight // w_min)

    m = model_mod.build(v, args.rounds, args.mode)
    model_mod.bound(m, target - 1)
    m.cnf.write(args.out)
    print(f"{args.out}: {m.cnf.nv} vars, {len(m.cnf.clauses)} clauses "
          f"({v.name}, {args.rounds} rounds, weight >= {args.weight})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
