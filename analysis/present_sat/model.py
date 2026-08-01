"""The differential model of a PRESENT-like variant, as CNF.

Difference propagation through this cipher is the clean case:

* the key addition is transparent to differences, so round keys never appear;
* the pLayer is a bit permutation, i.e. pure wiring, so it contributes **no clauses
  at all** - it is variable aliasing;
* only the S-box layer constrains anything.

So the formula is: one S-box relation per S-box instance, plus a cardinality
constraint on the objective, plus "the input difference is not zero".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from .cnf import CNF, at_most_k, relation_clauses, verify_relation
from .sbox import WeightModel
from .variants import N_SBOXES, SBOX_BITS, Variant

MODE_WEIGHT = "weight"
MODE_ACTIVE = "active"

_relation_cache: Dict[Tuple[Tuple[int, ...], str], Tuple[int, List[List[int]]]] = {}


def sbox_relation(variant: Variant, mode: str) -> Tuple[int, List[List[int]]]:
    """Clauses over (in bits, out bits[, unary weight bits]) for one S-box.

    Variable order inside the relation:
        0..3   input difference bits, LSB first
        4..7   output difference bits, LSB first
        8..    unary weight bits (weight mode only): bit j set iff weight > j

    Cached per S-box table, since a variant reuses the same S-box 16 * rounds times.
    """
    key = (tuple(variant.sbox), mode)
    if key in _relation_cache:
        return _relation_cache[key]

    wm: WeightModel = variant.weights
    if mode == MODE_ACTIVE:
        n_vars = 2 * SBOX_BITS
        valid = {a | (b << SBOX_BITS) for (a, b) in wm.transitions}
    elif mode == MODE_WEIGHT:
        maxw = wm.max_weight
        n_vars = 2 * SBOX_BITS + maxw
        valid = set()
        for (a, b), w in wm.transitions.items():
            unary = (1 << w) - 1
            valid.add(a | (b << SBOX_BITS) | (unary << (2 * SBOX_BITS)))
    else:
        raise ValueError(f"unknown mode {mode!r}")

    clauses = relation_clauses(n_vars, valid)
    verify_relation(n_vars, valid, clauses)
    _relation_cache[key] = (n_vars, clauses)
    return n_vars, clauses


@dataclass
class DifferentialModel:
    variant: Variant
    rounds: int
    mode: str
    cnf: CNF
    diff: List[List[int]]          # diff[r][bit] for r = 0..rounds
    objective: List[int]           # literals whose sum is the quantity being bounded
    weight_bits: List[List[List[int]]]  # [round][sbox][unary bit]
    active_bits: List[List[int]]   # [round][sbox]

    def max_objective(self) -> int:
        return len(self.objective)


def build(variant: Variant, rounds: int, mode: str = MODE_WEIGHT) -> DifferentialModel:
    if rounds < 1:
        raise ValueError("rounds must be >= 1")

    cnf = CNF()
    cnf.comment(f"variant={variant.name} rounds={rounds} mode={mode}")
    cnf.comment(f"sbox={variant.sbox}")

    n_rel_vars, rel_clauses = sbox_relation(variant, mode)
    maxw = variant.weights.max_weight if mode == MODE_WEIGHT else 0

    diff: List[List[int]] = [cnf.new_vars(64)]
    weight_bits: List[List[List[int]]] = []
    active_bits: List[List[int]] = []
    objective: List[int] = []

    for r in range(rounds):
        y = cnf.new_vars(64)
        round_w: List[List[int]] = []
        round_a: List[int] = []

        for i in range(N_SBOXES):
            in_bits = diff[r][SBOX_BITS * i: SBOX_BITS * (i + 1)]
            out_bits = y[SBOX_BITS * i: SBOX_BITS * (i + 1)]

            if mode == MODE_WEIGHT:
                u = cnf.new_vars(maxw)
                round_w.append(u)
                objective.extend(u)
                local = in_bits + out_bits + u
            else:
                local = in_bits + out_bits

            assert len(local) == n_rel_vars
            for cl in rel_clauses:
                cnf.add([(local[abs(lit) - 1] if lit > 0 else -local[abs(lit) - 1])
                         for lit in cl])

            if mode == MODE_ACTIVE:
                # a <-> (any input difference bit set). The S-box is a permutation,
                # so a zero input difference forces a zero output difference and the
                # S-box is inactive.
                a = cnf.new_var()
                round_a.append(a)
                objective.append(a)
                for b in in_bits:
                    cnf.add([-b, a])
                cnf.add([-a] + list(in_bits))

        if mode == MODE_WEIGHT:
            weight_bits.append(round_w)
        else:
            active_bits.append(round_a)

        # pLayer: pure wiring. Bit j of the S-box output becomes bit pbox[j] of the
        # next round's difference. No clauses.
        nxt = [0] * 64
        for j in range(64):
            nxt[variant.pbox[j]] = y[j]
        diff.append(nxt)

    # A trail must have a nonzero input difference, otherwise everything is zero.
    cnf.add(list(diff[0]))

    return DifferentialModel(variant=variant, rounds=rounds, mode=mode, cnf=cnf,
                             diff=diff, objective=objective, weight_bits=weight_bits,
                             active_bits=active_bits)


def bound(model: DifferentialModel, k: int) -> None:
    """Add `sum(objective) <= k` to the model's formula, in place."""
    at_most_k(model.cnf, model.objective, k)


def fix_difference(model: DifferentialModel, index: int, value: int) -> None:
    """Pin diff[index] to a concrete 64-bit difference. Used for trail clustering."""
    for bit in range(64):
        lit = model.diff[index][bit]
        model.cnf.add([lit] if (value >> bit) & 1 else [-lit])
