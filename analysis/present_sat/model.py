"""The differential model of a PRESENT-like variant, as CNF.

Difference propagation through this cipher is the clean case:

* the key addition is transparent to differences, so round keys never appear;
* the linear layer is linear over GF(2), so a difference passes through it by the
  same matrix the data does - no probability, just wiring and XORs;
* only the S-box layer constrains anything probabilistically.

So the formula is: one S-box relation per S-box instance, the linear layer's XORs,
a cardinality constraint on the objective, and "the input difference is not zero".

The layer is encoded from the *column form* that every variant carries, so one code
path serves both kinds. Output bit i of the layer is the XOR of the S-box outputs j
whose column contains bit i; for a bit permutation that row has exactly one entry,
the XOR chain degenerates to aliasing, and the layer contributes no clauses and no
variables at all - which is the classical PRESENT encoding, recovered rather than
special-cased. For lin444 the rows have 8.75 entries on average, so the layer costs
about 500 XOR gates and 2000 clauses per round.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from .cnf import CNF, at_most_k, relation_clauses, verify_relation
from .sbox import WeightModel
from .variants import Variant

MODE_WEIGHT = "weight"
MODE_ACTIVE = "active"

# Above this many variables the single-relation encoding stops being buildable: the
# cube search carries the whole truth table as a bitset, so it costs 2**n_vars bits per
# cube. A 4-bit S-box in weight mode needs 2*4+3 = 11; an 8-bit one would need
# 2*8+7 = 23, which is a megabyte per cube and eight million seeds. Wide S-boxes use
# the threshold decomposition in :func:`sbox_weight_relations` instead.
DIRECT_RELATION_MAX_VARS = 16

_relation_cache: Dict[Tuple[Tuple[int, ...], str], Tuple[int, List[List[int]]]] = {}
_threshold_cache: Dict[Tuple[Tuple[int, ...], int], List[List[int]]] = {}


def use_direct_weight_relation(variant: Variant) -> bool:
    """Whether one relation can carry the whole (in, out, weight) table."""
    return 2 * variant.sbox_bits + variant.weights.max_weight <= DIRECT_RELATION_MAX_VARS


def sbox_relation(variant: Variant, mode: str) -> Tuple[int, List[List[int]]]:
    """Clauses over (in bits, out bits[, unary weight bits]) for one S-box.

    Variable order inside the relation:
        0..n-1     input difference bits, LSB first
        n..2n-1    output difference bits, LSB first
        2n..       unary weight bits (weight mode only): bit j set iff weight > j

    In weight mode this is only used for S-boxes narrow enough to encode directly;
    see :func:`use_direct_weight_relation`. Cached per S-box table, since a variant
    reuses the same S-box n_sboxes * rounds times.
    """
    key = (tuple(variant.sbox), mode)
    if key in _relation_cache:
        return _relation_cache[key]

    n = variant.sbox_bits
    wm: WeightModel = variant.weights
    if mode == MODE_ACTIVE:
        n_vars = 2 * n
        valid = {a | (b << n) for (a, b) in wm.transitions}
    elif mode == MODE_WEIGHT:
        maxw = wm.max_weight
        n_vars = 2 * n + maxw
        valid = set()
        for (a, b), w in wm.transitions.items():
            unary = (1 << w) - 1
            valid.add(a | (b << n) | (unary << (2 * n)))
    else:
        raise ValueError(f"unknown mode {mode!r}")

    clauses = relation_clauses(n_vars, valid)
    verify_relation(n_vars, valid, clauses)
    _relation_cache[key] = (n_vars, clauses)
    return n_vars, clauses


def sbox_weight_relations(variant: Variant) -> Tuple[List[int], Dict[int, List[List[int]]]]:
    """Weight encoding for a wide S-box, split by threshold.

    Returns the distinct positive transition weights and, for each one t, clauses over
    (in bits, out bits, u_t) that force u_t whenever the transition's weight is at
    least t. With the prefix constraints u_j -> u_{j-1} added by the caller, forcing
    u_t forces u_1..u_t, so the unary weight of a transition of weight w is at least w.

    That is the direction soundness needs. The solver is free to set *more* unary bits
    than required, but it is minimising their sum, so at the optimum it does not -- and
    a solution that did would only report a larger weight, never a smaller one, so the
    bound stays valid either way.

    Transitions outside the DDT support are passed as don't-cares: the support relation
    already rejects them, and leaving them free here lets the cubes grow much larger.
    For cipher-D's S-box the weight-6 threshold collapses to eight two-literal clauses.
    """
    n = variant.sbox_bits
    wm = variant.weights
    support = {a | (b << n) for (a, b) in wm.transitions}
    dont_care = [x for x in range(1 << (2 * n)) if x not in support]

    thresholds = sorted({w for w in wm.transitions.values() if w > 0})
    out: Dict[int, List[List[int]]] = {}
    for t in thresholds:
        key = (tuple(variant.sbox), t)
        if key in _threshold_cache:
            out[t] = _threshold_cache[key]
            continue
        # Variable 2n+1 is u_t. Reject exactly (transition of weight >= t, u_t = 0).
        valid = set()
        for (a, b), w in wm.transitions.items():
            x = a | (b << n)
            valid.add(x | (1 << (2 * n)))          # u_t = 1 is always allowed
            if w < t:
                valid.add(x)                        # weight below t: u_t = 0 allowed
        dc = [x for x in dont_care] + [x | (1 << (2 * n)) for x in dont_care]
        clauses = relation_clauses(2 * n + 1, valid, dc)
        verify_relation(2 * n + 1, valid, clauses, dc)
        _threshold_cache[key] = clauses
        out[t] = clauses
    return thresholds, out


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
    sbox_out: List[List[int]]      # [round][bit]: difference after sBoxLayer

    def max_objective(self) -> int:
        return len(self.objective)


class UnsupportedLayer(NotImplementedError):
    """Raised for variants whose linear layer this model cannot encode."""


def _xor_into(cnf: CNF, lits: Sequence[int]) -> int:
    """A literal equal to the XOR of `lits`, via a Tseitin chain.

    One fresh variable and four clauses per binary XOR. A single-element list needs
    neither: the answer is that element, which is what makes a bit permutation free.
    """
    if not lits:
        raise ValueError("empty XOR: an invertible layer has no all-zero output row")
    acc = lits[0]
    for b in lits[1:]:
        z = cnf.new_var()
        # z <-> acc ^ b, as the four assignments that violate it
        cnf.add([acc, b, -z])
        cnf.add([acc, -b, z])
        cnf.add([-acc, b, z])
        cnf.add([-acc, -b, -z])
        acc = z
    return acc


def linear_layer_rows(variant: Variant) -> List[List[int]]:
    """rows[i] = indices j such that output bit i receives S-box output bit j.

    The transpose of the column form. Invertibility guarantees every row is
    non-empty, and the variant loader has already checked the columns compose with
    their inverse to the identity.
    """
    cols = variant.lin_cols
    n = variant.block_bits
    rows: List[List[int]] = [[] for _ in range(n)]
    for j in range(n):
        c = cols[j]
        while c:
            b = (c & -c).bit_length() - 1
            rows[b].append(j)
            c &= c - 1
    for i, r in enumerate(rows):
        if not r:
            raise UnsupportedLayer(
                f"variant {variant.name!r}: linear layer output bit {i} depends on "
                f"no input bit, so the layer is singular")
    return rows


def build(variant: Variant, rounds: int, mode: str = MODE_WEIGHT) -> DifferentialModel:
    if rounds < 1:
        raise ValueError("rounds must be >= 1")

    rows = linear_layer_rows(variant)

    cnf = CNF()
    cnf.comment(f"variant={variant.name} rounds={rounds} mode={mode}")
    cnf.comment(f"sbox={variant.sbox}")

    n = variant.sbox_bits
    n_sboxes = variant.n_sboxes
    maxw = variant.weights.max_weight if mode == MODE_WEIGHT else 0
    tiered = mode == MODE_WEIGHT and not use_direct_weight_relation(variant)

    if tiered:
        # Support relation over (in, out) plus one threshold relation per distinct
        # weight; see sbox_weight_relations.
        n_rel_vars, rel_clauses = sbox_relation(variant, MODE_ACTIVE)
        thresholds, thr_clauses = sbox_weight_relations(variant)
        cnf.comment(f"tiered weight encoding, thresholds={thresholds}")
    else:
        n_rel_vars, rel_clauses = sbox_relation(variant, mode)
        thresholds, thr_clauses = [], {}

    block = variant.block_bits
    diff: List[List[int]] = [cnf.new_vars(block)]
    sbox_out: List[List[int]] = []
    weight_bits: List[List[List[int]]] = []
    active_bits: List[List[int]] = []
    objective: List[int] = []

    def emit(clauses, local):
        for cl in clauses:
            cnf.add([(local[abs(lit) - 1] if lit > 0 else -local[abs(lit) - 1])
                     for lit in cl])

    for r in range(rounds):
        y = cnf.new_vars(block)
        round_w: List[List[int]] = []
        round_a: List[int] = []

        for i in range(n_sboxes):
            in_bits = diff[r][n * i: n * (i + 1)]
            out_bits = y[n * i: n * (i + 1)]

            if mode == MODE_WEIGHT:
                u = cnf.new_vars(maxw)
                round_w.append(u)
                objective.extend(u)
                local = in_bits + out_bits + ([] if tiered else u)
            else:
                local = in_bits + out_bits

            assert len(local) == n_rel_vars
            emit(rel_clauses, local)

            if tiered:
                # u is a prefix: u_j implies u_{j-1}. With that, forcing the highest
                # applicable threshold forces everything below it.
                for j in range(1, maxw):
                    cnf.add([-u[j], u[j - 1]])
                for t in thresholds:
                    emit(thr_clauses[t], in_bits + out_bits + [u[t - 1]])

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

        # The linear layer. Output bit i is the XOR of the S-box output bits named by
        # row i. For a permutation each row is a single j, _xor_into returns y[j]
        # unchanged, and this is exactly "bit j becomes bit pbox[j]" with no clauses.
        sbox_out.append(y)
        diff.append([_xor_into(cnf, [y[j] for j in rows[i]]) for i in range(block)])

    # A trail must have a nonzero input difference, otherwise everything is zero.
    cnf.add(list(diff[0]))

    return DifferentialModel(variant=variant, rounds=rounds, mode=mode, cnf=cnf,
                             diff=diff, objective=objective, weight_bits=weight_bits,
                             active_bits=active_bits, sbox_out=sbox_out)


def verify_solution(m: DifferentialModel, value) -> None:
    """Re-check a satisfying assignment against the cipher, not against the CNF.

    The encoding is the thing most likely to be quietly wrong -- a mistake in the
    linear layer's rows would not make the formula unsatisfiable, it would make it
    describe a different cipher and return a bound that is too good. So every trail
    the search accepts is replayed here: each S-box transition must appear in the
    DDT with the weight the model claims, and the difference after the linear layer
    must be what the layer's own column form produces. `value` maps a variable to
    its boolean assignment.
    """
    from . import linear as linlib

    def word(lits):
        return sum(1 << i for i, lit in enumerate(lits) if value(lit))

    if word(m.diff[0]) == 0:
        raise AssertionError("trail has a zero input difference")

    wm = m.variant.weights
    cols = m.variant.lin_cols
    n, mask = m.variant.sbox_bits, m.variant.sbox_mask
    # The tiered encoding forces a lower bound on each unary weight rather than pinning
    # it, so the replay checks that direction. Anything the solver over-claims makes the
    # reported bound more conservative, never less.
    tiered = m.mode == MODE_WEIGHT and not use_direct_weight_relation(m.variant)
    total = 0
    for r in range(m.rounds):
        a_word, b_word = word(m.diff[r]), word(m.sbox_out[r])
        for i in range(m.variant.n_sboxes):
            a = (a_word >> (n * i)) & mask
            b = (b_word >> (n * i)) & mask
            if (a, b) not in wm.transitions:
                raise AssertionError(
                    f"round {r} S-box {i}: transition {a:x}->{b:x} is not in the DDT")
            w = wm.transitions[(a, b)]
            if m.mode == MODE_WEIGHT:
                bits = [value(u) for u in m.weight_bits[r][i]]
                if bits != sorted(bits, reverse=True):
                    raise AssertionError(f"round {r} S-box {i}: unary weight not a prefix")
                if sum(bits) < w or (not tiered and sum(bits) != w):
                    raise AssertionError(
                        f"round {r} S-box {i}: model says weight {sum(bits)}, DDT says {w}")
                total += w
            else:
                total += 1 if a else 0

        want = linlib.apply_columns(cols, b_word)
        got = word(m.diff[r + 1])
        if want != got:
            raise AssertionError(
                f"round {r} linear layer: encoded {got:#018x}, layer gives {want:#018x}")

    claimed = sum(1 for lit in m.objective if value(lit))
    if claimed < total or (not tiered and claimed != total):
        raise AssertionError(f"objective is {claimed}, replay gives {total}")


def bound(model: DifferentialModel, k: int) -> None:
    """Add `sum(objective) <= k` to the model's formula, in place."""
    at_most_k(model.cnf, model.objective, k)


def fix_difference(model: DifferentialModel, index: int, value: int) -> None:
    """Pin diff[index] to a concrete difference. Used for trail clustering."""
    for bit in range(model.variant.block_bits):
        lit = model.diff[index][bit]
        model.cnf.add([lit] if (value >> bit) & 1 else [-lit])
