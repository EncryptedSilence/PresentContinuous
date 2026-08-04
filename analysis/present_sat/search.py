"""Optimal differential trail search.

The predicate "there is a trail of cost at most k" is monotone in k, so the smallest
k for which the formula is satisfiable is the optimum. We scan upward from a lower
bound: every call below the optimum is UNSAT, and the first SAT call gives both the
optimal value and a witness trail.

Scanning up from a good lower bound beats binary search here because the expensive
calls are the UNSAT ones just below the optimum, and binary search does not avoid
them - it only adds SAT calls higher up.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import model as model_mod
from . import solver as solver_mod
from .trail import Trail, decode
from .variants import Variant

EXACT = "exact"
LOWER_BOUND = "lower_bound"   # search timed out; the true value is >= `lower_bound`
FAILED = "failed"


@dataclass
class SearchResult:
    variant: str
    rounds: int
    mode: str
    value: Optional[int]
    status: str
    lower_bound: int
    trail: Optional[Trail]
    seconds: float
    calls: int
    n_vars: int = 0
    n_clauses: int = 0
    notes: str = ""

    def describe(self) -> str:
        label = "min weight" if self.mode == model_mod.MODE_WEIGHT else "min active S-boxes"
        if self.status == EXACT:
            return f"{label} over {self.rounds} rounds = {self.value}"
        if self.status == LOWER_BOUND:
            return f"{label} over {self.rounds} rounds >= {self.lower_bound} (timed out)"
        return f"{label} over {self.rounds} rounds: search failed"


def _search(variant: Variant, rounds: int, mode: str, start: int, max_k: int,
            timeout: Optional[float], solver: Optional[str],
            total_budget: Optional[float]) -> SearchResult:
    seconds = 0.0
    calls = 0
    n_vars = n_clauses = 0
    k = start

    while k <= max_k:
        m = model_mod.build(variant, rounds, mode)
        model_mod.bound(m, k)
        n_vars, n_clauses = m.cnf.nv, len(m.cnf.clauses)

        res = solver_mod.solve(m.cnf, timeout=timeout, solver=solver)
        seconds += res.seconds
        calls += 1

        if res.status == solver_mod.SAT:
            # Replay the assignment against the cipher before believing it. A
            # mis-encoded linear layer yields a satisfiable formula describing the
            # wrong cipher, i.e. a bound that is too good and looks fine.
            model_mod.verify_solution(m, res.value)
            return SearchResult(variant.name, rounds, mode, k, EXACT, k,
                                decode(m, res), seconds, calls, n_vars, n_clauses)
        if res.status == solver_mod.UNKNOWN:
            return SearchResult(variant.name, rounds, mode, None, LOWER_BOUND, k,
                                None, seconds, calls, n_vars, n_clauses,
                                notes=f"solver gave up at k={k}")
        # UNSAT: no trail this cheap exists, try the next value.
        k += 1
        if total_budget is not None and seconds > total_budget:
            return SearchResult(variant.name, rounds, mode, None, LOWER_BOUND, k,
                                None, seconds, calls, n_vars, n_clauses,
                                notes="time budget exhausted")

    return SearchResult(variant.name, rounds, mode, None, LOWER_BOUND, max_k + 1,
                        None, seconds, calls, n_vars, n_clauses,
                        notes=f"no trail with cost <= {max_k}")


def min_active_sboxes(variant: Variant, rounds: int, timeout: Optional[float] = 300,
                      solver: Optional[str] = None, max_k: Optional[int] = None,
                      total_budget: Optional[float] = None) -> SearchResult:
    """Fewest S-boxes that any differential characteristic over `rounds` rounds
    can activate. At least one S-box must be active in the first round."""
    max_k = max_k if max_k is not None else 16 * rounds
    return _search(variant, rounds, model_mod.MODE_ACTIVE, 1, max_k, timeout, solver,
                   total_budget)


def min_trail_weight(variant: Variant, rounds: int, timeout: Optional[float] = 300,
                     solver: Optional[str] = None, start: Optional[int] = None,
                     max_k: Optional[int] = None,
                     total_budget: Optional[float] = None) -> SearchResult:
    """Weight of the best (most probable) differential characteristic over `rounds`
    rounds. Weight w means probability 2^-w."""
    if start is None:
        start = variant.weights.min_active_weight()
    max_k = max_k if max_k is not None else 3 * 16 * rounds
    return _search(variant, rounds, model_mod.MODE_WEIGHT, start, max_k, timeout,
                   solver, total_budget)


def min_trail_weight_from_active(variant: Variant, rounds: int,
                                 active: SearchResult, **kwargs) -> SearchResult:
    """Same as :func:`min_trail_weight`, but seeded with the active-S-box bound.

    A trail with `a` active S-boxes costs at least `a * min_active_weight`, so the
    active-S-box search - which is much cheaper - gives a valid starting point and
    skips a run of UNSAT calls.
    """
    per_sbox = variant.weights.min_active_weight()
    if active.status == EXACT and active.value is not None:
        kwargs.setdefault("start", active.value * per_sbox)
    elif active.lower_bound:
        kwargs.setdefault("start", active.lower_bound * per_sbox)
    return min_trail_weight(variant, rounds, **kwargs)


@dataclass
class ClusterResult:
    weight: int
    trails: int
    exhausted: bool
    seconds: float


def count_trails(variant: Variant, rounds: int, weight: int, diff_in: int,
                 diff_out: int, limit: int = 1000, timeout: Optional[float] = 300,
                 solver: Optional[str] = None) -> ClusterResult:
    """Count distinct characteristics of weight *at most* `weight` joining the pair.

    Several characteristics can share the same input and output difference; their
    probabilities add up, so the differential is more probable than any single trail.
    This enumerates them by blocking each solution's intermediate differences and
    re-solving. Returns `exhausted=False` if it stopped at `limit`.

    The bound is `<=`, so successive calls give a cumulative count and the number at
    exactly w is the difference of consecutive results. Blocking is on the
    intermediate differences alone, which is what identifies a characteristic, so a
    tiered weight encoding -- where the modelled weight can exceed the true one --
    still counts each characteristic once.
    """
    m = model_mod.build(variant, rounds, model_mod.MODE_WEIGHT)
    model_mod.bound(m, weight)
    model_mod.fix_difference(m, 0, diff_in)
    model_mod.fix_difference(m, rounds, diff_out)

    # Intermediate differences identify a characteristic.
    inner: List[int] = []
    for r in range(1, rounds):
        inner.extend(m.diff[r])

    found = 0
    seconds = 0.0
    exhausted = True
    while found < limit:
        res = solver_mod.solve(m.cnf, timeout=timeout, solver=solver)
        seconds += res.seconds
        if res.status == solver_mod.UNSAT:
            break
        if res.status != solver_mod.SAT:
            exhausted = False
            break
        found += 1
        m.cnf.add([-v if res.value(v) else v for v in inner])
    else:
        exhausted = False

    return ClusterResult(weight=weight, trails=found, exhausted=exhausted, seconds=seconds)
