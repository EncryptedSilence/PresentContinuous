"""CNF construction: formula container, relation encoding, cardinality constraints.

Pure stdlib. Variables are positive integers starting at 1; a literal is a signed
variable, matching DIMACS.
"""

from __future__ import annotations

import itertools
from typing import Dict, Iterable, List, Sequence, Tuple


class CNF:
    def __init__(self) -> None:
        self.nv = 0
        self.clauses: List[List[int]] = []
        self.comments: List[str] = []

    def new_var(self) -> int:
        self.nv += 1
        return self.nv

    def new_vars(self, n: int) -> List[int]:
        return [self.new_var() for _ in range(n)]

    def add(self, clause: Iterable[int]) -> None:
        self.clauses.append(list(clause))

    def add_all(self, clauses: Iterable[Iterable[int]]) -> None:
        for c in clauses:
            self.add(c)

    def comment(self, text: str) -> None:
        self.comments.append(text)

    def to_dimacs(self) -> str:
        parts = [f"c {c}\n" for c in self.comments]
        parts.append(f"p cnf {self.nv} {len(self.clauses)}\n")
        parts.extend(" ".join(map(str, c)) + " 0\n" for c in self.clauses)
        return "".join(parts)

    def write(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_dimacs())

    def __repr__(self) -> str:
        return f"<CNF vars={self.nv} clauses={len(self.clauses)}>"


# --------------------------------------------------------------------------------------
# Encoding an arbitrary boolean relation as clauses
# --------------------------------------------------------------------------------------


def _cube_points(free: int, m: int) -> List[int]:
    """Every assignment in the cube through `m` whose free variables are `free`."""
    base = m & ~free
    out = [base]
    sub = free
    while sub:
        out.append(base | sub)
        sub = (sub - 1) & free
    return out


def _bitset(points: Iterable[int], n_vars: int) -> int:
    """Points as a 2**n_vars-bit integer. Built through a bytearray because OR-ing a
    shifted 1 into a growing big integer is quadratic in the number of points."""
    buf = bytearray(1 << max(n_vars - 3, 0))
    for p in points:
        buf[p >> 3] |= 1 << (p & 7)
    return int.from_bytes(buf, "little")


def relation_clauses(n_vars: int, valid: Iterable[int],
                     dont_care: Iterable[int] = ()) -> List[List[int]]:
    """Clauses over variables 1..n_vars accepting `valid` and rejecting the rest.

    `valid` holds assignments encoded as integers, bit i giving the value of variable
    i+1. Assignments in `dont_care` may be accepted or rejected -- the caller has some
    other constraint that already excludes them, and leaving them free lets the cubes
    below grow much larger. Everything else must be rejected.

    Each clause is the negation of a cube that lies wholly outside `valid`. Cubes are
    grown maximally from seeds that nothing covers yet, then an irredundancy pass drops
    any whose points the others already cover. Both passes work on the cubes' point
    sets rather than on a truth-table bitset: for a dense relation such as an 8-bit
    S-box's DDT support -- where half of all (a, b) pairs are valid, so a maximal cube
    holds only a handful of points -- that is what keeps this feasible. The result is
    checked independently by :func:`verify_relation` before it is used.
    """
    valid_set = set(valid)
    dc_set = set(dont_care) - valid_set
    reject = [a for a in range(1 << n_vars) if a not in valid_set and a not in dc_set]
    if not reject:
        return []
    reject_set = set(reject)

    # Expand. Freeing variable v doubles the cube; only the mirrored half is new, so
    # that is all this tests against the accept set.
    covered: set = set()
    cubes: List[Tuple[int, int, List[int]]] = []
    for m in reject:
        if m in covered:
            continue
        free, pts = 0, [m]
        for v in range(n_vars):
            shift = 1 << v
            mirror = [p ^ shift for p in pts]
            if any(p in valid_set for p in mirror):
                continue           # freeing v would swallow a valid assignment
            free |= shift
            pts = pts + mirror
        cubes.append((free, m, pts))
        covered.update(pts)

    # Irredundancy: a cube grown from a later seed often subsumes an earlier one. Only
    # reject points need covering -- don't-cares are free either way.
    count: Dict[int, int] = {}
    for _, _, pts in cubes:
        for p in pts:
            if p in reject_set:
                count[p] = count.get(p, 0) + 1
    keep: List[Tuple[int, int]] = []
    for free, m, pts in cubes:
        mine = [p for p in pts if p in reject_set]
        if all(count[p] >= 2 for p in mine):
            for p in mine:
                count[p] -= 1
        else:
            keep.append((free, m))

    clauses = []
    for free, m in keep:
        # The cube forbids this pattern on its fixed variables, so the clause is its
        # negation over exactly those variables.
        clauses.append([-(v + 1) if (m >> v) & 1 else (v + 1)
                        for v in range(n_vars) if not (free >> v) & 1])
    return clauses


def verify_relation(n_vars: int, valid: Iterable[int], clauses: Sequence[Sequence[int]],
                    dont_care: Iterable[int] = ()) -> None:
    """Check that `clauses` accept all of `valid` and reject everything outside it and
    `dont_care`. Raises on mismatch.

    A wrong S-box encoding would silently produce wrong cryptanalysis rather than an
    error -- the formula stays satisfiable and describes a different cipher -- so this
    runs every time an encoding is built. The check is rebuilt from the clause literals
    alone, not from the cubes the search produced, so it is independent of the code
    above rather than a restatement of it.
    """
    valid_set = set(valid)
    dc_set = set(dont_care) - valid_set

    accept = _bitset(valid_set, n_vars)
    reject = _bitset((a for a in range(1 << n_vars)
                      if a not in valid_set and a not in dc_set), n_vars)

    rejected = 0
    for cl in clauses:
        free = (1 << n_vars) - 1
        m = 0
        for lit in cl:
            v = abs(lit) - 1
            free &= ~(1 << v)
            if lit < 0:
                m |= 1 << v
        bs = _bitset(_cube_points(free, m), n_vars)
        if bs & accept:
            bad = bs & accept
            first = (bad & -bad).bit_length() - 1
            raise AssertionError(
                f"clause {cl} rejects valid assignment {first:0{n_vars}b}")
        rejected |= bs

    missed = reject & ~rejected
    if missed:
        first = (missed & -missed).bit_length() - 1
        raise AssertionError(
            f"no clause rejects invalid assignment {first:0{n_vars}b}")


# --------------------------------------------------------------------------------------
# Cardinality: sum of literals <= k
# --------------------------------------------------------------------------------------


def at_most_k(cnf: CNF, lits: Sequence[int], k: int) -> None:
    """Sinz's sequential counter encoding of sum(lits) <= k.

    O(n*k) auxiliary variables and clauses. Weighted sums are handled by the caller
    passing each weight in unary, so every literal here has weight one.
    """
    n = len(lits)
    if k < 0:
        cnf.add([])  # unsatisfiable
        return
    if k >= n:
        return
    if k == 0:
        for x in lits:
            cnf.add([-x])
        return

    s = [cnf.new_vars(k) for _ in range(n)]

    cnf.add([-lits[0], s[0][0]])
    for j in range(1, k):
        cnf.add([-s[0][j]])

    for i in range(1, n):
        cnf.add([-lits[i], s[i][0]])
        cnf.add([-s[i - 1][0], s[i][0]])
        for j in range(1, k):
            cnf.add([-lits[i], -s[i - 1][j - 1], s[i][j]])
            cnf.add([-s[i - 1][j], s[i][j]])
        cnf.add([-lits[i], -s[i - 1][k - 1]])


def at_least_one(cnf: CNF, lits: Sequence[int]) -> None:
    cnf.add(list(lits))


def count_solutions_bruteforce(n_vars: int, clauses: Sequence[Sequence[int]]) -> int:
    """Only for tests on tiny formulas."""
    total = 0
    for bits in itertools.product([0, 1], repeat=n_vars):
        ok = True
        for cl in clauses:
            if not any((lit > 0) == bool(bits[abs(lit) - 1]) for lit in cl):
                ok = False
                break
        total += ok
    return total
