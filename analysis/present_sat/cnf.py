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


def relation_clauses(n_vars: int, valid: Iterable[int]) -> List[List[int]]:
    """Clauses over variables 1..n_vars that are satisfied exactly by `valid`.

    `valid` holds assignments encoded as integers, bit i giving the value of variable
    i+1. The off-set is covered by cubes that are maximal within the off-set (each
    cube becomes one clause), then reduced by a greedy set cover. The result is
    verified exhaustively by :func:`verify_relation` before it is used.
    """
    size = 1 << n_vars
    valid_set = set(valid)
    onset = 0
    for a in valid_set:
        onset |= 1 << a

    offset_terms = [a for a in range(size) if a not in valid_set]
    if not offset_terms:
        return []

    cubes: Dict[Tuple[Tuple[int, ...], int], int] = {}
    for m in offset_terms:
        freed: List[int] = []
        bs = 1 << m
        for v in range(n_vars):
            shift = 1 << v
            grown = bs | (bs >> shift if (m >> v) & 1 else bs << shift)
            grown &= size_mask(size)
            if grown & onset:
                continue  # freeing v would swallow a valid assignment
            bs = grown
            freed.append(v)
        key = (tuple(sorted(set(range(n_vars)) - set(freed))), m)
        # normalise: the cube is determined by its fixed variables and their values
        fixed = key[0]
        value = sum(((m >> v) & 1) << v for v in fixed)
        cubes[(fixed, value)] = bs

    # Greedy set cover of the off-set by the cubes found.
    target = ((1 << size) - 1) & ~onset
    covered = 0
    chosen: List[Tuple[Tuple[int, ...], int]] = []
    items = list(cubes.items())
    while covered != target:
        best_key, best_bs, best_gain = None, 0, -1
        for key, bs in items:
            gain = bin(bs & ~covered & target).count("1")
            if gain > best_gain:
                best_key, best_bs, best_gain = key, bs, gain
        if best_gain <= 0:
            raise RuntimeError("cube cover failed to make progress")
        chosen.append(best_key)
        covered |= best_bs
        items = [(k, b) for (k, b) in items if k != best_key]

    clauses = []
    for fixed, value in chosen:
        # The cube forbids this assignment pattern, so the clause is its negation.
        clauses.append([-(v + 1) if (value >> v) & 1 else (v + 1) for v in fixed])
    return clauses


def size_mask(size: int) -> int:
    return (1 << size) - 1


def verify_relation(n_vars: int, valid: Iterable[int], clauses: Sequence[Sequence[int]]) -> None:
    """Exhaustively check that `clauses` accept exactly `valid`. Raises on mismatch.

    A wrong S-box encoding would silently produce wrong cryptanalysis rather than an
    error, so this check runs every time the encoding is built.
    """
    valid_set = set(valid)
    for a in range(1 << n_vars):
        ok = True
        for cl in clauses:
            sat = False
            for lit in cl:
                v = abs(lit) - 1
                bit = (a >> v) & 1
                if (lit > 0 and bit) or (lit < 0 and not bit):
                    sat = True
                    break
            if not sat:
                ok = False
                break
        if ok != (a in valid_set):
            raise AssertionError(
                f"relation encoding mismatch at assignment {a:0{n_vars}b}: "
                f"clauses say {ok}, table says {a in valid_set}"
            )


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
