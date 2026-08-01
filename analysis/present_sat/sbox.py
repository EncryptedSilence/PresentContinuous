"""S-box properties: DDT, LAT, and the differential weights used by the SAT model.

Pure stdlib. Everything here is derived from the S-box table; nothing is hardcoded.
"""

from __future__ import annotations

import math
from typing import Dict, List, Sequence, Tuple


def is_permutation(table: Sequence[int], n_bits: int) -> bool:
    size = 1 << n_bits
    return len(table) == size and sorted(table) == list(range(size))


def inverse(table: Sequence[int]) -> List[int]:
    inv = [0] * len(table)
    for x, y in enumerate(table):
        inv[y] = x
    return inv


def ddt(table: Sequence[int]) -> List[List[int]]:
    """Difference distribution table. ddt[a][b] = #{x : S(x) ^ S(x^a) == b}."""
    size = len(table)
    out = [[0] * size for _ in range(size)]
    for a in range(size):
        for x in range(size):
            out[a][table[x] ^ table[x ^ a]] += 1
    return out


def lat(table: Sequence[int]) -> List[List[int]]:
    """Linear approximation table, biased form.

    lat[a][b] = #{x : <a,x> == <b,S(x)>} - size/2, so lat[0][0] == size/2.
    """
    size = len(table)
    out = [[0] * size for _ in range(size)]
    for a in range(size):
        for b in range(size):
            count = 0
            for x in range(size):
                if (bin(a & x).count("1") & 1) == (bin(b & table[x]).count("1") & 1):
                    count += 1
            out[a][b] = count - size // 2
    return out


def differential_uniformity(table: Sequence[int]) -> int:
    """Largest DDT entry excluding the trivial (0,0) one. Lower is better."""
    d = ddt(table)
    size = len(table)
    return max(d[a][b] for a in range(1, size) for b in range(size))


def linearity(table: Sequence[int]) -> int:
    """2 * max |LAT| over non-trivial masks. Lower is better; 8 is optimal for 4 bits."""
    l = lat(table)
    size = len(table)
    return 2 * max(abs(l[a][b]) for a in range(size) for b in range(1, size))


def algebraic_degree(table: Sequence[int], n_bits: int) -> int:
    """Minimum algebraic degree over the output coordinate functions."""
    size = 1 << n_bits
    best = n_bits
    for bit in range(n_bits):
        coords = [(table[x] >> bit) & 1 for x in range(size)]
        # Moebius transform -> algebraic normal form
        anf = list(coords)
        step = 1
        while step < size:
            for i in range(size):
                if i & step:
                    anf[i] ^= anf[i ^ step]
            step <<= 1
        deg = max((bin(i).count("1") for i in range(size) if anf[i]), default=0)
        best = min(best, deg)
    return best


def branch_number(table: Sequence[int], n_bits: int) -> int:
    """Differential branch number: min over a != 0 of hw(a) + hw(S(x)^S(x^a))."""
    size = 1 << n_bits
    best = 2 * n_bits
    for a in range(1, size):
        for x in range(size):
            b = table[x] ^ table[x ^ a]
            best = min(best, bin(a).count("1") + bin(b).count("1"))
    return best


def fixed_points(table: Sequence[int]) -> int:
    return sum(1 for x, y in enumerate(table) if x == y)


def is_optimal_4bit(table: Sequence[int]) -> bool:
    """Leander-Poschmann optimality: bijective, uniformity 4, linearity 8."""
    return (
        is_permutation(table, 4)
        and differential_uniformity(table) == 4
        and linearity(table) == 8
    )


# --------------------------------------------------------------------------------------
# Differential weights for the SAT model
# --------------------------------------------------------------------------------------


class WeightModel:
    """Integer weights w = -log2(DDT[a][b] / size) for every possible transition.

    Weights are rounded *down* to the nearest integer. For an S-box whose DDT entries
    are all powers of two this is exact; otherwise the model yields a valid **lower
    bound** on the true trail weight, which is still a sound security statement (the
    real trail can only be less probable than the bound says).
    """

    def __init__(self, table: Sequence[int], n_bits: int = 4):
        self.table = list(table)
        self.n_bits = n_bits
        self.size = 1 << n_bits
        self.ddt = ddt(table)
        self.exact = True

        # transitions[(a, b)] = integer weight
        self.transitions: Dict[Tuple[int, int], int] = {}
        for a in range(self.size):
            for b in range(self.size):
                c = self.ddt[a][b]
                if c == 0:
                    continue
                p = c / self.size
                w_real = -math.log2(p)
                w = int(math.floor(w_real + 1e-9))
                if abs(w_real - w) > 1e-9:
                    self.exact = False
                self.transitions[(a, b)] = w

        self.max_weight = max(self.transitions.values())
        self.weights_used = sorted(set(self.transitions.values()))

    def min_active_weight(self) -> int:
        """Smallest weight over transitions with a nonzero input difference."""
        return min(w for (a, _b), w in self.transitions.items() if a != 0)

    def summary(self) -> Dict[str, object]:
        return {
            "differential_uniformity": differential_uniformity(self.table),
            "linearity": linearity(self.table),
            "algebraic_degree": algebraic_degree(self.table, self.n_bits),
            "branch_number": branch_number(self.table, self.n_bits),
            "fixed_points": fixed_points(self.table),
            "max_weight": self.max_weight,
            "min_active_weight": self.min_active_weight(),
            "weights_used": self.weights_used,
            "exact_weights": self.exact,
        }
