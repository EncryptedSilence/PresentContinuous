"""Straight-line programs for the lin444 layer, and what they cost.

Written out plainly each of the four output words is a four-term XOR, so the layer
costs 12 word-XORs -- 3 per state bit, 192 per round in a bitsliced backend. Two
lines can share a subexpression whenever the *same pair of operands* occurs in both
at the same relative rotation, and each such sharing saves one word-XOR.

This module enumerates every sharing rather than pattern-matching a few by hand,
which matters: the rule this replaces recognised only arithmetic progressions and
so priced 480 of the 4096 triples too high, hiding the cheapest usable family
entirely. Writing the operand pairs out for the forward direction,

    o0 : d0  R(d1,a)  R(d2,b)  R(d3,c)
    o1 : d1  R(d2,a)  R(d3,b)  R(o0,c)
    o2 : d2  R(d3,a)  R(o0,b)  R(o1,c)
    o3 : d3  R(o0,a)  R(o1,b)  R(o2,c)

three independent conditions each buy a sharing, and they overlap only in the
geometric family c = (a,2a,3a):

    c == a+b        (d1,d3) serves o0,o1;  (d2,o0) serves o1,o2;  (d3,o1) serves o2,o3
                    -> three sharings, 9 word-XORs, 144 per round
    b == 2a         (d1,d2) serves o0,o1;  (d3,o0) serves o2,o3
                    -> two sharings, 10 word-XORs, 160
    c-b == b-a      (d2,d3) serves o0,o1;  (o0,o1) serves o2,o3
                    -> two sharings, 10 word-XORs, 160
    otherwise       no pair repeats, 12 word-XORs, 192

The search below is restricted to temporaries that are a *pair* of operands. The
geometric family admits a nested form reaching 8 word-XORs (128 per round) by
reusing whole chains -- see TestXorCost._geo_form in the analysis tests -- which
this generator does not find. That costs nothing in practice: every triple in that
family diffuses badly, so none is a usable choice.

The program is emitted as a small IR so that tools/gen_c.py can turn it into C. The
cost model and the compiled layer therefore cannot disagree, and simulate() checks
any program against the definition in linear.py before it is used.
"""

from __future__ import annotations

import itertools
from typing import Dict, List, Sequence, Tuple

from . import linear

# An atom is where a value lives: ('in', w), ('out', w) or ('tmp', name).
# A term is (atom, rotation). A statement is (target_atom, [term, ...]).
Atom = Tuple[str, object]
Term = Tuple[Atom, int]
Stmt = Tuple[Atom, List[Term]]

NWORDS = linear.NWORDS


def lines_forward(c0: Sequence[int], word_bits: int = 16) -> List[Stmt]:
    """The four assignments of lin444, in the order they must be computed."""
    a, b, c = (int(x) % word_bits for x in c0)
    seq: List[Atom] = [("in", w) for w in range(NWORDS)] + [("out", w) for w in range(NWORDS)]
    return [(seq[i + NWORDS],
             [(seq[i], 0), (seq[i + 1], a), (seq[i + 2], b), (seq[i + 3], c)])
            for i in range(NWORDS)]


def lines_inverse(c0: Sequence[int], word_bits: int = 16) -> List[Stmt]:
    """The same four assignments undone bottom-up; ``in`` is the layer's output."""
    a, b, c = (int(x) % word_bits for x in c0)
    I = lambda w: ("in", w)      # noqa: E731
    O = lambda w: ("out", w)     # noqa: E731
    return [(O(3), [(I(3), 0), (I(0), a), (I(1), b), (I(2), c)]),
            (O(2), [(I(2), 0), (O(3), a), (I(0), b), (I(1), c)]),
            (O(1), [(I(1), 0), (O(2), a), (O(3), b), (I(0), c)]),
            (O(0), [(I(0), 0), (O(1), a), (O(2), b), (O(3), c)])]


def _shared_pairs(lines: List[Stmt], word_bits: int) -> Dict[tuple, Dict[int, tuple]]:
    """(A, B, d) -> {line index: (base rotation, covered term indices)}.

    The temporary is ``A ^ ROTL(B, d)``; line *i* uses it rotated by its base.
    Only pairs occurring in two or more lines can pay for themselves.
    """
    cand: Dict[tuple, Dict[int, tuple]] = {}
    for li, (_, terms) in enumerate(lines):
        for i, j in itertools.combinations(range(len(terms)), 2):
            (a_atom, p), (b_atom, q) = terms[i], terms[j]
            if b_atom < a_atom:
                a_atom, p, b_atom, q = b_atom, q, a_atom, p
            cand.setdefault((a_atom, b_atom, (q - p) % word_bits), {})[li] = (p, frozenset((i, j)))
    return {k: v for k, v in cand.items() if len(v) >= 2}


def build(lines: List[Stmt], word_bits: int = 16,
          max_temps: int = 99) -> Tuple[int, List[Stmt]]:
    """Cheapest pair-sharing program for ``lines``: (word-XOR count, statements).

    ``max_temps`` caps how many shared temporaries may be introduced. It exists
    because fewer XORs is not the same as less work -- a temporary is ``word_bits``
    values that cannot stay in registers, so it trades ``word_bits`` XORs for
    ``word_bits`` stores -- but measurement says the cap does not pay on AVX2, so
    nothing ships with it set. tools/gen_c.py has the numbers.
    """
    shared = _shared_pairs(lines, word_bits)

    per_line = []
    for li in range(len(lines)):
        usable = [(k, *shared[k][li]) for k in sorted(shared) if li in shared[k]]
        opts: List[tuple] = [()]
        opts += [(x,) for x in usable]
        opts += [(x, y) for x, y in itertools.combinations(usable, 2) if not (x[2] & y[2])]
        per_line.append(opts)

    best_cost, best_sel = None, None
    for sel in itertools.product(*per_line):
        used = {x[0] for opt in sel for x in opt}
        if len(used) > max_temps:
            continue
        cost = len(used) + sum(len(lines[i][1]) - 1 - len(opt) for i, opt in enumerate(sel))
        if best_cost is None or cost < best_cost:
            best_cost, best_sel = cost, sel

    # Emit each temporary just before the first line that uses it: its own operands
    # are then certainly defined, because they are operands of that line.
    first_use: Dict[tuple, int] = {}
    for li, opt in enumerate(best_sel):
        for (key, _base, _cov) in opt:
            first_use.setdefault(key, li)

    prog: List[Stmt] = []
    names = {key: f"t{n}" for n, key in enumerate(sorted(first_use, key=lambda k: first_use[k]))}
    for li, (target, terms) in enumerate(lines):
        for key in sorted(first_use, key=lambda k: (first_use[k], names[k])):
            if first_use[key] == li:
                a_atom, b_atom, d = key
                prog.append((("tmp", names[key]), [(a_atom, 0), (b_atom, d)]))
        covered: set = set()
        acc: List[Term] = []
        for (key, base, cov) in best_sel[li]:
            acc.append((("tmp", names[key]), base))
            covered |= cov
        acc += [t for i, t in enumerate(terms) if i not in covered]
        prog.append((target, acc))
    return best_cost, prog


def simulate(prog: List[Stmt], state: int, word_bits: int = 16) -> int:
    """Run an IR program on a 64-bit state, so a claimed cost can be checked."""
    val: Dict[Atom, int] = {("in", w): (state >> (word_bits * w)) & ((1 << word_bits) - 1)
                            for w in range(NWORDS)}
    for target, terms in prog:
        acc = 0
        for atom, rot in terms:
            acc ^= linear._rotl(val[atom], rot, word_bits)
        val[target] = acc
    return sum(val[("out", w)] << (word_bits * w) for w in range(NWORDS))


def verify(prog: List[Stmt], fn, c0: Sequence[int], word_bits: int = 16) -> None:
    """A linear map is determined by its columns, so the basis settles it."""
    for i in range(linear.BLOCK_BITS):
        got = simulate(prog, 1 << i, word_bits)
        want = fn(1 << i, c0, word_bits)
        if got != want:
            raise AssertionError(
                f"lin444 c0={tuple(c0)} program is wrong at basis vector {i}: "
                f"{got:#018x} != {want:#018x}")


def form(c0: Sequence[int], word_bits: int = 16) -> str:
    """Which sharing applies to encryption. Families overlap only at (a,2a,3a)."""
    a, b, c = (int(x) % word_bits for x in c0)
    if c == (a + b) % word_bits:
        return "sum"
    if b == (2 * a) % word_bits:
        return "b2a"
    if (c - b) % word_bits == (b - a) % word_bits:
        return "ap"
    return "gen"


def inv_form(c0: Sequence[int], word_bits: int = 16) -> str:
    """The same question for decryption.

    The inverse reads the chain from the other end -- d3 is recovered first, from
    o0..o2 -- which exchanges the roles of the first and last rotation. So the
    conditions are the mirror image: ``a == b+c`` where the forward wants
    ``c == a+b``, and ``b == 2c`` where it wants ``b == 2a``. The progression
    condition is symmetric under a <-> c and therefore serves both directions.

    A triple is normally cheap in one direction only. That is not a defect: the
    cheap encryption forms exist because the chain reuses values it has already
    produced, and running it backwards reuses a different set.
    """
    a, b, c = (int(x) % word_bits for x in c0)
    if a == (b + c) % word_bits:
        return "sum"
    if b == (2 * c) % word_bits:
        return "b2c"
    if (c - b) % word_bits == (b - a) % word_bits:
        return "ap"
    return "gen"


FORM_XORS = {"sum": 9, "b2a": 10, "b2c": 10, "ap": 10, "gen": 12}


def cost(c0: Sequence[int], word_bits: int = 16) -> int:
    """Bitsliced XOR count per round for encryption, as this project compiles it."""
    return FORM_XORS[form(c0, word_bits)] * word_bits


def inv_cost(c0: Sequence[int], word_bits: int = 16) -> int:
    """Bitsliced XOR count per round for decryption."""
    return FORM_XORS[inv_form(c0, word_bits)] * word_bits


def programs(c0: Sequence[int], word_bits: int = 16, max_temps: int = 99):
    """((forward, its XORs), (inverse, its XORs)), verified against linear.py.

    With no cap the XOR counts must match the closed forms in form()/inv_form();
    that equality is the check that the two descriptions of the layer agree.
    """
    n_fwd, fwd = build(lines_forward(c0, word_bits), word_bits, max_temps)
    n_inv, inv = build(lines_inverse(c0, word_bits), word_bits, max_temps)
    verify(fwd, linear.lin444, c0, word_bits)
    verify(inv, linear.lin444_inv, c0, word_bits)
    if max_temps >= 3:
        for got, want, why in ((n_fwd, cost(c0, word_bits), "form"),
                               (n_inv, inv_cost(c0, word_bits), "inv_form")):
            if got * word_bits != want:
                raise AssertionError(
                    f"lin444 c0={tuple(c0)}: {why}() says {want} XORs "
                    f"but the search found {got * word_bits}")
    return (fwd, n_fwd * word_bits), (inv, n_inv * word_bits)
