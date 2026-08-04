#!/usr/bin/env python3
"""Bitsliced circuit synthesis for a wide (8-bit) S-box.

tools/sbox_synth.c finds a *minimum* circuit for a 4-bit S-box by breadth-first search
over all 65536 truth tables of four variables. That does not scale: eight variables
give 2**256 functions, so exhaustive search is out and the result here is a heuristic,
not an optimum.

The construction is a shared reduced ordered BDD over the eight output bit functions,
turned into a multiplexer network. Each BDD node becomes one 2:1 multiplexer, which is
three gates in general -- ite(s, hi, lo) = lo ^ (s & (lo ^ hi)) -- and one gate when a
branch is constant, which happens often near the terminals. Sharing is what makes this
worth doing: the eight outputs are cofactored in the same variable order, so every
residual function they have in common is computed once. The bottom levels are shared
almost completely, because there are only so many functions of the last few variables.

Variable order matters and the search space is small enough to settle exactly: all 8!
= 40320 orders are tried and the cheapest kept, so the only heuristic left is the BDD
construction itself.

Two gate counts are reported because the backends have different instruction sets: the
u64 path has ANDN, ORN and XNOR natively, while AVX2 has only ANDN among them and pays
a second instruction for the others (vpternlogd would cover all of them, but it is
AVX-512).

    python3 tools/sbox_synth8.py --variant cipher-D
    python3 tools/sbox_synth8.py --variant cipher-D --emit c > circuit.h
"""

from __future__ import annotations

import argparse
import itertools
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analysis"))

from present_sat import variants as variants_mod  # noqa: E402

N = 8
FULL = (1 << (1 << N)) - 1          # truth table of the constant 1 over 8 variables

# Gate cost by operation, per backend. A NOT is free on neither, but u64 folds it into
# the neighbouring operation via ANDN/ORN/XNOR whereas AVX2 must materialise it.
COST = {
    "u64": {"and": 1, "or": 1, "xor": 1, "andn": 1, "orn": 1, "not": 1},
    "avx2": {"and": 1, "or": 1, "xor": 1, "andn": 1, "orn": 2, "not": 1},
}


def truth_tables(sbox, order):
    """Output bit k as a 256-bit truth table, indexed so order[0] is the top bit.

    Putting the first variable of the order in the most significant position makes
    cofactoring a shift and a mask rather than a strided bit extraction.
    """
    tts = [0] * N
    for x in range(1 << N):
        idx = 0
        for j, v in enumerate(order):
            idx |= ((x >> v) & 1) << (N - 1 - j)
        y = sbox[x]
        for k in range(N):
            if (y >> k) & 1:
                tts[k] |= 1 << idx
    return tts


def build_bdd(tts, order):
    """Shared ROBDD of the eight functions. Returns (nodes, roots).

    nodes[i] = (variable, low id, high id); ids 0 and 1 are the constant terminals and
    node ids start at 2. A node whose branches agree is not created -- that is the
    "reduced" in ROBDD, and it is where a variable the function does not depend on
    disappears.
    """
    nodes: list[tuple[int, int, int]] = []
    memo: dict[tuple[int, int], int] = {}

    def rec(depth: int, tt: int) -> int:
        m = N - depth
        full = (1 << (1 << m)) - 1
        if tt == 0:
            return 0
        if tt == full:
            return 1
        key = (depth, tt)
        hit = memo.get(key)
        if hit is not None:
            return hit
        half = 1 << (m - 1)
        low = tt & ((1 << half) - 1)
        high = tt >> half
        lo_id = rec(depth + 1, low)
        hi_id = rec(depth + 1, high)
        if lo_id == hi_id:
            memo[key] = lo_id
            return lo_id
        nodes.append((order[depth], lo_id, hi_id))
        nid = len(nodes) + 1            # 0 and 1 are the terminals
        memo[key] = nid
        return nid

    roots = [rec(0, tt) for tt in tts]
    return nodes, roots


def emit(nodes, roots, order):
    """Straight-line program for the BDD. Returns (ops, out_refs).

    An op is (dest, kind, a, b); a and b name earlier values: ("x", i) for an input,
    ("t", i) for an intermediate, ("c", 0|1) for a constant. A node with a constant
    branch collapses to a single gate, which is why the count comes out far below three
    times the node count.
    """
    ops: list[tuple] = []
    ref: dict[int, tuple] = {0: ("c", 0), 1: ("c", 1)}

    def newt():
        return ("t", len(ops))

    for i, (var, lo, hi) in enumerate(nodes):
        s = ("x", var)
        a, b = ref[lo], ref[hi]
        if a == ("c", 0) and b == ("c", 1):
            ref[i + 2] = s
            continue
        if a == ("c", 1) and b == ("c", 0):
            ops.append((newt(), "not", s, None))
        elif a == ("c", 0):
            ops.append((newt(), "and", s, b))
        elif b == ("c", 0):
            ops.append((newt(), "andn", s, a))          # ~s & lo
        elif a == ("c", 1):
            ops.append((newt(), "orn", s, b))           # ~s | hi
        elif b == ("c", 1):
            ops.append((newt(), "or", s, a))
        else:
            t1 = newt()
            ops.append((t1, "xor", a, b))
            t2 = ("t", len(ops))
            ops.append((t2, "and", s, t1))
            t3 = ("t", len(ops))
            ops.append((t3, "xor", t2, a))
        ref[i + 2] = ops[-1][0]

    return ops, [ref[r] for r in roots]


def cost(ops, backend):
    return sum(COST[backend][kind] for _, kind, _, _ in ops)


def synth(sbox, orders=None):
    """Cheapest circuit per backend over the given variable orders (all 8! by default).

    Returns {backend: (gates, order, ops, outs, n_nodes)}. Both backends are scored on
    the same BDD build because the build does not depend on the gate set -- only the
    price list does -- so one pass over the orders settles both.
    """
    best = {b: None for b in COST}
    for order in (orders if orders is not None else itertools.permutations(range(N))):
        nodes, roots = build_bdd(truth_tables(sbox, order), order)
        ops, outs = emit(nodes, roots, order)
        for backend in COST:
            c = cost(ops, backend)
            if best[backend] is None or c < best[backend][0]:
                best[backend] = (c, order, ops, outs, len(nodes))
    return best


def render_c(name, ops, outs, backend):
    ty = "__m256i" if backend == "avx2" else "uint64_t"
    lines = []
    if backend == "avx2":
        op_fmt = {
            "and": "_mm256_and_si256({a}, {b})",
            "or": "_mm256_or_si256({a}, {b})",
            "xor": "_mm256_xor_si256({a}, {b})",
            "andn": "_mm256_andnot_si256({a}, {b})",
            "orn": "_mm256_or_si256(_mm256_xor_si256({a}, ones), {b})",
            "not": "_mm256_xor_si256({a}, ones)",
        }
    else:
        op_fmt = {
            "and": "{a} & {b}", "or": "{a} | {b}", "xor": "{a} ^ {b}",
            "andn": "~{a} & {b}", "orn": "~{a} | {b}", "not": "~{a}",
        }

    def nm(r):
        kind, i = r
        return f"x{i}" if kind == "x" else (f"t[{i}]" if kind == "t" else
                                            ("zero" if i == 0 else "ones"))

    args = ", ".join(f"{ty} x{i}" for i in range(N))
    outp = ", ".join(f"{ty} *o{i}" for i in reversed(range(N)))
    lines.append(f"/* {cost(ops, backend)} gates, {len(ops)} operations. */")
    lines.append(f"static inline void present_circuit8_{backend}_{name}({outp},")
    lines.append(f"        {args})")
    lines.append("{")
    lines.append(f"    {ty} t[{len(ops)}];")
    if backend == "avx2":
        lines.append("    const __m256i ones = _mm256_set1_epi64x(-1);")
    for dest, kind, a, b in ops:
        expr = op_fmt[kind].format(a=nm(a), b=nm(b) if b else "")
        lines.append(f"    {nm(dest)} = {expr};")
    for k, r in enumerate(outs):
        lines.append(f"    *o{k} = {nm(r)};")
    lines.append("}")
    return "\n".join(lines)


def verify(sbox, ops, outs, order):
    """Replay the straight-line program on all 256 inputs, bitsliced 256 ways."""
    xs = []
    for i in range(N):
        col = 0
        for x in range(1 << N):
            if (x >> i) & 1:
                col |= 1 << x
        xs.append(col)
    vals = {("c", 0): 0, ("c", 1): FULL}
    for i in range(N):
        vals[("x", i)] = xs[i]
    for dest, kind, a, b in ops:
        va = vals[a]
        vb = vals[b] if b else 0
        if kind == "and":
            r = va & vb
        elif kind == "or":
            r = va | vb
        elif kind == "xor":
            r = va ^ vb
        elif kind == "andn":
            r = (~va) & vb & FULL
        elif kind == "orn":
            r = ((~va) | vb) & FULL
        else:
            r = (~va) & FULL
        vals[dest] = r
    for k, ref in enumerate(outs):
        got = vals[ref]
        want = 0
        for x in range(1 << N):
            if (sbox[x] >> k) & 1:
                want |= 1 << x
        if got != want:
            raise AssertionError(f"output bit {k} is wrong")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--variant", required=True)
    ap.add_argument("--inverse", action="store_true", help="synthesise the inverse S-box")
    ap.add_argument("--orders", type=int, default=0,
                    help="try only the first N variable orders (0 = all 8! = 40320)")
    ap.add_argument("--emit", choices=("c", "none"), default="none")
    args = ap.parse_args()

    v = variants_mod.get(args.variant)
    if v.sbox_bits != N:
        raise SystemExit(f"{v.name}: sbox_bits is {v.sbox_bits}, this tool is for {N}")
    sbox = v.sbox_inv if args.inverse else v.sbox

    orders = None
    if args.orders:
        orders = list(itertools.islice(itertools.permutations(range(N)), args.orders))

    results = synth(sbox, orders)
    which = "S^-1" if args.inverse else "S"
    for backend, (c, order, ops, outs, n_nodes) in results.items():
        verify(sbox, ops, outs, order)
        print(f"{v.name} {which} [{backend}]: {c} gates, {len(ops)} ops, "
              f"{n_nodes} BDD nodes, order {order}", file=sys.stderr)

    if args.emit == "c":
        name = "d_inv" if args.inverse else "d"
        for backend in ("u64", "avx2"):
            _, order, ops, outs, _ = results[backend]
            print(render_c(name, ops, outs, backend))
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
