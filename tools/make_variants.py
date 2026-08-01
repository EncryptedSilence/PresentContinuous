#!/usr/bin/env python3
"""Generate the variant JSON files in ``variants/``.

Everything except the original PRESENT S-box is *derived* or *searched for*, so the
definitions can be regenerated and audited rather than trusted. Randomised searches
use a fixed seed and a PRNG defined in this file, so output is reproducible across
Python versions.

Usage:  python3 tools/make_variants.py [--force]
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "analysis"))

from present_sat import sbox as sboxlib  # noqa: E402
from present_sat.variants import Variant, dump_variant, present_pbox  # noqa: E402

# The original PRESENT S-box (Bogdanov et al., CHES 2007), the one hardcoded constant
# in this project. Every other table is computed.
PRESENT_SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

SEED = 0x9E3779B97F4A7C15


class XorShift64:
    """Reproducible PRNG, independent of the Python version."""

    def __init__(self, seed: int):
        self.s = seed & 0xFFFFFFFFFFFFFFFF or 1

    def next(self) -> int:
        s = self.s
        s ^= (s << 13) & 0xFFFFFFFFFFFFFFFF
        s ^= s >> 7
        s ^= (s << 17) & 0xFFFFFFFFFFFFFFFF
        self.s = s
        return s

    def below(self, n: int) -> int:
        return self.next() % n

    def permutation(self, n: int) -> list[int]:
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.below(i + 1)
            p[i], p[j] = p[j], p[i]
        return p


def ddt_values_are_powers_of_two(table) -> bool:
    d = sboxlib.ddt(table)
    for a in range(1, 16):
        for b in range(16):
            c = d[a][b]
            if c and (c & (c - 1)):
                return False
    return True


def sbox_profile(table) -> tuple:
    return (
        sboxlib.differential_uniformity(table),
        sboxlib.linearity(table),
        sboxlib.algebraic_degree(table, 4),
        sboxlib.branch_number(table, 4),
    )


def search_sboxes(rng: XorShift64, want, max_tries: int = 4_000_000):
    """Find one S-box per requested (uniformity, linearity) target with a distinct profile.

    Returns a dict target -> list of tables, ordered by discovery.
    """
    found: dict[tuple, list[list[int]]] = {t: [] for t in want}
    seen_profiles: set[tuple] = {sbox_profile(PRESENT_SBOX)}
    remaining = {t: want[t] for t in want}

    for _ in range(max_tries):
        if not any(remaining.values()):
            break
        table = rng.permutation(16)
        du = sboxlib.differential_uniformity(table)
        lin = sboxlib.linearity(table)
        target = (du, lin)
        if target not in remaining or remaining[target] <= 0:
            continue
        if not ddt_values_are_powers_of_two(table):
            continue
        prof = sbox_profile(table)
        if prof in seen_profiles:
            continue
        seen_profiles.add(prof)
        found[target].append(table)
        remaining[target] -= 1
    return found


def build_variants():
    rng = XorShift64(SEED)
    P = present_pbox()
    out: list[Variant] = []

    out.append(Variant(
        name="present-80",
        description="Original PRESENT-80 (Bogdanov et al., CHES 2007). Reference variant.",
        sbox=PRESENT_SBOX, pbox=P, rounds=31, key_bits=80, key_schedule="present80",
    ))
    out.append(Variant(
        name="present-128",
        description="Original PRESENT-128: same round function, 128-bit key schedule.",
        sbox=PRESENT_SBOX, pbox=P, rounds=31, key_bits=128, key_schedule="present128",
    ))
    out.append(Variant(
        name="present-80-r16",
        description="PRESENT-80 reduced to 16 rounds. Round-count axis.",
        sbox=PRESENT_SBOX, pbox=P, rounds=16, key_bits=80, key_schedule="present80",
    ))

    # --- permutation-layer axis -------------------------------------------------
    out.append(Variant(
        name="present-80-identity-p",
        description=(
            "pLayer replaced by the identity: no diffusion between S-boxes at all. "
            "Deliberately broken; used to confirm the analysis detects weakness."
        ),
        sbox=PRESENT_SBOX, pbox=list(range(64)), rounds=31, key_bits=80,
        key_schedule="present80",
    ))
    out.append(Variant(
        name="present-80-rotate-p",
        description=(
            "pLayer replaced by a rotation of the state by one bit. Diffusion stays "
            "local: each S-box feeds only its neighbours."
        ),
        sbox=PRESENT_SBOX, pbox=[(i + 1) % 64 for i in range(64)], rounds=31,
        key_bits=80, key_schedule="present80",
    ))
    out.append(Variant(
        name="present-80-randperm-p",
        description=(
            "pLayer replaced by a pseudorandom bit permutation (seeded, reproducible). "
            "Tests whether PRESENT's designed pLayer beats an arbitrary one."
        ),
        sbox=PRESENT_SBOX, pbox=rng.permutation(64), rounds=31, key_bits=80,
        key_schedule="present80",
    ))

    # --- S-box axis -------------------------------------------------------------
    # Two optimal replacements (differential uniformity 4, linearity 8 -- the
    # Leander-Poschmann criteria that PRESENT's own S-box satisfies) and one
    # deliberately weaker S-box with differential uniformity 8.
    found = search_sboxes(rng, want={(4, 8): 2, (8, 8): 1, (8, 16): 1})

    for idx, table in enumerate(found[(4, 8)]):
        out.append(Variant(
            name=f"present-80-sbox-opt{idx + 1}",
            description=(
                "PRESENT-80 with an alternative optimal 4-bit S-box "
                "(differential uniformity 4, linearity 8), found by seeded search."
            ),
            sbox=table, pbox=P, rounds=31, key_bits=80, key_schedule="present80",
        ))
    for idx, table in enumerate(found[(8, 8)] + found[(8, 16)]):
        out.append(Variant(
            name=f"present-80-sbox-weak{idx + 1}",
            description=(
                "PRESENT-80 with a deliberately weaker S-box (differential uniformity 8), "
                "so a single active S-box can cost as little as one bit of probability."
            ),
            sbox=table, pbox=P, rounds=31, key_bits=80, key_schedule="present80",
        ))

    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--force", action="store_true", help="overwrite existing files")
    args = ap.parse_args()

    variants = build_variants()
    for v in variants:
        v.validate()
        path = dump_variant(v)
        props = v.weights.summary()
        print(
            f"{v.name:28s} rounds={v.rounds:2d} key={v.key_bits:3d} "
            f"du={props['differential_uniformity']:2d} lin={props['linearity']:2d} "
            f"deg={props['algebraic_degree']} bn={props['branch_number']} "
            f"w={props['weights_used']} -> {os.path.relpath(path)}"
        )
    print(f"\n{len(variants)} variants written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
