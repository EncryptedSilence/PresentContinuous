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


def aes_sbox() -> list[int]:
    """The AES S-box, built from its definition rather than pasted as a table.

    FIPS-197: invert in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x11B), mapping 0 to
    itself, then apply the affine map b_i = a_i ^ a_{i+4} ^ a_{i+5} ^ a_{i+6} ^
    a_{i+7} ^ c_i with indices mod 8 and c = 0x63.

    Deriving it keeps the same rule the rest of this file follows -- only PRESENT's
    own table is a hardcoded constant -- and the known-answer check below is what
    makes the derivation trustworthy.
    """

    def mul(a: int, b: int) -> int:
        r = 0
        while b:
            if b & 1:
                r ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11B
            b >>= 1
        return r

    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if mul(a, b) == 1:
                inv[a] = b
                break

    table = []
    for x in range(256):
        a = inv[x]
        y = 0
        for i in range(8):
            bit = ((a >> i) ^ (a >> ((i + 4) % 8)) ^ (a >> ((i + 5) % 8))
                   ^ (a >> ((i + 6) % 8)) ^ (a >> ((i + 7) % 8)) ^ (0x63 >> i)) & 1
            y |= bit << i
        table.append(y)

    # Known-answer check against four published entries, including both endpoints.
    for x, want in ((0x00, 0x63), (0x01, 0x7C), (0x53, 0xED), (0xFF, 0x16)):
        if table[x] != want:
            raise AssertionError(f"AES S-box derivation is wrong at {x:#04x}")
    return table


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

    # --- linear-layer axis: not a permutation ------------------------------------
    # PRESENT's pLayer is a bit permutation. lin444 (from ShiftGen2's lin444_r1) is
    # a general GF(2)-linear XOR-and-rotate layer over four 16-bit words, so a
    # single input bit reaches 8.75 output bits on average instead of exactly one.
    # The rotation triples come from tools/shiftgen_present.c, which sweeps all
    # 16^3 candidates under the default ShiftGen2 weights (1, 2, 1, 2, 1) and also
    # reports each one's bitsliced XOR cost. (2,9,7) takes the top score; (0,1,3)
    # is 0.6% behind on score but one whole unit better on bmin, the single-bit
    # bound on the differential branch number.
    #
    # (1,15,13) was picked as the cheapest good triple under a cost rule that
    # recognised only arithmetic progressions. That rule was wrong: c2 == c0+c1
    # buys three shared subexpressions rather than two, for 144 XORs per round,
    # and it priced all 240 such triples at 192. (2,1,3) is the best of them and
    # beats (1,15,13) on every axis at once -- cheaper (144 against 160), better
    # score (12.25 against 11.66), better two-round avalanche (19.25 against
    # 17.75), same bmin. It is kept alongside rather than instead, because
    # (1,15,13) is what the old rule would have chosen and the comparison is the
    # point. See analysis/present_sat/slp.py for the enumeration.
    for c0, tag, why in (
        ([2, 9, 7], "297", "highest ShiftGen2 score (13.19); bmin 6; 192 XORs/round"),
        ([0, 1, 3], "013", "best branch number (bmin 7); score 13.11; 192 XORs/round"),
        ([1, 15, 13], "1-15-13",
         "best arithmetic-progression triple, so 160 XORs/round; bmin 7; score 11.66"),
        ([2, 1, 3], "213",
         "best triple with c2 == c0+c1, so 144 XORs/round; bmin 7; score 12.25"),
    ):
        out.append(Variant(
            name=f"present-80-lin444-{tag}",
            description=(
                f"pLayer replaced by the lin444_r1 XOR-rotate layer with c0={tuple(c0)}: "
                f"{why}. Four 16-bit words, unitriangular over GF(2) so always invertible."
            ),
            sbox=PRESENT_SBOX,
            linear={"type": "lin444", "word_bits": 16, "c0": c0},
            rounds=31, key_bits=80, key_schedule="present80",
        ))

    # Spending the margin instead of banking it. The SAT search proves 2^-64 in 9
    # rounds for (2,9,7) and 8 for (0,1,3), against 16 for PRESENT's own pLayer, so
    # at PRESENT's margin ratio of 31/16 = 1.94x these need 18 and 16 rounds. That
    # is the fair speed comparison: equal proven margin, not equal round count.
    for c0, tag, rounds in (([2, 9, 7], "297", 18), ([0, 1, 3], "013", 16)):
        out.append(Variant(
            name=f"present-80-lin444-{tag}-r{rounds}",
            description=(
                f"lin444 c0={tuple(c0)} cut to {rounds} rounds, the count at which its "
                f"proven differential margin matches full PRESENT's 1.94x. Answers "
                f"whether a stronger-but-slower layer wins once the rounds it saves "
                f"are taken into account."
            ),
            sbox=PRESENT_SBOX,
            linear={"type": "lin444", "word_bits": 16, "c0": c0},
            rounds=rounds, key_bits=80, key_schedule="present80",
        ))

    # --- equal-margin axis: one round past what the SAT search proves -----------
    # A second way to equalise the comparison, and the one docs/speed-at-equal-
    # security.md uses. Each cipher is cut to X = (fewest rounds proven to bound
    # every characteristic at 2^-64) + 1, so every variant carries exactly one
    # round of margin over the proof and none carries more. That makes cyc/B
    # directly comparable: whatever is left is the round function's own cost.
    #
    # rounds@64 is settled by analysis/prove_bound.py, one solver call per round
    # count: r-1 admits a characteristic of weight <= 63, r does not. That is tighter
    # than the window bound results/report.md reports, which multiplies an exact
    # W(r) over disjoint windows and is therefore only as good as the deepest exact
    # search -- for PRESENT-80 it says 16 where the direct answer is 15.
    #
    # present-80's own X = 16 needs no variant here: present-80-r16 already exists on
    # the round-count axis above.
    out.append(Variant(
        name="present-80-lin444-297-r8",
        description=(
            "lin444 c0=(2, 9, 7) on PRESENT's S-box, cut to 8 rounds. Its 2^-64 round "
            "count is bracketed rather than pinned -- 4 rounds admit weight 50, and "
            "W(3)=29 with W(4)>=38 compose to prove 7 rounds cost at least 2^-67 -- so "
            "8 is the pessimistic end of X, and r6/r7 are kept to show the whole range."
        ),
        sbox=PRESENT_SBOX,
        linear={"type": "lin444", "word_bits": 16, "c0": [2, 9, 7]},
        rounds=8, key_bits=80, key_schedule="present80",
    ))
    for r in (6, 7):
        out.append(Variant(
            name=f"present-80-lin444-297-r{r}",
            description=(
                f"lin444 c0=(2, 9, 7) on PRESENT's S-box, cut to {r} rounds. The "
                f"optimistic end of the equal-margin bracket; see the r8 variant."
            ),
            sbox=PRESENT_SBOX,
            linear={"type": "lin444", "word_bits": 16, "c0": [2, 9, 7]},
            rounds=r, key_bits=80, key_schedule="present80",
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

    # --- cipher-D's S-box axis ---------------------------------------------------
    # cipher-D and its lin444 rewrites live in hand-written JSON, because their
    # 8-bit S-box was supplied as a specification rather than derived. This one is
    # derived, so it belongs here: same cipher, same lin444 c0=(2,9,7) layer, same
    # 8 rounds and raw 576-bit key, with the AES S-box in place of the supplied
    # table. It matches cipher-D's own S-box on differential uniformity (4),
    # linearity (32) and algebraic degree (7), and differs on branch number
    # (2 against 3) -- so it isolates that one property.
    aes = aes_sbox()
    for rounds, tag, why in (
        (8, "", "cipher-D's own round count"),
        (5, "-r5", "cut to the point where the proven bound is still past 2^-64"),
    ):
        out.append(Variant(
            name=f"cipher-D-lin444-297-aes{tag}",
            description=(
                f"cipher-D-lin444-297 with the AES S-box (FIPS-197: inversion in "
                f"GF(2^8) mod 0x11B, then the AES affine map), {rounds} rounds -- "
                f"{why}. Same lin444 c0=(2, 9, 7) layer, same raw key. The AES S-box "
                f"has a published Boyar-Peralta circuit, 132 gates as realized over "
                f"AVX2's gate set, against the ~1100 gates this repository's BDD "
                f"synthesis finds for cipher-D's supplied table."
            ),
            sbox=aes, sbox_bits=8,
            linear={"type": "lin444", "word_bits": 16, "c0": [2, 9, 7]},
            rounds=rounds, key_bits=(rounds + 1) * 64, key_schedule="independent",
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
