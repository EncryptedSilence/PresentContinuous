#!/usr/bin/env python3
"""Hand-derived bitslice circuits for S-boxes that have a published one.

tools/sbox_synth8.py synthesises a circuit for *any* 8-bit S-box, by building a
shared BDD over the eight output bits. That is the right tool for a table with no
structure -- cipher-D's supplied S-box, say -- and it lands around 1100 gates.

An S-box with algebraic structure can do far better than a BDD ever will, because
the BDD only ever sees the truth table. The AES S-box is inversion in GF(2^8)
followed by an affine map, and Boyar and Peralta's circuit exploits exactly that:
it maps into a tower of subfields, inverts there, and maps back, which is a few
dozen gates rather than a thousand. No generic synthesiser recovers that from 256
table entries.

Keeping the two side by side is the point. The BDD number says what an arbitrary
8-bit S-box costs bitsliced; the published number says what a *designed* one costs.
The gap between them is the whole argument for picking a structured S-box.

Every circuit here is checked against all 256 inputs by tools/gen_c.py before it is
emitted, so a transcription error cannot reach the generated header.

Reference:
  Boyar, Peralta, "A new combinational logic minimization technique with
  applications to cryptology", SEA 2010; and the circuit distributed with it.
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

# --- the Boyar-Peralta AES S-box ------------------------------------------------
#
# Written in the source form the authors publish: U0 is the *most* significant input
# bit and S0 the most significant output bit, with an implicit inversion on S1, S2,
# S6 and S7 (the constant 0x63 of the AES affine map, minus what the linear part
# already accounts for).
#
# Three stages. The top is a linear map into the tower-field basis, the middle is the
# inversion itself and holds every AND gate, and the bottom maps back out and applies
# the affine transform. The middle's shape -- 34 ANDs, the last 18 of which multiply
# a result back against a top-stage signal -- is what a truth-table method cannot see.

_AES_TOP = """
T1 = U0 ^ U3
T2 = U0 ^ U5
T3 = U0 ^ U6
T4 = U3 ^ U5
T5 = U4 ^ U6
T6 = T1 ^ T5
T7 = U1 ^ U2
T8 = U7 ^ T6
T9 = U7 ^ T7
T10 = T6 ^ T7
T11 = U1 ^ U5
T12 = U2 ^ U5
T13 = T3 ^ T4
T14 = T6 ^ T11
T15 = T5 ^ T11
T16 = T5 ^ T12
T17 = T9 ^ T16
T18 = U3 ^ U7
T19 = T7 ^ T18
T20 = T1 ^ T19
T21 = U6 ^ U7
T22 = T7 ^ T21
T23 = T2 ^ T22
T24 = T2 ^ T10
T25 = T20 ^ T17
T26 = T3 ^ T16
T27 = T1 ^ T12
"""

_AES_MID = """
M1 = T13 & T6
M2 = T23 & T8
M3 = T14 ^ M1
M4 = T19 & U7
M5 = M4 ^ M1
M6 = T3 & T16
M7 = T22 & T9
M8 = T26 ^ M6
M9 = T20 & T17
M10 = M9 ^ M6
M11 = T1 & T15
M12 = T4 & T27
M13 = M12 ^ M11
M14 = T2 & T10
M15 = M14 ^ M11
M16 = M3 ^ M2
M17 = M5 ^ T24
M18 = M8 ^ M7
M19 = M10 ^ M15
M20 = M16 ^ M13
M21 = M17 ^ M15
M22 = M18 ^ M13
M23 = M19 ^ T25
M24 = M22 ^ M23
M25 = M22 & M20
M26 = M21 ^ M25
M27 = M20 ^ M21
M28 = M23 ^ M25
M29 = M28 & M27
M30 = M26 & M24
M31 = M20 & M23
M32 = M27 & M31
M33 = M27 ^ M25
M34 = M21 & M22
M35 = M24 & M34
M36 = M24 ^ M25
M37 = M21 ^ M29
M38 = M32 ^ M33
M39 = M23 ^ M30
M40 = M35 ^ M36
M41 = M38 ^ M40
M42 = M37 ^ M39
M43 = M37 ^ M38
M44 = M39 ^ M40
M45 = M42 ^ M41
M46 = M44 & T6
M47 = M40 & T8
M48 = M39 & U7
M49 = M43 & T16
M50 = M38 & T9
M51 = M37 & T17
M52 = M42 & T15
M53 = M45 & T27
M54 = M41 & T10
M55 = M44 & T13
M56 = M40 & T23
M57 = M39 & T19
M58 = M43 & T3
M59 = M38 & T22
M60 = M37 & T20
M61 = M42 & T1
M62 = M45 & T4
M63 = M41 & T2
"""

_AES_BOT = """
L0 = M61 ^ M62
L1 = M50 ^ M56
L2 = M46 ^ M48
L3 = M47 ^ M55
L4 = M54 ^ M58
L5 = M49 ^ M61
L6 = M62 ^ L5
L7 = M46 ^ L3
L8 = M51 ^ M59
L9 = M52 ^ M53
L10 = M53 ^ L4
L11 = M60 ^ L2
L12 = M48 ^ M51
L13 = M50 ^ L0
L14 = M52 ^ M61
L15 = M55 ^ L1
L16 = M56 ^ L0
L17 = M57 ^ L1
L18 = M58 ^ L8
L19 = M63 ^ L4
L20 = L0 ^ L1
L21 = L1 ^ L7
L22 = L3 ^ L12
L23 = L18 ^ L2
L24 = L15 ^ L9
L25 = L6 ^ L10
L26 = L7 ^ L9
L27 = L8 ^ L10
L28 = L11 ^ L14
L29 = L11 ^ L17
S0 = L6 ^ L24
S1' = L16 ^ L26
S2' = L19 ^ L28
S3 = L6 ^ L21
S4 = L20 ^ L22
S5 = L25 ^ L29
S6' = L13 ^ L27
S7' = L6 ^ L23
"""


def _parse(blocks: Sequence[str]) -> Tuple[List[tuple], List[tuple]]:
    """Turn the published listing into sbox_synth8's straight-line-program form.

    An op is (dest, kind, a, b) over refs ("x", i) for inputs and ("t", i) for
    intermediates -- the same shape tools/sbox_synth8.py emits, so render_c(),
    cost() and verify() all take this without knowing where it came from.

    The two bit orders are opposite: the listing counts U0 and S0 from the most
    significant end, this repository indexes bit i by its value 1 << i. Hence the
    7 - i on both sides.
    """
    ops: List[tuple] = []
    ref: Dict[str, tuple] = {f"U{i}": ("x", 7 - i) for i in range(8)}

    for block in blocks:
        for line in block.strip().splitlines():
            dest, rhs = (s.strip() for s in line.split("="))
            kind = "and" if "&" in rhs else "xor"
            a, b = (s.strip() for s in rhs.split("&" if kind == "and" else "^"))
            dst = ("t", len(ops))
            ops.append((dst, kind, ref[a], ref[b]))
            ref[dest] = dst

    # A trailing apostrophe marks an output the listing leaves complemented.
    outs: List[tuple] = [None] * 8
    for i in range(8):
        if f"S{i}" in ref:
            outs[7 - i] = ref[f"S{i}"]
        else:
            dst = ("t", len(ops))
            ops.append((dst, "not", ref[f"S{i}'"], None))
            outs[7 - i] = dst
    return ops, outs


def _aes_sbox_circuit() -> Tuple[List[tuple], List[tuple]]:
    return _parse((_AES_TOP, _AES_MID, _AES_BOT))


# Keyed by the S-box table itself rather than by a variant name, so any variant that
# happens to use the AES S-box picks the circuit up. Built lazily and cached, since
# most generator runs never look at it.
_BUILDERS = {"aes": _aes_sbox_circuit}
_TABLES: Dict[str, Tuple[int, ...]] = {}
_CACHE: Dict[str, Tuple[List[tuple], List[tuple]]] = {}


def _aes_table() -> Tuple[int, ...]:
    """The AES S-box, derived the same way tools/make_variants.py derives it."""

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
    out = []
    for x in range(256):
        a = inv[x]
        y = 0
        for i in range(8):
            y |= (((a >> i) ^ (a >> ((i + 4) % 8)) ^ (a >> ((i + 5) % 8))
                   ^ (a >> ((i + 6) % 8)) ^ (a >> ((i + 7) % 8)) ^ (0x63 >> i)) & 1) << i
        out.append(y)
    return tuple(out)


def lookup(table: Sequence[int]) -> Tuple[List[tuple], List[tuple], str] | None:
    """(ops, outs, name) for a table with a published circuit, else None."""
    if len(table) != 256:
        return None
    if not _TABLES:
        _TABLES["aes"] = _aes_table()
    key = tuple(table)
    for name, known in _TABLES.items():
        if key == known:
            if name not in _CACHE:
                _CACHE[name] = _BUILDERS[name]()
            ops, outs = _CACHE[name]
            return ops, outs, name
    return None
