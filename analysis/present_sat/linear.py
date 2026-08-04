"""Linear layers that are not bit permutations.

PRESENT's pLayer is a bit permutation, which is why it costs nothing to implement
and nothing to encode in CNF. This module adds the ``lin444`` family, an
XOR-and-rotate layer taken from ShiftGen2 (see ShiftGen2/ShiftGen2/main.cpp,
``lin444_r1``), so a variant can replace the pLayer with a genuinely linear -- but
not permutation -- map.

The state is read as ``NWORDS`` words of ``word_bits`` bits, little-endian in the
bit index: word *w* bit *k* is state bit ``w * word_bits + k``. With 4 x 16 that
keeps PRESENT's nibbles word-aligned (nibble *n* lives in word *n // 4*).

    o0 = d0 ^ ROTL(d1,c0) ^ ROTL(d2,c1) ^ ROTL(d3,c2)
    o1 = d1 ^ ROTL(d2,c0) ^ ROTL(d3,c1) ^ ROTL(o0,c2)
    o2 = d2 ^ ROTL(d3,c0) ^ ROTL(o0,c1) ^ ROTL(o1,c2)
    o3 = d3 ^ ROTL(o0,c0) ^ ROTL(o1,c1) ^ ROTL(o2,c2)

Each line introduces one new unknown given the ones above it, so the map is
unitriangular over GF(2) and therefore invertible for *every* choice of c0 -- no
search is needed to avoid singular constants. Undoing the lines bottom-up gives an
inverse of exactly the same cost:

    d3 = o3 ^ ROTL(o0,c0) ^ ROTL(o1,c1) ^ ROTL(o2,c2)
    d2 = o2 ^ ROTL(d3,c0) ^ ROTL(o0,c1) ^ ROTL(o1,c2)
    d1 = o1 ^ ROTL(d2,c0) ^ ROTL(d3,c1) ^ ROTL(o0,c2)
    d0 = o0 ^ ROTL(d1,c0) ^ ROTL(d2,c1) ^ ROTL(d3,c2)

Everything downstream (the table build, the reference implementation, the
consistency checks) works from the *column form*: ``columns(...)[i]`` is the
64-bit mask that input bit *i* contributes to the output, so

    L(x) = XOR of columns[i] over the set bits i of x.

A bit permutation is the special case where every column is a single bit, which is
why one code path in C covers both.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

NWORDS = 4
BLOCK_BITS = 64                     # the default block; a spec may imply a wider one

# "aes" is ShiftRows followed by MixColumns over a 128-bit state -- the whole of an
# AES round except SubBytes, which the S-box layer already applies. It is here so
# real AES can be measured against the variants in this repository on the same
# differential model, rather than by quoting its published bounds.
LIN_TYPES = ("lin444", "aes")


def spec_block_bits(spec: Dict[str, object]) -> int:
    """Block width a linear spec implies. Four words for lin444, fixed for aes."""
    if spec.get("type") == "aes":
        return 128
    return int(spec.get("word_bits", 16)) * NWORDS


def _rotl(a: int, c: int, word_bits: int) -> int:
    mask = (1 << word_bits) - 1
    c %= word_bits
    return ((a << c) | (a >> (word_bits - c))) & mask if c else a & mask


def _split(state: int, word_bits: int) -> List[int]:
    mask = (1 << word_bits) - 1
    return [(state >> (word_bits * w)) & mask for w in range(NWORDS)]


def _join(words: Sequence[int], word_bits: int) -> int:
    return sum(w << (word_bits * i) for i, w in enumerate(words))


def lin444(state: int, c0: Sequence[int], word_bits: int = 16) -> int:
    d = _split(state, word_bits)
    o = [0] * NWORDS
    o[0] = d[0] ^ _rotl(d[1], c0[0], word_bits) ^ _rotl(d[2], c0[1], word_bits) ^ _rotl(d[3], c0[2], word_bits)
    o[1] = d[1] ^ _rotl(d[2], c0[0], word_bits) ^ _rotl(d[3], c0[1], word_bits) ^ _rotl(o[0], c0[2], word_bits)
    o[2] = d[2] ^ _rotl(d[3], c0[0], word_bits) ^ _rotl(o[0], c0[1], word_bits) ^ _rotl(o[1], c0[2], word_bits)
    o[3] = d[3] ^ _rotl(o[0], c0[0], word_bits) ^ _rotl(o[1], c0[1], word_bits) ^ _rotl(o[2], c0[2], word_bits)
    return _join(o, word_bits)


def lin444_inv(state: int, c0: Sequence[int], word_bits: int = 16) -> int:
    o = _split(state, word_bits)
    d = [0] * NWORDS
    d[3] = o[3] ^ _rotl(o[0], c0[0], word_bits) ^ _rotl(o[1], c0[1], word_bits) ^ _rotl(o[2], c0[2], word_bits)
    d[2] = o[2] ^ _rotl(d[3], c0[0], word_bits) ^ _rotl(o[0], c0[1], word_bits) ^ _rotl(o[1], c0[2], word_bits)
    d[1] = o[1] ^ _rotl(d[2], c0[0], word_bits) ^ _rotl(d[3], c0[1], word_bits) ^ _rotl(o[0], c0[2], word_bits)
    d[0] = o[0] ^ _rotl(d[1], c0[0], word_bits) ^ _rotl(d[2], c0[1], word_bits) ^ _rotl(d[3], c0[2], word_bits)
    return _join(d, word_bits)


def lin444_cost(c0: Sequence[int], word_bits: int = 16) -> int:
    """Bitsliced XOR count per round for encryption, which depends on the constants.

    Delegates to slp, which enumerates every sharing instead of pattern-matching a
    few. See that module for the four families; the short version is 144 when
    c2 == c0+c1, 160 when c1 == 2*c0 or the constants are in arithmetic
    progression, and 192 otherwise. Use slp.inv_cost for decryption, which has the
    mirror-image conditions.
    """
    from . import slp
    return slp.cost(c0, word_bits)


# --- AES: ShiftRows then MixColumns ------------------------------------------------
#
# FIPS-197 numbers the state column-major: byte r + 4c is row r, column c. This model
# indexes state bit 8*i + j as bit j of byte i, so byte i is (row i mod 4, col i//4)
# and no renumbering is needed beyond that.

AES_MODULUS = 0x11B


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ AES_MODULUS) & 0xFF if a & 0x100 else a


def _gf_mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


# The MixColumns matrix, row-major. InvMixColumns is not written out: the inverse of
# the whole layer is recovered by Gaussian elimination in invert_columns(), which is
# checked against the forward map and so cannot silently disagree with it.
AES_MIX = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))


def aes_layer(state: int) -> int:
    """ShiftRows then MixColumns on a 128-bit state. SubBytes is the S-box layer."""
    b = [(state >> (8 * i)) & 0xFF for i in range(16)]
    # ShiftRows: row r rotates left by r, so (r, c) takes the byte from (r, c + r).
    sr = [0] * 16
    for c in range(4):
        for r in range(4):
            sr[r + 4 * c] = b[r + 4 * ((c + r) % 4)]
    out = [0] * 16
    for c in range(4):
        col = [sr[r + 4 * c] for r in range(4)]
        for r in range(4):
            acc = 0
            for k in range(4):
                acc ^= _gf_mul(col[k], AES_MIX[r][k])
            out[r + 4 * c] = acc
    return sum(v << (8 * i) for i, v in enumerate(out))


def columns(fn, *args, n: int = BLOCK_BITS) -> List[int]:
    """Column form of a linear map: the image of each basis vector."""
    return [fn(1 << i, *args) for i in range(n)]


def invert_columns(cols: Sequence[int], n: int) -> List[int]:
    """Inverse of a GF(2)-linear map given in column form, by Gaussian elimination.

    Used for layers with no closed-form inverse written out (AES's). lin444 supplies
    its own inverse instead, because the point there is that undoing it costs the
    same as doing it -- which an elimination would not show.
    """
    # Augment each column with the basis vector it came from, then reduce.
    rows = [(cols[i], 1 << i) for i in range(n)]
    inv = [0] * n
    pivots: Dict[int, tuple] = {}
    for vec, src in rows:
        v, s = vec, src
        while v:
            top = v.bit_length() - 1
            if top not in pivots:
                pivots[top] = (v, s)
                break
            pv, ps = pivots[top]
            v ^= pv
            s ^= ps
        else:
            raise AssertionError("linear layer is singular: a column reduced to zero")
    if len(pivots) != n:
        raise AssertionError(f"linear layer is singular: rank {len(pivots)} < {n}")
    # Back-substitute to turn the echelon form into the actual inverse.
    for i in range(n):
        v, s = 1 << i, 0
        while v:
            top = v.bit_length() - 1
            pv, ps = pivots[top]
            v ^= pv
            s ^= ps
        inv[i] = s
    return inv


def apply_columns(cols: Sequence[int], x: int) -> int:
    out = 0
    i = 0
    while x:
        if x & 1:
            out ^= cols[i]
        x >>= 1
        i += 1
    return out


def is_permutation_columns(cols: Sequence[int], n: int = BLOCK_BITS) -> bool:
    """True iff the layer is a bit permutation, i.e. every column is one bit."""
    seen = 0
    for c in cols:
        if c == 0 or (c & (c - 1)):
            return False
        seen |= c
    return seen == (1 << n) - 1


def density(cols: Sequence[int]) -> float:
    """Average number of output bits touched by one input bit."""
    return sum(bin(c).count("1") for c in cols) / float(len(cols))


def validate_spec(spec: Dict[str, object], why: str) -> None:
    if spec.get("type") not in LIN_TYPES:
        raise ValueError(f"{why}: linear.type must be one of {LIN_TYPES}, got {spec.get('type')!r}")
    if spec["type"] == "aes":
        return
    word_bits = int(spec.get("word_bits", 16))
    if word_bits * NWORDS not in (64, 128):
        raise ValueError(f"{why}: linear.word_bits={word_bits} gives a "
                         f"{word_bits * NWORDS}-bit block; only 64 and 128 are modelled")
    c0 = spec.get("c0")
    if not isinstance(c0, (list, tuple)) or len(c0) != 3:
        raise ValueError(f"{why}: linear.c0 must be three rotation constants")
    for x in c0:
        if not isinstance(x, int) or not 0 <= x < word_bits:
            raise ValueError(f"{why}: linear.c0 entries must be in 0..{word_bits - 1}, got {c0}")


def build(spec: Dict[str, object]) -> tuple[List[int], List[int]]:
    """(forward columns, inverse columns) for a validated linear spec."""
    n = spec_block_bits(spec)
    if spec["type"] == "aes":
        fwd = columns(aes_layer, n=n)
        inv = invert_columns(fwd, n)
    else:
        word_bits = int(spec.get("word_bits", 16))
        c0 = [int(x) for x in spec["c0"]]  # type: ignore[index]
        fwd = columns(lin444, c0, word_bits, n=n)
        inv = columns(lin444_inv, c0, word_bits, n=n)
    # Cheap but total: the two must compose to the identity on a basis.
    for i in range(n):
        if apply_columns(inv, fwd[i]) != (1 << i):
            raise AssertionError(f"{spec['type']} inverse is wrong at basis vector {i}")
    return fwd, inv
