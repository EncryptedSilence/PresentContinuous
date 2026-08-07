#!/usr/bin/env python3
"""Generate the Cortex-M4 known-answer vectors from the trusted host build.

Nothing on the board is timed until it has reproduced these ciphertexts. The
numbers here are therefore not allowed to come from the firmware, from a
Python reimplementation of the ciphers, or from anything else that could be
wrong in the same way the firmware is wrong. They come from the host build:

  - the five 64-bit ciphers from ``build/present-cli``, which is asked for the
    same block under the same key three times over -- ``--impl ref``,
    ``--impl table`` and ``--impl bitslice`` -- and all three must agree before
    the vector is written out;
  - the two 128-bit ciphers from ``build/m4_kat_oracle``, an argv wrapper
    around ``bench/wide_ciphers.h``'s ``aes_encrypt1`` and ``lin_encrypt_ref``;
  - with ``build/wide_bench`` run first as the attestation for the latter: it
    checks the host AES against the FIPS-197 C.1 vector and cross-checks every
    other 128-bit kernel against the scalar reference, and exits nonzero if any
    of that fails.

The seven ciphers and their round counts come from ``tools/cipher_set.py``. They
are never restated here: an M4 row and an FPGA row must name the same cipher at
the same round count, and one definition is what guarantees that.

Usage:  tools/gen_m4_kats.py [--out fw/m4/gen/kat_vectors.h]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

from cipher_set import is_wide, resolve  # noqa: E402

BUILD = os.path.join(ROOT, "build")
PRESENT_CLI = os.path.join(BUILD, "present-cli")
WIDE_ORACLE = os.path.join(BUILD, "m4_kat_oracle")
WIDE_BENCH = os.path.join(BUILD, "wide_bench")

DEFAULT_OUT = os.path.join(ROOT, "fw", "m4", "gen", "kat_vectors.h")

# One fixed key for every cipher. Also AES-128's FIPS-197 C.1 key, which is what
# lets the sanity check below compare the host AES against the published vector
# using the very same oracle binary that produces the KATs.
KAT_KEY = bytes(range(16))

# Fixed plaintexts, in the style of PRESENT_KATS at tools/gen_fpga.py:37 --
# all-zero, all-ones, and two structured values. The 128-bit ciphers get the
# same four values left-padded with zeros, so a reader can line the two block
# widths up by eye.
PLAINTEXTS_64 = [
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x0123456789ABCDEF,
    0xFEDCBA9876543210,
]
PLAINTEXTS_128 = [
    bytes(16),
    b"\xff" * 16,
    bytes(8) + (0x0123456789ABCDEF).to_bytes(8, "big"),
    bytes(8) + (0xFEDCBA9876543210).to_bytes(8, "big"),
]

# FIPS-197 C.1: AES-128, key 000102..0f, plaintext 00112233..ff, 10 rounds.
FIPS197_C1_PT = bytes(range(0x00, 0x100, 0x11))
FIPS197_C1_CT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

GOLDEN = 0x9E3779B97F4A7C15
M64 = (1 << 64) - 1


def kat_expand_key(seed: bytes, n: int) -> bytes:
    """Derive n key bytes from the 16-byte KAT key. Mirrors kat_expand_key() in
    fw/m4/kat.c byte for byte -- the two must never diverge.

    The 64-bit ciphers need anything from 10 bytes (PRESENT-80) to 72 bytes
    (cipher-D's raw 576-bit independent round keys), and a kat_t carries only
    the 16-byte seed, so both sides derive the rest the same way. SplitMix64
    seeded from both halves of the seed: short, exactly reproducible in either
    language, and it makes every round key of an independent-schedule variant
    different, which a plain repeat-the-seed rule would not -- a bug that mixed
    two round keys up would then still produce the right ciphertext.
    """
    state = (int.from_bytes(seed[:8], "big") ^ ((int.from_bytes(seed[8:], "big") + GOLDEN) & M64)) & M64
    out = bytearray()
    while len(out) < n:
        state = (state + GOLDEN) & M64
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        z ^= z >> 31
        out += z.to_bytes(8, "big")
    return bytes(out[:n])


def need(path: str, how: str) -> None:
    if not os.path.exists(path):
        sys.exit(f"missing {os.path.relpath(path, ROOT)} -- build it first ({how})")


def variant_key_bytes(json_path: str) -> int:
    """Key bytes present_init expects, straight from the variant's own JSON."""
    import json

    with open(os.path.join(ROOT, json_path)) as fh:
        v = json.load(fh)
    if v["key_bits"] % 8:
        sys.exit(f"{json_path}: key_bits is not a whole number of bytes")
    return v["key_bits"] // 8


def cli_encrypt(variant: str, key_hex: str, block: int, impl: str) -> int:
    out = subprocess.run(
        [PRESENT_CLI, "encrypt", "--variant", variant, "--key", key_hex,
         "--block", f"{block:016x}", "--impl", impl],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0:
        sys.exit(f"present-cli failed for {variant}/{impl}: {out.stderr.strip()}")
    return int(out.stdout.strip(), 16)


def oracle_encrypt(kind: str, rounds: int, key: bytes, pt: bytes) -> bytes:
    out = subprocess.run(
        [WIDE_ORACLE, kind, str(rounds), key.hex(), pt.hex()],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0:
        sys.exit(f"m4_kat_oracle failed for {kind}: {out.stderr.strip()}")
    return bytes.fromhex(out.stdout.strip())


def attest_wide_build() -> list[str]:
    """Run build/wide_bench, which self-checks the 128-bit implementations.

    It verifies the host AES against FIPS-197 C.1 and every other 128-bit kernel
    against the scalar reference, and calls die() -- nonzero exit -- on any
    mismatch. Running it here is what makes build/m4_kat_oracle a *trusted*
    oracle rather than merely a convenient one.
    """
    out = subprocess.run([WIDE_BENCH, "--rounds", "5"],
                         capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0:
        sys.exit("wide_bench self-check failed -- the host 128-bit ciphers "
                 f"disagree, so no vector generated from them can be trusted:\n{out.stdout}\n{out.stderr}")
    lines = [ln.strip() for ln in out.stdout.splitlines() if ln.startswith("ok ")]
    if not any("FIPS-197" in ln for ln in lines):
        sys.exit("wide_bench did not report the FIPS-197 AES check; refusing to "
                 "generate AES vectors from an unattested build")
    return lines


def c_bytes(b: bytes) -> str:
    return "{ " + ", ".join(f"0x{x:02x}" for x in b) + " }"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    need(PRESENT_CLI, "make build/present-cli")
    need(WIDE_ORACLE, "make build/m4_kat_oracle")
    need(WIDE_BENCH, "make build/wide_bench")

    attestation = attest_wide_build()

    fips = oracle_encrypt("aes", 10, KAT_KEY, FIPS197_C1_PT)
    if fips != FIPS197_C1_CT:
        sys.exit(f"the oracle's AES does not reproduce FIPS-197 C.1: got {fips.hex()}")

    rows: list[str] = []
    summary: list[str] = []
    for json_path, name, rounds in resolve():
        if is_wide(json_path):
            kind = "lin" if "lin444" in name else "aes"
            key = KAT_KEY
            for pt in PLAINTEXTS_128:
                ct = oracle_encrypt(kind, rounds, key, pt)
                rows.append(f'    {{ "{name}", {rounds}, {c_bytes(KAT_KEY)},\n'
                            f'      {c_bytes(pt)},\n'
                            f'      {c_bytes(ct)}, 16 }},')
            summary.append(f"{name} r={rounds} wide/{kind}")
        else:
            variant = name  # cipher_set only overrides the names of the wide pair
            key = kat_expand_key(KAT_KEY, variant_key_bytes(json_path))
            for pt in PLAINTEXTS_64:
                cts = {impl: cli_encrypt(variant, key.hex(), pt, impl)
                       for impl in ("ref", "table", "bitslice")}
                if len(set(cts.values())) != 1:
                    sys.exit(f"{variant}: host implementations disagree on "
                             f"{pt:016x}: " + ", ".join(f"{k}={v:016x}" for k, v in cts.items()))
                ct = cts["ref"]
                rows.append(f'    {{ "{name}", {rounds}, {c_bytes(KAT_KEY)},\n'
                            f'      {c_bytes(pt.to_bytes(8, "big") + bytes(8))},\n'
                            f'      {c_bytes(ct.to_bytes(8, "big") + bytes(8))}, 8 }},')
            summary.append(f"{name} r={rounds} src/ key={len(key)}B")

    header = [
        "/* AUTO-GENERATED by tools/gen_m4_kats.py. Do not edit.",
        " *",
        " * Known-answer vectors for the Cortex-M4 benchmark's correctness gate, one",
        " * row per (cipher, plaintext). Produced by the host build -- build/present-cli",
        " * for the 64-bit ciphers (ref, table and bitslice all agreeing), and",
        " * build/m4_kat_oracle for the 128-bit pair, with build/wide_bench's",
        " * self-check as its attestation:",
        " *",
    ] + [f" *   {ln}" for ln in attestation] + [
        " *",
        " * Block conventions, both directions of the firmware's comparison:",
        " *   block_bytes == 8   pt/ct hold the 64-bit block big-endian in bytes 0..7",
        " *                      (pt[0] is bits 63..56), bytes 8..15 zero.",
        " *   block_bytes == 16  pt/ct are the 16 block bytes in order, exactly as",
        " *                      aes_encrypt1/lin_encrypt_ref read and write them.",
        " *",
        " * key is the same 16-byte seed for every cipher. The 128-bit ciphers take it",
        " * as their key directly (aes_key_schedule/lin_key_schedule). The 64-bit ones",
        " * need between 10 and 72 bytes, so they take kat_expand_key(key, n) -- see",
        " * fw/m4/kat.c, whose expansion tools/gen_m4_kats.py mirrors exactly.",
        " */",
        "#ifndef M4_KAT_VECTORS_H",
        "#define M4_KAT_VECTORS_H",
        "",
        "#include <stdint.h>",
        "",
        "typedef struct {",
        "    const char *cipher;",
        "    int rounds;",
        "    uint8_t key[16];",
        "    uint8_t pt[16];",
        "    uint8_t ct[16];",
        "    int block_bytes;    /* 8 for the src/ variants, 16 for the wide ciphers */",
        "} kat_t;",
        "",
        "static const kat_t KATS[] = {",
    ] + rows + [
        "};",
        "",
        "#define N_KATS (sizeof KATS / sizeof KATS[0])",
        "",
        "#endif /* M4_KAT_VECTORS_H */",
    ]

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        fh.write("\n".join(header) + "\n")

    print(f"gen_m4_kats: {len(rows)} vectors -> {os.path.relpath(args.out, ROOT)}")
    for line in summary:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
