#!/usr/bin/env python3
"""Generate the long-message known-answer files for ChaCha20 and Ascon-AEAD128.

The short vectors come from the standards themselves (RFC 8439 for ChaCha20, the
NIST SP 800-232 LWC KAT file shipped with ascon-c for Ascon). Those stop at 32
bytes of plaintext, which never reaches the multi-block, multi-lane and tail code
of an optimised implementation. These files fill that gap, produced by two
oracles that share no code with anything under test:

  ChaCha20       -- the `cryptography` package (OpenSSL's EVP ChaCha20)
  Ascon-AEAD128  -- pyascon, the designers' Python implementation

Plaintext and associated data are not stored: they are a deterministic function
of (seed, length) that tests/kat_common.h reproduces byte for byte, so a 64 KiB
vector costs one line. Ciphertext is stored in full up to 512 bytes and as a
64-bit FNV-1a digest beyond that; the Ascon tag is always stored in full.

Usage: python3 chacha_ascon/tools/gen_kats.py   (writes chacha_ascon/kat/*.txt)
"""
import importlib.util
import os
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PYASCON = os.path.join(ROOT, "..", "third_party", "ext", "pyascon", "ascon.py")

FULL_HEX_MAX = 512


def gen_bytes(seed: int, n: int) -> bytes:
    """xorshift32 byte stream; mirrored by kat_bytes() in tests/kat_common.h."""
    x = (seed * 0x9E3779B9 + 0x7F4A7C15) & 0xFFFFFFFF or 1
    out = bytearray(n)
    for i in range(n):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        out[i] = x & 0xFF
    return bytes(out)


def fnv1a64(b: bytes) -> int:
    h = 0xCBF29CE484222325
    for c in b:
        h ^= c
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def ct_field(ct: bytes) -> str:
    if len(ct) <= FULL_HEX_MAX:
        return "CT = " + ct.hex().upper()
    return "CTFNV = %016X" % fnv1a64(ct)


# Lengths that exercise every boundary the implementations have: 0, one byte, the
# block / rate edges (16 for Ascon, 64 for ChaCha, 256/512 for 4- and 8-lane
# ChaCha, 1024 for a 16-lane group), a few odd sizes, and the benchmark frames.
LENGTHS = sorted(set(
    list(range(0, 70)) + [127, 128, 129, 191, 192, 193, 255, 256, 257, 383, 384,
                          385, 511, 512, 513, 640, 767, 768, 769, 1023, 1024, 1025,
                          2047, 2048, 2049, 3000, 4095, 4096, 4097, 8192, 16384,
                          65535, 65536]))


def chacha_kats(path):
    rng = random.Random(8439)
    lines = ["# ChaCha20 (RFC 8439: 256-bit key, 96-bit nonce, 32-bit block counter).",
             "# Oracle: python cryptography %s (OpenSSL EVP)." % __import__("cryptography").__version__,
             "# PT = kat_bytes(Seed, Len); see chacha_ascon/tools/gen_kats.py.", ""]
    count = 0
    for n in LENGTHS:
        for rep in range(2):
            count += 1
            key = bytes(rng.getrandbits(8) for _ in range(32))
            nonce = bytes(rng.getrandbits(8) for _ in range(12))
            # counters near the top of the 32-bit range check that no implementation
            # carries the block counter into the nonce word or uses 64-bit counters,
            # while staying clear of the wrap the RFC forbids.
            if rep == 0:
                ctr = rng.choice([0, 1, 7])
            else:
                nblk = (n + 63) // 64
                ctr = 0xFFFFFFFF - nblk - rng.randrange(0, 4)
                ctr = max(ctr, 0)
            seed = rng.getrandbits(31)
            pt = gen_bytes(seed, n)
            enc = Cipher(algorithms.ChaCha20(key, ctr.to_bytes(4, "little") + nonce), mode=None).encryptor()
            ct = enc.update(pt) + enc.finalize()
            lines += ["Count = %d" % count, "Key = " + key.hex().upper(),
                      "Nonce = " + nonce.hex().upper(), "Counter = %d" % ctr,
                      "Seed = %d" % seed, "Len = %d" % n, ct_field(ct), ""]
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return count


def ascon_kats(path):
    spec = importlib.util.spec_from_file_location("pyascon_oracle", PYASCON)
    ascon = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ascon)
    rng = random.Random(800232)
    lines = ["# Ascon-AEAD128 (NIST SP 800-232), long-message vectors.",
             "# Oracle: pyascon (third_party/ext/pyascon, pinned in tools/fetch_ext.sh).",
             "# PT = kat_bytes(Seed, Len), AD = kat_bytes(Seed ^ 0x5A5A5A5A, ADLen).", ""]
    count = 0
    for n in LENGTHS:
        for adlen in ([0, 1, 16, 33] if n < 70 else [0, 15]):
            count += 1
            key = bytes(rng.getrandbits(8) for _ in range(16))
            nonce = bytes(rng.getrandbits(8) for _ in range(16))
            seed = rng.getrandbits(31)
            pt = gen_bytes(seed, n)
            ad = gen_bytes(seed ^ 0x5A5A5A5A, adlen)
            out = ascon.ascon_encrypt(key, nonce, ad, pt, "Ascon-AEAD128")
            ct, tag = out[:-16], out[-16:]
            assert ascon.ascon_decrypt(key, nonce, ad, out, "Ascon-AEAD128") == pt
            lines += ["Count = %d" % count, "Key = " + key.hex().upper(),
                      "Nonce = " + nonce.hex().upper(), "Seed = %d" % seed,
                      "Len = %d" % n, "ADLen = %d" % adlen, ct_field(ct),
                      "Tag = " + tag.hex().upper(), ""]
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return count


if __name__ == "__main__":
    os.makedirs(os.path.join(ROOT, "kat"), exist_ok=True)
    n1 = chacha_kats(os.path.join(ROOT, "kat", "chacha20_long.txt"))
    n2 = ascon_kats(os.path.join(ROOT, "kat", "ascon_aead128_long.txt"))
    print("chacha20: %d vectors, ascon: %d vectors" % (n1, n2))
