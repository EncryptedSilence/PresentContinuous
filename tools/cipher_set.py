"""The seven ciphers under test, shared by every hardware target.

An FPGA number and a Cortex-M4 number must always name the same cipher at the
same round count. Keeping one definition here is what guarantees that; both
tools/gen_fpga.py and tools/run_m4_bench.py import it rather than restating it.
"""

import json
import os

DEFAULT_VARIANTS = [
    "variants/present-80-r16.json",
    "variants/present-80-lin444-297-r7.json",
    "variants/cipher-D.json",
    "variants/cipher-D-lin444-297-r5.json",
    "variants/cipher-D-lin444-297-aes-r5.json",
    "variants/wide/aes.json",
    "variants/wide/aes-lin444-0-8-15.json",
]

# Two variants are benchmarked at a round count their JSON does not declare.
# name in JSON -> (name to report, rounds to run)
VARIANT_OVERRIDES = {
    "aes": ("aes-r5", 5),
    "aes-lin444-0-8-15": ("aes-lin444-0-8-15-r4", 4),
}

# The 128-bit ciphers live in bench/wide_ciphers.h, not src/.
WIDE_VARIANTS = frozenset({"aes", "aes-lin444-0-8-15"})


def _name_of(json_path: str) -> str:
    return json_path.rsplit("/", 1)[-1][: -len(".json")]


def resolve() -> list[tuple[str, str, int]]:
    """Returns (json_path, reported_name, rounds) for each of the seven ciphers.

    Rounds come from VARIANT_OVERRIDES when present, otherwise from the JSON.
    """
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    out = []
    for path in DEFAULT_VARIANTS:
        base = _name_of(path)
        with open(os.path.join(root, path)) as fh:
            declared = json.load(fh)["rounds"]
        name, rounds = VARIANT_OVERRIDES.get(base, (base, declared))
        out.append((path, name, rounds))
    return out


def is_wide(json_path: str) -> bool:
    return _name_of(json_path) in WIDE_VARIANTS
