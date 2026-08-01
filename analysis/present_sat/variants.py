"""Loading and validating cipher variants.

A variant is one JSON file in ``variants/``. The same file drives the C code
generator and the SAT analysis, so a variant can never mean two different things
in the speed pipeline and the strength pipeline.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from . import sbox as sboxlib

BLOCK_BITS = 64
SBOX_BITS = 4
N_SBOXES = BLOCK_BITS // SBOX_BITS

KEY_SCHEDULES = ("present80", "present128")


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def variants_dir() -> str:
    return os.path.join(repo_root(), "variants")


@dataclass
class Variant:
    name: str
    sbox: List[int]
    pbox: List[int]
    rounds: int
    key_bits: int
    key_schedule: str
    description: str = ""
    path: str = ""
    _weights: sboxlib.WeightModel | None = field(default=None, repr=False, init=False)

    # -- derived ------------------------------------------------------------------
    @property
    def sbox_inv(self) -> List[int]:
        return sboxlib.inverse(self.sbox)

    @property
    def pbox_inv(self) -> List[int]:
        return sboxlib.inverse(self.pbox)

    @property
    def weights(self) -> sboxlib.WeightModel:
        if self._weights is None:
            self._weights = sboxlib.WeightModel(self.sbox, SBOX_BITS)
        return self._weights

    def validate(self) -> None:
        why = f"variant {self.name!r}"
        if not sboxlib.is_permutation(self.sbox, SBOX_BITS):
            raise ValueError(f"{why}: sbox is not a permutation of 0..15")
        if not sboxlib.is_permutation(self.pbox, 6):
            raise ValueError(f"{why}: pbox is not a permutation of 0..63")
        if self.rounds < 1:
            raise ValueError(f"{why}: rounds must be >= 1")
        if self.key_schedule not in KEY_SCHEDULES:
            raise ValueError(
                f"{why}: key_schedule must be one of {KEY_SCHEDULES}, got {self.key_schedule!r}"
            )
        expected_bits = {"present80": 80, "present128": 128}[self.key_schedule]
        if self.key_bits != expected_bits:
            raise ValueError(
                f"{why}: key_schedule {self.key_schedule} implies key_bits={expected_bits}, "
                f"got {self.key_bits}"
            )
        # The round counter is 5 bits wide in both PRESENT key schedules.
        if self.rounds > 31:
            raise ValueError(
                f"{why}: rounds > 31 would overflow the 5-bit round counter of the "
                f"PRESENT key schedule"
            )

    def to_json(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "sbox": self.sbox,
            "pbox": self.pbox,
            "rounds": self.rounds,
            "key_bits": self.key_bits,
            "key_schedule": self.key_schedule,
        }

    def c_ident(self) -> str:
        return self.name.replace("-", "_").replace(".", "_")


def load_variant(path: str) -> Variant:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    missing = {"name", "sbox", "pbox", "rounds", "key_bits", "key_schedule"} - set(data)
    if missing:
        raise ValueError(f"{path}: missing keys {sorted(missing)}")
    v = Variant(
        name=data["name"],
        sbox=[int(x) for x in data["sbox"]],
        pbox=[int(x) for x in data["pbox"]],
        rounds=int(data["rounds"]),
        key_bits=int(data["key_bits"]),
        key_schedule=data["key_schedule"],
        description=data.get("description", ""),
        path=path,
    )
    v.validate()
    return v


def load_all(directory: str | None = None) -> List[Variant]:
    directory = directory or variants_dir()
    out = []
    for fn in sorted(os.listdir(directory)):
        if fn.endswith(".json"):
            out.append(load_variant(os.path.join(directory, fn)))
    if not out:
        raise RuntimeError(f"no variant JSON files found in {directory}")
    return out


def get(name: str, directory: str | None = None) -> Variant:
    for v in load_all(directory):
        if v.name == name:
            return v
    raise KeyError(f"unknown variant {name!r}")


def present_pbox() -> List[int]:
    """The original PRESENT bit permutation: P(i) = 16i mod 63, P(63) = 63."""
    return [(16 * i) % 63 if i != 63 else 63 for i in range(64)]


def dump_variant(v: Variant, directory: str | None = None) -> str:
    directory = directory or variants_dir()
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"{v.name}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(v.to_json(), fh, indent=2)
        fh.write("\n")
    return path
