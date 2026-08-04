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

from . import linear as linlib
from . import sbox as sboxlib

BLOCK_BITS = 64
SBOX_BITS = 4                       # the default; a variant may override it
N_SBOXES = BLOCK_BITS // SBOX_BITS

# 4-bit is PRESENT's own; 8-bit is a byte-oriented variant such as cipher-D. Any
# divisor of BLOCK_BITS would work in the model, but only these two are exercised.
SBOX_WIDTHS = (4, 8)

# "independent" means the round keys are not derived from a master key at all: the
# caller supplies (rounds + 1) * 64 bits of key material and each round key is read
# off directly. That is the right model for differential analysis, where the schedule
# is invisible anyway, and it is what a design specifies when it wants the schedule
# treated as out of scope.
KEY_SCHEDULES = ("present80", "present128", "independent")


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def variants_dir() -> str:
    return os.path.join(repo_root(), "variants")


@dataclass
class Variant:
    """One cipher variant.

    The linear layer is given either as ``pbox`` (a bit permutation, PRESENT's own
    form) or as ``linear`` (a spec for a general GF(2)-linear map, see
    present_sat.linear) -- exactly one of the two. ``lin_cols``/``lin_cols_inv``
    present both cases uniformly as a 64-column matrix, which is what the C
    generator and the table build consume.
    """

    name: str
    sbox: List[int]
    rounds: int
    key_bits: int
    key_schedule: str
    pbox: List[int] | None = None
    linear: Dict[str, object] | None = None
    description: str = ""
    path: str = ""
    sbox_bits: int = SBOX_BITS
    _weights: sboxlib.WeightModel | None = field(default=None, repr=False, init=False)

    # -- derived ------------------------------------------------------------------
    @property
    def block_bits(self) -> int:
        """Block width. 64 unless the linear layer implies otherwise (AES is 128).

        The C pipeline is 64-bit throughout, so a wider variant is analysis-only and
        lives in a subdirectory of variants/ that load_all() does not walk into. The
        SAT model, which is the only consumer that has to be width-agnostic, reads
        this rather than the module constant.
        """
        if self.linear is None:
            return BLOCK_BITS
        return linlib.spec_block_bits(self.linear)

    @property
    def n_sboxes(self) -> int:
        return self.block_bits // self.sbox_bits

    @property
    def sbox_mask(self) -> int:
        return (1 << self.sbox_bits) - 1

    @property
    def sbox_inv(self) -> List[int]:
        return sboxlib.inverse(self.sbox)

    @property
    def pbox_inv(self) -> List[int]:
        if self.pbox is None:
            raise ValueError(f"variant {self.name!r} has no pbox; it uses a general linear layer")
        return sboxlib.inverse(self.pbox)

    @property
    def is_permutation_layer(self) -> bool:
        return self.linear is None

    @property
    def lin_cols(self) -> List[int]:
        """Column form of the linear layer: input bit i contributes this mask."""
        if self.linear is None:
            assert self.pbox is not None
            return [1 << self.pbox[i] for i in range(BLOCK_BITS)]
        return linlib.build(self.linear)[0]

    @property
    def lin_cols_inv(self) -> List[int]:
        if self.linear is None:
            inv = self.pbox_inv
            return [1 << inv[i] for i in range(BLOCK_BITS)]
        return linlib.build(self.linear)[1]

    @property
    def weights(self) -> sboxlib.WeightModel:
        if self._weights is None:
            self._weights = sboxlib.WeightModel(self.sbox, self.sbox_bits)
        return self._weights

    def validate(self) -> None:
        why = f"variant {self.name!r}"
        if self.sbox_bits not in SBOX_WIDTHS:
            raise ValueError(f"{why}: sbox_bits must be one of {SBOX_WIDTHS}, "
                             f"got {self.sbox_bits}")
        if len(self.sbox) != 1 << self.sbox_bits:
            raise ValueError(f"{why}: sbox_bits={self.sbox_bits} needs "
                             f"{1 << self.sbox_bits} entries, got {len(self.sbox)}")
        if not sboxlib.is_permutation(self.sbox, self.sbox_bits):
            raise ValueError(f"{why}: sbox is not a permutation of "
                             f"0..{(1 << self.sbox_bits) - 1}")
        if (self.pbox is None) == (self.linear is None):
            raise ValueError(f"{why}: give exactly one of 'pbox' and 'linear'")
        if self.pbox is not None and not sboxlib.is_permutation(self.pbox, 6):
            raise ValueError(f"{why}: pbox is not a permutation of 0..63")
        if self.linear is not None:
            linlib.validate_spec(self.linear, why)
            linlib.build(self.linear)  # also checks the inverse
        if self.rounds < 1:
            raise ValueError(f"{why}: rounds must be >= 1")
        if self.key_schedule not in KEY_SCHEDULES:
            raise ValueError(
                f"{why}: key_schedule must be one of {KEY_SCHEDULES}, got {self.key_schedule!r}"
            )
        if self.key_schedule == "independent":
            # One 64-bit round key per round, plus the final whitening key.
            expected_bits = (self.rounds + 1) * self.block_bits
        else:
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
        out: Dict[str, object] = {
            "name": self.name,
            "description": self.description,
            "sbox": self.sbox,
        }
        if self.sbox_bits != SBOX_BITS:
            out["sbox_bits"] = self.sbox_bits
        if self.pbox is not None:
            out["pbox"] = self.pbox
        else:
            out["linear"] = self.linear
        out.update({
            "rounds": self.rounds,
            "key_bits": self.key_bits,
            "key_schedule": self.key_schedule,
        })
        return out

    def c_ident(self) -> str:
        return self.name.replace("-", "_").replace(".", "_")


def load_variant(path: str) -> Variant:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    missing = {"name", "sbox", "rounds", "key_bits", "key_schedule"} - set(data)
    if missing:
        raise ValueError(f"{path}: missing keys {sorted(missing)}")
    if ("pbox" in data) == ("linear" in data):
        raise ValueError(f"{path}: give exactly one of 'pbox' and 'linear'")
    v = Variant(
        name=data["name"],
        sbox=[int(x) for x in data["sbox"]],
        pbox=[int(x) for x in data["pbox"]] if "pbox" in data else None,
        linear=data.get("linear"),
        rounds=int(data["rounds"]),
        key_bits=int(data["key_bits"]),
        key_schedule=data["key_schedule"],
        description=data.get("description", ""),
        path=path,
        sbox_bits=int(data.get("sbox_bits", SBOX_BITS)),
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
