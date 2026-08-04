"""Decoding a satisfying assignment into a readable differential characteristic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .model import MODE_WEIGHT, DifferentialModel
from .solver import Result


@dataclass
class RoundStep:
    index: int
    diff_in: int                # 64-bit difference entering the S-box layer
    active: List[int] = field(default_factory=list)   # indices of active S-boxes
    weights: List[int] = field(default_factory=list)  # weight of each active S-box


@dataclass
class Trail:
    variant: str
    rounds: int
    steps: List[RoundStep]
    diff_out: int
    total_weight: Optional[int]
    total_active: int

    @property
    def diff_in(self) -> int:
        return self.steps[0].diff_in

    def format(self) -> str:
        lines = [
            f"trail for {self.variant}, {self.rounds} rounds",
            f"  input  difference  {self.diff_in:016x}",
            f"  output difference  {self.diff_out:016x}",
            f"  active S-boxes     {self.total_active}",
        ]
        if self.total_weight is not None:
            lines.append(f"  weight             {self.total_weight}  (probability 2^-{self.total_weight})")
        lines.append("")
        lines.append("  round  difference         active S-boxes (index:weight)")
        for st in self.steps:
            detail = " ".join(
                f"{i}:{w}" for i, w in zip(st.active, st.weights)
            ) if st.weights else " ".join(str(i) for i in st.active)
            lines.append(f"  {st.index:5d}  {st.diff_in:016x}  {detail}")
        lines.append(f"  {'out':>5}  {self.diff_out:016x}")
        return "\n".join(lines)


def _word(res: Result, bits: List[int]) -> int:
    value = 0
    for i, v in enumerate(bits):
        if res.value(v):
            value |= 1 << i
    return value


def decode(model: DifferentialModel, res: Result) -> Trail:
    steps: List[RoundStep] = []
    total_weight = 0 if model.mode == MODE_WEIGHT else None
    total_active = 0

    n, mask = model.variant.sbox_bits, model.variant.sbox_mask
    for r in range(model.rounds):
        diff_in = _word(res, model.diff[r])
        step = RoundStep(index=r, diff_in=diff_in)
        for i in range(model.variant.n_sboxes):
            if (diff_in >> (n * i)) & mask == 0:
                continue
            step.active.append(i)
            total_active += 1
            if model.mode == MODE_WEIGHT:
                w = sum(1 for u in model.weight_bits[r][i] if res.value(u))
                step.weights.append(w)
                total_weight += w
        steps.append(step)

    return Trail(
        variant=model.variant.name,
        rounds=model.rounds,
        steps=steps,
        diff_out=_word(res, model.diff[model.rounds]),
        total_weight=total_weight,
        total_active=total_active,
    )
