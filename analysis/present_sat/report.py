"""Turning search results into security statements, CSV and Markdown.

The important function here is :func:`weight_lower_bound`. Given the exact optimal
trail weight for a small number of rounds, we get a *proof* about many more rounds
for free: a characteristic over ``m * r`` rounds restricts to a valid characteristic
on each of its m disjoint windows of r rounds, so its weight is at least
``m * W(r)``. That turns a search we can actually run (six, eight, ten rounds) into a
lower bound on the full-round cipher, rather than an extrapolation.
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from .variants import Variant, repo_root


@dataclass
class RoundRow:
    rounds: int
    min_active: Optional[int]
    active_status: str
    min_weight: Optional[int]
    weight_status: str
    seconds: float = 0.0
    calls: int = 0
    n_vars: int = 0
    n_clauses: int = 0


CSV_FIELDS = ["variant", "rounds", "min_active", "active_status", "min_weight",
              "weight_status", "seconds", "calls", "n_vars", "n_clauses"]


def results_dir() -> str:
    path = os.path.join(repo_root(), "results")
    os.makedirs(path, exist_ok=True)
    return path


def write_rows(variant_name: str, rows: Sequence[RoundRow]) -> str:
    path = os.path.join(results_dir(), f"{variant_name}-differential.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({
                "variant": variant_name, "rounds": r.rounds,
                "min_active": "" if r.min_active is None else r.min_active,
                "active_status": r.active_status,
                "min_weight": "" if r.min_weight is None else r.min_weight,
                "weight_status": r.weight_status,
                "seconds": f"{r.seconds:.3f}", "calls": r.calls,
                "n_vars": r.n_vars, "n_clauses": r.n_clauses,
            })
    return path


def read_rows(variant_name: str) -> List[RoundRow]:
    path = os.path.join(results_dir(), f"{variant_name}-differential.csv")
    if not os.path.exists(path):
        return []
    out = []
    with open(path, newline="", encoding="utf-8") as fh:
        for rec in csv.DictReader(fh):
            out.append(RoundRow(
                rounds=int(rec["rounds"]),
                min_active=int(rec["min_active"]) if rec["min_active"] else None,
                active_status=rec["active_status"],
                min_weight=int(rec["min_weight"]) if rec["min_weight"] else None,
                weight_status=rec["weight_status"],
                seconds=float(rec["seconds"] or 0),
                calls=int(rec["calls"] or 0),
                n_vars=int(rec["n_vars"] or 0),
                n_clauses=int(rec["n_clauses"] or 0),
            ))
    return out


def weight_lower_bound(rows: Sequence[RoundRow], target_rounds: int) -> int:
    """Best provable lower bound on the optimal trail weight over `target_rounds`.

    Uses only rows whose weight is exact: a trail over target_rounds contains
    floor(target/r) disjoint windows of r rounds, each of weight at least W(r).
    """
    best = 0
    for row in rows:
        if row.weight_status != "exact" or row.min_weight is None or row.rounds < 1:
            continue
        windows = target_rounds // row.rounds
        best = max(best, windows * row.min_weight)
    return best


def rounds_for_weight(rows: Sequence[RoundRow], target_weight: int,
                      max_rounds: int = 64) -> Optional[int]:
    """Fewest rounds for which we can *prove* the best trail costs >= target_weight."""
    for r in range(1, max_rounds + 1):
        if weight_lower_bound(rows, r) >= target_weight:
            return r
    return None


def read_speed(path: Optional[str] = None) -> Dict[str, Dict[str, float]]:
    """speed.csv -> {variant: {"impl/mode": cycles_per_byte}}"""
    path = path or os.path.join(results_dir(), "speed.csv")
    out: Dict[str, Dict[str, float]] = {}
    if not os.path.exists(path):
        return out
    with open(path, newline="", encoding="utf-8") as fh:
        for rec in csv.DictReader(fh):
            out.setdefault(rec["variant"], {})[f"{rec['impl']}/{rec['mode']}"] = \
                float(rec["cycles_per_byte"])
    return out


def read_gate_counts(path: Optional[str] = None) -> Dict[str, int]:
    """Synthesised bitslice S-box gate count per variant, from the benchmark CSV."""
    path = path or os.path.join(results_dir(), "speed.csv")
    out: Dict[str, int] = {}
    if not os.path.exists(path):
        return out
    with open(path, newline="", encoding="utf-8") as fh:
        for rec in csv.DictReader(fh):
            gates = int(rec.get("sbox_gates") or 0)
            if gates:
                out[rec["variant"]] = gates
    return out


SECURITY_TARGET = 64  # bits; a characteristic of weight >= 64 cannot be used with
                      # fewer than 2^64 pairs, i.e. more than the whole codebook


def build_report(variants: Sequence[Variant], solver_name: str = "") -> str:
    speed = read_speed()
    gate_counts = read_gate_counts()
    lines: List[str] = []
    lines.append("# PRESENT_mod results\n")
    lines.append("Speed and differential strength for every variant.\n")
    if solver_name:
        lines.append(f"SAT solver: `{solver_name}`\n")

    # ---- summary table --------------------------------------------------------
    lines.append("## Summary\n")
    lines.append(
        "`du/bn` are the S-box's differential uniformity and differential branch "
        "number (lower du is better, higher bn is better). `gates` is the size of the "
        "synthesised bitslice circuit. `cyc/B` is the table implementation's "
        "throughput figure; `bitslice` is the 64-block-parallel one. `w(r)` columns "
        "give the optimal differential characteristic weight, so probability `2^-w`, "
        "and `w/round` is that divided by the deepest round count searched. "
        "`rounds@64` is the smallest round count for which the data below *proves* "
        "every characteristic costs at least 2^-64; `margin` is the variant's actual "
        "round count divided by that.\n"
    )
    header = ("| variant | rounds | S-box du/bn | gates | cyc/B table | cyc/B bitslice | "
              "active(5) | w(5) | w(6) | w/round | best bound w(31) | rounds@64 | margin |")
    lines.append(header)
    lines.append("|" + "---|" * 13)

    for v in variants:
        rows = read_rows(v.name)
        by_round = {r.rounds: r for r in rows}
        sp = speed.get(v.name, {})
        props = v.weights.summary()

        def w(r: int) -> str:
            row = by_round.get(r)
            if not row or row.min_weight is None:
                return "-" if not row else f"≥{row.rounds}"
            return str(row.min_weight) if row.weight_status == "exact" else f"≥{row.min_weight}"

        a5 = by_round.get(5)
        a5s = "-" if not a5 or a5.min_active is None else str(a5.min_active)

        bound31 = weight_lower_bound(rows, 31)
        need = rounds_for_weight(rows, SECURITY_TARGET)
        margin = f"{v.rounds / need:.2f}x" if need else "-"

        # Asymptotic cost per round, from the deepest exact row available.
        exact = [r for r in rows if r.weight_status == "exact" and r.min_weight]
        per_round = f"{max(exact, key=lambda r: r.rounds).min_weight / max(exact, key=lambda r: r.rounds).rounds:.2f}" if exact else "-"

        lines.append(
            f"| `{v.name}` | {v.rounds} | "
            f"{props['differential_uniformity']}/{props['branch_number']} | "
            f"{gate_counts.get(v.name, '-')} | "
            f"{sp.get('table/throughput', float('nan')):.2f} | "
            f"{sp.get('bitslice/throughput', float('nan')):.2f} | "
            f"{a5s} | {w(5)} | {w(6)} | {per_round} | "
            f"{bound31 if bound31 else '-'} | {need or '-'} | {margin} |"
        )

    # ---- per-variant detail ---------------------------------------------------
    lines.append("\n## Per-variant detail\n")
    for v in variants:
        rows = read_rows(v.name)
        props = v.weights.summary()
        lines.append(f"### `{v.name}`\n")
        lines.append(f"{v.description}\n")
        lines.append(
            f"- S-box: differential uniformity {props['differential_uniformity']}, "
            f"linearity {props['linearity']}, algebraic degree "
            f"{props['algebraic_degree']}, branch number {props['branch_number']}"
        )
        lines.append(
            f"- Weight per active S-box: {props['weights_used']} "
            f"({'exact' if props['exact_weights'] else 'rounded down, bounds only'})"
        )
        bound31 = weight_lower_bound(rows, 31)
        if bound31:
            lines.append(
                f"- Provable bound: every differential characteristic over {v.rounds} "
                f"rounds has probability at most 2^-{weight_lower_bound(rows, v.rounds)}"
            )
        lines.append("")
        if rows:
            lines.append("| rounds | min active S-boxes | min weight | probability | solver s |")
            lines.append("|---|---|---|---|---|")
            for r in rows:
                act = "-" if r.min_active is None else (
                    str(r.min_active) if r.active_status == "exact" else f"≥{r.min_active}")
                wt = "-" if r.min_weight is None else (
                    str(r.min_weight) if r.weight_status == "exact" else f"≥{r.min_weight}")
                prob = f"2^-{r.min_weight}" if r.min_weight is not None else "-"
                lines.append(f"| {r.rounds} | {act} | {wt} | {prob} | {r.seconds:.2f} |")
            lines.append("")
        else:
            lines.append("_no differential results yet; run `make analysis`_\n")

    lines.append("\n## Caveats\n")
    lines.append(
        "- These are single-characteristic bounds. A differential can cluster many "
        "characteristics with the same input and output difference, making the "
        "differential more probable than the best single characteristic. Use "
        "`analysis/cli.py cluster` to measure clustering for a specific difference pair.\n"
        "- A bound on characteristic probability is not a proof of resistance to "
        "differential cryptanalysis, and says nothing about linear, algebraic, or "
        "related-key attacks.\n"
        "- Cycle counts are nominal TSC ticks, not core clock cycles; see the README.\n"
    )
    return "\n".join(lines) + "\n"


def write_report(text: str) -> str:
    path = os.path.join(results_dir(), "report.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path
