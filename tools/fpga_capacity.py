#!/usr/bin/env python3
"""Estimate parallel FPGA brute-force capacity from Gowin build reports."""

from __future__ import annotations

import argparse
import csv
import math
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analysis"))

from present_sat.variants import load_all  # noqa: E402


ALVEO_V80 = {
    "target": "alveo-v80",
    "source": "AMD Alveo V80 product page: 2.6M LUTs; https://www.amd.com/en/products/accelerators/alveo/v80.html",
    "logic": 2_600_000,
    "registers": None,
    "bsram": None,
}


def parse_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    return int(float(value))


def parse_kb(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    m = re.fullmatch(r"([0-9.]+)\s*Kb", value, re.IGNORECASE)
    if m:
        return int(float(m.group(1)))
    return None


def variant_key(name: str) -> tuple[str, str]:
    for suffix in ("_area", "_speed"):
        if name.endswith(suffix):
            return name[: -len(suffix)].replace("_", "-"), suffix[1:]
    raise ValueError(f"cannot infer variant/mode from core name {name!r}")


def load_rounds() -> dict[str, int]:
    return {v.name.replace("-", "_"): v.rounds for v in load_all()}


def load_biggest_gowin(gowin_root: Path) -> dict[str, object]:
    path = gowin_root / "IDE/data/device/device_info.csv"
    best: dict[str, object] | None = None
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if len(row) < 19:
                continue
            try:
                logic = int(row[11])
                registers = int(row[12])
            except ValueError:
                continue
            bsram = parse_kb(row[16]) or parse_kb(row[14]) or parse_kb(row[15])
            if best is None or logic > int(best["logic"]):
                best = {
                    "target": "gowin-largest-installed",
                    "part": row[1],
                    "device": row[3],
                    "source": str(path),
                    "logic": logic,
                    "registers": registers,
                    "bsram": bsram,
                }
    if best is None:
        raise RuntimeError(f"could not find Gowin capacities in {path}")
    return best


def fit_count(row: dict[str, str], target: dict[str, object]) -> tuple[int, str]:
    limits: list[tuple[str, int]] = []
    logic_used = (parse_int(row.get("luts")) or 0) + (parse_int(row.get("alus")) or 0)
    registers_used = parse_int(row.get("registers"))
    bsram_used = parse_int(row.get("bsram"))

    if logic_used and target.get("logic"):
        limits.append(("logic", int(target["logic"]) // logic_used))
    if registers_used and target.get("registers"):
        limits.append(("registers", int(target["registers"]) // registers_used))
    if bsram_used and target.get("bsram"):
        limits.append(("bsram", int(target["bsram"]) // bsram_used))
    if not limits:
        return 0, "none"
    resource, count = min(limits, key=lambda x: x[1])
    return count, resource


def rate_for(row: dict[str, str], rounds: int, cores: int) -> tuple[int, float, float]:
    mode = variant_key(row["core"])[1]
    ii = 1 if mode == "speed" else rounds + 2
    fmax = float(row["fmax_mhz"])
    blocks_per_sec = cores * fmax * 1_000_000.0 / ii
    gbps = blocks_per_sec * 64.0 / 1_000_000_000.0
    return ii, blocks_per_sec, gbps


def collect(report_csv: Path, targets: list[dict[str, object]]) -> list[dict[str, str]]:
    rounds_by_variant = load_rounds()
    with report_csv.open(newline="", encoding="ascii") as fh:
        rows = list(csv.DictReader(fh))
    out: list[dict[str, str]] = []
    for row in rows:
        if row.get("status") != "ok" or not row.get("fmax_mhz"):
            continue
        variant_name, mode = variant_key(row["core"])
        rounds = rounds_by_variant.get(variant_name.replace("-", "_"))
        if rounds is None:
            raise KeyError(f"round count not found for {variant_name}")
        for target in targets:
            cores, limit = fit_count(row, target)
            ii, blocks_per_sec, gbps = rate_for(row, rounds, cores)
            out.append({
                "target": str(target["target"]),
                "core": row["core"],
                "mode": mode,
                "rounds": str(rounds),
                "timing_met_at_constraint": row["timing_met"],
                "constraint_mhz": row.get("clock_constraint_mhz", ""),
                "postroute_fmax_mhz": row["fmax_mhz"],
                "initiation_interval_cycles": str(ii),
                "cores_fit": str(cores),
                "limiting_resource": limit,
                "blocks_per_sec": f"{blocks_per_sec:.3f}",
                "gbps": f"{gbps:.3f}",
            })
    return out


def write_outputs(rows: list[dict[str, str]], csv_path: Path, md_path: Path, targets: list[dict[str, object]]) -> None:
    fields = [
        "target",
        "core",
        "mode",
        "rounds",
        "timing_met_at_constraint",
        "constraint_mhz",
        "postroute_fmax_mhz",
        "initiation_interval_cycles",
        "cores_fit",
        "limiting_resource",
        "blocks_per_sec",
        "gbps",
    ]
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="ascii") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    lines = ["# FPGA Brute-Force Capacity", ""]
    lines.append(
        "All successfully routed cores are included. Throughput uses post-route `Actual Fmax`, "
        "not the nominal 100 MHz constraint. Area cores use initiation interval `rounds + 2`; "
        "speed cores use initiation interval `1`."
    )
    lines.append("")
    lines.append("## Targets")
    lines.append("")
    lines.append("| target | logic | registers | bsram | source |")
    lines.append("| --- | --- | --- | --- | --- |")
    for t in targets:
        lines.append(
            f"| {t['target']} | {t.get('logic') or ''} | {t.get('registers') or ''} | "
            f"{t.get('bsram') or ''} | {t.get('source') or ''} |"
        )
    lines.append("")
    lines.append("## Capacity")
    lines.append("")
    lines.append("| " + " | ".join(fields) + " |")
    lines.append("| " + " | ".join("---" for _ in fields) + " |")
    for row in rows:
        lines.append("| " + " | ".join(row[field] for field in fields) + " |")
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-csv", type=Path, default=ROOT / "results/fpga-gowin.csv")
    parser.add_argument("--csv", type=Path, default=ROOT / "results/fpga-capacity.csv")
    parser.add_argument("--md", type=Path, default=ROOT / "results/fpga-capacity.md")
    parser.add_argument("--gowin-root", type=Path, default=Path(os.environ.get("GOWIN", "~/gowin/Gowin_V1.9.12.02_linux")).expanduser())
    args = parser.parse_args()

    targets = [ALVEO_V80, load_biggest_gowin(args.gowin_root)]
    rows = collect(args.report_csv, targets)
    write_outputs(rows, args.csv, args.md, targets)
    print(f"wrote {args.csv}")
    print(f"wrote {args.md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
