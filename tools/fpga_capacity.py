#!/usr/bin/env python3
"""Estimate Alveo V80 brute-force capacity from measured Gowin core reports."""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


ALVEO_V80 = {
    "target": "alveo-v80",
    "source": "AMD Alveo V80 product brief and Versal CLB architecture manual",
    "source_url": "https://www.amd.com/content/dam/amd/en/documents/products/accelerators/alveo/v80/alveo-v80-product-brief.pdf",
    "architecture_url": "https://docs.amd.com/r/en-US/am005-versal-clb/CLB-Resources",
    "logic": 2_600_000,
    # Versal CLBs contain two flip-flops per LUT (32 LUTs and 64 FFs per CLB).
    "registers": 5_200_000,
    # V80 has 132 Mb BRAM. Gowin T_Bsram counts 18 Kb units.
    "bsram": int(132 * 1024 / 18),
    "usable_fraction": 0.80,
}


def parse_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    return int(float(value))


def fit_count(row: dict[str, str], target: dict[str, object], fraction: float) -> tuple[int, str]:
    limits: list[tuple[str, int]] = []
    logic_used = (parse_int(row.get("luts")) or 0) + (parse_int(row.get("alus")) or 0)
    registers_used = parse_int(row.get("registers"))
    bsram_used = parse_int(row.get("bsram"))

    if logic_used and target.get("logic"):
        limits.append(("logic", int(int(target["logic"]) * fraction) // logic_used))
    if registers_used and target.get("registers"):
        limits.append(("registers", int(int(target["registers"]) * fraction) // registers_used))
    if bsram_used and target.get("bsram"):
        limits.append(("bsram", int(int(target["bsram"]) * fraction) // bsram_used))
    if not limits:
        return 0, "none"
    resource, count = min(limits, key=lambda x: x[1])
    return count, resource


def rate_for(row: dict[str, str], ii: int, cores: int) -> tuple[float, float]:
    fmax = float(row["fmax_mhz"])
    blocks_per_sec = cores * fmax * 1_000_000.0 / ii
    gbps = blocks_per_sec * 64.0 / 1_000_000_000.0
    return blocks_per_sec, gbps


def collect(report_csv: Path, core_csv: Path, target: dict[str, object]) -> list[dict[str, str]]:
    with report_csv.open(newline="", encoding="ascii") as fh:
        rows = list(csv.DictReader(fh))
    with core_csv.open(newline="", encoding="ascii") as fh:
        cores = {row["core"]: row for row in csv.DictReader(fh)}
    out: list[dict[str, str]] = []
    for row in rows:
        if row.get("status") != "ok" or row.get("timing_met") != "yes" or not row.get("fmax_mhz"):
            continue
        spec = cores.get(row["core"])
        if spec is None:
            raise KeyError(f"core metadata not found for {row['core']}")
        theoretical_cores, theoretical_limit = fit_count(row, target, 1.0)
        estimated_cores, estimated_limit = fit_count(row, target, float(target["usable_fraction"]))
        ii = int(spec["initiation_interval_cycles"])
        blocks_per_sec, gbps = rate_for(row, ii, estimated_cores)
        key_bits = int(spec["key_bits"])
        log10_years = key_bits * math.log10(2) - math.log10(blocks_per_sec) - math.log10(365.25 * 24 * 3600)
        out.append({
            "core": row["core"],
            "mode": spec["mode"],
            "rounds": spec["rounds"],
            "key_bits": str(key_bits),
            "core_registers": str(parse_int(row.get("registers")) or 0),
            "core_logic": str((parse_int(row.get("luts")) or 0) + (parse_int(row.get("alus")) or 0)),
            "core_bsram18k": str(parse_int(row.get("bsram")) or 0),
            "gowin_constraint_mhz": row.get("clock_constraint_mhz", ""),
            "gowin_postroute_fmax_mhz": row["fmax_mhz"],
            "initiation_interval_cycles": str(ii),
            "theoretical_cores": str(theoretical_cores),
            "theoretical_limit": theoretical_limit,
            "estimated_cores_80pct": str(estimated_cores),
            "estimated_limit": estimated_limit,
            "candidate_tests_per_sec": f"{blocks_per_sec:.6e}",
            "throughput_gbps": f"{gbps:.3f}",
            "full_keyspace_years": f"1e{log10_years:.2f}",
        })
    return out


def write_outputs(rows: list[dict[str, str]], csv_path: Path, md_path: Path, target: dict[str, object]) -> None:
    fields = [
        "core",
        "mode",
        "rounds",
        "key_bits",
        "core_registers",
        "core_logic",
        "core_bsram18k",
        "gowin_constraint_mhz",
        "gowin_postroute_fmax_mhz",
        "initiation_interval_cycles",
        "theoretical_cores",
        "theoretical_limit",
        "estimated_cores_80pct",
        "estimated_limit",
        "candidate_tests_per_sec",
        "throughput_gbps",
        "full_keyspace_years",
    ]
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="ascii") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    lines = ["# Alveo V80 FPGA Capacity Estimate", ""]
    lines.append(
        "Only cores meeting their Gowin post-route clock constraint are included. The V80 estimate "
        "uses Gowin post-route Fmax without an assumed frequency uplift and reserves 20% of each "
        "resource class for routing, control, clocking, and host integration."
    )
    lines.append("")
    lines.append("## Target")
    lines.append("")
    lines.append("| target | LUTs | flip-flops | BRAM 18 Kb equivalents | usable | source |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    lines.append(
        f"| {target['target']} | {target['logic']} | {target['registers']} | {target['bsram']} | "
        f"{float(target['usable_fraction']):.0%} | "
        f"[V80 product brief]({target['source_url']}), "
        f"[Versal CLB manual]({target['architecture_url']}) |"
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
    parser.add_argument("--core-csv", type=Path, default=ROOT / "fpga/generated/cores.csv")
    parser.add_argument("--csv", type=Path, default=ROOT / "results/fpga-capacity.csv")
    parser.add_argument("--md", type=Path, default=ROOT / "results/fpga-capacity.md")
    args = parser.parse_args()

    rows = collect(args.report_csv, args.core_csv, ALVEO_V80)
    write_outputs(rows, args.csv, args.md, ALVEO_V80)
    print(f"wrote {args.csv}")
    print(f"wrote {args.md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
