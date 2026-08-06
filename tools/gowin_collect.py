#!/usr/bin/env python3
"""Collect Gowin resource/timing reports for generated FPGA cipher cores."""

from __future__ import annotations

import argparse
import csv
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from gowin_resources import find_default_xml, parse_total_own


ROOT = Path(__file__).resolve().parents[1]


def newest(paths: list[Path]) -> Path | None:
    paths = [p for p in paths if p.is_file()]
    if not paths:
        return None
    return max(paths, key=lambda p: p.stat().st_mtime)


def xml_metrics(project_dir: Path) -> dict[str, str]:
    try:
        xml_path = find_default_xml(project_dir)
    except FileNotFoundError:
        return {"status": "missing-resource-xml"}
    root = ET.parse(xml_path).getroot()

    def pick(t_key: str, plain_key: str) -> int | None:
        value = root.attrib.get(t_key, root.attrib.get(plain_key))
        total, _ = parse_total_own(value)
        return total

    return {
        "status": "ok",
        "resource_xml": str(xml_path),
        "registers": str(pick("T_Register", "Register") or ""),
        "alus": str(pick("T_Alu", "Alu") or ""),
        "luts": str(pick("T_Lut", "Lut") or ""),
        "bsram": str(pick("T_Bsram", "Bsram") or ""),
    }


def timing_metrics(project_dir: Path) -> dict[str, str]:
    reports = list((project_dir / "impl").rglob("*timing*.rpt"))
    reports += list((project_dir / "impl").rglob("*_tr.rpt"))
    reports += list((project_dir / "impl").rglob("*_tr_content.html"))
    report = newest(reports)
    if report is None:
        return {"timing_report": "", "clock_constraint_mhz": "", "fmax_mhz": "", "wns_ns": "", "timing_met": ""}
    text = report.read_text(encoding="utf-8", errors="replace")

    constraint = ""
    fmax = ""
    m = re.search(
        r"Max_Frequency_Report.*?Total_Negative_Slack_Report",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if m:
        mhz = re.findall(r">([0-9.]+)\(MHz\)<", m.group(0))
        if len(mhz) >= 2:
            constraint, fmax = mhz[0], mhz[1]
    if not fmax:
        for pattern in (
            r"Maximum\s+Frequency[:\s]+([0-9.]+)\s*MHz",
            r"Fmax[:\s]+([0-9.]+)\s*MHz",
        ):
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                fmax = m.group(1)
                break

    wns = ""
    m = re.search(
        r"Setup_Slack_Table.*?<tr[^>]*>\s*<td>1</td>\s*<td[^>]*>([-+]?[0-9.]+)</td>",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if m:
        wns = m.group(1)
    else:
        for pattern in (
            r"\bWNS\b[^-+0-9]*([-+]?[0-9.]+)",
            r"worst\s+negative\s+slack[^-+0-9]*([-+]?[0-9.]+)",
        ):
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                wns = m.group(1)
                break

    timing_met = ""
    if re.search(r"timing\s+(?:constraints\s+)?(?:met|passed)", text, re.IGNORECASE):
        timing_met = "yes"
    elif re.search(r"timing\s+(?:constraints\s+)?(?:not\s+met|failed)", text, re.IGNORECASE):
        timing_met = "no"
    elif wns:
        try:
            timing_met = "yes" if float(wns) >= 0.0 else "no"
        except ValueError:
            pass

    return {
        "timing_report": str(report),
        "clock_constraint_mhz": constraint,
        "fmax_mhz": fmax,
        "wns_ns": wns,
        "timing_met": timing_met,
    }


def collect(gen_dir: Path) -> list[dict[str, str]]:
    modules = [line.strip() for line in (gen_dir / "modules.txt").read_text().splitlines()]
    rows = []
    for mod in modules:
        if not mod:
            continue
        project_dir = gen_dir / "gowin" / mod
        row = {"core": mod, "project_dir": str(project_dir)}
        row.update(xml_metrics(project_dir))
        row.update(timing_metrics(project_dir))
        rows.append(row)
    return rows


def write_markdown(rows: list[dict[str, str]], path: Path) -> None:
    cols = [
        "core",
        "status",
        "registers",
        "alus",
        "luts",
        "bsram",
        "clock_constraint_mhz",
        "fmax_mhz",
        "wns_ns",
        "timing_met",
    ]
    lines = ["# Gowin FPGA Report", ""]
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("| " + " | ".join("---" for _ in cols) + " |")
    for row in rows:
        lines.append("| " + " | ".join(row.get(c, "") for c in cols) + " |")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gen-dir", type=Path, default=ROOT / "fpga/generated")
    parser.add_argument("--csv", type=Path, default=ROOT / "results/fpga-gowin.csv")
    parser.add_argument("--md", type=Path, default=ROOT / "results/fpga-gowin.md")
    args = parser.parse_args()

    rows = collect(args.gen_dir)
    args.csv.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "core",
        "status",
        "registers",
        "alus",
        "luts",
        "bsram",
        "clock_constraint_mhz",
        "fmax_mhz",
        "wns_ns",
        "timing_met",
        "project_dir",
        "resource_xml",
        "timing_report",
    ]
    with args.csv.open("w", newline="", encoding="ascii") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})
    write_markdown(rows, args.md)
    print(f"wrote {args.csv}")
    print(f"wrote {args.md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
