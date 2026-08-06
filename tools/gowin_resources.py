#!/usr/bin/env python3
"""
Print Gowin synthesis resource utilization from *_syn_rsc.xml
(impl/gwsynthesis/<project>_syn_rsc.xml).

Values use Gowin's convention total(own) on T_* attributes when present.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_total_own(value: str | None) -> tuple[int | None, int | None]:
    """Parse '1875(4)' -> (1875, 4); '62' -> (62, 62)."""
    if value is None or not value.strip():
        return None, None
    s = value.strip()
    if "(" in s:
        left, _, right = s.partition("(")
        tot = int(left.strip())
        own = int(right.rstrip(")").strip())
        return tot, own
    v = int(s)
    return v, v


def fmt_cell(tot: int | None, own: int | None) -> str:
    if tot is None:
        return "-"
    if own is None or own == tot:
        return str(tot)
    return f"{tot}({own})"


def node_metrics(elem: ET.Element) -> tuple[str, str, str, str]:
    """Return formatted Reg, ALU, LUT, BSRAM cells for one element."""
    attrs = elem.attrib

    def pick_tot_own(t_key: str, plain_key: str) -> tuple[int | None, int | None]:
        if t_key in attrs:
            return parse_total_own(attrs[t_key])
        if plain_key in attrs:
            v, _ = parse_total_own(attrs[plain_key])
            return v, v
        return None, None

    r_t, r_o = pick_tot_own("T_Register", "Register")
    a_t, a_o = pick_tot_own("T_Alu", "Alu")
    l_t, l_o = pick_tot_own("T_Lut", "Lut")
    b_t, b_o = pick_tot_own("T_Bsram", "Bsram")

    return (
        fmt_cell(r_t, r_o),
        fmt_cell(a_t, a_o),
        fmt_cell(l_t, l_o),
        fmt_cell(b_t, b_o),
    )


def find_default_xml(root: Path) -> Path:
    """Newest impl/gwsynthesis/*_syn_rsc.xml under root."""
    syn_dir = root / "impl" / "gwsynthesis"
    if not syn_dir.is_dir():
        raise FileNotFoundError(f"No directory: {syn_dir}")
    candidates = sorted(
        syn_dir.glob("*_syn_rsc.xml"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise FileNotFoundError(f"No *_syn_rsc.xml under {syn_dir}")
    return candidates[0]


def walk_modules(
    elem: ET.Element,
    prefix: list[str],
    rows: list[tuple[str, str, str, str, str]],
) -> None:
    name = elem.get("name")
    if elem.tag == "Module" and name is not None:
        path = name
        child_prefix = [name]
    elif name is not None:
        path = "/".join(prefix + [name])
        child_prefix = prefix + [name]
    else:
        path = "/".join(prefix) if prefix else "(anonymous)"
        child_prefix = prefix

    r, a, l, b = node_metrics(elem)
    rows.append((path, r, a, l, b))

    for child in elem:
        if child.tag in ("Module", "SubModule"):
            walk_modules(child, child_prefix, rows)


def print_table(rows: list[tuple[str, str, str, str, str]], source: Path) -> None:
    w_path = max(len(r[0]) for r in rows) if rows else 10
    w_path = max(w_path, len("Module (hierarchy)"))
    w_cell = 14

    print(f"Source: {source.resolve()}")
    print()
    header = (
        f"{'Module (hierarchy)':<{w_path}}  "
        f"{'Reg':>{w_cell}}  "
        f"{'ALU':>{w_cell}}  "
        f"{'LUT':>{w_cell}}  "
        f"{'BSRAM':>{w_cell}}"
    )
    print(header)
    print("-" * len(header))
    for path, r, a, l, b in rows:
        print(
            f"{path:<{w_path}}  "
            f"{r:>{w_cell}}  "
            f"{a:>{w_cell}}  "
            f"{l:>{w_cell}}  "
            f"{b:>{w_cell}}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print Gowin per-module synthesis resources from *_syn_rsc.xml"
    )
    parser.add_argument(
        "xml_file",
        nargs="?",
        default=None,
        help="Path to *_syn_rsc.xml (default: newest under impl/gwsynthesis/)",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=None,
        help="Project root when resolving default XML (default: script directory)",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    root = args.project_root.resolve() if args.project_root else script_dir

    try:
        if args.xml_file:
            xml_path = Path(args.xml_file).expanduser().resolve()
        else:
            xml_path = find_default_xml(root)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not xml_path.is_file():
        print(f"Error: not a file: {xml_path}", file=sys.stderr)
        return 1

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(f"Error: invalid XML: {e}", file=sys.stderr)
        return 1

    root_el = tree.getroot()
    if root_el.tag != "Module":
        print(
            f"Error: expected root <Module>, got <{root_el.tag}>",
            file=sys.stderr,
        )
        return 1

    rows: list[tuple[str, str, str, str, str]] = []
    walk_modules(root_el, [], rows)
    print_table(rows, xml_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
