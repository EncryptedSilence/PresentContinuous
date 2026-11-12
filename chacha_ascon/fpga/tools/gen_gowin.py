#!/usr/bin/env python3
"""Gowin IDE projects for the full-round cores (GW5A-25A), in the layout the project's existing
Gowin tooling expects, so the batch build and the report collector are reused unchanged:

  chacha_ascon/fpga/gen/modules.txt                  one project name per line
  chacha_ascon/fpga/gen/gowin/<name>/<name>.gprj     sources: ../../../rtl/<core>.v + rtl/tops.v
  chacha_ascon/fpga/gen/gowin/<name>/cipher_core.sdc clock constraint
  chacha_ascon/fpga/gen/gowin/<name>/build_gowin.tcl gw_sh script (top module top_<core>)

Build and collect once a license is available (from the repository root):
  GEN_DIR=chacha_ascon/fpga/gen GOWIN=... GW_SH=... fpga/build_all_gowin.sh
  python3 tools/gowin_collect.py --gen-dir chacha_ascon/fpga/gen \
      --csv chacha_ascon/results/fpga/gowin-gw5a.csv --md chacha_ascon/results/fpga/gowin-gw5a.md
The collector reports the resources of the instance named `core` (the wrappers in rtl/tops.v
name the core instance `core`) and the Fmax from the timing report.

Clock constraint: the open-source flow's median Fmax (results/fpga/oss-gw5a.csv) when that file
exists (the higher of the two yosys mappers), else 200 MHz. The Gowin Fmax figure is the post-route maximum from its timing report, so
the constraint only steers effort; rerun with --mhz name=F to tighten one core.
Usage: gen_gowin.py [--mhz aes128=250,...]"""
from __future__ import annotations

import argparse
import csv
import shutil
from pathlib import Path

FPGA = Path(__file__).resolve().parents[1]
GEN = FPGA / "gen"
OSS_CSV = FPGA.parent / "results" / "fpga" / "oss-gw5a.csv"
DEVICE, PART, DEVICE_ID = "GW5A-25A", "GW5A-LV25MG121NES", "gw5a25a-000"

# project name -> (rtl files, top module)
CORES = {
    "aes128": (["aes_ctr.v"], "top_aes128"),
    "aes256": (["aes_ctr.v"], "top_aes256"),
    "qalqan": (["qalqan_ctr.v"], "top_qalqan"),
    "chacha20": (["chacha20_ctr.v"], "top_chacha20"),
    "ascon128": (["ascon128_aead.v"], "top_ascon128"),
    "present80": (["present80_ctr.v"], "top_present80"),
}
# The Qalqan core (rtl/qalqan_ctr.v) is not distributed; skip any core whose RTL is absent.
CORES = {k: v for k, v in CORES.items() if all((FPGA / "rtl" / f).is_file() for f in v[0])}


def oss_mhz() -> dict[str, float]:
    if not OSS_CSV.is_file():
        return {}
    lines = [l for l in OSS_CSV.read_text().splitlines() if not l.startswith("#")]
    out = {}
    for r in csv.DictReader(lines):
        try:
            out[r["core"]] = max(out.get(r["core"], 0.0), float(r["fmax_mhz_median"]))
        except (KeyError, TypeError, ValueError):
            pass
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mhz", default="", help="name=MHz[,name=MHz] overrides")
    a = ap.parse_args()
    mhz = {n: 200.0 for n in CORES}
    mhz.update({k: v for k, v in oss_mhz().items() if k in CORES})
    for kv in filter(None, a.mhz.split(",")):
        k, v = kv.split("=")
        mhz[k] = float(v)
    if (GEN / "gowin").exists():
        shutil.rmtree(GEN / "gowin")
    for name, (files, top) in CORES.items():
        d = GEN / "gowin" / name
        d.mkdir(parents=True)
        (d / "cipher_core.sdc").write_text(
            f"create_clock -name clk -period {1000.0 / mhz[name]:.3f} [get_ports {{clk}}]\n", encoding="ascii")
        srcs = [f"../../../rtl/{f}" for f in files] + ["../../../rtl/tops.v"]
        gprj = ['<?xml version="1.0" encoding="UTF-8"?>', "<!DOCTYPE gowin-fpga-project>", "<Project>",
                "    <Template>FPGA</Template>", "    <Version>5</Version>",
                f'    <Device name="{DEVICE}" pn="{PART}">{DEVICE_ID}</Device>', "    <FileList>"]
        gprj += [f'        <File path="{s}" type="file.verilog" enable="1"/>' for s in srcs]
        gprj += ['        <File path="cipher_core.sdc" type="file.sdc" enable="1"/>', "    </FileList>", "</Project>"]
        (d / f"{name}.gprj").write_text("\n".join(gprj) + "\n", encoding="ascii")
        tcl = ['puts "Gowin build: starting"',
               "set project_root [file dirname [file normalize [info script]]]",
               f'set gprj [file normalize [file join $project_root "{name}.gprj"]]',
               'puts "Gowin build: open_project $gprj"', "open_project $gprj",
               # the S-box .vh files are included from rtl/
               'set_option -include_path [file normalize [file join $project_root ../../../rtl]]',
               f"set_option -top_module {top}",
               'puts "Gowin build: run all"', "run all", 'puts "Gowin build: done"']
        (d / "build_gowin.tcl").write_text("\n".join(tcl) + "\n", encoding="ascii")
        print(f"{name:<10} top {top:<14} clock {mhz[name]:.1f} MHz")
    (GEN / "modules.txt").write_text("\n".join(CORES) + "\n", encoding="ascii")
    print(f"wrote {GEN}")


if __name__ == "__main__":
    main()
