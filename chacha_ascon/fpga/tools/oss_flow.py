#!/usr/bin/env python3
"""Open-source estimate of the full-round FPGA cores on the GW5A-25A, for while the Gowin IDE
has no license: yosys `synth_gowin -family gw5a` and nextpnr-himbaechel (Apicula chip database).

Per core:
  1. synthesis of the core module alone -> logic and register counts (the core only, without
     the pin wrapper of rtl/tops.v);
  2. synthesis of the wrapper top_<core> and place-and-route with NSEEDS placer seeds ->
     post-route Fmax from nextpnr's timing model and the device utilisation of the whole design.
Throughput = Fmax x block bits / clocks per block (the steady-state II measured in simulation).

Calibration: the same two steps on the reduced-round cores of fpga/generated/, which have real
Gowin IDE results (results/fpga-gowin.md), so the open-source numbers can be compared with the
vendor tool on the same device before any conclusion is drawn from them.

Tools (YoWASP builds, two virtualenvs because they need different wasmtime versions):
  YOSYS    ~/.local/share/fpga-oss/bin/yowasp-yosys        (yowasp-yosys 0.59, wasmtime 29)
  NEXTPNR  ~/.local/share/fpga-oss-pnr/bin/yowasp-nextpnr-himbaechel-gowin (0.11, wasmtime 47)
Pin file: the user I/O of the MBGA121N package, read from the Gowin IDE's device data
(GOWIN, default ~/gowin/Gowin_V1.9.12.02_linux; only the JSON pin table is read, no license
is needed).

Usage: oss_flow.py [--jobs N] [--seeds N] [--only NAME[,NAME]] [--no-calib] [--mappers abc9,abc]
(--only merges into the existing CSV, replacing only the rows it reruns)"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

FPGA = Path(__file__).resolve().parents[1]          # chacha_ascon/fpga
CA = FPGA.parent                                    # chacha_ascon
ROOT = CA.parent                                    # PRESENT_mod
BUILD = ROOT / "build" / "ca" / "fpga" / "oss"
OUT_CSV = CA / "results" / "fpga" / "oss-gw5a.csv"
GOWIN = Path(os.environ.get("GOWIN", Path.home() / "gowin" / "Gowin_V1.9.12.02_linux"))
YOSYS = os.environ.get("YOSYS", str(Path.home() / ".local/share/fpga-oss/bin/yowasp-yosys"))
NEXTPNR = os.environ.get("NEXTPNR", str(Path.home() / ".local/share/fpga-oss-pnr/bin/yowasp-nextpnr-himbaechel-gowin"))
DEVICE, FAMILY, PACKAGE_JSON = "GW5A-LV25MG121NES", "GW5A-25A", "GW5A-25A/MBGA121N.json"
TARGET_MHZ = 250

# name, rtl files, core module, core parameters, wrapper module, block bits, clocks per block, what
CORES = [
    ("aes128", ["aes_ctr.v", "aes_sbox.vh"], "aes_ctr", {"NK": 4}, "top_aes128", 128, 10, "AES-128-CTR, 1 round/clock"),
    ("aes256", ["aes_ctr.v", "aes_sbox.vh"], "aes_ctr", {"NK": 8}, "top_aes256", 128, 14, "AES-256-CTR, 1 round/clock"),
    ("qalqan", ["qalqan_ctr.v", "qalqan_sbox.vh"], "qalqan_ctr", {}, "top_qalqan", 128, 15, "Qalqan-CTR, 1 round/clock"),
    ("chacha20", ["chacha20_ctr.v"], "chacha20_ctr", {}, "top_chacha20", 512, 20, "ChaCha20, 1 round (4 QR)/clock"),
    ("ascon128", ["ascon128_aead.v"], "ascon128_aead", {}, "top_ascon128", 128, 8, "Ascon-AEAD128, 1 round/clock, long messages"),
    ("present80", ["present80_ctr.v"], "present80_ctr", {}, "top_present80", 64, 31, "PRESENT-80-CTR, 1 round/clock"),
]


def run(cmd: list[str], cwd: Path, log: Path, timeout: int = 7200) -> int:
    with log.open("w") as f:
        p = subprocess.run(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT, timeout=timeout)
    return p.returncode


def parse_stat(text: str) -> dict:
    """Cell counts from the last yosys `stat` (the flattened top)."""
    last = text[text.rfind("Printing statistics"):]
    cells = {m.group(2): int(m.group(1)) for m in re.finditer(r"^\s+(\d+)\s+(\S+)\s*$", last, re.M)}
    lut = sum(v for k, v in cells.items() if re.fullmatch(r"LUT[1-4]", k))
    wide = sum(v for k, v in cells.items() if k.startswith("MUX2_LUT"))
    ff = sum(v for k, v in cells.items() if re.fullmatch(r"DFF\w*", k))
    return {"lut4": lut, "mux2_lut": wide, "alu": cells.get("ALU", 0), "ff": ff,
            "lutram": sum(v for k, v in cells.items() if k.startswith("RAM16")),
            "bsram": sum(v for k, v in cells.items() if k in ("SDPB", "SP", "DPB", "DPX9B", "SDPX9B", "pROM"))}


def synth(work: Path, files: list[str], top: str, params: dict, tag: str, json_out: str | None,
          mapper: str = "abc9") -> tuple[int, str]:
    reads = "; ".join(f"read_verilog {f}" for f in files if f.endswith(".v"))
    chp = "; ".join(f"chparam -set {k} {v} {top}" for k, v in params.items())
    script = f"{reads}; {chp + '; ' if chp else ''}synth_gowin -family gw5a -top {top}"
    script += " -nolutram"  # nextpnr-himbaechel has no GW5A BEL for LUT RAM (RAM16SDP4); use FFs
    if mapper == "abc":
        script += " -noabc9"   # classic ABC LUT mapping (area recovery) instead of the default abc9
    script += f" -json {json_out}" if json_out else " -noiopads"
    script += "; stat"
    log = work / f"yosys_{tag}.log"
    rc = run([YOSYS, "-p", script], work, log)
    return rc, log.read_text(errors="replace")


def cst_for(work: Path, json_path: Path, top: str) -> Path:
    pins = [p["INDEX"] for p in json.loads((GOWIN / "IDE/data/device" / PACKAGE_JSON).read_text())["PIN_DATA"]
            if p["TYPE"] == "I/O" and "CFG" not in p]
    mod = json.loads(json_path.read_text())["modules"][top]
    names = []
    for port, d in mod["ports"].items():
        if port == "clk":
            continue
        n = len(d["bits"])
        names += [port] if n == 1 else [f"{port}[{i}]" for i in range(n)]
    if len(names) > len(pins):
        raise RuntimeError(f"{top}: {len(names)} pins needed, {len(pins)} available")
    lines = ['IO_LOC "clk" C11;'] + [f'IO_LOC "{n}" {pins[i]};' for i, n in enumerate(names)]
    cst = work / "top.cst"
    cst.write_text("\n".join(lines) + "\n")
    return cst


def pnr(work: Path, seed: int) -> dict:
    log = work / f"nextpnr_seed{seed}.log"
    rc = run([NEXTPNR, "--device", DEVICE, "--vopt", f"family={FAMILY}", "--vopt", "cst=top.cst",
              "--json", "top.json", "--freq", str(TARGET_MHZ), "--seed", str(seed), "--timing-allow-fail"], work, log)
    text = log.read_text(errors="replace")
    fm = re.findall(r"Max frequency for clock '[^']*': ([\d.]+) MHz", text)
    util = {m.group(1): int(m.group(2)) for m in re.finditer(r"^Info:\s+(\w+):\s+(\d+)/\s*\d+", text, re.M)}
    return {"rc": rc, "fmax": float(fm[-1]) if fm else None, "util": util}


def do_core(spec: tuple, seeds: int, mapper: str) -> dict:
    name, files, core_mod, params, top, bits, ii, what = spec[:8]
    src_dir = spec[8] if len(spec) > 8 else FPGA / "rtl"
    work = BUILD / (name if mapper == "abc9" else f"{name}.{mapper}")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    for f in files:
        shutil.copy(Path(src_dir) / f if not os.path.isabs(f) else f, work / Path(f).name)
    files = [Path(f).name for f in files]
    t0 = time.time()
    row = {"core": name, "mapper": mapper, "what": what, "block_bits": bits, "clocks_per_block": ii}
    rc, text = synth(work, [f for f in files if f != "tops.v"], core_mod, params, "core", None, mapper)
    if rc:
        return {**row, "status": f"core synth failed (rc {rc}), see {work}/yosys_core.log"}
    row.update({f"core_{k}": v for k, v in parse_stat(text).items()})
    rc, _ = synth(work, files, top, params if top == core_mod else {}, "top", "top.json", mapper)
    if rc:
        return {**row, "status": f"top synth failed (rc {rc}), see {work}/yosys_top.log"}
    cst_for(work, work / "top.json", top)
    results = [pnr(work, s) for s in range(1, seeds + 1)]
    fms = [r["fmax"] for r in results if r["rc"] == 0 and r["fmax"]]
    if not fms:
        return {**row, "status": f"place-and-route failed, see {work}/nextpnr_seed1.log"}
    util = results[0]["util"]
    row.update({"fmax_mhz_best": max(fms), "fmax_mhz_median": statistics.median(fms), "seeds": len(fms),
                "top_lut4": util.get("LUT4"), "top_alu": util.get("ALU"), "top_dff": util.get("DFF"),
                "top_mux2": sum(v for k, v in util.items() if k.startswith("MUX2_LUT")),
                "top_bsram": util.get("BSRAM"),
                "status": "ok", "minutes": round((time.time() - t0) / 60, 1)})
    if ii:
        row["mbit_s_best"] = round(max(fms) * bits / ii, 1)
        row["mbit_s_median"] = round(statistics.median(fms) * bits / ii, 1)
    return row


def calib_specs() -> list[tuple]:
    """Reduced-round cores with Gowin IDE results (results/fpga-gowin.md)."""
    gen = ROOT / "fpga" / "generated"
    rows = {}
    for line in (ROOT / "results" / "fpga-gowin.md").read_text().splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 11 and cells[1] == "ok":
            rows[cells[0]] = {"gowin_ff": cells[3], "gowin_alu": cells[4], "gowin_lut": cells[5],
                              "gowin_bsram": cells[6], "gowin_fmax_mhz": cells[8]}
    specs = []
    for mod, g in rows.items():
        v, top = gen / f"{mod}.v", gen / "gowin" / mod / f"{mod}_gowin_top.v"
        if v.is_file() and top.is_file():
            specs.append((f"calib_{mod}", [str(v), str(top)], mod, {}, f"{mod}_gowin_top", 0, 0,
                          "reduced-round core with a Gowin IDE result", gen, g))
    return specs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--only", default="")
    ap.add_argument("--no-calib", action="store_true")
    ap.add_argument("--mappers", default="abc9,abc", help="yosys LUT mappers to run: abc9 (default flow), abc")
    a = ap.parse_args()
    # the Qalqan core (rtl/qalqan_ctr.v) is not distributed: skip cores whose RTL is absent
    specs = [(*c, FPGA / "rtl") for c in CORES if all((FPGA / "rtl" / f).is_file() for f in c[1])]
    specs = [(s[0], s[1] + ["tops.v"], *s[2:]) for s in specs]
    if not a.no_calib:
        specs += calib_specs()
    if a.only:
        keep = set(a.only.split(","))
        specs = [s for s in specs if s[0] in keep]
    BUILD.mkdir(parents=True, exist_ok=True)
    rows = []
    with cf.ProcessPoolExecutor(max_workers=a.jobs) as ex:
        mappers = a.mappers.split(",")
        futs = {ex.submit(do_core, s[:9], a.seeds, m): s for s in specs for m in mappers}
        for fu in cf.as_completed(futs):
            s = futs[fu]
            try:
                r = fu.result()
            except Exception as e:  # noqa: BLE001
                r = {"core": s[0], "status": f"exception: {e}"}
            if len(s) > 9:
                r.update(s[9])
            rows.append(r)
            print(f"{r['core']:<40} {r.get('mapper', ''):<5} {r.get('status')}  core LUT4 {r.get('core_lut4')} FF {r.get('core_ff')} "
                  f"ALU {r.get('core_alu')}  Fmax best {r.get('fmax_mhz_best')} median {r.get('fmax_mhz_median')}"
                  + (f"  Gowin LUT {r.get('gowin_lut')} FF {r.get('gowin_ff')} Fmax {r.get('gowin_fmax_mhz')}" if len(s) > 9 else ""),
                  flush=True)
    # --only: keep the other cores' rows of an earlier run
    if a.only and OUT_CSV.is_file():
        done = {(r["core"], r.get("mapper", "abc9")) for r in rows}
        prev = [l for l in OUT_CSV.read_text().splitlines() if not l.startswith("#")]
        rows += [{k: v for k, v in r.items() if v != ""} for r in csv.DictReader(prev)
                 if (r["core"], r.get("mapper") or "abc9") not in done]
    order = {s[0]: i for i, s in enumerate([(*c, None) for c in CORES] + calib_specs())}
    rows.sort(key=lambda r: (order.get(r["core"], 999), r.get("mapper") != "abc9"))
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    fields = []
    for r in rows:
        fields += [k for k in r if k not in fields]
    with OUT_CSV.open("w", newline="") as f:
        f.write(f"# produced_by: chacha_ascon/fpga/tools/oss_flow.py, {time.strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"# device: {DEVICE} ({FAMILY}); yosys synth_gowin -family gw5a; nextpnr-himbaechel-gowin, "
                f"target {TARGET_MHZ} MHz, {a.seeds} placer seeds\n")
        f.write("# core_*: the core module synthesized alone; top_*: nextpnr utilisation of the pin wrapper "
                "(rtl/tops.v) incl. the core\n")
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {OUT_CSV}")


if __name__ == "__main__":
    main()
