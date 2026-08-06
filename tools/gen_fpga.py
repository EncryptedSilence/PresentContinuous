#!/usr/bin/env python3
"""Generate simple FPGA RTL and KAT testbenches for 64-bit cipher variants."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analysis"))

from present_sat.variants import Variant, load_variant  # noqa: E402


DEFAULT_VARIANTS = [
    "variants/present-80-r16.json",
    "variants/present-80-lin444-297-r7.json",
    "variants/cipher-D.json",
    "variants/cipher-D-lin444-297-r5.json",
    "variants/cipher-D-lin444-297-aes-r5.json",
]

PRESENT_KATS = [
    (0x00000000000000000000, 0x0000000000000000),
    (0xFFFFFFFFFFFFFFFFFFFF, 0x0000000000000000),
    (0x00000000000000000000, 0xFFFFFFFFFFFFFFFF),
    (0xFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
]

INDEP_KATS = [
    (0x0000000000000000, 0x0000000000000000),
    (0x0123456789ABCDEF, 0x0011223344556677),
    (0xFEDCBA9876543210, 0x8899AABBCCDDEEFF),
]


def ident(name: str) -> str:
    return name.replace("-", "_").replace(".", "_")


def rotl(value: int, shift: int, width: int) -> int:
    mask = (1 << width) - 1
    shift %= width
    if shift == 0:
        return value & mask
    return ((value << shift) | (value >> (width - shift))) & mask


def schedule80(v: Variant, key: int) -> list[int]:
    key &= (1 << 80) - 1
    rks = []
    for r in range(v.rounds + 1):
        rks.append((key >> 16) & ((1 << 64) - 1))
        if r == v.rounds:
            break
        key = rotl(key, 61, 80)
        top = (key >> 76) & 0xF
        key = (key & ~(0xF << 76)) | (v.sbox[top] << 76)
        key ^= (r + 1) << 15
    return rks


def schedule_independent(v: Variant, seed: int) -> list[int]:
    x = seed & ((1 << 64) - 1)
    rks = []
    for r in range(v.rounds + 1):
        x = (x + 0x9E3779B97F4A7C15 + ((r + 1) << 7)) & ((1 << 64) - 1)
        x ^= x >> 29
        x = (x * 0xD6E8FEB86659FD93) & ((1 << 64) - 1)
        x ^= x >> 32
        rks.append(x)
    return rks


def encrypt(v: Variant, rks: list[int], pt: int) -> int:
    s = pt
    for r in range(v.rounds):
        s ^= rks[r]
        t = 0
        mask = (1 << v.sbox_bits) - 1
        for i in range(v.n_sboxes):
            t |= v.sbox[(s >> (i * v.sbox_bits)) & mask] << (i * v.sbox_bits)
        s = 0
        for i, col in enumerate(v.lin_cols):
            if (t >> i) & 1:
                s ^= col
    return (s ^ rks[v.rounds]) & ((1 << 64) - 1)


def vecs_for(v: Variant) -> list[tuple[int, int, int]]:
    vecs = []
    if v.key_schedule == "present80":
        seeds = PRESENT_KATS
        for key, pt in seeds:
            rks = schedule80(v, key)
            vecs.append((key, pt, encrypt(v, rks, pt)))
    elif v.key_schedule == "independent":
        for seed, pt in INDEP_KATS:
            rks = schedule_independent(v, seed)
            key = 0
            for rk in rks:
                key = (key << 64) | rk
            vecs.append((key, pt, encrypt(v, rks, pt)))
    else:
        raise ValueError(f"{v.name}: FPGA generator supports present80 and independent schedules")
    return vecs


def hex_const(width: int, value: int) -> str:
    digits = (width + 3) // 4
    return f"{width}'h{value:0{digits}x}"


def sbox_case(v: Variant) -> str:
    lines = [f"function [{v.sbox_bits - 1}:0] sbox;", f"  input [{v.sbox_bits - 1}:0] x;", "  begin", "    case (x)"]
    for i, y in enumerate(v.sbox):
        lines.append(f"      {hex_const(v.sbox_bits, i)}: sbox = {hex_const(v.sbox_bits, y)};")
    lines += ["      default: sbox = 0;", "    endcase", "  end", "endfunction"]
    return "\n".join(lines)


def round_key_fn(v: Variant) -> str:
    if v.key_schedule == "independent":
        return "\n".join([
            "function [63:0] round_key;",
            f"  input [{v.key_bits - 1}:0] key;",
            "  input integer r;",
            "  begin",
            f"    round_key = key[{v.key_bits - 1} - 64*r -: 64];",
            "  end",
            "endfunction",
        ])
    lines = [
        "function [63:0] round_key;",
        f"  input [{v.key_bits - 1}:0] key;",
        "  input integer r;",
        "  integer i;",
        "  reg [79:0] k;",
        "  begin",
        "    k = key;",
        "    for (i = 0; i < r; i = i + 1) begin",
        "      k = {k[18:0], k[79:19]};",
        "      k[79:76] = sbox(k[79:76]);",
        "      k[19:15] = k[19:15] ^ (i + 1);",
        "    end",
        "    round_key = k[79:16];",
        "  end",
        "endfunction",
    ]
    return "\n".join(lines)


def layer_expr(v: Variant, src: str, dst: str) -> str:
    lines = []
    for out_bit in range(64):
        terms = [f"{src}[{i}]" for i, col in enumerate(v.lin_cols) if (col >> out_bit) & 1]
        expr = " ^ ".join(terms) if terms else "1'b0"
        lines.append(f"  assign {dst}[{out_bit}] = {expr};")
    return "\n".join(lines)


def sbox_layer(v: Variant, src: str, dst: str) -> str:
    lines = []
    for i in range(v.n_sboxes):
        lo = i * v.sbox_bits
        hi = lo + v.sbox_bits - 1
        lines.append(f"  assign {dst}[{hi}:{lo}] = sbox({src}[{hi}:{lo}]);")
    return "\n".join(lines)


def emit_core(v: Variant, mode: str) -> str:
    name = f"{ident(v.name)}_{mode}"
    body = [
        "// AUTO-GENERATED by tools/gen_fpga.py. Do not edit.",
        "`timescale 1ns/1ps",
        f"module {name}(",
        "  input wire clk,",
        "  input wire rst,",
        "  input wire start,",
        "  input wire [63:0] plaintext,",
        f"  input wire [{v.key_bits - 1}:0] key,",
        "  output reg [63:0] ciphertext,",
        "  output reg valid,",
        "  output wire busy",
        ");",
        sbox_case(v),
        round_key_fn(v),
    ]
    if mode == "area":
        body += [
            "reg [63:0] state;",
            "reg [5:0] round;",
            "reg running;",
            "wire [63:0] addkey = state ^ round_key(key, round);",
            "wire [63:0] sb;",
            "wire [63:0] lin;",
            sbox_layer(v, "addkey", "sb"),
            layer_expr(v, "sb", "lin"),
            "assign busy = running;",
            "always @(posedge clk) begin",
            "  if (rst) begin",
            "    state <= 0; round <= 0; running <= 0; ciphertext <= 0; valid <= 0;",
            "  end else begin",
            "    valid <= 0;",
            "    if (start && !running) begin",
            "      state <= plaintext; round <= 0; running <= 1;",
            f"    end else if (running && round < {v.rounds}) begin",
            "      state <= lin; round <= round + 1;",
            "    end else if (running) begin",
            f"      ciphertext <= state ^ round_key(key, {v.rounds});",
            "      valid <= 1; running <= 0;",
            "    end",
            "  end",
            "end",
        ]
    else:
        body += ["assign busy = 1'b0;"]
        for r in range(v.rounds):
            body += [
                f"reg [63:0] pipe_{r};",
                f"wire [63:0] addkey_{r} = " + ("plaintext" if r == 0 else f"pipe_{r - 1}") + f" ^ round_key(key, {r});",
                f"wire [63:0] sb_{r};",
                f"wire [63:0] lin_{r};",
                sbox_layer(v, f"addkey_{r}", f"sb_{r}"),
                layer_expr(v, f"sb_{r}", f"lin_{r}"),
            ]
        body += [f"reg [{v.rounds}:0] valid_pipe;", "integer j;", "always @(posedge clk) begin"]
        body += [
            "  if (rst) begin",
            "    ciphertext <= 0; valid <= 0; valid_pipe <= 0;",
            f"    for (j = 0; j < {v.rounds}; j = j + 1) begin",
        ]
        for r in range(v.rounds):
            body.append(f"      if (j == {r}) pipe_{r} <= 0;")
        body += [
            "    end",
            "  end else begin",
            f"    pipe_0 <= lin_0;",
        ]
        for r in range(1, v.rounds):
            body.append(f"    pipe_{r} <= lin_{r};")
        body += [
            f"    valid_pipe <= {{valid_pipe[{v.rounds - 1}:0], start}};",
            f"    ciphertext <= pipe_{v.rounds - 1} ^ round_key(key, {v.rounds});",
            f"    valid <= valid_pipe[{v.rounds}];",
            "  end",
            "end",
        ]
    body.append("endmodule")
    return "\n".join(body) + "\n"


def emit_tb(v: Variant, mode: str, vecs: list[tuple[int, int, int]]) -> str:
    mod = f"{ident(v.name)}_{mode}"
    lines = [
        "// AUTO-GENERATED by tools/gen_fpga.py. Do not edit.",
        "`timescale 1ns/1ps",
        f"module tb_{mod};",
        "reg clk = 0, rst = 1, start = 0;",
        "reg [63:0] plaintext;",
        f"reg [{v.key_bits - 1}:0] key;",
        "wire [63:0] ciphertext;",
        "wire valid, busy;",
        f"{mod} dut(.clk(clk), .rst(rst), .start(start), .plaintext(plaintext), .key(key), .ciphertext(ciphertext), .valid(valid), .busy(busy));",
        "always #5 clk = ~clk;",
        "integer errors = 0;",
        "task run_vec;",
        f"  input [{v.key_bits - 1}:0] k;",
        "  input [63:0] pt;",
        "  input [63:0] ct;",
        "  begin",
        "    @(negedge clk); key = k; plaintext = pt; start = 1;",
        "    @(negedge clk); start = 0;",
        "    while (!valid) @(negedge clk);",
        "    if (ciphertext !== ct) begin",
        "      $display(\"FAIL %s got=%016h expected=%016h\", pt, ciphertext, ct); errors = errors + 1;",
        "    end",
        "  end",
        "endtask",
        "initial begin",
        "  key = 0; plaintext = 0;",
        "  repeat (3) @(negedge clk); rst = 0;",
    ]
    for key, pt, ct in vecs:
        lines.append(f"  run_vec({hex_const(v.key_bits, key)}, {hex_const(64, pt)}, {hex_const(64, ct)});")
    lines += [
        "  if (errors) begin $display(\"FAIL\"); $finish(1); end",
        f"  $display(\"PASS {mod}\");",
        "  $finish;",
        "end",
        "endmodule",
    ]
    return "\n".join(lines) + "\n"


def write_gowin_project(out_dir: Path, modules: list[str], device: str, part: str) -> None:
    gowin_dir = out_dir / "gowin"
    if gowin_dir.exists():
        shutil.rmtree(gowin_dir)
    gowin_dir.mkdir(parents=True, exist_ok=True)
    for mod in modules:
        proj_dir = gowin_dir / mod
        proj_dir.mkdir(parents=True, exist_ok=True)
        (proj_dir / "cipher_core.sdc").write_text(
            "create_clock -name clk -period 10 [get_ports {clk}]\n",
            encoding="ascii",
        )
        gprj = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            "<!DOCTYPE gowin-fpga-project>",
            "<Project>",
            "    <Template>FPGA</Template>",
            "    <Version>5</Version>",
            f'    <Device name="{device}" pn="{part}">{device.lower()}-000</Device>',
            "    <FileList>",
            f'        <File path="../../{mod}.v" type="file.verilog" enable="1"/>',
            '        <File path="cipher_core.sdc" type="file.sdc" enable="1"/>',
            "    </FileList>",
            "</Project>",
        ]
        (proj_dir / f"{mod}.gprj").write_text("\n".join(gprj) + "\n", encoding="ascii")
        tcl = [
            'puts "Gowin build: starting"',
            "set project_root [file dirname [file normalize [info script]]]",
            f'set gprj [file normalize [file join $project_root "{mod}.gprj"]]',
            'puts "Gowin build: open_project $gprj"',
            "open_project $gprj",
            'puts "Gowin build: run all"',
            "run all",
            'puts "Gowin build: done"',
        ]
        (proj_dir / "build_gowin.tcl").write_text("\n".join(tcl) + "\n", encoding="ascii")


def generate(args: argparse.Namespace) -> None:
    out_dir = ROOT / args.out_dir
    tb_dir = out_dir / "tb"
    out_dir.mkdir(parents=True, exist_ok=True)
    tb_dir.mkdir(parents=True, exist_ok=True)
    modules = []
    for path in args.variants:
        v = load_variant(str(ROOT / path))
        if v.block_bits != 64:
            raise ValueError(f"{v.name}: only 64-bit FPGA cores are generated here")
        vecs = vecs_for(v)
        for mode in ("area", "speed"):
            mod = f"{ident(v.name)}_{mode}"
            modules.append(mod)
            (out_dir / f"{mod}.v").write_text(emit_core(v, mode), encoding="ascii")
            (tb_dir / f"tb_{mod}.v").write_text(emit_tb(v, mode, vecs), encoding="ascii")
    write_gowin_project(out_dir, modules, args.device, args.part)
    (out_dir / "modules.txt").write_text("\n".join(modules) + "\n", encoding="ascii")
    print(f"generated {len(modules)} FPGA cores in {out_dir}")


def check_gowin(args: argparse.Namespace) -> None:
    gw = shutil.which(args.gw_sh) if os.path.basename(args.gw_sh) == args.gw_sh else args.gw_sh
    if not gw:
        print(f"Gowin {args.gw_sh} not found")
        raise SystemExit(77)
    res = subprocess.run([gw, "-v"])
    if res.returncode != 0:
        raise SystemExit(res.returncode)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("--out-dir", default="fpga/generated")
    gen.add_argument("--device", default=os.environ.get("GOWIN_DEVICE", "GW5A-25A"))
    gen.add_argument("--part", default=os.environ.get("GOWIN_PART", "GW5A-LV25MG121NES"))
    gen.add_argument("variants", nargs="*", default=DEFAULT_VARIANTS)
    gen.set_defaults(func=generate)
    chk = sub.add_parser("check-gowin")
    chk.add_argument("--gw-sh", default=os.environ.get("GW_SH", "gw_sh"))
    chk.set_defaults(func=check_gowin)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
