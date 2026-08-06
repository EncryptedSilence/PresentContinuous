#!/usr/bin/env python3
"""Generate simple FPGA RTL and KAT testbenches for 64-bit cipher variants."""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analysis"))

from present_sat.variants import Variant, load_variant  # noqa: E402
from known_circuits import lookup as lookup_known_circuit  # noqa: E402


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


def _circuit_ref(ref: tuple[str, int]) -> str:
    kind, index = ref
    if kind == "x":
        return f"x[{index}]"
    if kind == "t":
        return f"t[{index}]"
    return "1'b1" if index else "1'b0"


def sbox_function(v: Variant) -> str:
    known = lookup_known_circuit(v.sbox)
    if known is not None:
        ops, outs, circuit_name = known
        lines = [
            f"// {circuit_name} S-box: verified Boolean circuit from tools/known_circuits.py.",
            f"function [{v.sbox_bits - 1}:0] sbox;",
            f"  input [{v.sbox_bits - 1}:0] x;",
            f"  reg [{len(ops) - 1}:0] t;",
            "  begin",
        ]
        symbols = {"and": "&", "or": "|", "xor": "^"}
        for dest, kind, a, b in ops:
            lhs = _circuit_ref(dest)
            if kind == "not":
                rhs = f"~{_circuit_ref(a)}"
            elif kind == "andn":
                rhs = f"~{_circuit_ref(a)} & {_circuit_ref(b)}"
            elif kind == "orn":
                rhs = f"~{_circuit_ref(a)} | {_circuit_ref(b)}"
            else:
                rhs = f"{_circuit_ref(a)} {symbols[kind]} {_circuit_ref(b)}"
            lines.append(f"    {lhs} = {rhs};")
        for bit, ref in enumerate(outs):
            lines.append(f"    sbox[{bit}] = {_circuit_ref(ref)};")
        lines += ["  end", "endfunction"]
        return "\n".join(lines)

    lines = [f"function [{v.sbox_bits - 1}:0] sbox;", f"  input [{v.sbox_bits - 1}:0] x;", "  begin", "    case (x)"]
    for i, y in enumerate(v.sbox):
        lines.append(f"      {hex_const(v.sbox_bits, i)}: sbox = {hex_const(v.sbox_bits, y)};")
    lines += ["      default: sbox = 0;", "    endcase", "  end", "endfunction"]
    return "\n".join(lines)


def _logic_expr(kind: str, a: str, b: str | None) -> str:
    if kind == "not":
        return f"~{a}"
    if kind == "andn":
        return f"~{a} & {b}"
    if kind == "orn":
        return f"~{a} | {b}"
    symbol = {"and": "&", "or": "|", "xor": "^"}[kind]
    return f"{a} {symbol} {b}"


def aes_pipeline_modules(v: Variant) -> str:
    known = lookup_known_circuit(v.sbox)
    if known is None or known[2] != "aes":
        return ""
    ops, outs, _ = known
    if len(ops) != 132:
        raise ValueError(f"unexpected AES circuit length: {len(ops)}")

    lines = ["// Pipeline cuts follow the published AES circuit's top/middle/bottom stages."]

    def render_module(name: str, input_decl: str, output_decl: str, start: int, end: int,
                      ref_name, output_assignments: list[tuple[str, tuple[str, int]]]) -> None:
        lines.extend([
            f"module {name}(x, y);",
            input_decl.replace("input wire ", "  input wire ") + ";",
            output_decl.replace("output wire ", "  output wire ") + ";",
            f"  wire [{end - start - 1}:0] t;",
        ])
        for absolute in range(start, end):
            _, kind, a, b = ops[absolute]
            rhs = _logic_expr(kind, ref_name(a), ref_name(b) if b else None)
            lines.append(f"  assign t[{absolute - start}] = {rhs};")
        for lhs, ref in output_assignments:
            lines.append(f"  assign {lhs} = {ref_name(ref)};")
        lines.extend(["endmodule", ""])

    def top_ref(ref: tuple[str, int]) -> str:
        kind, index = ref
        return f"x[{index}]" if kind == "x" else f"t[{index}]"

    render_module(
        "aes_sbox_top_stage",
        "input wire [7:0] x",
        "output wire [27:0] y",
        0,
        27,
        top_ref,
        [(f"y[{i}]", ("t", i)) for i in range(27)] + [("y[27]", ("x", 0))],
    )

    def mid_ref(ref: tuple[str, int]) -> str:
        kind, index = ref
        if kind == "x":
            if index != 0:
                raise ValueError(f"unexpected AES middle-stage input x[{index}]")
            return "x[27]"
        if index < 27:
            return f"x[{index}]"
        return f"t[{index - 27}]"

    render_module(
        "aes_sbox_middle_stage",
        "input wire [27:0] x",
        "output wire [17:0] y",
        27,
        90,
        mid_ref,
        [(f"y[{i}]", ("t", 72 + i)) for i in range(18)],
    )

    def bottom_ref(ref: tuple[str, int]) -> str:
        kind, index = ref
        if kind != "t":
            return "1'b1" if index else "1'b0"
        if index < 90:
            if index < 72:
                raise ValueError(f"unexpected AES bottom-stage input t[{index}]")
            return f"x[{index - 72}]"
        return f"t[{index - 90}]"

    render_module(
        "aes_sbox_bottom_stage",
        "input wire [17:0] x",
        "output wire [7:0] y",
        90,
        132,
        bottom_ref,
        [(f"y[{bit}]", ref) for bit, ref in enumerate(outs)],
    )
    return "\n".join(lines)


def present_key_fn(v: Variant) -> str:
    if v.key_schedule != "present80":
        return ""
    return "\n".join([
        "function [79:0] next_key;",
        "  input [79:0] k;",
        "  input [4:0] round_number;",
        "  reg [79:0] n;",
        "  begin",
        "    n = {k[18:0], k[79:19]};",
        "    n[79:76] = sbox(n[79:76]);",
        "    n[19:15] = n[19:15] ^ round_number;",
        "    next_key = n;",
        "  end",
        "endfunction",
    ])


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
    staged_aes = mode == "speed" and bool(aes_pipeline_modules(v))
    body = [
        "// AUTO-GENERATED by tools/gen_fpga.py. Do not edit.",
        "`timescale 1ns/1ps",
    ]
    if staged_aes:
        body += [aes_pipeline_modules(v)]
    body += [
        f"module {name} /* synthesis syn_hier = \"hard\" */ (",
        "  input wire clk,",
        "  input wire rst,",
        "  input wire start,",
        "  input wire [63:0] plaintext,",
        f"  input wire [{v.key_bits - 1}:0] key,",
        "  output reg [63:0] ciphertext,",
        "  output reg valid,",
        "  output wire busy",
        ");",
        sbox_function(v),
        present_key_fn(v),
    ]
    if mode == "area":
        index_bits = max(1, (v.n_sboxes - 1).bit_length())
        body += [
            "// Area architecture: one physical S-box, reused across the whole block.",
            "reg [63:0] state_shift /* synthesis syn_preserve = 1 */;",
            "reg [63:0] sub_acc /* synthesis syn_preserve = 1 */;",
            "reg [5:0] round;",
            f"reg [{index_bits - 1}:0] sbox_index;",
            "reg running;",
        ]
        if v.key_schedule == "present80":
            body += [
                "reg [79:0] key_state /* synthesis syn_preserve = 1 */;",
                "reg [63:0] key_shift /* synthesis syn_preserve = 1 */;",
                f"wire [{v.sbox_bits - 1}:0] sbox_input = "
                f"state_shift[63 -: {v.sbox_bits}] ^ key_shift[63 -: {v.sbox_bits}];",
                "wire [79:0] advanced_key = next_key(key_state, round[4:0] + 5'd1);",
                "wire [63:0] final_round_key = advanced_key[79:16];",
            ]
        else:
            body += [
                f"reg [{v.key_bits - 1}:0] key_state /* synthesis syn_preserve = 1 */;",
                f"wire [{v.sbox_bits - 1}:0] sbox_input = "
                f"state_shift[63 -: {v.sbox_bits}] ^ key_state[{v.key_bits - 1} -: {v.sbox_bits}];",
                f"wire [{v.key_bits - 1}:0] advanced_key = key_state << {v.sbox_bits};",
                f"wire [63:0] final_round_key = advanced_key[{v.key_bits - 1} -: 64];",
            ]
        body += [
            f"wire [{v.sbox_bits - 1}:0] sbox_output = sbox(sbox_input);",
            f"wire [63:0] sub_next = {{sub_acc[{63 - v.sbox_bits}:0], sbox_output}};",
            "wire [63:0] lin_next;",
            layer_expr(v, "sub_next", "lin_next"),
            "assign busy = running;",
            "always @(posedge clk) begin",
            "  if (rst) begin",
            "    state_shift <= 0; sub_acc <= 0; round <= 0; sbox_index <= 0;",
            "    running <= 0; ciphertext <= 0; valid <= 0; key_state <= 0;",
        ]
        if v.key_schedule == "present80":
            body.append("    key_shift <= 0;")
        body += [
            "  end else begin",
            "    valid <= 0;",
            "    if (start && !running) begin",
            "      state_shift <= plaintext; sub_acc <= 0; round <= 0; sbox_index <= 0;",
            "      running <= 1; key_state <= key;",
        ]
        if v.key_schedule == "present80":
            body.append("      key_shift <= key[79:16];")
        body += [
            "    end else if (running) begin",
        ]
        if v.key_schedule == "independent":
            body.append("      key_state <= advanced_key;")
        body += [
            f"      if (sbox_index == {v.n_sboxes - 1}) begin",
            f"        if (round == {v.rounds - 1}) begin",
            "          ciphertext <= lin_next ^ final_round_key;",
            "          valid <= 1; running <= 0;",
            "        end else begin",
            "          state_shift <= lin_next; sub_acc <= 0; round <= round + 6'd1; sbox_index <= 0;",
        ]
        if v.key_schedule == "present80":
            body += [
                "          key_state <= advanced_key;",
                "          key_shift <= advanced_key[79:16];",
            ]
        body += [
            "        end",
            "      end else begin",
            f"        state_shift <= state_shift << {v.sbox_bits};",
            f"        sub_acc <= sub_next; sbox_index <= sbox_index + {index_bits}'d1;",
        ]
        if v.key_schedule == "present80":
            body.append(f"        key_shift <= key_shift << {v.sbox_bits};")
        body += [
            "      end",
            "    end",
            "  end",
            "end",
        ]
    else:
        body += [
            "// Speed architecture: fully streaming, with S-box and linear-layer stages.",
            "assign busy = 1'b0;",
        ]
        for r in range(v.rounds):
            state_input = "plaintext" if r == 0 else f"lin_pipe_{r - 1}"
            if v.key_schedule == "present80":
                key_input = "key" if r == 0 else f"key_lin_{r - 1}"
                round_key = f"{key_input}[79:16]"
                key_width = 80
                key_advance = f"next_key({key_input}, 5'd{r + 1})"
            else:
                input_width = (v.rounds + 1 - r) * 64
                key_input = "key" if r == 0 else f"key_lin_{r - 1}"
                round_key = f"{key_input}[{input_width - 1} -: 64]"
                key_width = input_width - 64
                key_advance = f"{key_input}[{key_width - 1}:0]"
            if staged_aes:
                body += [
                    f"reg [223:0] aes_top_pipe_{r} /* synthesis syn_preserve = 1 */;",
                    f"reg [143:0] aes_middle_pipe_{r} /* synthesis syn_preserve = 1 */;",
                    f"reg [63:0] sb_pipe_{r} /* synthesis syn_preserve = 1 */;",
                    f"reg [63:0] lin_pipe_{r} /* synthesis syn_preserve = 1 */;",
                    f"reg [{key_width - 1}:0] key_top_{r} /* synthesis syn_preserve = 1 */;",
                    f"reg [{key_width - 1}:0] key_middle_{r} /* synthesis syn_preserve = 1 */;",
                    f"reg [{key_width - 1}:0] key_sb_{r} /* synthesis syn_preserve = 1 */;",
                    f"reg [{key_width - 1}:0] key_lin_{r} /* synthesis syn_preserve = 1 */;",
                    f"wire [63:0] addkey_{r} = {state_input} ^ {round_key};",
                    f"wire [223:0] aes_top_{r};",
                    f"wire [143:0] aes_middle_{r};",
                    f"wire [63:0] sb_{r};",
                    f"wire [63:0] lin_{r};",
                ]
                for i in range(8):
                    body += [
                        f"aes_sbox_top_stage aes_top_{r}_{i}(.x(addkey_{r}[{8 * i + 7}:{8 * i}]), "
                        f".y(aes_top_{r}[{28 * i + 27}:{28 * i}]));",
                        f"aes_sbox_middle_stage aes_middle_{r}_{i}(.x(aes_top_pipe_{r}[{28 * i + 27}:{28 * i}]), "
                        f".y(aes_middle_{r}[{18 * i + 17}:{18 * i}]));",
                        f"aes_sbox_bottom_stage aes_bottom_{r}_{i}(.x(aes_middle_pipe_{r}[{18 * i + 17}:{18 * i}]), "
                        f".y(sb_{r}[{8 * i + 7}:{8 * i}]));",
                    ]
                body += [
                    layer_expr(v, f"sb_pipe_{r}", f"lin_{r}"),
                    f"wire [{key_width - 1}:0] key_advance_{r} = {key_advance};",
                ]
            else:
                body += [
                    f"reg [63:0] sb_pipe_{r} /* synthesis syn_preserve = 1 */;",
                    f"reg [63:0] lin_pipe_{r} /* synthesis syn_preserve = 1 */;",
                    f"reg [{key_width - 1}:0] key_sb_{r} /* synthesis syn_preserve = 1 */;",
                    f"reg [{key_width - 1}:0] key_lin_{r} /* synthesis syn_preserve = 1 */;",
                    f"wire [63:0] addkey_{r} = {state_input} ^ {round_key};",
                    f"wire [63:0] sb_{r};",
                    f"wire [63:0] lin_{r};",
                    sbox_layer(v, f"addkey_{r}", f"sb_{r}"),
                    layer_expr(v, f"sb_pipe_{r}", f"lin_{r}"),
                    f"wire [{key_width - 1}:0] key_advance_{r} = {key_advance};",
                ]
        latency = (4 if staged_aes else 2) * v.rounds
        body += [f"reg [{latency - 1}:0] valid_pipe;", "always @(posedge clk) begin"]
        body += [
            "  if (rst) begin",
            "    ciphertext <= 0; valid <= 0; valid_pipe <= 0;",
        ]
        for r in range(v.rounds):
            if staged_aes:
                body += [
                    f"    aes_top_pipe_{r} <= 0; aes_middle_pipe_{r} <= 0;",
                    f"    sb_pipe_{r} <= 0; lin_pipe_{r} <= 0;",
                    f"    key_top_{r} <= 0; key_middle_{r} <= 0; key_sb_{r} <= 0; key_lin_{r} <= 0;",
                ]
            else:
                body += [
                    f"    sb_pipe_{r} <= 0; lin_pipe_{r} <= 0;",
                    f"    key_sb_{r} <= 0; key_lin_{r} <= 0;",
                ]
        body += [
            "  end else begin",
        ]
        for r in range(v.rounds):
            if staged_aes:
                body += [
                    f"    aes_top_pipe_{r} <= aes_top_{r};",
                    f"    key_top_{r} <= key_advance_{r};",
                    f"    aes_middle_pipe_{r} <= aes_middle_{r};",
                    f"    key_middle_{r} <= key_top_{r};",
                    f"    sb_pipe_{r} <= sb_{r};",
                    f"    key_sb_{r} <= key_middle_{r};",
                    f"    lin_pipe_{r} <= lin_{r};",
                    f"    key_lin_{r} <= key_sb_{r};",
                ]
            else:
                body += [
                    f"    sb_pipe_{r} <= sb_{r};",
                    f"    key_sb_{r} <= key_advance_{r};",
                    f"    lin_pipe_{r} <= lin_{r};",
                    f"    key_lin_{r} <= key_sb_{r};",
                ]
        body += [
            f"    valid_pipe <= {{valid_pipe[{latency - 2}:0], start}};",
        ]
        if v.key_schedule == "present80":
            final_round_key = f"key_lin_{v.rounds - 1}[79:16]"
        else:
            final_round_key = f"key_lin_{v.rounds - 1}"
        body += [
            f"    ciphertext <= lin_pipe_{v.rounds - 1} ^ {final_round_key};",
            f"    valid <= valid_pipe[{latency - 1}];",
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
    if mode == "area":
        for key, pt, ct in vecs:
            lines.append(f"  run_vec({hex_const(v.key_bits, key)}, {hex_const(64, pt)}, {hex_const(64, ct)});")
    else:
        lines += [
            "  // Different keys on consecutive cycles verify that key material is pipelined with state.",
        ]
        for key, pt, _ in vecs:
            lines += [
                f"  @(negedge clk); key = {hex_const(v.key_bits, key)}; plaintext = {hex_const(64, pt)}; start = 1;",
            ]
        lines += [
            "  @(negedge clk); start = 0;",
        ]
        for _, pt, ct in vecs:
            lines += [
                "  while (!valid) @(negedge clk);",
                f"  if (ciphertext !== {hex_const(64, ct)}) begin",
                f"    $display(\"FAIL {pt:016x} got=%016h expected={ct:016x}\", ciphertext); errors = errors + 1;",
                "  end",
                "  @(negedge clk);",
            ]
    lines += [
        "  if (errors) begin $display(\"FAIL\"); $finish(1); end",
        f"  $display(\"PASS {mod}\");",
        "  $finish;",
        "end",
        "endmodule",
    ]
    return "\n".join(lines) + "\n"


def emit_gowin_top(v: Variant, mode: str) -> str:
    mod = f"{ident(v.name)}_{mode}"
    top = f"{mod}_gowin_top"
    if v.key_bits > 64:
        key_next = (
            f"{{key[{v.key_bits - 65}:0], "
            f"key[{v.key_bits - 1}:{v.key_bits - 64}] ^ 64'h9e3779b97f4a7c15}}"
        )
    else:
        key_next = "key ^ 64'h9e3779b97f4a7c15"
    lines = [
        "// AUTO-GENERATED by tools/gen_fpga.py. Do not edit.",
        "`timescale 1ns/1ps",
        f"module {top}(",
        "  input wire clk,",
        "  input wire rst,",
        "  output reg [7:0] digest",
        ");",
        "reg start;",
        "reg [63:0] plaintext;",
        f"reg [{v.key_bits - 1}:0] key;",
        "wire [63:0] ciphertext;",
        "wire valid;",
        "wire busy;",
        f"{mod} core(.clk(clk), .rst(rst), .start(start), .plaintext(plaintext), .key(key), .ciphertext(ciphertext), .valid(valid), .busy(busy));",
        "always @(posedge clk) begin",
        "  if (rst) begin",
        "    start <= 0;",
        "    plaintext <= 64'h0011223344556677;",
        f"    key <= {v.key_bits}'h1;",
        "    digest <= 0;",
        "  end else begin",
        "    start <= !busy;",
        "    if (!busy) begin",
        "      plaintext <= {plaintext[62:0], plaintext[63] ^ plaintext[61] ^ plaintext[60] ^ plaintext[59]};",
        f"      key <= {key_next};",
        "    end",
        "    if (valid) digest <= digest ^ ciphertext[7:0] ^ ciphertext[15:8];",
        "  end",
        "end",
        "endmodule",
    ]
    return "\n".join(lines) + "\n"


def write_gowin_project(
    out_dir: Path,
    module_specs: list[tuple[str, Variant, str]],
    device: str,
    part: str,
    device_id: str,
) -> None:
    gowin_dir = out_dir / "gowin"
    if gowin_dir.exists():
        shutil.rmtree(gowin_dir)
    gowin_dir.mkdir(parents=True, exist_ok=True)
    for mod, variant, mode in module_specs:
        proj_dir = gowin_dir / mod
        proj_dir.mkdir(parents=True, exist_ok=True)
        top = f"{mod}_gowin_top"
        wrapper = f"{top}.v"
        v_path = out_dir / f"{mod}.v"
        if not v_path.is_file():
            raise FileNotFoundError(v_path)
        if mode == "speed" and variant.name == "cipher-D":
            # The fully preserved 64-ROM implementation closes near 157 MHz on GW5A.
            period_ns = 6.667
        elif mode == "speed" and variant.name == "cipher-D-lin444-297-r5":
            period_ns = 5.556
        elif mode == "speed" and variant.name == "cipher-D-lin444-297-aes-r5":
            period_ns = 6.061
        elif mode == "speed":
            period_ns = 5.0
        elif lookup_known_circuit(variant.sbox) is not None:
            period_ns = 8.4
        else:
            period_ns = 8.0
        (proj_dir / "cipher_core.sdc").write_text(
            f"create_clock -name clk -period {period_ns:.3f} [get_ports {{clk}}]\n",
            encoding="ascii",
        )
        (proj_dir / wrapper).write_text(emit_gowin_top(variant, mode), encoding="ascii")
        gprj = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            "<!DOCTYPE gowin-fpga-project>",
            "<Project>",
            "    <Template>FPGA</Template>",
            "    <Version>5</Version>",
            f'    <Device name="{device}" pn="{part}">{device_id}</Device>',
            "    <FileList>",
            f'        <File path="../../{mod}.v" type="file.verilog" enable="1"/>',
            f'        <File path="{wrapper}" type="file.verilog" enable="1"/>',
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
            f"set_option -top_module {top}",
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
    module_specs = []
    core_rows = []
    for path in args.variants:
        v = load_variant(str(ROOT / path))
        if v.block_bits != 64:
            raise ValueError(f"{v.name}: only 64-bit FPGA cores are generated here")
        vecs = vecs_for(v)
        for mode in ("area", "speed"):
            mod = f"{ident(v.name)}_{mode}"
            modules.append(mod)
            module_specs.append((mod, v, mode))
            if mode == "area":
                latency = v.rounds * v.n_sboxes
                ii = latency + 1
                architecture = "serialized-sbox-rolling-key"
            else:
                staged_aes = bool(aes_pipeline_modules(v))
                latency = (4 if staged_aes else 2) * v.rounds
                ii = 1
                architecture = (
                    "streaming-aes-4stage-round-pipeline"
                    if staged_aes else "streaming-sbox-linear-pipeline"
                )
            core_rows.append({
                "core": mod,
                "variant": v.name,
                "mode": mode,
                "rounds": v.rounds,
                "key_bits": v.key_bits,
                "sbox_bits": v.sbox_bits,
                "sboxes_per_block": v.n_sboxes,
                "latency_cycles": latency,
                "initiation_interval_cycles": ii,
                "architecture": architecture,
            })
            (out_dir / f"{mod}.v").write_text(emit_core(v, mode), encoding="ascii")
            (tb_dir / f"tb_{mod}.v").write_text(emit_tb(v, mode, vecs), encoding="ascii")
    write_gowin_project(out_dir, module_specs, args.device, args.part, args.device_id)
    (out_dir / "modules.txt").write_text("\n".join(modules) + "\n", encoding="ascii")
    with (out_dir / "cores.csv").open("w", newline="", encoding="ascii") as fh:
        fields = list(core_rows[0])
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(core_rows)
    print(f"generated {len(modules)} FPGA cores in {out_dir}")


def check_gowin(args: argparse.Namespace) -> None:
    gw = shutil.which(args.gw_sh) if os.path.basename(args.gw_sh) == args.gw_sh else args.gw_sh
    if not gw or not os.path.isfile(gw) or not os.access(gw, os.X_OK):
        print(f"Gowin {args.gw_sh} not found")
        raise SystemExit(77)
    print(f"Gowin shell: {gw}")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("--out-dir", default="fpga/generated")
    gen.add_argument("--device", default=os.environ.get("GOWIN_DEVICE", "GW5A-25A"))
    gen.add_argument("--part", default=os.environ.get("GOWIN_PART", "GW5A-LV25MG121NES"))
    gen.add_argument("--device-id", default=os.environ.get("GOWIN_DEVICE_ID", "gw5a25a-000"))
    gen.add_argument("variants", nargs="*", default=DEFAULT_VARIANTS)
    gen.set_defaults(func=generate)
    chk = sub.add_parser("check-gowin")
    chk.add_argument("--gw-sh", default=os.environ.get("GW_SH", "gw_sh"))
    chk.set_defaults(func=check_gowin)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
