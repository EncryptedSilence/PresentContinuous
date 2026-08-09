#!/usr/bin/env python3
"""Per-kernel Flash and RAM for the Cortex-M4 build.

Why this exists
---------------
results/m4-speed.csv reports three whole-image memory figures -- ccm used, bss
used, stack peak. They describe the *benchmark*, which holds a present_ctx_t with
its 16 KiB fused table, bitsliced planes at both word widths, an AES schedule, a
lin444 schedule and a 2 KiB working set simultaneously, because it measures every
implementation family in one run. Reading the resulting ~57 KiB as any one
cipher's memory cost is a category error, and it is the one this file removes.

The two halves come from different places on purpose:

  RAM     from the firmware, which knows the real sizeof of everything it
          allocates and emits `footprint <cipher>,<rounds>,<impl>,<state>,<work>,
          <kernel_id>` lines for the round count it actually ran. Re-deriving
          those here would mean a second copy of the sizing rules that could
          disagree with the code without anything failing.

  Flash   from the linked ELF, which is the only place a kernel's code size
          exists. -ffunction-sections (added at the same time as this tool) puts
          every function in its own section, so a per-kernel figure is a sum over
          a call-graph closure rather than a guess at where one function ends.

What the Flash column is, precisely
-----------------------------------
The transitive closure of direct calls from the kernel's entry point, summed over
symbol sizes. It answers "how much code would a build containing only this kernel
carry", which is the product question.

Three limits, stated because a number like this invites over-reading:

  * Direct branches only (bl / blx / b / b.w to a named symbol). An indirect call
    through a function pointer is invisible to this analysis. The benchmark has
    exactly one -- the fixed-round table dispatch through present_table_fixed_fn
    -- and it is handled by naming present_encrypt_table_rN as the root directly
    (ROOTS below), not by following the pointer.

  * Code only. Constant tables in .rodata are NOT included, so a kernel whose
    S-box lives in flash (the 128-bit ciphers') is undercounted by that table's
    size relative to one whose table is built into RAM (the 64-bit ciphers', whose
    16 KiB lands in the RAM column instead). The two columns together are what is
    comparable; neither alone is.

  * The bitsliced entry points switch over every kernel in
    PRESENT_KERNEL_ENC_LIST, so a closure from the entry point charges each cipher
    for all sixteen. The firmware reports which kernel each cipher enters and the
    root is that kernel, not the dispatcher -- see the kernel_id field.

Usage:  tools/m4_footprint.py --elf build/m4/bench_m4.elf --stream <run log>
        (run_m4_bench.py calls it with the stream it already captured)
"""

import argparse
import collections
import os
import re
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

OBJDUMP = "arm-none-eabi-objdump"
NM = "arm-none-eabi-nm"

# A `footprint` line as the firmware emits it.
FOOTPRINT_RE = re.compile(
    r"^footprint ([A-Za-z0-9_.\-]+),(\d+),([A-Za-z0-9_.\-]+),(\d+),(\d+),(-?\d+)\s*$")

# objdump -d: "08001234 <symbol>:" starts a function body.
FUNC_RE = re.compile(r"^([0-9a-f]+) <([^>]+)>:")
# A direct branch with a resolved target: "... bl 8001234 <symbol>" (possibly
# "<symbol+0x8>", which is a branch into the middle of a function -- still an edge
# to that function).
CALL_RE = re.compile(r"\b(?:bl|blx|b|b\.w|b\.n|bx)\s+[0-9a-f]+ <([^>+]+)(?:\+0x[0-9a-f]+)?>")


class Failure(Exception):
    pass


def symbol_sizes(elf):
    """symbol -> size, for code symbols only (nm type T/t/W/w)."""
    out = subprocess.run([NM, "-S", "--defined-only", elf],
                         capture_output=True, text=True, check=True).stdout
    sizes = {}
    for line in out.splitlines():
        f = line.split()
        # "addr size type name" -- symbols without a size have only 3 fields.
        if len(f) != 4:
            continue
        addr, size, typ, name = f
        if typ not in ("T", "t", "W", "w"):
            continue
        sizes[name] = int(size, 16)
    return sizes


def call_graph(elf):
    """symbol -> set of directly-called symbols."""
    out = subprocess.run([OBJDUMP, "-d", elf],
                         capture_output=True, text=True, check=True).stdout
    graph = collections.defaultdict(set)
    cur = None
    for line in out.splitlines():
        m = FUNC_RE.match(line)
        if m:
            cur = m.group(2)
            graph.setdefault(cur, set())
            continue
        if cur is None:
            continue
        m = CALL_RE.search(line)
        if m and m.group(1) != cur:
            graph[cur].add(m.group(1))
    return graph


def closure(roots, graph, sizes):
    """Transitive closure of `roots`, and its total size.

    Unknown targets (a branch to a symbol nm reported no size for -- a PLT-less
    veneer, an assembly label) contribute nothing to the total but are still
    followed, so a kernel reached only through such a label is not lost.
    """
    seen, stack, missing = set(), list(roots), []
    while stack:
        s = stack.pop()
        if s in seen:
            continue
        seen.add(s)
        if s not in sizes:
            missing.append(s)
        stack.extend(graph.get(s, ()))
    return seen, sum(sizes.get(s, 0) for s in seen), missing


def roots_for(impl, rounds, kid, block_bytes, cipher):
    """The entry symbols a product build of this (impl, cipher) would need.

    Returns None when the impl has no kernel on this target, which is not an
    error -- the firmware does not emit a footprint line for those.
    """
    if block_bytes == 8:
        if impl == "ref":
            return ["present_encrypt_ref"]
        if impl == "table":
            # The fixed-round specialisation is what the speed row times, so it is
            # what the footprint must describe. Reached through a function pointer,
            # hence named rather than discovered -- see the module docstring.
            return ["present_encrypt_table_r%d" % rounds]
        if impl == "table-x4":
            return ["present_encrypt_table_x4"]
        if kid < 0:
            return None
        if impl in ("bitslice32", "bitslice32-bs"):
            r = ["bs32_enc_k%d" % kid]
            if impl == "bitslice32":
                r += ["present_bitslice32_pack", "present_bitslice32_unpack"]
            return r
        if impl in ("bitslice64", "bitslice64-bs"):
            r = ["bs_enc_k%d" % kid]
            if impl == "bitslice64":
                r += ["present_transpose64"]
            return r
        return None

    if block_bytes == 16:
        # The 128-bit kernels are `static inline` in bench/wide_ciphers.h and leave
        # no symbol of their own. The roots are the harness's per-round-count pass
        # wrappers, which exist as symbols precisely so this analysis has something
        # to close over -- so these figures include the working-set loop around the
        # kernel, unlike the 64-bit rows. See the note in bench_m4_main.c.
        if impl == "ref":
            return ["lin_ref_pass_r%d" % rounds]
        if impl == "table":
            return ["aes_table_pass_r%d" % rounds]
        if impl == "table-x4":
            return ["aes_table_x4_pass_r%d" % rounds]
        # Same for the bitsliced pair: the kernels themselves are inlined into the
        # harness wrappers (GCC clones some of them and inlines others outright --
        # `aes_encrypt_bs32_bs` leaves no symbol at all), so the wrapper is the only
        # stable root. Uniform across all four 128-bit impls for that reason.
        fam = "lin" if "lin444" in cipher else "aes"
        if impl == "bitslice32":
            return ["%s_bs32_pass_r%d" % (fam, rounds)]
        if impl == "bitslice32-bs":
            return ["%s_bs32_bs_pass_r%d" % (fam, rounds)]
        return None
    return None


def resolve_roots(names, sizes):
    """Map wanted root names onto the symbols the ELF actually defines.

    Two mismatches are routine and neither is a fault:
      * `static` functions that GCC cloned for constant propagation appear as
        `name.constprop.0`, and inlining can leave `name.isra.0` / `name.part.0`.
      * A `static inline` in a header instantiated in several objects appears
        several times; the sizes are equal, so any one of them is the right answer
        and taking the largest is a safe tie-break.
    Returns (resolved, unresolved).
    """
    resolved, unresolved = [], []
    for want in names:
        if want in sizes:
            resolved.append(want)
            continue
        cands = [s for s in sizes
                 if s == want or s.startswith(want + ".")]
        if cands:
            resolved.append(max(cands, key=lambda s: sizes[s]))
        else:
            unresolved.append(want)
    return resolved, unresolved


def parse_stream(text):
    """The firmware's footprint lines, in emission order."""
    rows = []
    for line in text.splitlines():
        m = FOOTPRINT_RE.match(line.strip())
        if m:
            rows.append({
                "cipher": m.group(1),
                "rounds": int(m.group(2)),
                "impl": m.group(3),
                "state": int(m.group(4)),
                "work": int(m.group(5)),
                "kid": int(m.group(6)),
            })
    return rows


def block_bytes_of(cipher):
    """8 or 16, from the cipher set rather than from the name's shape."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import cipher_set
    for path, name, _rounds in cipher_set.resolve():
        if name == cipher:
            return 16 if cipher_set.is_wide(path) else 8
    raise Failure("cipher %r is not in the benchmarked set" % cipher)


def build(rows, elf):
    sizes = symbol_sizes(elf)
    graph = call_graph(elf)
    out = []
    for r in rows:
        bb = block_bytes_of(r["cipher"])
        want = roots_for(r["impl"], r["rounds"], r["kid"], bb, r["cipher"])
        if want is None:
            out.append(dict(r, flash=None, note="no entry symbol for this impl"))
            continue
        found, unresolved = resolve_roots(want, sizes)
        if unresolved:
            out.append(dict(r, flash=None,
                            note="unresolved: " + " ".join(sorted(unresolved))))
            continue
        _syms, total, missing = closure(found, graph, sizes)
        note = ""
        if missing:
            note = "sizeless targets followed: " + " ".join(sorted(set(missing))[:4])
        out.append(dict(r, flash=total, note=note))
    return out


def render(rows, elf, image_note):
    w = []
    w.append("# results/m4-footprint.csv -- per-kernel Flash and RAM, Cortex-M4.")
    w.append("#")
    w.append("# THIS IS NOT results/m4-speed.csv's memory figures, and it is meant to")
    w.append("# replace how they get quoted. Those three lines (ccm used, bss used,")
    w.append("# stack peak) describe the benchmark image, which holds every")
    w.append("# implementation family at once; the ~57 KiB of CCM in particular is not")
    w.append("# any cipher's footprint and never was. Each row below is what ONE kernel")
    w.append("# needs, sized to the round count that was measured.")
    w.append("#")
    w.append("# flash_bytes   code only: the transitive closure of direct calls from")
    w.append("#               this kernel's entry point, over the linked ELF's")
    w.append("#               per-function sections. Excludes .rodata, so a cipher")
    w.append("#               whose constant tables live in flash is undercounted here")
    w.append("#               and a cipher whose tables are built into RAM is charged")
    w.append("#               for them in ram_state_bytes instead. Compare the pair,")
    w.append("#               never one column alone.")
    w.append("# ram_state_bytes  persistent: round keys, plus any table built in RAM.")
    w.append("# ram_work_bytes   transient: buffers live only inside a call.")
    w.append("#               Caller-owned plaintext/ciphertext excluded from both, so")
    w.append("#               kernels with different block counts stay comparable.")
    w.append("#")
    w.append("# Produced by tools/m4_footprint.py; read its docstring for the three")
    w.append("# limits of the Flash analysis before quoting a flash_bytes figure.")
    w.append("# RAM comes from the firmware's own emission, Flash from the ELF:")
    w.append("#   %s" % image_note)
    w.append("#")
    w.append("cipher,rounds,impl,flash_bytes,ram_state_bytes,ram_work_bytes,note")
    for r in rows:
        w.append("%s,%d,%s,%s,%d,%d,%s" % (
            r["cipher"], r["rounds"], r["impl"],
            "" if r["flash"] is None else r["flash"],
            r["state"], r["work"], r["note"]))
    return "\n".join(w) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--elf", default=os.path.join(ROOT, "build", "m4", "bench_m4.elf"))
    ap.add_argument("--stream", required=True,
                    help="a run log containing the firmware's `footprint` lines")
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "m4-footprint.csv"))
    args = ap.parse_args()

    with open(args.stream, encoding="utf-8", errors="replace") as fh:
        rows = parse_stream(fh.read())
    if not rows:
        raise Failure("no `footprint` lines in %s -- is this a bench_m4 run from a "
                      "firmware new enough to emit them?" % args.stream)

    built = build(rows, args.elf)
    note = "%s" % os.path.relpath(args.elf, ROOT)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(render(built, args.elf, note))
    print("wrote %s (%d rows)" % (args.out, len(built)))


if __name__ == "__main__":
    try:
        main()
    except Failure as e:
        sys.stderr.write("m4_footprint: %s\n" % e)
        sys.exit(1)
