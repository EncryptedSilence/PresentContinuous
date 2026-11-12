#!/usr/bin/env python3
"""Trace-driven cycle estimate for Cortex-M4 and Cortex-A7 (no board available).

Input: an ELF, the qemu-arm log of `-one-insn-per-tb -d exec,nochain` (one line
per executed instruction, PC in the second bracketed field), and the REGION
lines bench_arm.c printed. Regions are the instruction runs between consecutive
entries into ca_mark(); region 0 is empty and gives the marker overhead, which
is subtracted from every other region.

Each executed instruction is priced from its disassembly (arm-none-eabi-objdump)
and from what really happened next in the trace (a branch is taken iff the next
PC is not the fall-through address).

--core m4: the ARM Cortex-M4 TRM (r0p1, table 3-1) costs, zero-wait memory:
  ALU incl. shifted/rotated operand 1;  MUL/MLA/UMULL/SMULL/(U|S)MLAL 1;
  LDR single 2, but 1 when it directly follows a single LDR and its address
  registers are not that LDR's destination (the TRM's "neighbouring load and
  store single instructions can pipeline"; a load-to-address dependency cannot);
  STR with immediate offset 1 (TRM: "STR Rx,[Ry,#imm] is always one cycle",
  the write completes while later instructions execute); other STR 2, or 1
  after a single LDR;  LDRD/STRD 3;  LDM/STM/PUSH/POP 1+N;
  taken branch 1+P with P=2 (TRM: P = 1..3; an assumption, not a measurement);
  LDR into PC 3+P, LDM/POP with PC 1+N+P, TBB/TBH 2+P;
  not-taken conditional branch 1;  IT 0 after a 16-bit instruction (folded,
  approximate: the TRM's folding conditions are narrower) else 1;
  UDIV/SDIV 7 (TRM 2..12).
  Predication: qemu traces condition-failed instructions too (in IT blocks and,
  on the A7, conditional ARM instructions); both cores issue them, so each is
  charged -- at its opcode's price, which overstates a failed load or store by
  about one cycle. None of the measured kernels here has a conditional memory
  access or conditional branch inside its loops (checked when written).
  ALU -> address dependency: no extra stall is modelled (the M4 forwards ALU
  results to the AGU); this, and the store-buffer rules, are where the M4
  model is least certain -- see the calibration residuals in the report.
--core a7: an in-order dual-issue scoreboard (class A7). Arm publishes no
  instruction-level A7 timing; the slot structure follows GCC's Arm-contributed
  cortex-a7.md, the remaining free parameters were FITTED on measured PRESENT
  kernels from the project's Cortex-A7 board (a7_params(), tools/calib/fit_a7.py,
  which also reports the sensitivity of every estimate to the parameter sets
  the fit cannot reject). Operands are decoded per instruction form (Thumb
  two-operand ALU, NZCV, writeback, register lists, NEON transposes). NEON runs
  on its own in-order cursor behind a bounded queue, 1 cycle per 64-bit half.
"""
import argparse
import bisect
import collections
import csv
import re
import subprocess
import sys

TRACE_RE = re.compile(rb"Trace \d+: 0x[0-9a-f]+ \[[0-9a-f]+/([0-9a-f]+)/")
DIS_RE = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{4,8} ?)+)\s+(\S+)\s*(.*)$")
REG_RE = re.compile(r"\b(r1[0-5]|r[0-9]|sb|sl|fp|ip|sp|lr|pc|[dq][0-9]{1,2}|s[0-9]{1,2})\b")
ALIAS = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12", "sp": "r13", "lr": "r14", "pc": "r15"}

COND = r"(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)?"


def disassemble(elf):
    out = subprocess.run(["arm-none-eabi-objdump", "-d", "--no-show-raw-insn", elf],
                         capture_output=True, text=True, check=True).stdout
    # --no-show-raw-insn loses sizes; get them from a raw listing instead
    raw = subprocess.run(["arm-none-eabi-objdump", "-d", elf], capture_output=True, text=True, check=True).stdout
    ins = {}
    for line in raw.splitlines():
        m = DIS_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        hexes = m.group(2).split()
        size = sum(len(h) // 2 for h in hexes)
        mnem = m.group(3)
        ops = m.group(4).split(";")[0].split("@")[0].strip()
        ins[addr] = (mnem, ops, size)
    syms = subprocess.run(["arm-none-eabi-nm", elf], capture_output=True, text=True, check=True).stdout
    mark = None
    for line in syms.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] == "ca_mark":
            mark = int(p[0], 16) & ~1
    if mark is None:
        sys.exit("ca_mark not found in ELF")
    return ins, mark


def regs(s):
    return [ALIAS.get(r, r) for r in REG_RE.findall(s)]


def base_mnem(m):
    m = m.lower()
    for suf in (".w", ".n"):
        if m.endswith(suf):
            m = m[:-2]
    return m


def reglist_count(ops):
    m = re.search(r"\{([^}]*)\}", ops)
    if not m:
        return 1
    n = 0
    for part in m.group(1).split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ra, rb = regs(a), regs(b)
            if ra and rb and ra[0][0] == rb[0][0]:
                n += int(rb[0][1:]) - int(ra[0][1:]) + 1
                continue
        n += 1
    return n


LOAD1 = re.compile(r"^ldr(b|h|sb|sh|ex|t|bt|ht)?" + COND + "$")
STORE1 = re.compile(r"^str(b|h|ex|t|bt|ht)?" + COND + "$")
LDRD = re.compile(r"^(ldr|str)d" + COND + "$")
MULTI = re.compile(r"^(ldm|stm)(ia|ib|da|db|fd|ea)?" + COND + "$|^(push|pop)" + COND + "$")
BRANCH = re.compile(r"^(b|bl|blx|bx)" + COND + "$|^cbn?z$|^tb[bh]$")
MUL = re.compile(r"^(mul|mla|mls|umull|smull|umlal|smlal|smul..|smla..|smmul|smmla|smlad|smuad)s?" + COND + "$")
DIV = re.compile(r"^[us]div" + COND + "$")


M4_P = 2  # pipeline refill after a taken branch (TRM: 1..3)
M4_AGU_STALL = 0  # extra cycle when a load/store address uses the previous ALU result (--m4-agu-stall)


def _addr_regs(ops):
    """Registers inside the [...] address operand."""
    m = re.search(r"\[([^\]]*)\]", ops)
    return regs(m.group(1)) if m else []


def m4_cost(mnem, ops, size, taken, prev):
    """Returns (cycles, state) for one executed instruction; prev = previous
    state (kind, size, destination registers)."""
    m = base_mnem(mnem)
    if m.startswith("it"):
        return (0 if prev and prev[1] == 2 else 1), ("it", size, [])
    agu = M4_AGU_STALL if (prev and prev[0] == "alu" and (LOAD1.match(m) or STORE1.match(m) or LDRD.match(m))
                           and set(_addr_regs(ops)) & set(prev[2])) else 0
    c, st = _m4_cost(m, ops, size, taken, prev)
    return c + agu, st


def _m4_cost(m, ops, size, taken, prev):
    if m.startswith("tb") and BRANCH.match(m):
        return 2 + M4_P, ("br", size, [])
    if LOAD1.match(m) and not LDRD.match(m):
        dst = regs(ops.split(",")[0])
        pipelined = prev and prev[0] == "ld" and not (set(_addr_regs(ops)) & set(prev[2]))
        c = 1 if pipelined else 2
        if dst == ["r15"]:
            c = 3 + M4_P
        return c, ("ld", size, dst)
    if STORE1.match(m) and not LDRD.match(m):
        a = _addr_regs(ops)
        imm_off = len(a) == 1 and "]!" not in ops and not re.search(r"\],\s*r", ops)
        if imm_off:
            c = 1
        else:
            c = 1 if prev and prev[0] == "ld" and not (set(a) & set(prev[2])) else 2
        return c, ("st", size, [])
    if LDRD.match(m):
        return 3, ("ldd", size, regs(ops)[:2] if m.startswith("ldr") else [])
    if MULTI.match(m):
        n = reglist_count(ops)
        c = 1 + n
        if (m.startswith("pop") or m.startswith("ldm")) and "pc" in ops:
            c += M4_P
        return c, ("multi", size, [])
    if BRANCH.match(m):
        return (1 + M4_P if taken else 1), ("br", size, [])
    if MUL.match(m):
        return 1, ("alu", size, [])
    if DIV.match(m):
        return 7, ("alu", size, [])
    if regs(ops.split(",")[0])[:1] == ["r15"] and taken:  # mov pc / add pc
        return 1 + M4_P, ("br", size, [])
    return 1, ("alu", size, regs(ops.split(",")[0])[:1])


class FlashART:
    """INSTRUCTION-FETCH-ONLY sensitivity model, not a model of the STM32F4
    memory system: data reads from flash (literal pools, constant tables), the
    D-Code path and bus arbitration between fetch and data are not modelled.
    Fetch side (--flash-ws N): 128-bit lines, ART instruction cache of
    64 lines (fully associative LRU assumed), one sequential prefetch line. A line
    not in the cache costs N+1 cycles from request; the prefetch of line+1 starts
    when a line is first fetched. Returns the stall before an instruction issues."""

    def __init__(self, ws, lines=64):
        self.ws = ws
        self.cache = collections.OrderedDict()
        self.lines = lines
        self.pf_line, self.pf_ready = None, 0

    def fetch(self, pc, size, now):
        stall = 0
        for line in {pc >> 4, (pc + size - 1) >> 4}:
            if line in self.cache:
                self.cache.move_to_end(line)
                continue
            t = now + stall
            if line == self.pf_line:
                stall += max(0, self.pf_ready - t)
            else:
                stall += self.ws + 1
            self.cache[line] = True
            if len(self.cache) > self.lines:
                self.cache.popitem(last=False)
            self.pf_line, self.pf_ready = line + 1, now + stall + self.ws + 1
        return stall


CONDS = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le")
DP = {"add", "adc", "sub", "sbc", "rsb", "rsc", "and", "orr", "eor", "bic", "orn", "mov", "mvn", "lsl", "lsr",
      "asr", "ror", "mul", "neg", "cmp", "cmn", "tst", "teq", "mla", "mls", "ubfx", "sbfx", "bfi", "bfc", "uxtb",
      "uxth", "sxtb", "sxth", "rev", "rev16", "clz", "movw", "movt", "ldr", "str", "ldrb", "strb", "ldrh", "strh",
      "ldrd", "strd", "umull", "smull", "rrx", "pkhbt", "pkhtb", "uxtab", "uxtah", "rbit", "adr"}
TWO_OP = {"add", "adc", "sub", "sbc", "and", "orr", "eor", "bic", "orn", "lsl", "lsr", "asr", "ror", "mul"}
NO_DEST = {"cmp", "cmn", "tst", "teq"}
FLAG_READ = {"adc", "sbc", "rsc", "rrx"}
NEON_RW = ("vtrn", "vzip", "vuzp", "vswp")
NEON_READS_DEST = ("vsri", "vsli", "vmla", "vmls", "vbsl", "vbit", "vbif", "vtbx", "vsra", "vrsra", "vaba")


def split_cond(m):
    """'addeq' -> ('add', 'eq'); 'eors' -> ('eors', None). Flag-setting 's' kept."""
    for c in CONDS:
        if m.endswith(c) and len(m) > 2:
            b = m[:-2]
            if b in DP or (b.endswith("s") and b[:-1] in DP):
                return b, c
    return m, None


def regs_x(s):
    """Registers in an operand string, register-list ranges (r4-r7, d0-d3) expanded."""
    out = []
    for part in re.split(r"(\{[^}]*\})", s):
        if part.startswith("{"):
            for item in part[1:-1].split(","):
                item = item.strip()
                if "-" in item:
                    a, b = (regs(x) for x in item.split("-", 1))
                    if a and b and a[0][0] == b[0][0] and a[0][1:].isdigit() and b[0][1:].isdigit():
                        out += ["%s%d" % (a[0][0], i) for i in range(int(a[0][1:]), int(b[0][1:]) + 1)]
                        continue
                out += regs(item)
        else:
            out += regs(part)
    return out


def _q2d(lst):
    o = []
    for r in lst:
        if r[0] == "q":
            i = int(r[1:])
            o += ["d%d" % (2 * i), "d%d" % (2 * i + 1)]
        else:
            o.append(r)
    return o


def a7_decode(mnem, ops):
    """(class, base mnemonic, dests, srcs, shifted_src, writes_flags, writeback).
    dests/srcs in D-register / rN names, flags as pseudo-register 'nzcv'."""
    m = base_mnem(mnem)
    if m.startswith("v"):
        rs = _q2d(regs_x(ops))
        if m in ("vpush", "vpop"):
            lst = _q2d(regs_x(ops))
            if m == "vpop":
                return "nld", m, lst + ["r13"], ["r13"], None, False, "r13"
            return "nst", m, ["r13"], lst + ["r13"], None, False, "r13"
        if m.startswith(("vld", "vst")):
            braces = re.search(r"\{([^}]*)\}", ops)
            lst = _q2d(regs_x("{" + braces.group(1) + "}")) if braces else [r for r in rs if r[0] == "d"]
            addr = _addr_regs(ops)
            wb = addr[0] if addr and ("]!" in ops or re.search(r"\],\s*r", ops)) else None
            if m.startswith("vld"):
                srcs = addr + (lst if braces and "[" in braces.group(1) else [])  # lane load merges
                d = lst + ([wb] if wb else [])
                return "nld", m, d, srcs, None, False, wb
            return "nst", m, [wb] if wb else [], lst + addr, None, False, wb
        if m.startswith(("vmov", "vdup")) and rs and rs[0][0] == "r":
            return "f2r", m, [r for r in rs if r[0] == "r"], [r for r in rs if r[0] == "d"], None, False, None
        if m.startswith(("vmov", "vdup")) and any(r[0] == "r" for r in rs):
            return "r2f", m, [r for r in rs if r[0] == "d"], [r for r in rs if r[0] == "r"], None, False, None
        if m.startswith(NEON_RW):
            return "neon", m, rs, rs, None, False, None
        if not rs:
            return "neon", m, [], [], None, False, None
        first = _q2d(regs_x(ops.split(",")[0]))
        srcs = [r for r in rs if r not in first] if not m.startswith(NEON_READS_DEST) else rs
        if m.startswith(("vtbl",)):
            srcs = rs[len(first):]
        return "neon", m, first, srcs, None, False, None
    if m.startswith("it"):
        return "it", m, [], ["nzcv"], None, False, None
    b, cond = split_cond(m)
    rs = regs_x(ops)
    readsf = cond is not None
    if BRANCH.match(m) or BRANCH.match(b):
        c = re.match(r"^b(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)$", m)
        return "br", m, (["r14"] if m.startswith("bl") else []), rs + (["nzcv"] if c else []), None, False, None
    if MULTI.match(m):
        lst = regs_x(re.search(r"\{[^}]*\}", ops).group(0)) if "{" in ops else []
        base = ["r13"] if m.startswith(("push", "pop")) else regs(ops.split(",")[0])[:1]
        wb = base[0] if base and (m.startswith(("push", "pop")) or "!" in ops.split(",")[0]) else None
        if m.startswith(("ldm", "pop")):
            return "multi", m, lst + ([wb] if wb else []), base, None, False, wb
        return "multi", m, [wb] if wb else [], lst + base, None, False, wb
    if LDRD.match(m) or LOAD1.match(m) or STORE1.match(m):
        k = "ldd" if LDRD.match(m) else ("ld" if LOAD1.match(m) else "st")
        addr = _addr_regs(ops)
        head = ops.split("[")[0]
        data = regs_x(head)
        wb = addr[0] if addr and ("]!" in ops or re.search(r"\],\s*(#|r|sb|sl|fp|ip|lr)", ops)) else None
        if k == "st" or m.startswith("strd"):
            k = "st" if k == "st" else "ldd"
            return k, m, [wb] if wb else [], data + addr + (["nzcv"] if readsf else []), None, False, wb
        return k, m, data + ([wb] if wb else []), addr + (["nzcv"] + data if readsf else []), None, False, wb
    core = b[:-1] if (b.endswith("s") and b[:-1] in DP) else b
    wflags = core in NO_DEST or (b != core)
    readsf = readsf or core in FLAG_READ
    if MUL.match(m) or MUL.match(b):
        k = "mul"
    elif DIV.match(m):
        k = "div"
    elif re.search(r",\s*(lsl|lsr|asr|ror)\s+r", ops):
        k = "regsh"
    elif re.search(r",\s*(lsl|lsr|asr|ror|rrx)", ops):
        k = "immsh"
    elif "#" in ops:
        k = "alui"
    else:
        k = "alu"
    if core in NO_DEST:
        dests, srcs = [], rs
    else:
        dests, srcs = rs[:1], rs[1:]
        nops = len([x for x in ops.split(",") if x.strip()])
        if core in TWO_OP and nops == 2:      # Thumb 2-operand form: rd = rd op rm/#imm
            srcs = rs
        if cond:                              # a failed condition keeps the old value
            srcs = srcs + rs[:1]
        if core in ("movt", "bfi", "bfc"):
            srcs = srcs + rs[:1]
    sh = None
    msh = re.search(r"(\w+)\s*,\s*(lsl|lsr|asr|ror)\b", ops)
    if k in ("immsh", "regsh") and msh:
        sh = (regs(msh.group(1)) or [None])[0]
    if wflags:
        dests = dests + ["nzcv"]
    if readsf:
        srcs = srcs + ["nzcv"]
    return k, m, dests, srcs, sh, wflags, None


class A7:
    """In-order dual-issue scoreboard for Cortex-A7 (see module docstring).

    Integer side: one cursor `t`; an instruction issues at max(t, operands ready).
    It may take the younger slot of a pair when the previous instruction issued
    alone, (older class, younger class) is in `dual`, and it does not read the
    older one's results. Slot eligibility follows the Arm-contributed GCC
    cortex-a7.md: immediate ALU ops and branches may be younger; register and
    shifted-operand ALU ops, loads and stores only older; multiplies, LDRD/STRD,
    LDM/STM, register-shifted ops and NEON dispatch never pair (the last is a
    fitted option). Results forward in 1 cycle, +shift_fwd when consumed as the
    shifted operand (GCC's bypass rules), loads in load_lat.
    NEON side: its own in-order cursor `tn` behind a queue of `nqueue` entries
    (dispatch stalls while it is full); an op costs 1 cycle per 64-bit half, a
    load/store 1 per D register (64-bit load/store path). Core->NEON transfers
    go through the queue; NEON->core transfers wait for the value. Scalar loads
    wait for every earlier NEON store to complete (no address trace, so any of
    them may alias -- the conservative choice). Region time = max(t, tn)."""

    def __init__(self, p):
        self.p = p
        self.t = 0
        self.tn = 0
        self.ready = collections.defaultdict(int)
        self.alu_made = set()        # registers whose latest producer was an integer ALU op
        self.prev_alone = None       # (issue cycle, class, dests) of previous lone integer issue
        self.bp = {}                 # pc -> 2-bit counter (0..3, >=2 predicts taken)
        self.nq = collections.deque()  # start times of queued/executing NEON ops
        self.nst_done = 0

    def step(self, mnem, ops, size, taken, pc=0):
        p = self.p
        k, m, dests, srcs, sh, wflags, wb = a7_decode(mnem, ops)
        srcs = [r for r in srcs if r != "r15"]
        rdy = 0
        for r in srcs:
            v = self.ready[r]
            if r == sh and r in self.alu_made:
                v += p["shift_fwd"]
            rdy = max(rdy, v)

        if k in ("neon", "nld", "nst", "r2f"):
            # wait for a queue entry, then dispatch in an integer slot
            Q = p["nqueue"]
            while self.nq and self.nq[0] <= self.t:
                self.nq.popleft()
            if len(self.nq) >= Q:
                self.t = max(self.t, self.nq[len(self.nq) - Q])
                self.prev_alone = None
            disp = self._int_issue("ndisp", [], [], 1)
            if k in ("nld", "nst"):
                n = len([r for r in (dests if k == "nld" else srcs) if r[0] == "d"])
                cost, lat = max(1, n), p["nload_lat"]
            elif k == "r2f":
                cost, lat = 1, p["r2f_lat"]
            else:
                cost = 2 if "q" in ops.lower() and re.search(r"\bq\d", ops) else 1
                lat = p["neon_slow_lat"] if m.startswith(p["neon_slow"]) else p["neon_lat"]
            start = max(self.tn, rdy, disp)
            self.tn = start + cost
            self.nq.append(start)
            for d in dests:
                if d[0] == "r":  # base-register writeback happens at dispatch
                    self.ready[d] = disp + 1
                    self.alu_made.discard(d)
                else:
                    self.ready[d] = start + cost - 1 + lat
            if k == "nst":
                self.nst_done = max(self.nst_done, start + cost)
            return max(self.t, self.tn)
        if k == "f2r":
            start = self._int_issue("f2r", srcs, dests, 1, rdy)
            for d in dests:
                self.ready[d] = start + p["f2r_lat"]
                self.alu_made.discard(d)
            return max(self.t, self.tn)

        cost = {"ldd": 1, "multi": max(1, (len([r for r in (dests + srcs) if r[0] == "r" and r != wb]) + 1) // 2),
                "regsh": p["regsh_cost"], "it": 0, "div": p["div_cost"]}.get(k, 1)
        lat = {"ld": p["load_lat"], "ldd": p["load_lat"], "multi": p["load_lat"], "mul": p["mul_lat"],
               "regsh": 2, "div": p["div_cost"]}.get(k, 1)
        if k in ("ld", "ldd") or (k == "multi" and m.startswith(("ldm", "pop"))):
            rdy = max(rdy, self.nst_done)
        start = self._int_issue(k, srcs, dests, cost, rdy)
        for d in dests:
            self.ready[d] = start + (1 if d == wb else lat)
            if k in ("alu", "alui", "immsh", "regsh", "mul") and d != "nzcv":
                self.alu_made.add(d)
            else:
                self.alu_made.discard(d)
        if k == "br":
            conditional = bool(re.match(r"^(b(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)|cbn?z)$", m))
            if conditional:
                c = self.bp.get(pc, 1)
                if (c >= 2) != taken:
                    self.t += p["mispredict"]
                    self.prev_alone = None
                self.bp[pc] = min(3, c + 1) if taken else max(0, c - 1)
            if taken:
                self.t += p["taken_br"]
                self.prev_alone = None
        elif "r15" in dests and taken:
            self.t += p["taken_br"] + 2
            self.prev_alone = None
        return max(self.t, self.tn)

    def _int_issue(self, k, srcs, dests, cost, rdy=0):
        pa = self.prev_alone
        if (pa is not None and (pa[1], k) in self.p["dual"] and rdy <= pa[0]
                and not (set(srcs) & set(pa[2])) and not (set(dests) & set(pa[2]))):
            self.prev_alone = None
            return pa[0]
        start = max(self.t, rdy)
        self.t = start + max(cost, 1 if k != "it" else 0)
        self.prev_alone = (start, k, dests) if cost <= 1 and k not in ("it", "ldd", "mul", "div", "multi", "regsh") else None
        return start


# Pairing rules. "gcc" is the structure of GCC's cortex-a7.md (older slot: any
# single-cycle integer op; younger slot: immediate ALU or branch; no branch pair).
# The other entries are fitted alternatives, kept for the sensitivity report.
DUAL_SETS = {
    "gcc": "alui|alu|immsh|ld|st|br|f2r-alui|br",
    "gcc+ndisp": "alui|alu|immsh|ld|st|br|f2r-alui|br,ndisp-alui|alu|br,alui|alu-ndisp",
    "gcc+regreg": "alui|alu|immsh|ld|st|br|f2r-alui|alu|br",
}


# Defaults: the best of 48 candidates (tools/calib/fit_a7.py) on four measured
# PRESENT kernels (Orange Pi R1, results/speed-arm.csv, 1296 MHz): table +5.4%,
# bitslice -6.1%, neon +7.6%, ref +6.2%. Not fitted, from GCC cortex-a7.md or
# assumed: slot structure, regsh/mul/div costs, r2f/f2r latencies, the NEON
# 1-cycle-per-64-bit rule. Checked against figures never used in the fit:
# ascon-c/neon 27.2 (sensitivity range 27.2..30.2) vs 30.7 c/B measured by the
# designers; scalar ascon-c/armv6 34.7 vs eBACS's 37.5 (Ascon v1.2-era code and
# compiler, an indirect anchor only). The fit report lists every candidate.
def a7_params(dual="gcc+regreg", **kw):
    pairs = set()
    for grp in DUAL_SETS.get(dual, dual).split(","):
        old, young = grp.split("-")
        for a in old.split("|"):
            for b in young.split("|"):
                if not (a == "br" and b == "br"):
                    pairs.add((a, b))
    p = dict(load_lat=3, mul_lat=3, regsh_cost=2, shift_fwd=0, div_cost=5, neon_lat=3, nload_lat=4,
             neon_slow_lat=4, neon_slow=("vmul", "vmla", "vtbl", "vtbx", "vzip", "vuzp", "vtrn", "vext", "vrev"),
             r2f_lat=4, f2r_lat=2, nqueue=16, taken_br=3, mispredict=12, dual=pairs, dual_name=dual)
    p.update(kw)
    return p


A7_PARAMS = a7_params()


def run(elf, trace, core, a7p=None, flash_ws=None, flash_lines=64):
    ins, mark = disassemble(elf)
    sizes = {}
    pcs = []
    with open(trace, "rb") as f:
        for line in f:
            m = TRACE_RE.match(line)
            if m:
                pcs.append(int(m.group(1), 16))
    regions = []
    cur = None
    bad = collections.Counter()  # unknown / data PCs per interval
    a7 = A7(a7p or A7_PARAMS) if core == "a7" else None
    flash = FlashART(flash_ws, flash_lines) if flash_ws is not None else None
    now = 0
    prev = None
    cyc = 0
    counts = 0
    last_t = 0
    unknown = 0
    for i, pc in enumerate(pcs):
        if pc == mark:
            if cur is not None:
                regions.append((cur[0], cyc, counts, core_cyc))
            cur = (len(regions),)
            cyc = 0
            core_cyc = 0
            counts = 0
            if a7:
                last_t = max(a7.t, a7.tn)
        if cur is None:
            continue
        info = ins.get(pc)
        if info is None or info[0].startswith("."):
            bad[cur[0]] += 1
            unknown += 1
            cyc += 1
            core_cyc += 1
            counts += 1
            continue
        mnem, ops, size = info
        nxt = pcs[i + 1] if i + 1 < len(pcs) else pc + size
        taken = nxt != pc + size
        if a7:
            t = a7.step(mnem, ops, size, taken, pc)
            cyc = t - last_t
            core_cyc = cyc
        else:
            c, prev = m4_cost(mnem, ops, size, taken, prev)
            core_cyc += c
            if flash:
                c += flash.fetch(pc, size, now)
            now += c
            cyc += c
        counts += 1
    measured_bad = {k: v for k, v in bad.items() if k % 2 == 0}
    if measured_bad:
        sys.exit("error: executed PCs with no instruction in the disassembly inside measured "
                 "intervals %s" % sorted(measured_bad.items()))
    if unknown:
        print("warning: %d unknown PCs in harness (unmeasured) code" % unknown, file=sys.stderr)
    # The pattern is mark() [region] mark() ...; every second interval between
    # marks is a measured region, the others are harness code (printf etc.).
    return regions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", choices=["m4", "a7"], required=True)
    ap.add_argument("--elf", required=True)
    ap.add_argument("--trace", required=True)
    ap.add_argument("--regions", required=True)
    ap.add_argument("--csv")
    ap.add_argument("--flash-ws", type=int, help="m4: model STM32F4 flash + ART with this many wait states")
    ap.add_argument("--flash-lines", type=int, default=64,
                    help="m4 --flash-ws: ART cache lines (1 = ART off: only the current-line buffer)")
    ap.add_argument("--m4-agu-stall", type=int, default=None, help="m4: extra cycles for an ALU->address dependency")
    a = ap.parse_args()
    global M4_AGU_STALL
    if a.m4_agu_stall is not None:
        M4_AGU_STALL = a.m4_agu_stall
    intervals = run(a.elf, a.trace, a.core, flash_ws=a.flash_ws, flash_lines=a.flash_lines)  # trace may be a FIFO: read it first
    labels = [l.split() for l in open(a.regions) if l.startswith("REGION")]
    # marks: region 0 = mark,mark (empty); each later region = mark, call, mark,
    # then harness code until the next region's first mark. So intervals
    # alternate: [region0, gap, region1, gap, region2, ...].
    meas = intervals[0::2]
    if len(intervals) != 2 * len(labels) - 1:
        sys.exit("trace has %d marker intervals, expected %d for %d regions"
                 % (len(intervals), 2 * len(labels) - 1, len(labels)))
    if [int(l[1]) for l in labels] != list(range(len(labels))):
        sys.exit("REGION labels are not numbered 0..n-1")
    # Region 0 (two back-to-back marks) is the marker's own execution cost. Its
    # CORE price is subtracted: under --flash-ws region 0 runs with a cold fetch
    # model, and that one-off miss cost must not be credited to later regions.
    base_c, base_n = meas[0][3], meas[0][2]
    rows = []
    for lab, (_, c, n, _cc) in zip(labels[1:], meas[1:]):
        _, idx, cipher, impl, lanes, msg, total = lab
        c -= base_c
        n -= base_n
        total = int(total)
        rows.append(dict(target=a.core, cipher=cipher, impl=impl, lanes=int(lanes), msg_bytes=int(msg),
                         payload_bytes=total, instructions=n, est_cycles=c,
                         est_cycles_per_byte=round(c / total, 3), est_cycles_per_bit=round(c / total / 8, 4)))
    for r in rows:
        print("%-3s %-9s %-26s L=%d %5d B  %9d insns  %10d cyc  %8.2f cyc/B  %7.3f cyc/bit" % (
            r["target"], r["cipher"], r["impl"], r["lanes"], r["msg_bytes"], r["instructions"],
            r["est_cycles"], r["est_cycles_per_byte"], r["est_cycles_per_bit"]))
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            f.write("# produced_by: chacha_ascon/tools/arm_cycles.py --core %s (trace-driven ESTIMATE, no board)\n" % a.core)
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)


if __name__ == "__main__":
    main()
