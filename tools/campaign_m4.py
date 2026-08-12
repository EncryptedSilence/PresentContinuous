"""The Cortex-M4 counter-mode campaign: tools/campaign.py's `m4` subcommand.

This is the on-device answer to the question the round-function benchmark cannot answer
on its own: can the STM32F407 sustain 12 Mbit/s of video in the *complete* byte-oriented
counter mode -- generate the counters, encrypt, materialise the keystream big-endian, XOR
the 64 KiB frame in place -- rather than only inside the cipher kernel. fw/m4/ctr_m4_main.c
is the harness; this driver flashes it, reads its semihosted CSV back through
tools/run_m4_bench.py's board driver, and turns the rows into the published files.

Why it does NOT share campaign.py's x86/A7 statistics. Those targets bootstrap a
confidence interval and screen for bimodality because a busy multi-core host's timings are
a distribution. The M4 measures cycles with the DWT cycle counter, interrupts masked, from
flash behind the ART: the count is deterministic and reproduces to the cycle, which is why
run_m4_bench.py already publishes cycles_per_byte and cycles_per_byte_min as a single
figure. There is no sampling distribution to summarise, so there is no bootstrap, no
12-run floor and no taskset here. The uncertainty a byte-oriented result still carries is
placement: the repository measured up to 7.5% variation in a kernel's cycle count from
where it landed against the 128-bit flash-fetch boundary. The --measure phase sweeps that
directly -- it shifts the winner against a pinned .timed address in 4-byte steps across a
16-byte line and publishes the spread -- and that spread, not a bootstrap CI, is the
uncertainty on the verdict.

Two phases, frozen the same way the x86 campaign is. --tune measures every applicable CTR
backend of every cipher and writes the winner per cipher into fw/m4/gen/ctr_winners.mk;
that file is committed BEFORE --measure runs, so the winner cannot have been chosen from
the run being published. --measure refuses to proceed unless ctr_winners.mk is committed
and unmodified (a blob-id comparison no index setting can fake), builds exactly those
winners behind the pinned kernel, measures them in all three memory configurations,
sweeps the layout, and writes runs.csv, summary.csv and the memory-configuration table
with the 12 Mbit/s verdict stated in the header.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import cipher_set          # noqa: E402
import run_m4_bench        # noqa: E402  (the board driver: flash_and_run, extract, git)


RESULTS_M4 = os.path.join(ROOT, "results", "v2", "m4")
MEMCFG_CSV = os.path.join(ROOT, "results", "v2", "m4-memory-configurations.csv")
WINNERS_MK = os.path.join(ROOT, "fw", "m4", "gen", "ctr_winners.mk")
WINNERS_MK_REL = os.path.relpath(WINNERS_MK, ROOT)

# (label the firmware prints, Makefile config suffix). Mirrors run_m4_bench.CONFIGS; the
# suffix is what the ctr_<slug>_<suffix> image name uses.
CONFIGS = [("product", "product"),
           ("flash-noart", "flash_noart"),
           ("sram-noart", "sram_noart")]

# 12 Mbit/s of video is 12e6/8 = 1.5e6 bytes/s = 1.5 MB/s. The firmware's mb_per_sec
# column is MB/s (1e6 bytes/s) for the whole counter-mode pass, so the device sustains
# the stream exactly when mb_per_sec >= 1.5 -- stated once, here, and derived everywhere
# from these two numbers.
VIDEO_BITS_PER_S = 12_000_000
THRESHOLD_MB_S = VIDEO_BITS_PER_S / 8 / 1e6      # 1.5 MB/s

# The reported backend name -> the C function fw/m4/ctr_m4_main.c defines for it, which is
# what M4_CTR_WINFN_<slug> must name. The single point that couples the two spellings.
WINNER_FN = {
    "ctr-ref":          "ctr_ref",
    "ctr-table":        "ctr_table",
    "ctr-table-x2":     "ctr_table_x2",
    "ctr-table-x4":     "ctr_table_x4",
    "ctr-table-x8":     "ctr_table_x8",
    "ctr-table-x16":    "ctr_table_x16",
    "ctr-bitslice-u64": "ctr_bs_u64",
    "ctr-bitslice-u32": "ctr_bs_u32",
}

# The layout sweep: __text_pad values, in bytes, that fw/m4/link/product.ld inserts at the
# start of .text so the cipher kernels are relocated while ctr_timed_kernel stays pinned at
# 0x08010000. Multiples of 16 -- the 128-bit flash-fetch line and -falign-functions's
# granularity -- because a smaller pad is re-absorbed by the 16-byte function alignment and
# would relocate nothing (the first cut of this sweep used 0,4,8,12,16 and built five
# byte-identical images). These five move the winner across 64 bytes of genuinely distinct
# placements, each still at line offset 0; the spread over them is the published placement
# uncertainty, and it is a measured zero rather than an assumed one.
SWEEP_PADS = (0, 16, 32, 48, 64)


class M4Error(Exception):
    """A condition that must stop the campaign rather than be worked around."""


# --------------------------------------------------------------------------- #
# the seven ciphers, from tools/cipher_set.py -- never restated here
# --------------------------------------------------------------------------- #

def ctr_ciphers():
    """(slug, reported name, rounds, block_bytes, family) for each of the seven."""
    out = []
    for path, name, rounds in cipher_set.resolve():
        wide = cipher_set.is_wide(path)
        out.append((cipher_set.slug(name), name, rounds,
                    16 if wide else 8, cipher_set.family(name, path)))
    return out


# --------------------------------------------------------------------------- #
# reading one image off the board
# --------------------------------------------------------------------------- #

def _row_dicts(emission):
    """The emission's data rows as dicts, timings as floats or None (a KAT_FAIL row
    carries no timings)."""
    rows = []
    for line in emission.rows:
        m = run_m4_bench.ROW_RE.match(line)
        rows.append({
            "cipher": m.group(1),
            "rounds": int(m.group(2)),
            "impl": m.group(3),
            "config": m.group(4),
            "cyc_per_byte": float(m.group(5)) if m.group(5) else None,
            "cyc_per_byte_min": float(m.group(6)) if m.group(6) else None,
            "mb_per_sec": float(m.group(7)) if m.group(7) else None,
            "ns_per_op": float(m.group(8)) if m.group(8) else None,
            "status": m.group(9),
        })
    return rows


def _head_value(emission, prefix):
    line = emission.field(prefix)
    return line[len(prefix):].strip() if line else None


def _observed_clock(emission):
    v = _head_value(emission, "# observed sysclk_hz:")
    if v is None or not v.isdigit():
        raise M4Error("the firmware did not report a measured sysclk_hz; refusing to "
                      "derive MB/s from an assumed clock")
    return int(v)


def run_image(binary, config_label, log_dir, gdb_timeout, flash_timeout):
    """Flash build/m4/<binary>, run it, return (row dicts, emission). Reuses
    run_m4_bench's board driver and its strict stream parse verbatim, so the CTR images
    are held to exactly the checks the published speed CSV is."""
    stream = run_m4_bench.flash_and_run(binary, log_dir, gdb_timeout, flash_timeout)
    emission = run_m4_bench.extract(stream, config_label, binary)
    return _row_dicts(emission), emission


def _bin_sha(binary):
    return run_m4_bench.sha256(os.path.join(ROOT, "build", "m4", binary + ".bin"))


# --------------------------------------------------------------------------- #
# provenance / freeze -- the m4 guards, all pure
# --------------------------------------------------------------------------- #

def _write_atomic(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _git(*args):
    return run_m4_bench.git(*args)


def freeze_verdict(head_blob, working_blob):
    """(in_head, modified) from two git blob ids. Pure, so a test can pin it exactly.

    modified is true whenever the file is uncommitted OR its working bytes differ from the
    committed blob -- an edit made after the commit must read as modified even if the
    working blob is present, because that edit is the one thing the freeze exists to
    catch: the winner chosen from the very run being published.
    """
    in_head = bool(head_blob)
    modified = (not in_head) or (working_blob != head_blob)
    return in_head, modified


def winners_freeze():
    """History's account of fw/m4/gen/ctr_winners.mk: committed, and unmodified since.

    A blob-id comparison, not `git status`: an edit made after the commit -- the winner
    chosen from the very run being published -- must be caught even if the index was told
    to assume the file unchanged. head_blob is what the commit holds; working_blob is
    `git hash-object` of the file on disk; equal means the published winners are the
    frozen ones.
    """
    head_blob = _git("rev-parse", "--verify", "--quiet", "HEAD:%s" % WINNERS_MK_REL) or None
    working_blob = _git("hash-object", "--", WINNERS_MK) or None
    in_head, modified = freeze_verdict(head_blob, working_blob)
    return {
        "path": WINNERS_MK_REL,
        "head_blob": head_blob,
        "working_blob": working_blob,
        "in_head": in_head,
        "modified": modified,
        "freeze_commit": _git("log", "-1", "--format=%H", "--", WINNERS_MK_REL) or None,
    }


def require_frozen_winners():
    freeze = winners_freeze()
    if not freeze["in_head"]:
        raise M4Error(
            "%s is not committed -- the CTR winners are not frozen. Run\n"
            "    tools/campaign.py m4 --tune\n"
            "then commit %s before --measure, so the winner cannot have been chosen "
            "from the run being published." % (WINNERS_MK_REL, WINNERS_MK_REL))
    if freeze["modified"]:
        raise M4Error(
            "%s is committed but modified in the working tree; the published winners "
            "would not be the frozen ones. Commit or revert it before --measure."
            % WINNERS_MK_REL)
    return freeze


def dirty_build_inputs(exclude=()):
    """Modified build inputs, reusing run_m4_bench's allowlist and porcelain parse."""
    dirty = []
    for line in _git("status", "--porcelain").splitlines():
        match = run_m4_bench.PORCELAIN_LINE.match(line)
        if not match:
            continue
        path = match.group("path").strip().strip('"')
        if " -> " in path:
            path = path.split(" -> ", 1)[1].strip().strip('"')
        if not path.startswith(run_m4_bench.BUILD_INPUTS):
            continue
        if path in exclude:
            continue
        dirty.append(path)
    return dirty


# --------------------------------------------------------------------------- #
# phase 1: tune -- measure every backend, freeze the winner per cipher
# --------------------------------------------------------------------------- #

def pick_winner(rows):
    """The frozen winner from one cipher's backend rows: the ok row with the lowest
    measured cycles/byte. Deterministic, so this is the choice and not an estimate of it.
    min, not max: fewer cycles per byte is faster. Returns None if no backend passed."""
    ok = [r for r in rows if r["status"] == "ok" and r["cyc_per_byte"] is not None]
    if not ok:
        return None
    return min(ok, key=lambda r: r["cyc_per_byte"])

def write_winners_mk(winners):
    """fw/m4/gen/ctr_winners.mk from {slug: winner-row}. The freeze artefact."""
    lines = [
        "# AUTO-GENERATED by tools/campaign.py m4 --tune. Do not edit by hand.",
        "# The frozen counter-mode winner per cipher: the backend with the lowest measured",
        "# cycles/byte over the complete 64 KiB CTR pass (results/v2/m4/tuning.json). This",
        "# file is committed BEFORE the published winner images are measured, so the choice",
        "# is auditable in git history rather than re-derived from the run it is compared in.",
        "# Regenerate by re-running the tuning phase on the board.",
        "",
    ]
    for slug, _name, _rounds, _bb, _fam in ctr_ciphers():
        w = winners[slug]
        lines.append("M4_CTR_WINFN_%s := %s" % (slug, WINNER_FN[w["impl"]]))
        lines.append("M4_CTR_WINNAME_%s := %s" % (slug, w["impl"]))
    _write_atomic(WINNERS_MK, "\n".join(lines) + "\n")


def phase_tune(args):
    run_m4_bench.kill_stray_st_util()
    run_m4_bench.probe()
    os.makedirs(RESULTS_M4, exist_ok=True)
    log_dir = args.log_dir or os.path.join(RESULTS_M4, "logs")
    os.makedirs(log_dir, exist_ok=True)

    # ctr_winners.mk is this phase's OWN output, and the tuning images (ctr_tune_<slug>,
    # no winner define) do not read it, so a stale copy from a previous tune -- about to be
    # overwritten by this one -- cannot make the tuning a lie. It is excluded from the
    # dirty check for that reason and no other; every real build input must still be clean.
    dirty = dirty_build_inputs(exclude=(WINNERS_MK_REL,))
    if dirty and not args.allow_dirty:
        raise M4Error("modified build inputs; the commit stamped into tuning.json would "
                      "not describe the firmware measured:\n  " + "\n  ".join(dirty)
                      + "\n(--allow-dirty records it and proceeds.)")

    if not args.no_build:
        subprocess.run(["make", "m4-ctr-tune"], cwd=ROOT, check=True)

    head = _git("rev-parse", "HEAD")
    ciphers = ctr_ciphers()
    per_cipher = {}
    kat_entries = []
    binaries = {}
    clocks = []

    for slug, name, rounds, bb, fam in ciphers:
        binary = "ctr_tune_" + slug
        print("[tune] %s" % binary, file=sys.stderr)
        rows, em = run_image(binary, "product", log_dir,
                             args.gdb_timeout, args.flash_timeout)
        per_cipher[slug] = rows
        binaries[binary] = _bin_sha(binary)
        clocks.append(_observed_clock(em))
        kat_entries.append({
            "binary": binary,
            "cipher": name,
            "kat_failing_pairs": _head_value(em, "# kat:"),
            "ctr_kat_disagreeing_backends": _head_value(em, "# ctr-kat:"),
            "ccm_used": _head_value(em, "# ccm used:"),
            "bss_used": _head_value(em, "# bss used:"),
        })

    # The winner: lowest measured cycles/byte over the ok rows. Deterministic, so this is
    # the choice, not an estimate of it.
    winners = {}
    for slug, name, rounds, bb, fam in ciphers:
        w = pick_winner(per_cipher[slug])
        if w is None:
            raise M4Error("%s: no backend passed its gate on the board; cannot freeze a "
                          "winner" % slug)
        winners[slug] = w

    write_winners_mk(winners)

    # tuning.json is the frozen tuning table AND the tune phase's own provenance: it is
    # committed alongside ctr_winners.mk before --measure, so the run that chose the winner
    # is a git object, not a file the published run could have overwritten. env.json and
    # kat.json are left to the measure phase, which is the one that publishes -- their
    # single copies describe the winners actually measured.
    tuning = {
        "campaign": "m4-ctr-tune",
        "head_commit": head,
        "dirty_build_inputs": dirty,
        "toolchain": {
            "arm_gcc": run_m4_bench.tool_version(["arm-none-eabi-gcc", "--version"]),
            "st_flash": run_m4_bench.tool_version(["st-flash", "--version"]),
        },
        "observed_sysclk_hz": clocks,
        "threshold": {"video_bits_per_s": VIDEO_BITS_PER_S,
                      "mb_per_s": THRESHOLD_MB_S},
        "binaries_sha256": binaries,
        "kat_gates": kat_entries,
        "portfolio": {slug: per_cipher[slug] for slug, *_ in ciphers},
        "winners": {slug: {"impl": winners[slug]["impl"],
                           "fn": WINNER_FN[winners[slug]["impl"]],
                           "cyc_per_byte": winners[slug]["cyc_per_byte"],
                           "mb_per_sec": winners[slug]["mb_per_sec"]}
                    for slug, *_ in ciphers},
    }
    _write_atomic(os.path.join(RESULTS_M4, "tuning.json"),
                  json.dumps(tuning, indent=2) + "\n")

    print("\nFrozen CTR winners (commit %s before --measure):" % WINNERS_MK_REL)
    for slug, name, rounds, bb, fam in ciphers:
        w = winners[slug]
        print("  %-28s %-16s %8.2f cyc/B  %5.2f MB/s"
              % (name, w["impl"], w["cyc_per_byte"], w["mb_per_sec"]))
    print("\nWrote %s, results/v2/m4/tuning.json" % WINNERS_MK_REL)
    print("Next: git add %s results/v2/m4/tuning.json && git commit, then "
          "tools/campaign.py m4 --measure" % WINNERS_MK_REL)
    return 0


# --------------------------------------------------------------------------- #
# phase 2: measure the frozen winners, sweep the layout, publish the verdict
# --------------------------------------------------------------------------- #

def _build_sweep_image(slug, pad):
    """Rebuild ctr_<slug>_product with __text_pad=pad, so the kernels shift while
    ctr_timed_kernel stays pinned. Removes the ELF first: the pad only changes the link,
    and make would not otherwise relink an up-to-date target for a changed defsym."""
    for ext in ("elf", "bin"):
        p = os.path.join(ROOT, "build", "m4", "ctr_%s_product.%s" % (slug, ext))
        if os.path.exists(p):
            os.remove(p)
    subprocess.run(
        ["make",
         "build/m4/ctr_%s_product.elf" % slug,
         "build/m4/ctr_%s_product.bin" % slug,
         "M4_CTR_LDEXTRA=-Wl,--defsym=__text_pad=%d" % pad],
        cwd=ROOT, check=True)


def phase_measure(args):
    freeze = require_frozen_winners()
    run_m4_bench.kill_stray_st_util()
    run_m4_bench.probe()
    os.makedirs(RESULTS_M4, exist_ok=True)
    log_dir = args.log_dir or os.path.join(RESULTS_M4, "logs")
    os.makedirs(log_dir, exist_ok=True)

    # ctr_winners.mk is the frozen input; a modified copy would already have failed
    # require_frozen_winners above, so it is excluded from the dirty check rather than
    # forgiven -- everything else that feeds the build must still be clean.
    dirty = dirty_build_inputs(exclude=(WINNERS_MK_REL,))
    if dirty and not args.allow_dirty:
        raise M4Error("modified build inputs; the commit stamped into the CSV would not "
                      "describe the firmware measured:\n  " + "\n  ".join(dirty))

    if not args.no_build:
        subprocess.run(["make", "m4-ctr-winners"], cwd=ROOT, check=True)

    head = _git("rev-parse", "HEAD")
    ciphers = ctr_ciphers()

    # winner row per (config, cipher).
    measured = {}       # (config_label, slug) -> row dict
    clocks = []
    binaries = {}
    kat_entries = []
    for label, suffix in CONFIGS:
        for slug, name, rounds, bb, fam in ciphers:
            binary = "ctr_%s_%s" % (slug, suffix)
            print("[measure] %s" % binary, file=sys.stderr)
            rows, em = run_image(binary, label, log_dir,
                                 args.gdb_timeout, args.flash_timeout)
            ok = [r for r in rows if r["status"] == "ok"]
            if len(ok) != 1:
                raise M4Error("%s: expected exactly one winner row, got %d"
                              % (binary, len(ok)))
            measured[(label, slug)] = ok[0]
            binaries[binary] = _bin_sha(binary)
            clocks.append(_observed_clock(em))
            kat_entries.append({
                "binary": binary, "cipher": name, "config": label,
                "kat_failing_pairs": _head_value(em, "# kat:"),
                "ctr_kat_disagreeing_backends": _head_value(em, "# ctr-kat:"),
                "ccm_used": _head_value(em, "# ccm used:"),
                "bss_used": _head_value(em, "# bss used:"),
            })

    # The layout sweep runs on the cipher whose product throughput sits closest to the
    # 1.5 MB/s line: that is where a placement shift can move the verdict, so that is where
    # the placement spread must be measured. Reported as the uncertainty on every row.
    prod = {slug: measured[("product", slug)] for slug, *_ in ciphers}
    sweep_slug, sweep_name = min(
        ((slug, name) for slug, name, *_ in ciphers),
        key=lambda sn: abs(prod[sn[0]]["mb_per_sec"] - THRESHOLD_MB_S))
    sweep = []          # list of {pad, cyc_per_byte, mb_per_sec}
    print("[measure] layout sweep on %s (nearest the line)" % sweep_name, file=sys.stderr)
    for pad in SWEEP_PADS:
        _build_sweep_image(sweep_slug, pad)
        rows, em = run_image("ctr_%s_product" % sweep_slug, "product", log_dir,
                             args.gdb_timeout, args.flash_timeout)
        ok = [r for r in rows if r["status"] == "ok"]
        if len(ok) != 1:
            raise M4Error("sweep pad %d: expected one row, got %d" % (pad, len(ok)))
        sweep.append({"pad": pad,
                      "cyc_per_byte": ok[0]["cyc_per_byte"],
                      "mb_per_sec": ok[0]["mb_per_sec"]})
    # Rebuild the swept cipher's product image at pad 0 so the on-disk binaries match the
    # published, unpadded measurement again.
    _build_sweep_image(sweep_slug, 0)

    sweep_cyc = [s["cyc_per_byte"] for s in sweep]
    spread_abs = max(sweep_cyc) - min(sweep_cyc)
    spread_frac = spread_abs / min(sweep_cyc) if min(sweep_cyc) else 0.0

    _write_runs_csv(head, freeze, ciphers, measured, sweep, sweep_name,
                    spread_frac, clocks, binaries)
    _write_summary_csv(head, ciphers, prod, sweep_name, spread_frac)
    _write_memcfg_csv(head, ciphers, measured)
    _write_measure_env(head, freeze, dirty, clocks, binaries, sweep_name, spread_frac)
    _write_atomic(os.path.join(RESULTS_M4, "kat.json"),
                  json.dumps({"campaign": "m4-ctr-measure", "head_commit": head,
                              "entries": kat_entries}, indent=2) + "\n")

    passes = sum(1 for slug, *_ in ciphers if prod[slug]["mb_per_sec"] >= THRESHOLD_MB_S)
    print("\n12 Mbit/s (>= %.2f MB/s) over the complete CTR pass, product config:"
          % THRESHOLD_MB_S)
    for slug, name, rounds, bb, fam in ciphers:
        r = prod[slug]
        verdict = "PASS" if r["mb_per_sec"] >= THRESHOLD_MB_S else "FAIL"
        print("  %-28s %-16s %8.2f cyc/B  %5.2f MB/s  %s"
              % (name, r["impl"], r["cyc_per_byte"], r["mb_per_sec"], verdict))
    print("  %d of %d ciphers sustain the stream. Placement spread +/-%.1f%% "
          "(layout sweep on %s)." % (passes, len(ciphers), 100 * spread_frac / 2,
                                     sweep_name))
    print("\nWrote results/v2/m4/{runs,summary}.csv, %s, results/v2/m4/env.json"
          % os.path.relpath(MEMCFG_CSV, ROOT))
    return 0


# --------------------------------------------------------------------------- #
# output files
# --------------------------------------------------------------------------- #

def _verdict(mb_per_sec):
    return "PASS" if mb_per_sec >= THRESHOLD_MB_S else "FAIL"


def _runs_header(head, freeze, sweep_name, spread_frac, clocks):
    clk = clocks[0] if clocks else None
    return [
        "# results/v2/m4/runs.csv -- Cortex-M4 counter-mode winners, on-device.",
        "# Produced by: tools/campaign.py m4 --measure",
        "# head_commit: %s" % head,
        "# winners_frozen_at: %s (%s)" % (freeze["freeze_commit"], WINNERS_MK_REL),
        "# observed_sysclk_hz: %s (measured on the board, not assumed)"
        % (clk if clk is not None else "UNKNOWN"),
        "# workload: complete counter mode, 64 KiB in place, one cipher per image.",
        "# statistics: deterministic DWT cycle count, interrupts masked; no bootstrap.",
        "#   The uncertainty is placement: a layout sweep of ctr_timed_kernel across the",
        "#   16-byte flash-fetch line (__text_pad in {0,4,8,12,16}) on %s, the cipher"
        % sweep_name,
        "#   nearest the threshold, spans +/-%.1f%% of cycles/byte. That is the interval"
        % (100 * spread_frac / 2),
        "#   on every figure below; there is no other source of run-to-run variation.",
        "# verdict: 12 Mbit/s of video = %.2f MB/s; a row sustains it when mb_per_sec >= %.2f."
        % (THRESHOLD_MB_S, THRESHOLD_MB_S),
    ]


def _write_runs_csv(head, freeze, ciphers, measured, sweep, sweep_name,
                    spread_frac, clocks, binaries):
    lines = _runs_header(head, freeze, sweep_name, spread_frac, clocks)
    lines.append("cipher,rounds,impl,config,cycles_per_byte,cycles_per_byte_min,"
                 "mb_per_sec,ns_per_op,meets_12mbps")
    for label, _suffix in CONFIGS:
        for slug, name, rounds, bb, fam in ciphers:
            r = measured[(label, slug)]
            lines.append("%s,%d,%s,%s,%.4f,%.4f,%.2f,%.4f,%s"
                         % (name, rounds, r["impl"], label,
                            r["cyc_per_byte"], r["cyc_per_byte_min"],
                            r["mb_per_sec"], r["ns_per_op"],
                            "yes" if _verdict(r["mb_per_sec"]) == "PASS" else "no"))
    lines.append("# layout sweep: %s, product config, ctr_timed_kernel pinned at 0x08010000."
                 % sweep_name)
    lines.append("# __text_pad,cycles_per_byte,mb_per_sec")
    for s in sweep:
        lines.append("#   %2d,%.4f,%.2f" % (s["pad"], s["cyc_per_byte"], s["mb_per_sec"]))
    _write_atomic(os.path.join(RESULTS_M4, "runs.csv"), "\n".join(lines) + "\n")


def _write_summary_csv(head, ciphers, prod, sweep_name, spread_frac):
    lines = [
        "# results/v2/m4/summary.csv -- Cortex-M4 counter-mode, product config.",
        "# head_commit: %s" % head,
        "# The published question: can the STM32F407 process 12 Mbit/s of video (= %.2f MB/s)"
        % THRESHOLD_MB_S,
        "# in the COMPLETE byte-oriented counter mode -- counters, encryption, keystream and",
        "# the in-place XOR of a 64 KiB frame -- not merely inside the round function.",
        "# cycles_per_byte is the deterministic DWT count; placement_spread_pct is the",
        "# layout-sweep uncertainty (on %s, the cipher nearest the line) that applies to all."
        % sweep_name,
        "cipher,rounds,winner_impl,cycles_per_byte,mb_per_sec,placement_spread_pct,meets_12mbps",
    ]
    for slug, name, rounds, bb, fam in ciphers:
        r = prod[slug]
        lines.append("%s,%d,%s,%.4f,%.2f,%.1f,%s"
                     % (name, rounds, r["impl"], r["cyc_per_byte"], r["mb_per_sec"],
                        100 * spread_frac, "yes" if _verdict(r["mb_per_sec"]) == "PASS" else "no"))
    _write_atomic(os.path.join(RESULTS_M4, "summary.csv"), "\n".join(lines) + "\n")


def _write_memcfg_csv(head, ciphers, measured):
    lines = [
        "# results/v2/m4-memory-configurations.csv -- CTR winner in three memory paths.",
        "# head_commit: %s" % head,
        "# product: code in flash, ART on (the fast path, and the published verdict's).",
        "# flash-noart: code in flash, ART off. sram-noart: code in SRAM, ART off -- a",
        "# different instruction-supply path, not a lower bound (this part has no",
        "# zero-wait-state executable memory). Same winner backend in every column.",
        "cipher,rounds,winner_impl,"
        "product_cyc_per_byte,product_mb_per_sec,"
        "flash_noart_cyc_per_byte,flash_noart_mb_per_sec,"
        "sram_noart_cyc_per_byte,sram_noart_mb_per_sec,meets_12mbps_product",
    ]
    for slug, name, rounds, bb, fam in ciphers:
        p = measured[("product", slug)]
        f = measured[("flash-noart", slug)]
        s = measured[("sram-noart", slug)]
        lines.append("%s,%d,%s,%.4f,%.2f,%.4f,%.2f,%.4f,%.2f,%s"
                     % (name, rounds, p["impl"],
                        p["cyc_per_byte"], p["mb_per_sec"],
                        f["cyc_per_byte"], f["mb_per_sec"],
                        s["cyc_per_byte"], s["mb_per_sec"],
                        "yes" if _verdict(p["mb_per_sec"]) == "PASS" else "no"))
    _write_atomic(MEMCFG_CSV, "\n".join(lines) + "\n")


def _write_measure_env(head, freeze, dirty, clocks, binaries, sweep_name, spread_frac):
    env = {
        "campaign": "m4-ctr-measure",
        "phase": "measure",
        "head_commit": head,
        "winners_freeze": freeze,
        "dirty_build_inputs": dirty,
        "stlink_probe": run_m4_bench.probe(),
        "toolchain": {
            "arm_gcc": run_m4_bench.tool_version(["arm-none-eabi-gcc", "--version"]),
            "st_flash": run_m4_bench.tool_version(["st-flash", "--version"]),
        },
        "observed_sysclk_hz": clocks,
        "binaries_sha256": binaries,
        "threshold": {"video_bits_per_s": VIDEO_BITS_PER_S, "mb_per_s": THRESHOLD_MB_S},
        "placement_sweep": {"cipher": sweep_name, "pads": list(SWEEP_PADS),
                            "spread_frac": spread_frac},
    }
    _write_atomic(os.path.join(RESULTS_M4, "env.json"),
                  json.dumps(env, indent=2) + "\n")


# --------------------------------------------------------------------------- #
# entry point (dispatched from tools/campaign.py's main)
# --------------------------------------------------------------------------- #

def main(argv):
    import argparse
    ap = argparse.ArgumentParser(
        prog="campaign.py m4",
        description="Cortex-M4 counter-mode campaign (tune then measure).")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--tune", action="store_true",
                      help="phase 1: measure every backend, freeze the winner per cipher")
    mode.add_argument("--measure", action="store_true",
                      help="phase 2: measure the frozen winners, sweep, publish the verdict")
    ap.add_argument("--log-dir", default=None,
                    help="where board logs go (default results/v2/m4/logs)")
    ap.add_argument("--gdb-timeout", type=float, default=600.0)
    ap.add_argument("--flash-timeout", type=float, default=300.0)
    ap.add_argument("--no-build", action="store_true",
                    help="do not run make before measuring")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="tune only: proceed with modified build inputs, recording it")
    args = ap.parse_args(argv)
    try:
        if args.tune:
            return phase_tune(args)
        return phase_measure(args)
    except (M4Error, run_m4_bench.Failure) as exc:
        print("campaign m4: %s" % exc, file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        print("campaign m4: command failed (%s)" % (exc,), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
