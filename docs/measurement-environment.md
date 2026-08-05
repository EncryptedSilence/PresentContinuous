# Measurement environment

The exact toolchain, commit, machine and power configuration behind every number in
[speed-at-equal-security.md](speed-at-equal-security.md) and
[results/bound-search/](../results/bound-search/), plus the three caveats that limit how far
those numbers travel.

Captured 2026-08-05. See [What this does not pin down](#what-this-does-not-pin-down) before
treating any of it as a controlled experiment — parts of it are a record of the defaults the
machine happened to have, not of settings that were chosen and enforced.

---

## Toolchain

| | |
|---|---|
| compiler | `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, target `x86_64-linux-gnu` |
| binary actually invoked | `/usr/bin/cc` → `/etc/alternatives/cc` → `/usr/bin/x86_64-linux-gnu-gcc-13` |
| glibc | 2.39-0ubuntu8.8 |
| Python | 3.12.3 |
| cadical | 3.0.1, `third_party/cadical` @ `c607304` |
| kissat | 4.0.4, `third_party/kissat` @ `8af8e56` |
| cryptominisat | 5.11.15, built from the `5.11.15` tag |

The Makefile's `CC ?= gcc` is a **no-op**. Make predefines `CC = cc`, and `?=` assigns only to
variables that are not already set, so the recipe expands to `cc`. On this system that is the
same gcc 13.3.0 by a different path, and nothing measured here is affected — but anyone
overriding the compiler should know the default was never literally `gcc`.

CryptoMiniSat took three attempts to build: master requires `gmp`, the `5.11.22` tag requires a
`cadiback` library, and `5.11.15` builds against what is installed. Its full CLI additionally
needs `boost::program_options`, which is absent here, so the usable binary is
`cryptominisat5_simple` — the same solver core behind a minimal CLI that wants `--verb=0`
rather than `--verb 0`, and silently exits 0 on an unrecognised flag.

## Compiler command lines

Verbatim from `make -n`:

```
cc -O3 -march=native -std=gnu11 -Wall -Wextra -Wpedantic -Iinclude -Isrc \
   -o build/bench bench/bench_main.c build/src/variant.o build/src/keyschedule.o \
   build/src/present_core.o build/src/present_ref.o build/src/present_table.o \
   build/src/present_table_x.o build/src/present_bitslice.o build/src/present_avx2.o \
   build/src/gen/variants_gen.o

cc -O3 -march=native -std=gnu11 -Wall -Wextra -Wpedantic -Iinclude -Isrc \
   -o build/wide_bench bench/wide_bench.c
```

`-march=native` resolves to **`-march=alderlake -mtune=alderlake`**: gcc 13.3 carries no Raptor
Lake tuning model and maps this part onto its Alder Lake predecessor. No AVX-512 (fused off on
14900HX), and no GFNI or VAES, which is what the document's no-hardware-acceleration ground
rule requires.

## Run command lines

Speed:

```
taskset -c 2 ./build/bench --csv results/speed.csv
taskset -c 2 ./build/wide_bench --rounds 4 --c0 0 8 15 --csv results/wide-speed-r4.csv
taskset -c 2 ./build/wide_bench --rounds 5 --c0 0 8 15 --csv results/wide-speed-r5.csv
taskset -c 2 ./build/wide_bench --rounds 5 --c0 1 10 15
```

The three results that settled `rounds@64` for present-80-lin444-297:

```
python3 analysis/dump_cnf.py --variant present-80-lin444-297 --rounds 6 --weight 64 --out r6.cnf
third_party/cadical/build/cadical -q --unsat --seed=1005 r6.cnf     # UNSAT, 20002 s
third_party/cadical/build/cadical -q --unsat --seed=4005 r6.cnf     # UNSAT, 20719 s

python3 analysis/dump_cnf.py --variant present-80-lin444-297 --rounds 5 --weight 64 --out r5.cnf
third_party/kissat/build/kissat  -q --unsat --seed=3008 r5.cnf      # SAT,  36688 s

python3 analysis/prove_bound.py --variant present-80-lin444-297 --rounds 4 --weight 50
                                                                    # SAT,    650 s
```

Every other cipher's `rounds@64` came from a single `prove_bound.py` call; the commands are in
[speed-at-equal-security.md](speed-at-equal-security.md#reproducing).

## Repository state

Commit **`f76c0d77b7c801273171676cb75aa323a3b4fbfa`** — "Document equal-margin bound search",
2026-08-05 10:08:26 +0500.

The benchmarks were run against the working tree shortly *before* that commit was made. The
measurement-relevant sources are byte-identical in it: the only later edits to anything the
binaries read were `description` strings in the `present-80-lin444-297-r6/r7/r8` variant JSONs,
never `rounds`, `sbox` or `linear`. The uncommitted `Makefile` change in the tree adds an
unrelated `build/avalanche` target.

## Machine

| | |
|---|---|
| system | ASUSTeK ROG Strix G18, board `G815JPR` |
| BIOS | American Megatrends **G815JPR.318**, 2026-05-20 |
| CPU | Intel Core i9-14900HX — family 6, model 183, stepping 1 (Raptor Lake-HX) |
| topology | 24 cores / 32 threads: 8 P-cores (SMT) + 16 E-cores |
| microcode | **0x133** |
| kernel | 6.17.0-22-generic, Ubuntu 24.04.2 LTS |

Pinned core for every measurement: **CPU 2**, a P-core (SMT sibling 2–3, `cpu_capacity` 1024),
range 800–5600 MHz.

## Power and frequency configuration

| setting | value |
|---|---|
| scaling driver | `intel_pstate` (HWP) |
| governor | `powersave`, all 32 CPUs |
| energy performance preference | `performance`, all 32 CPUs |
| turbo | **enabled** — `intel_pstate/no_turbo = 0` |
| `min_perf_pct` / `max_perf_pct` | 15 / 100 |
| `hwp_dynamic_boost` | 0 |
| SMT | **on** |
| ACPI platform profile | **performance** (of quiet / balanced / performance) |
| power source | AC |
| TSC flags | `constant_tsc`, `nonstop_tsc` |

`powersave` + EPP `performance` is the stock Ubuntu HWP arrangement and is not power-saving in
the classic sense — the governor name is vestigial under `intel_pstate`. These are the
defaults; none of them was set for the benchmarks.

---

## What this does not pin down

Three limitations, in descending order of how much they matter.

### 1. `cyc/B` counts nominal TSC ticks, not core cycles

`bench_main.c` measures with `__rdtsc()`. On this part the TSC runs at a fixed nominal rate
independent of the core clock, and that rate is recoverable from `results/speed.csv`, since
`cycles_per_byte × mb_per_sec / 1000` is the tick rate in GHz. Over all 375 rows the median is
**2.419 GHz** (min 2.297, max 2.547). The pinned core meanwhile boosts to 5.6 GHz and was
observed at 5027 MHz.

That ±5% spread is an artefact of the two columns being independent medians over 15 trials
rather than a single ratio, so it is not itself a frequency measurement — but it is a fair
indication of the trial-to-trial variation underneath every figure in these documents.

So **true core cycles per byte are up to ~2.3× every figure reported**. This does not disturb
the comparisons — all rows are counted the same way — but the absolute numbers are nominal tick
counts, and quoting them as cycle counts against figures from another machine or another
measurement method would be wrong. `bench_main.c`'s header says this too; it is repeated here
because the number is easy to lift out of a table without the caveat attached.

### 2. Frequency was not pinned

The governor was left at its default, turbo left on, SMT left on. Nothing prevented the core
from changing frequency mid-run. What was controlled instead: a single pinned core, a
verified-idle machine (`pgrep -c cadical` = 0, load 0.44 before the final pass), 3 warm-up
passes and the median of 15 trials.

That is enough for the within-process comparisons the document leans on, and it is why the
document treats gaps under ~10% as ties. It is worth being concrete about the sharpest case:
PRESENT-lin444-297 leads PRESENT-80 by 1.10×, which sounds comfortable but is **0.051 cyc/B** —
inside the run-to-run drift observed between passes. Both rows come from a single `bench`
process, which is the tight end of that drift, but the lead is not wide.

### 3. These settings were recorded afterwards

The configuration above was captured after the fact, not during the benchmark runs. Every item
is static configuration that almost certainly did not change, but that cannot be demonstrated
from the artefacts. Since the measurements, the machine has run 31–32 solver threads for about
16 hours: thermal history differs, configuration does not.

A future run should dump this table alongside the CSV at measurement time rather than
reconstructing it later.

## Reproducing the environment check

```sh
gcc --version; gcc -march=native -Q --help=target | grep -E '^\s+-march='
make -n bench wide_bench | grep '^cc'
git rev-parse HEAD; git status --short
cat /sys/class/dmi/id/bios_version /sys/class/dmi/id/board_name
grep -m1 microcode /proc/cpuinfo
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_{driver,governor} \
    /sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference \
    /sys/devices/system/cpu/intel_pstate/no_turbo \
    /sys/devices/system/cpu/smt/control \
    /sys/firmware/acpi/platform_profile
```
