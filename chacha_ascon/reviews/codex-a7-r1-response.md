# Response to Codex A7 review, round 1

Review: `codex-a7-r1.md`. Codex found no functional bug in `chacha20_neon.c` or `ascon_neon_multi.c`, which it checked against RFC 8439 and SP 800-232, including in-place use, odd job counts and tails. All 16 A7 implementations pass the KATs under qemu `-cpu cortex-a7`. Every model finding was accepted. The A7 part of `tools/arm_cycles.py` was rewritten, refitted and re-run.

| # | Finding | Action |
|---|---------|--------|
| 1 | Transposes lose their dependencies | `a7_decode()` returns explicit read and write sets per instruction form. `vtrn/vzip/vuzp/vswp` read and write both operands. `vsri/vsli/vmla/vbsl/vbit/vbif/vtbx/vsra` and lane loads read their destination. Checked: `vtrn.32 q0,q1` with `q0` ready at 100 now completes after 100. |
| 2 | Scalar dependencies missing | The Thumb two-operand form (`eors r0,r3`) reads its destination. NZCV is a pseudo-register: S-suffix ops and `cmp/cmn/tst/teq` write it; `adc/sbc/rsc`, conditional instructions, IT and conditional branches read it. A conditional instruction also reads its old destination. Writebacks (`[rn]!`, post-index, `ldm rn!`, push/pop/vpush/vpop) write the base register, and `sp` is tracked. Register lists with ranges are expanded. Checked: `ldr r0,[r1]; eors r0,r2` now finishes at cycle 4, not 1. |
| 3 | Unbounded NEON run-ahead and impossible memory ordering | NEON dispatch now waits for a slot in a bounded queue (`nqueue`, fitted from {4, 16}). Scalar loads wait for every earlier NEON store to complete; without address traces this is the conservative choice. Core→NEON transfers go through the queue, and NEON→core transfers wait for the value. Transfers in the two directions now have separate latencies (GCC: r2f 4, f2r 2). |
| 4 | Undefended prices and pairing | Slot structure taken from GCC's `cortex-a7.md`: immediate ALU ops and branches may be the younger instruction; register and shifted ALU ops, loads and stores only the older; no branch–branch pair; LDRD/STRD one cycle on both slots; multiplies and divides never pair (divide 5 cycles); immediate and register ALU ops are separate classes; shifted-operand forwarding (`shift_fwd`) is a fitted parameter. `vld/vst` cost one cycle per D register (64-bit path), and `vpush/vpop` are NEON stores/loads. The docstring separates what is fitted from what is taken from GCC or assumed. |
| 5 | eBACS 37.5 c/B is not a matched measurement | Agreed. It no longer selects any rule. The structural rules come from GCC, the rest is fitted on PRESENT only, and the eBACS point is now reported only as an indirect, historical comparison (Ascon v1.2-era code and compiler). The refitted model gives 34.7 c/B for `ascon-c/armv6` without using it (−7.5%). |
| 6 | The fit pins few parameters; config mismatch | `fit_a7.py` now searches 48 candidates: 3 pairing sets × load_lat {2,3} × neon_lat {3,4} × nqueue {4,16} × shift_fwd {0,1}. It also prices the study's own kernels under every candidate within 3% of the best fit and prints the min..max range. Full log: `results/arm/a7-fit.txt`. The calibration build is documented in the header of `a7_present_calib.c` (gcc 14, -O3, Thumb-2, 4 KiB working set), and the report states that this differs from the study's build (gcc 13.2.1, -O2, ARM mode). The fit does not establish prediction accuracy. |
| 7 | The 1% neon-x2 vs ascon-c/neon gap is not a ranking | Agreed. The report calls them "equal within the model's resolution". |

## Results after the fix

Best fit (`gcc+regreg`, load_lat 3, neon_lat 3, nqueue 16, shift_fwd 0) on the PRESENT kernels: table +5.4%, bitslice −6.1%, neon +7.6%, ref +6.2%. The pure-GCC pairing set fits worse at best (worst error 11.7%, with ref +11.7%).

Comparison with measurements that were not used in the fit:

| | measured | model (range over retained fits) |
|---|---:|---:|
| ascon-c/neon, long | 30.7 | 27.2 (27.2–30.2) |
| ascon-c/neon, 64 B | 55.9 | 50.4 |
| ascon-c/armv6-class scalar, long (eBACS, indirect) | 37.5 | 34.7 |

Study estimates at 4096 B, c/B (range in brackets):
- ChaCha20 neon-x4: 13.6 (13.6–15.5);
- lazy-rot: 22.7;
- ascon-c/neon: 27.2 (27.2–30.2);
- neon-x2: 26.4 (26.4–28.8);
- best scalar Ascon, bi32_armv7m: 32.4.
