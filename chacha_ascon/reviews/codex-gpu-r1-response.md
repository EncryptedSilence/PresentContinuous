# Response to Codex GPU review, round 1 (codex-gpu-r1.md)

| # | Finding | Verdict | Change |
|---|---------|---------|--------|
| 1 | 256 MiB Ascon launches timed but not verified | Accepted | The gate now runs exactly the timed launch shapes, `(mlen, total/mlen)` for both totals, every ciphertext and tag compared with the host oracle (plus the odd-size 3001-message cases). |
| 2 | SM clock from a different workload | Accepted | New in-kernel clock: each kernel is a template on `CLK`; one extra launch of `<true>` per row has lane 0 of every warp fold `clock64()` and `%globaltimer` into per-SM min/max (keyed by `%smid`). Reported `sm_mhz_kernel` is the median over SMs, with `sms_seen`. Timed launches use `<false>`, identical SASS profile to the old kernels: an RAII guard in the timed kernel itself was tried first and pushed ChaCha's keystream to the stack, so it was not kept. Spin probe kept as context only. The CSV header now says scaling bytes/SM-cycle to another clock is a compute-bound estimate bounded by memory bandwidth. Result: 180 MHz on all 36 SMs during encryption, i.e. the throttled clock is real, not a probe artefact. |
| 3 | KAT verification not enforced in the CUDA build/binary | Accepted | `cuda/Makefile` runs `make -C .. test` (rebuilds changed host objects, runs the full KAT suite) before linking; `ca_gpu` links `oracle_gate.c` + embedded KATs and checks `chacha20_xor_avx2_x8` (206 vectors) and `ascon_multi_avx2_x8` (1089 LWC vectors, 9 jobs each, so both the 8-lane group and remainder paths) at startup. `make run` writes `results/cuda/gpu.csv`. |
| 4 | "L2-resident / cipher-only" overclaims | Accepted | Wording changed to small/large repeated working sets; no residency claim. |
| 5 | x86 sampler data race; silent fallback to scalar probe | Accepted | Sampler state behind a mutex; the window is closed and samples copied out under the lock. No samples -> core-cycle column is NaN. intel_pstate is in **active** mode on this host (checked `/sys/devices/system/cpu/intel_pstate/status`), so `scaling_cur_freq` is the average since the last read. |
| 6 | ASan build allocates n+1 | Accepted | `malloc(n + CANARY)` exactly (size 1 only for n=0, never touched); overflow check. |
| 7 | Long vectors only at L+1 jobs | Accepted | Exemption removed; all of {1, L, L+1, 2L+1} for every vector. Test still runs in 0.25 s. |
| 8 | Numeric KAT parsing permissive | Accepted | `kat_num_max`: digits of the base only (no sign/space), `ERANGE` rejected, range-checked; `kat_u32` for Counter/Seed, `kat_size` for lengths. |
| — | Inactive smem lanes read unwritten slots | Accepted | Inactive lanes stage zeros. |

Tests after the changes: `make test` and `make asan-test`: 12 implementations, 0 failures.
