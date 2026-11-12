# Response to codex-aes-qalqan-r1

1. **Signed loop end in the adapted S&S kernels (len ≥ 2 GiB).** Fixed in the wrapper,
   src/aes/aes128_m4ss.c: the whole-block prefix is fed to the kernel in chunks of at
   most 1 GiB (`M4SS_CHUNK`, a multiple of 32), with the counter recomputed per chunk;
   for the bitsliced kernel p.blk[3] is now set before every call (the comment claiming
   the kernel advances it was wrong, as noted). Qalqan's M4 kernels count blocks and end
   on `bne`, so they have no such limit.

2. **The gate could not see out-of-range reads.** Added an MPU bounds gate to the board
   firmware (fw_m4/ca_fw_main.c, bc_guard_test): every bc_impl runs on 30 lengths
   (1..4103) with input and output butted against 32-byte MPU regions with no access
   (AP=000, applies to privileged code), before and after, out of place and in place,
   counters 0 and 0xFFFFFFFF; 3120 runs. A fault vectors (SRAM copy of the vector
   table) to a handler that prints MPU_GUARD_FAULT and ends the run, so no KAT_END
   status=0 and tools/m4_board.py writes nothing; the parser also requires the
   "bc MPU guard: ok" line. `make -C arm TARGET=m4hw guard-selftest` builds a firmware
   that reads one byte past the end on purpose; on the board it is caught. The full
   board run passes the gate. qemu (semihosted, no MMU/MPU) cannot run this, and the
   x86 kernels are covered by ASan as before.

3. **No misaligned in-place case.** tests/test_bc.c gains mode 3: in place at offset
   1..3 (varying with the length), with the bytes before the buffer checked. Passes on
   x86, ASan, qemu M4/A7 and on the board (656 CTR runs per implementation).

4. **x86 core-cyc/B is an estimate.** Agreed and now stated in docs/chacha20-ascon.md
   §0.1: the column is median time × median sampled frequency in the same window, not a
   hardware cycle counter (perf is closed on this host, perf_event_paranoid=4). The
   process is pinned by taskset -c 2 and the sampler reads cpu2's frequency; the TSC
   column is measured directly and is published alongside.
