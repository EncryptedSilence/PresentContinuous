Found four issues, ranked by severity. Paths below are relative to `chacha_ascon/`.

1. **P2 — Adapted AES kernels terminate early for lengths ≥ 2 GiB.**  
   `src/aes/aes128_ctr_m4ss.S:1227` and `src/aes/aes128_ctr_m4ss_bs.S:4669` use signed `ble` after decrementing an unsigned byte count. For example, length `0x80000010` makes the T-table kernel return after one block, leaving the remainder untouched. All four T-table variants inherit this. The wrappers pass the full unsigned length without chunking (`src/aes/aes128_m4ss.c:65`). Use zero termination for the guaranteed positive block multiples, or chunk calls below `INT32_MAX`. This violates “any len,” though it cannot affect the STM32F407’s small buffers or current benchmark sizes.

2. **P2 — The on-board gate cannot detect out-of-range reads.**  
   `tests/test_bc.c:59` allocates 16 accessible bytes beyond every logical buffer; checks at `:253` detect output corruption, but reads into that padding remain invisible. A kernel that reads a full block past a partial tail, while writing only the requested bytes, can pass. Host ASan helps instrumented C, but does not validate the M4 assembly’s accesses. Add protected-boundary tests under an appropriate emulator/MPU setup, or memory-access tracing for assembly. Passing the current gate does not establish the read-bounds contract.

3. **P2 — Alignment coverage misses misaligned in-place operation.**  
   `tests/test_bc.c:240` tests in-place only at the allocation base; `:242` tests misalignment only with distinct input/output buffers. A kernel that fails specifically for `out == in` at an unaligned address can pass both `test_bc` and the board gate. Add misaligned in-place cases, preferably exercising every offset modulo the relevant word/vector alignment. Key and nonce alignment are also not systematically varied.

4. **P2 — x86 `core-cyc/B` is an estimate that can be numerically wrong.**  
   `bench/bench_ca.c:176–182` multiplies median elapsed ns/B by a separately sampled median frequency across all trials. Those medians need not describe the same execution interval; frequency changes, throttling and descheduling can distort the result. The measurement thread is also not pinned by the program, although the sampled CPU is selected once. Measure hardware core cycles for each trial, or explicitly label this column as estimated and enforce affinity. This affects the existing harness as well as the newly added AES/Qalqan rows.

The existing x86, x86-ASan and Cortex-M4/QEMU test binaries passed. ASan required leak detection disabled because LeakSanitizer cannot run under this environment’s tracing restrictions; I could not rebuild in the read-only workspace.

Both S&S generated assembly files reproduce exactly from the adaptation scripts. Apart from the inherited signed-length issue, I found no concrete counter-wrap, lane, tail, callee-saved-register, stack-frame or AAPCS defect in the inspected kernels. The bitsliced wrapper’s comment that the kernel advances the counter by `full/16` is inaccurate—the kernel skips its final update—but the wrapper explicitly reconstructs the tail counter, preserving output correctness.

The board benchmark keeps key setup outside timing and divides CTR cycles by message bytes, without multiplying by lane count. I found no denominator error in `results/arm/m4-board.csv`; the recorded board run was not independently repeated.