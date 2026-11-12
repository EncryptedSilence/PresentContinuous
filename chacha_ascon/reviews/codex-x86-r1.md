Reviewed commit `328f87e`. `make -C chacha_ascon && build/ca/x86/test_ca` succeeded using existing build artifacts: **12 implementations tested, 0 skipped, 0 failures**. No files changed.

**Critical: none found.** No confirmed wrong ciphertext/tag or out-of-bounds access in the implementation paths under their documented buffer and counter contracts.

1. **Major — Core-cycle figures use a different workload’s clock.**  
   `chacha_ascon/bench/bench_ca.c:43`, `:103`  
   `core_cyc_per_byte` multiplies encryption time by the best frequency from separate scalar-add loops. AVX2 encryption can run at a different frequency because of turbo, power limits, or thermal conditions; averaging the before/after probes does not measure that frequency. For example, encryption at 4 GHz combined with a 5 GHz probe overstates cycles/byte by 25%.  
   **Fix:** measure hardware core cycles during encryption, or omit this column and report elapsed throughput and explicitly labelled TSC cycles.

2. **Major — Multi-stream implementations never receive the exhaustive short AD KATs.**  
   `chacha_ascon/tests/test_ca.c:193`; `chacha_ascon/tools/gen_kats.py:111`  
   `ascon_multi()` consumes only long vectors, whose AD lengths are `{0,1,15,16,33}`. The 1089 short KATs run only against single-stream implementations. A bug in multi-stream AD padding for an eight-byte tail, for example, would pass every test. Job counts also vary with vector index instead of testing every vector at every relevant count.  
   **Fix:** run the short KATs through every multi implementation, covering complete SIMD groups and remainder counts with distinct lane inputs.

3. **Minor — Tests do not detect writes beyond ciphertext/tag or reads beyond input tails.**  
   `chacha_ascon/tests/test_ca.c:47`, `:205`, `:236`  
   ChaCha buffers have substantial spare capacity; Ascon jobs have seven unchecked bytes after the expected output. An implementation that writes a rounded-up SIMD tail can produce correct compared bytes and still pass. Overreads into accessible spare memory likewise remain invisible.  
   **Fix:** check output canaries and use exact-size sanitizer allocations or guard-page placements for input/output tails, including misaligned in-place calls.

4. **Minor — Cache residency differs between single- and multi-stream measurements.**  
   `chacha_ascon/bench/bench_ca.c:82`, `:176`, `:185`  
   Repeated calls reuse the same buffers. At 4 KiB, single-stream implementations repeatedly touch one 4 KiB frame, while multi-stream implementations touch roughly 96 KiB across 24 frames. At 64 KiB, that becomes roughly 1.5 MiB. Consequently, comparisons include different cache working sets, and the reported throughput describes repeatedly reused buffers rather than general streaming traffic.  
   **Fix:** label these as warm-buffer measurements and add a comparison using equal total working sets, plus a separate large-buffer streaming measurement.

5. **Minor — Hex parsing silently accepts malformed vectors.**  
   `chacha_ascon/tests/kat_common.h:35`; `chacha_ascon/tests/test_ca.c:93`  
   `%2x` accepts a single valid digit: `"0G"` decodes as zero, after which the parser skips both characters. Odd trailing digits are silently dropped, and callers ignore decoded key/nonce/tag lengths. Thus malformed vector fields can be accepted or leave bytes uninitialized despite record-count checks.  
   **Fix:** require exactly two hexadecimal digits per byte, reject trailing garbage and odd lengths, and validate every fixed-size field’s decoded length.

I found no dead-code elimination in the existing benchmark binary; encryption calls remain in the timed loops. Payload-byte accounting, including the multi-stream job multiplier, is consistent with the stated metric.