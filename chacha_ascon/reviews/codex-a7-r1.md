I found substantial defects in the cycle model and weaknesses in the validation claims, but **no functional encryption bug in either NEON implementation under the documented contracts**. The A7 estimates should not currently support close performance rankings.

Reviewed branch `chacha-ascon`, commit `a9b5885`. I read the implementations, harnesses, calibration code, and results; inspected A7 object disassembly; and ran:

```text
qemu-arm -cpu cortex-a7 build/ca/a7/test_ca.elf
16 implementations tested, 0 skipped, 0 failures
```

No files were modified.

1. **High — The model loses both input and output dependencies of NEON transposes.**  
   [arm_cycles.py:277](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/arm_cycles.py:277)

   The generic “first register is destination, remaining registers are sources” rule is wrong for `vtrn`, `vzip`, `vuzp`, and `vswp`: both operands are read and written. The special handling at line 279 does not cover them.

   **Concrete failure:** `vtrn.32 q0,q1; veor q2,q1,q3` lets the XOR consume the old readiness of `q1`. Conversely, the transpose does not wait for its own `q0` input. Setting `q0` readiness to cycle 100 and stepping `vtrn.32 q0,q1` produces completion accounting at cycle 2 and resets its readiness to cycle 5.

   This affects actual ChaCha output code: object offset `0x624` contains `vtrn.32 q15,q0`, followed by stores of the updated `d0/d1`. Their producer dependency is missing.

   **Fix:** decode instruction-specific read/write sets, including both transpose operands, before recalibrating and regenerating the CSV.

2. **High — The scalar scoreboard misses dependencies present in the Thumb implementations.**  
   [arm_cycles.py:268](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/arm_cycles.py:268)

   Two-operand Thumb arithmetic reads its destination, but the model treats that register as write-only. Flags, address writeback, and several implicit operands are also absent.

   **Concrete failure:** `ldr r0,[r1]; eors r0,r2` issues the XOR at cycle 1 and marks `r0` ready at cycle 2, although the load supplying its input is ready at cycle 3. The built `ascon-c/armv7m.o` contains this two-operand form—for example, `eors r0,r3` at offset `0x98`.

   Likewise, `subs; sbc` carry chains are not represented, and `vld1 ...,[r3]!` does not record its update to `r3`. Ignoring `sp` as a source at line 293 also suppresses stack-address dependencies.

   **Fix:** normalize Thumb shorthand into explicit operands; track NZCV dependencies and base-register updates; handle multi-register transfers and implicit operands explicitly.

3. **High — The decoupled cursors permit impossible memory ordering and unlimited dispatch ahead of NEON.**  
   [arm_cycles.py:296](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/arm_cycles.py:296), [arm_cycles.py:320](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/arm_cycles.py:320)

   Integer dispatch advances independently of NEON execution without queue capacity, shared memory-resource constraints, or dependencies between NEON stores and scalar reloads.

   **Concrete failure reproduced using `A7.step`:**

   ```text
   10 dependent Q-register XORs: integer cursor 10, NEON cursor 38
   subsequent NEON store:       integer cursor 11, NEON cursor 41
   scalar reload of same address: result ready at cycle 14
   ```

   The reload obtains its modeled result before the store supplying it executes. Compiler-generated stack spills and transfers between scalar and vector code make this relevant to these kernels.

   **Fix:** model finite dispatch capacity and cross-pipeline memory ordering. Without address traces, use conservative synchronization for potentially aliasing accesses and publish sensitivity to that assumption.

4. **High — Several instruction prices and pairing rules lack defensible A7-specific support.**  
   [arm_cycles.py:299](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/arm_cycles.py:299), [arm_cycles.py:320](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/arm_cycles.py:320), [arm_cycles.py:364](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/arm_cycles.py:364)

   Concrete problems include:

   - `vld1.8 {d0-d1},[r0]` transfers 16 bytes but receives **one** NEON cursor cycle. That contradicts the stated one-cycle-per-64-bit-half rule. Arm documents a 64-bit A7 load/store path. [Arm Cortex-A7 specifications](https://support.arm.com/compute-ip/cortex-a7?icid=CY23Q1ProductUpdate)
   - `vpush {d8-d15}` is classified as arithmetic, costs one cycle, and incorrectly writes `d8`. Register ranges are not expanded by `regs()`, so `{d0-d3}` also loses intermediate registers.
   - `LDRD/STRD` always consume two issue cycles; integer division gets multiply latency and one issue cycle.
   - A plain register-register ALU operation and an immediate ALU operation share one class. The fitted `immsh` switch therefore cannot accurately express actual slot restrictions or operand-specific forwarding.
   - Transfers in both directions share one latency and synchronize both cursors indiscriminately.

   The **Arm-contributed GCC A7 scheduling description** distinguishes immediate versus register ALU operations, shifted-operand forwarding, transfer direction, division occupancy, and doubleword memory operations. It also models NEON issue differently from this dispatch scheme. Compiler scheduling tables are not hardware measurements, but these discrepancies require explanation. [GCC A7 scheduling model](https://raw.githubusercontent.com/gcc-mirror/gcc/master/gcc/config/arm/cortex-a7.md)

   **Fix:** establish an instruction-form timing table with documented sources and uncertainty. A 64-bit datapath makes two-cycle Q arithmetic plausible; it does **not** establish universal throughput, latency, or queue behavior.

5. **High — The scalar calibration anchor is mislabeled as a measurement of the current algorithm.**  
   [arm_cycles.py:361](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/arm_cycles.py:361), [ascon-c README:209](/home/leo/projects/PRESENT_mod/third_party/ext/ascon-c/README.md:209)

   The README’s **37.5 c/B** scalar A7 entry carries an asterisk explicitly identifying it as an eBACS result for **Ascon v1.2**. It is not a matched measurement of this SP 800-232 implementation, compiler, or binary. Nevertheless, it selects a pairing rule that changes the modeled scalar Ascon result by roughly 40%.

   **Failure scenario:** a difference caused by algorithm version, implementation, or compiler is attributed to issue-slot eligibility, and that selected rule is then transferred to ChaCha and other Ascon variants.

   **Fix:** identify the original implementation and measurement configuration. Until matched evidence exists, describe this as an indirect historical anchor and retain both pairing alternatives as sensitivity cases.

   The code **correctly admits that the scalar point is in-sample**. That disclosure is honest; the provenance and strength of the inference are the problems.

6. **Medium — The PRESENT fit does not identify the model’s important assumptions or reproduce the production configuration.**  
   [fit_a7.py:39](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/calib/fit_a7.py:39), [a7_present_calib.c:1](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/calib/a7_present_calib.c:1), [arm/Makefile:30](/home/leo/projects/PRESENT_mod/chacha_ascon/arm/Makefile:30)

   The grid varies only pairing, taken-branch cost, and misprediction penalty. `load_lat` and `neon_lat` each have one candidate. Transfer latency, NEON memory timing, slow-operation classes, and decoupling behavior are not fitted.

   The calibration describes GCC 14, `-O3`, Thumb-2; the study defaults to `-O2`, ARM mode, and the existing ELF identifies GCC **13.2.1**. Calibration also uses a 4 KiB working set, while the original throughput harness uses 64 KiB. These differences do not prohibit transfer, but they invalidate treating small training residuals as established prediction accuracy.

   **Fix:** preserve calibration build commands, compiler versions, binaries or hashes, converted target values, and replay results. Distinguish fitted parameters from assumed ones; report sensitivity across the actual instruction mixes and build modes.

   **The unit conversion itself is correct:** the historical column is ns/B, so multiply by **1.296**, equivalently use `1296 / MB/s`. The ordinary `bitslice` and `neon` calibration calls include packing/unpacking and match those row names; they should not use the `*-bs` measurements.

7. **Medium — The external NEON comparison cannot justify the reported close ranking.**  
   [arm_cycles.py:363](/home/leo/projects/PRESENT_mod/chacha_ascon/tools/arm_cycles.py:363), [a7-cycles.csv:41](/home/leo/projects/PRESENT_mod/chacha_ascon/results/arm/a7-cycles.csv:41), [a7-cycles.csv:50](/home/leo/projects/PRESENT_mod/chacha_ascon/results/arm/a7-cycles.csv:50)

   `ascon-c/neon` is outside the stated fitting inputs, so calling it **out of fit** is reasonable if the model was frozen before consulting it. It remains an unmatched external comparison, not a controlled held-out experiment.

   The model gives **27.085 versus 30.7 c/B**, an **11.8% underestimate**. At 64 bytes it gives **48.172 versus 55.9**, a **13.8% underestimate**. Meanwhile, the predicted long-message advantage of `neon-x2` over `ascon-c/neon` is only **1.0%**.

   **Failure scenario:** that small difference is reported as evidence that two-message NEON is faster, although model defects and observed external disagreement comfortably exceed it.

   **Fix:** report these implementations as unresolved by the model. Keep the CSV’s existing **ESTIMATE, no board** labeling, and attach configuration/provenance and sensitivity results rather than implying ranking confidence from decimal precision.

What I checked and found correct:

- **ChaCha20:** rotations, quarter-round ordering, feed-forward, all four transposes, and output block ordering are correct. The vector loop handles whole 256-byte groups; the scalar tail receives the counter advanced by four per group. Exact in-place operation is safe, and byte-vector accesses support unaligned message buffers. Counter wrap is explicitly a caller restriction in [chacha20.h:7](/home/leo/projects/PRESENT_mod/chacha_ascon/include/chacha20.h:7); wrapping after the final permitted block does not cause an extra block to be generated.
- **Ascon:** IV, round constants, S-box, rotations, little-endian `0x01` padding, domain-separation bit, key additions, and tag extraction agree with [SP 800-232, Algorithm 3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.pdf). Empty AD skips absorption; nonempty block-aligned AD gets the extra padded block. Plaintext always gets final padding, including empty and block-aligned inputs.
- **Ascon jobs and aliasing:** paired lanes use independent inputs; odd jobs fall back correctly; zero jobs dereference no job. Full plaintext blocks are loaded before stores, and partial blocks are buffered, making per-job `c == m` safe.
- **Build and accounting:** the A7 registry selects the intended implementations, Thumb-only assembly gets Thumb compilation, and multi-message results divide by total payload bytes. The tests cover ChaCha misalignment and counter-boundary vectors, and Ascon partial blocks, AD lengths, distinct lanes, odd job counts, and in-place operation. These passing functional checks establish no hardware timing accuracy.