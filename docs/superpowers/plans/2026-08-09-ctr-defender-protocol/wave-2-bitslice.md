# Wave 2 — Bitsliced CTR backends

Tasks 4, 5 and 6 may run in three parallel sessions. All three depend on `bench/ctr_backend.h` being committed by Task 1, and each touches exactly one line of `bench/ctr_registry.c`. See [README.md](README.md) for global constraints.

The public header already states the principle these tasks implement: *"in counter mode that is the normal case: the counters can be produced in bitsliced form directly, since all but the low bits are shared between blocks."* Nobody had written that code. This is it.

---

## Task 4: Bitsliced CTR backends for x86

**Files:**
- Create: `src/present_ctr.h`, `src/present_ctr_bitslice.c`, `src/present_ctr_avx2.c`
- Modify: `bench/ctr_registry.c` (two lines), `tests/test_ctr.c` (one added block), `Makefile`

**Interfaces:**
- Consumes: `ctr_backend_t` from `bench/ctr_backend.h`; `present_encrypt_bitslice_bs`, `present_encrypt_bitslice32_bs`, `present_encrypt_avx2_bs`, `present_avx2_unpack`, `present_transpose64`, `present_have_avx2` from `include/present/present.h`.
- Produces:
  - `void present_ctr_counters64(uint64_t *state, uint64_t base)` — 64 slices for 64 consecutive counters
  - `void present_ctr_counters32(uint32_t *state, uint64_t base)` — 64 slices for 32 consecutive counters
  - `ctr_backends_bitslice[]` / `ctr_backends_bitslice_count`
  - `ctr_backends_avx2[]` / `ctr_backends_avx2_count`

- [ ] **Step 1: Write the failing test for bitsliced counter generation**

Add to `tests/test_ctr.c`, before `return test_summary(...)`, with `#include "present/present.h"` and `#include "present_ctr.h"` at the top:

```c
    /* Bitsliced counter generation must agree with transposing the counters the
     * slow way. This is the one step with no reference implementation to fall
     * back on, so it gets its own check rather than only being covered by the
     * end-to-end ciphertext comparison -- a counter generator that is wrong in
     * the same way for every backend would pass that comparison. */
    {
        uint64_t plain[64], want[64], got[64];
        for (uint64_t base = 0; base < 256; base += 64) {
            for (int i = 0; i < 64; i++) plain[i] = base + (uint64_t)i;
            present_transpose64(plain, want);
            present_ctr_counters64(got, base);
            for (int i = 0; i < 64; i++)
                CHECK_EQ64(got[i], want[i], "counter slice %d at base %llu",
                           i, (unsigned long long)base);
        }
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `make build/test_ctr`
Expected: FAIL — `implicit declaration of function 'present_ctr_counters64'`.

- [ ] **Step 3: Implement counter generation**

Create `src/present_ctr.h` with the two declarations, and implement in `src/present_ctr_bitslice.c`:

```c
/* The 64 slices of the 64 consecutive counters base .. base+63, where base is a
 * multiple of 64.
 *
 * Why this is cheap -- which is what makes a bitsliced CTR backend honest rather
 * than a transpose in disguise: for i < 6, bit i of (base + j) equals bit i of j,
 * because base's low six bits are zero, so slice i is a constant that does not
 * depend on base at all. For i >= 6 all 64 blocks share the same bit, so the
 * slice is all-ones or all-zeroes. Six constants and 58 broadcasts, against a
 * 64x64 transpose's couple of hundred operations.
 *
 * The six constants are the transpose's own masks, which is not a coincidence:
 * slice i of the identity counter block IS the bit-i-of-index pattern. */
static const uint64_t ctr_low_slice[6] = {
    0xAAAAAAAAAAAAAAAAull, 0xCCCCCCCCCCCCCCCCull, 0xF0F0F0F0F0F0F0F0ull,
    0xFF00FF00FF00FF00ull, 0xFFFF0000FFFF0000ull, 0xFFFFFFFF00000000ull,
};

void present_ctr_counters64(uint64_t *state, uint64_t base)
{
    for (int i = 0; i < 6; i++) state[i] = ctr_low_slice[i];
    for (int i = 6; i < 64; i++)
        state[i] = (uint64_t)0 - ((base >> i) & 1);   /* 0 or all-ones */
}
```

`present_ctr_counters32` is the same with five constant slices (`0xAAAAAAAA`, `0xCCCCCCCC`, `0xF0F0F0F0`, `0xFF00FF00`, `0xFFFF0000`), 59 broadcasts, and groups of 32.

- [ ] **Step 4: Run the test to verify it passes**

Run: `make build/test_ctr && ./build/test_ctr`
Expected: PASS on the counter-slice checks.

- [ ] **Step 5: Implement `ctr-bitslice-u64` and `ctr-bitslice-u32`**

Per group: generate the bitsliced counters, run the bitsliced round function, transpose the result back, XOR the big-endian-serialised keystream into the buffer. **The transpose stays inside this loop** — moving it out is precisely the thing this protocol exists to stop.

```c
static void run_bs64(const void *st, uint8_t *buf, size_t len, uint64_t ctr0)
{
    const present_ctx_t *ctx = st;
    _Alignas(32) uint64_t state[64], scratch[64], ks[64];

    for (size_t off = 0; off < len; off += 64 * 8) {
        present_ctr_counters64(state, ctr0 + off / 8);
        present_transpose64(present_encrypt_bitslice_bs(ctx, state, scratch), ks);
        for (int i = 0; i < 64; i++)
            for (int b = 0; b < 8; b++)
                buf[off + 8 * i + b] ^= (uint8_t)(ks[i] >> (56 - 8 * b));
    }
}
```

`present_encrypt_bitslice_bs` ping-pongs between the two buffers and returns whichever holds the answer, so use its return value rather than assuming `state`.

For the u32 variant, mind the sizing trap the public header calls out: `present_encrypt_bitslice32_bs` wants **64** `uint32_t` of state and scratch, not 32. Sizing it by block count gives half what the kernel writes.

`ctr0` must be a multiple of the group size. The harness always starts at 0 with a whole number of groups, so assert it rather than handling the general case — a partial first group would need a different counter generator and no caller wants one.

- [ ] **Step 6: Implement `ctr-bitslice-avx2`**

In `src/present_ctr_avx2.c`: 256 blocks per group, four 64-bit words per slice. Slices 0..7 are constant patterns spanning the four words; slices 8..63 are broadcasts. Unpack with `present_avx2_unpack`. 32-byte alignment on `state` and `scratch`. `available = present_have_avx2`.

- [ ] **Step 7: Register and run the full gate**

Append the two entries to `bench/ctr_registry.c`'s `groups[]` and add the objects to the Makefile rules for both `test_ctr` and `ctr_bench`.

Run: `make test`
Expected: `ok   ctr` with the three new backends included for all five 64-bit ciphers, and every other suite still passing.

- [ ] **Step 8: Confirm the ceiling gap is real**

Run: `./build/ctr_bench --csv /tmp/a.csv --cipher present-80-r16`

Compare `ctr-bitslice-avx2` against the `avx2-bs` row of `results/speed.csv`.

Expected: the CTR figure is **lower**. The gap is the transpose plus the byte-oriented XOR — the cost this whole protocol exists to stop hiding. Put the observed ratio in the commit message; it is the headline justification for the change, and a reviewer should be able to read it without rerunning anything.

If the CTR figure is *not* lower, stop and investigate before committing: either the transpose is being optimised out of the timed region, or the comparison is not against the same round count.

- [ ] **Step 9: Commit**

```bash
git add src/present_ctr.h src/present_ctr_bitslice.c src/present_ctr_avx2.c \
        bench/ctr_registry.c tests/test_ctr.c Makefile
git commit -m "Generate CTR counters in bitsliced form and pay the transpose"
```

---

## Task 5: Bitsliced CTR backend for NEON

Runs in parallel with Task 4.

**Files:**
- Create: `src/present_ctr_neon.c`
- Modify: `bench/ctr_registry.c` (one line), `Makefile`

**Interfaces:**
- Consumes: `present_encrypt_neon_bs`, `present_neon_unpack`, `present_have_neon` from `include/present/present.h`; `present_ctr_counters64` from Task 4. **If Task 4 has not landed, copy the six-constant table into this file rather than blocking**, and flag the duplicate for the reviewer to merge at integration — a cross-session dependency is not worth a stall here.
- Produces: `ctr_backends_neon[]` / `ctr_backends_neon_count`.

- [ ] **Step 1: Confirm the registry-driven test covers this**

`tests/test_ctr.c` iterates the registry, so a newly registered backend is tested with no new test code. Verify that is actually true before relying on it.

Run: `grep -n "ctr_backend_at\|ctr_backend_count" tests/test_ctr.c`
Expected: the loop over `ctr_backend_count()` from Task 1. If it is absent, Task 1 is not committed — stop and say so rather than working around it.

- [ ] **Step 2: Verify the backend is absent**

Run on the A7 (or with the armhf cross-compiler): `./build/ctr_bench --csv /tmp/n.csv --impl ctr-bitslice-neon`
Expected: no rows.

- [ ] **Step 3: Implement**

128 blocks per group, two 64-bit lanes per slice, so a slice is two words. Slices 0..6 are constant patterns spanning the pair; slices 7..63 are broadcasts. Unpack with `present_neon_unpack`. 16-byte alignment on `state` and `scratch`. `available = present_have_neon`.

- [ ] **Step 4: Register, then run the gate on the board**

Append one entry to `groups[]`, add the object to the Makefile rules.

Run on the A7: `make test`
Expected: `ok   ctr` including `ctr-bitslice-neon` for all five 64-bit ciphers.

- [ ] **Step 5: Compare against the ceiling row**

Run on the A7: `./build/ctr_bench --csv /tmp/n.csv --cipher present-80-r16` and compare against the `neon-bs` row of `results/speed-arm.csv`.
Expected: lower, for the same reason as Task 4 Step 8. Record the ratio in the commit message.

- [ ] **Step 6: Commit**

```bash
git add src/present_ctr_neon.c bench/ctr_registry.c Makefile
git commit -m "Add the NEON bitsliced CTR backend"
```

---

## Task 6: NEON bitslice for AES and AES-lin444

The largest single piece of work in the plan, and the only one whose outcome the spec predicts may be negative.

**Files:**
- Create: `bench/wide_bitslice_neon.h`, `bench/ctr_wide_neon.c`, `tests/test_wide_bitslice_neon.c`
- Modify: `bench/ctr_registry.c` (one line), `Makefile`

**Interfaces:**
- Consumes: `bench/wide_bitslice32.h` as the structural model; `aes_key_t`, `lin_key_t` and the scalar reference encrypt from `bench/wide_ciphers.h`.
- Produces: `wide_neon_pack`, `wide_neon_unpack`, `wide_aes_encrypt_neon_bs`, `wide_lin_encrypt_neon_bs`, and `ctr_backends_wide_neon[]` / `ctr_backends_wide_neon_count`.

**Recorded before the work starts, so the outcome cannot be reinterpreted afterwards:** ARMv7 NEON has sixteen 128-bit registers and a 64-bit integer datapath, while a bitsliced 128-bit AES state is 128 lanes × 128 bits = 2 KiB. It will spill heavily and may lose to the table path. That is a legitimate measured result and the task is complete either way. Do not tune past the point of diminishing returns to rescue it, and do not quietly drop the row if it loses — a bitslice that loses on this core is itself the answer to one of `docs/platform-estimate.md`'s open predictions.

- [ ] **Step 1: Write the failing test**

Create `tests/test_wide_bitslice_neon.c`, modelled on the existing `tests/test_wide_bitslice32.c`: encrypt 128 known blocks through the scalar reference from `bench/wide_ciphers.h` and through `pack` → bitsliced rounds → `unpack`, then compare. Cover both `aes` at 5 rounds and `aes-lin444-0-8-15` at 4.

- [ ] **Step 2: Run it to verify it fails**

Run: `make build/test_wide_bitslice_neon`
Expected: FAIL — `fatal error: wide_bitslice_neon.h: No such file or directory`.

- [ ] **Step 3: Port the S-box**

Translate `bench/wide_bitslice32.h`'s AES S-box circuit to NEON intrinsics (`veorq_u32`, `vandq_u32`, `vornq_u32`, `vbicq_u32`). **Same gate order, same circuit.** A different circuit would make the two platforms incomparable, which is the asymmetry this task exists to remove — and the comparison, not the speed, is what the paper rests on.

- [ ] **Step 4: Port ShiftRows, MixColumns and the lin444 layer**

ShiftRows is a slice permutation and costs nothing at run time — it is a renaming of registers. MixColumns is the xtime chain over bitsliced bytes. The lin444 layer is the XOR chain from `bench/wide_ciphers.h`'s `lin_key_t` path.

- [ ] **Step 5: Run the test to verify it passes**

Run on the A7: `make build/test_wide_bitslice_neon && ./build/test_wide_bitslice_neon`
Expected: PASS for both ciphers.

- [ ] **Step 6: Wrap as a CTR backend**

Create `bench/ctr_wide_neon.c` with the same counter-in-bitsliced-form structure as Task 5, over the 16-byte block: the counter occupies the low 64 bits, so slices 0..6 are the constant index patterns, slices 7..63 are broadcasts, and slices 64..127 are all zero. Append one entry to `groups[]`.

- [ ] **Step 7: Run the gate**

Run on the A7: `make test`
Expected: `ok   ctr` including `ctr-bitslice-neon` for `aes-r5` and `aes-lin444-0-8-15-r4`. All seven constructions now have a bitslice row on both CPU platforms, which is what closes the gap `results/wide-speed-arm.csv`'s header currently documents as a caveat.

- [ ] **Step 8: Commit**

```bash
git add bench/wide_bitslice_neon.h bench/ctr_wide_neon.c \
        tests/test_wide_bitslice_neon.c bench/ctr_registry.c Makefile
git commit -m "Give the 128-bit pair a NEON bitslice so all seven match on both CPUs"
```
