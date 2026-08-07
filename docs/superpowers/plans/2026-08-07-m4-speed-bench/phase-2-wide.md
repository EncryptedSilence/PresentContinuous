# Phase 2 — The 128-bit ciphers

Tasks 4–5. Host-only; no hardware needed. See [README.md](README.md) for global constraints.

AES and AES-lin444 share no code with `src/` — they live standalone in `bench/wide_bench.c`, which mixes the cipher definitions with an x86-specific measurement harness. The firmware needs the ciphers without the harness, and needs a bitslice path that is not AVX2.

---

### Task 4: Extract the wide cipher cores

A pure extraction with no behaviour change. Doing it as its own task means the refactor can be verified against byte-identical benchmark output before any new code depends on it.

**Files:**
- Create: `bench/wide_ciphers.h`
- Modify: `bench/wide_bench.c`

**Interfaces:**
- Consumes: `src/gen/sbox_circuits.h`.
- Produces: `aes_key_t`, `lin_key_t`, `aes_key_schedule(aes_key_t *, const uint8_t key[16])`, `lin_key_schedule(lin_key_t *, const uint8_t key[16])`, `aes_encrypt1(const aes_key_t *, int rounds, const uint8_t in[16], uint8_t out[16])`, `aes_encrypt4(const aes_key_t *, int rounds, const uint8_t *in, uint8_t *out)`, `lin_encrypt_ref(...)`, `lin_encrypt1(...)` — same signatures as today except that every encrypt function takes an explicit `int rounds` parameter where it currently reads a file-scope value.

- [ ] **Step 1: Record the current output as the regression baseline**

```bash
make build/wide_bench && ./build/wide_bench --csv /tmp/wide-before.csv && head -3 /tmp/wide-before.csv
```
Expected: a CSV whose header is `cipher,rounds,impl,cycles_per_byte,cycles_per_byte_min,mb_per_sec`. Keep this file for Step 3.

- [ ] **Step 2: Move the cipher code into the header**

Move these regions of `bench/wide_bench.c` verbatim into `bench/wide_ciphers.h`, wrapped in an `#ifndef WIDE_CIPHERS_H` include guard:

- the key-schedule types and functions (`aes_key_t`, `lin_key_t`, `aes_key_schedule`, `lin_key_schedule`, around `:145`)
- `aes_encrypt1` (`:186`), `aes_encrypt4` (`:203`)
- `lin_encrypt_ref` (`:282`), `lin_encrypt1` (`:331`)
- the AES S-box / round-constant tables and `AES_SHIFTROWS` data those functions read

**Leave in `wide_bench.c`:** `aes_encrypt_bs` (`:618`), `lin_encrypt_bs` (`:633`), the `__m256i` transposes (`:378` onward), and the whole measurement harness. Those are x86-only, and Task 5 supersedes them for the M4.

Replace the moved regions with `#include "wide_ciphers.h"`.

Where a moved function read a file-scope round count, add an `int rounds` parameter and pass the same value at each call site. The header must not declare any file-scope mutable state — the firmware includes it too.

- [ ] **Step 3: Verify byte-identical benchmark output**

```bash
make build/wide_bench && ./build/wide_bench --csv /tmp/wide-after.csv
diff <(cut -d, -f1-3 /tmp/wide-before.csv) <(cut -d, -f1-3 /tmp/wide-after.csv)
```
Expected: no output from `diff`. Columns 1-3 are cipher/rounds/impl; the timing columns vary run to run and are deliberately not compared.

- [ ] **Step 4: Verify no host regression**

Run: `make test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bench/wide_ciphers.h bench/wide_bench.c
git commit -m "Extract wide cipher cores from the x86 benchmark harness"
```

---

### Task 5: 32-bit bitslice for the wide ciphers

**Files:**
- Create: `bench/wide_bitslice32.h`
- Create: `tests/test_wide_bitslice32.c`
- Modify: `Makefile` (`TESTS`)

**Interfaces:**
- Consumes: `bench/wide_ciphers.h` (Task 4), `present_circuit8_u32_dispatch` (Task 2).
- Produces:
  ```c
  #define WIDE_BS32_BLOCKS 32
  #define WIDE_BS32_BITS   128
  void aes_encrypt_bs32(const aes_key_t *k, int rounds, const uint8_t *in, uint8_t *out);
  void lin_encrypt_bs32(const lin_key_t *k, int rounds, const uint8_t *in, uint8_t *out);
  ```
  `in` and `out` are `WIDE_BS32_BLOCKS * 16` bytes.

- [ ] **Step 1: Write the failing test**

```c
/* tests/test_wide_bitslice32.c -- wide bitslice32 agrees with the scalar path. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "wide_ciphers.h"
#include "wide_bitslice32.h"

int main(void)
{
    uint8_t key[16], in[WIDE_BS32_BLOCKS * 16];
    uint8_t got[WIDE_BS32_BLOCKS * 16], want[16];
    int failures = 0;

    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (size_t i = 0; i < sizeof in; i++) in[i] = (uint8_t)(i * 31 + 5);

    /* The two round counts the benchmark actually uses: AES at 5, lin444 at 4. */
    aes_key_t ak; aes_key_schedule(&ak, key);
    aes_encrypt_bs32(&ak, 5, in, got);
    for (int b = 0; b < WIDE_BS32_BLOCKS; b++) {
        aes_encrypt1(&ak, 5, in + b * 16, want);
        if (memcmp(got + b * 16, want, 16) != 0) {
            printf("  aes r=5 block %d mismatch\n", b); failures++; break;
        }
    }

    lin_key_t lk; lin_key_schedule(&lk, key);
    lin_encrypt_bs32(&lk, 4, in, got);
    for (int b = 0; b < WIDE_BS32_BLOCKS; b++) {
        lin_encrypt1(&lk, 4, in + b * 16, want);
        if (memcmp(got + b * 16, want, 16) != 0) {
            printf("  aes-lin444 r=4 block %d mismatch\n", b); failures++; break;
        }
    }

    if (failures) { printf("FAIL: %d wide bitslice32 mismatches\n", failures); return 1; }
    printf("ok: wide bitslice32 matches the scalar path\n");
    return 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
make build/test_wide_bitslice32
```
Expected: FAIL to compile — `wide_bitslice32.h` does not exist.

- [ ] **Step 3: Implement `bench/wide_bitslice32.h`**

Port `aes_encrypt_bs` / `lin_encrypt_bs` from `bench/wide_bench.c` with three substitutions:

| AVX2 | 32-bit |
|---|---|
| `__m256i` | `uint32_t` |
| `_mm256_xor_si256(a, b)` | `(a) ^ (b)` |
| `present_circuit8_avx2_c2(...)` | `present_circuit8_u32_dispatch(cid, ...)` |

State is `WIDE_BS32_BITS` (128) `uint32_t` words — 128 state bits × 32 blocks. Note this is the *same generated circuit* the AVX2 path uses, which is the property `bench/wide_bench.c:373` already maintains: one AES S-box circuit, shared, never a second copy.

The transpose follows Task 3's shape, one bit-width up:

```c
#define WIDE_BS32_BLOCKS 32
#define WIDE_BS32_BITS   128

static void wide_bs32_pack(const uint8_t *in, uint32_t *state)
{
    for (int bit = 0; bit < WIDE_BS32_BITS; bit++) {
        uint32_t w = 0;
        for (int blk = 0; blk < WIDE_BS32_BLOCKS; blk++) {
            const uint8_t *p = in + blk * 16;
            w |= (uint32_t)((p[bit >> 3] >> (bit & 7)) & 1u) << blk;
        }
        state[bit] = w;
    }
}

static void wide_bs32_unpack(const uint32_t *state, uint8_t *out)
{
    memset(out, 0, (size_t)WIDE_BS32_BLOCKS * 16);
    for (int bit = 0; bit < WIDE_BS32_BITS; bit++)
        for (int blk = 0; blk < WIDE_BS32_BLOCKS; blk++)
            out[blk * 16 + (bit >> 3)] |=
                (uint8_t)(((state[bit] >> blk) & 1u) << (bit & 7));
}
```

The bit-within-byte convention here (`p[bit >> 3] >> (bit & 7)`) must match whatever `aes_encrypt1` uses for its state bytes. If the test fails on every block with a byte-permuted result, that convention is the first thing to check.

- [ ] **Step 4: Run the test to verify it passes**

```bash
make build/test_wide_bitslice32 && ./build/test_wide_bitslice32
```
Expected: PASS — `ok: wide bitslice32 matches the scalar path`

- [ ] **Step 5: Verify no host regression**

Run: `make test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add bench/wide_bitslice32.h tests/test_wide_bitslice32.c Makefile
git commit -m "Add 32-bit bitslice path for the 128-bit ciphers"
```
