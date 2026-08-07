# Phase 1 — Generator and the 32-bit path

Tasks 1–3. Host-only; no hardware needed. See [README.md](README.md) for global constraints.

---

### Task 1: Shared cipher set

Moves the seven-cipher definition out of the FPGA tool so the FPGA and M4 targets cannot drift apart.

**Files:**
- Create: `tools/cipher_set.py`
- Create: `tools/tests/test_cipher_set.py`
- Modify: `tools/gen_fpga.py:22-35`

**Interfaces:**
- Consumes: nothing.
- Produces: `cipher_set.DEFAULT_VARIANTS: list[str]` (repo-relative JSON paths), `cipher_set.VARIANT_OVERRIDES: dict[str, tuple[str, int]]` mapping variant name → (display name, rounds), and `cipher_set.resolve() -> list[tuple[str, str, int]]` returning (json_path, display_name, rounds) for all seven.

- [ ] **Step 1: Write the failing test**

```python
# tools/tests/test_cipher_set.py
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cipher_set  # noqa: E402


class TestCipherSet(unittest.TestCase):
    def test_resolve_returns_seven_ciphers_with_expected_rounds(self):
        got = {name: rounds for _, name, rounds in cipher_set.resolve()}
        self.assertEqual(got, {
            "present-80-r16": 16,
            "present-80-lin444-297-r7": 7,
            "cipher-D": 8,
            "cipher-D-lin444-297-r5": 5,
            "cipher-D-lin444-297-aes-r5": 5,
            "aes-r5": 5,
            "aes-lin444-0-8-15-r4": 4,
        })

    def test_every_variant_file_exists(self):
        root = os.path.join(os.path.dirname(__file__), "..", "..")
        for path, _, _ in cipher_set.resolve():
            self.assertTrue(os.path.isfile(os.path.join(root, path)), path)

    def test_gen_fpga_reexports_the_same_set(self):
        import gen_fpga
        self.assertEqual(gen_fpga.DEFAULT_VARIANTS, cipher_set.DEFAULT_VARIANTS)
        self.assertEqual(gen_fpga.FPGA_VARIANT_OVERRIDES, cipher_set.VARIANT_OVERRIDES)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest discover -s tools/tests -t tools -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'cipher_set'`

- [ ] **Step 3: Write the module**

```python
# tools/cipher_set.py
"""The seven ciphers under test, shared by every hardware target.

An FPGA number and a Cortex-M4 number must always name the same cipher at the
same round count. Keeping one definition here is what guarantees that; both
tools/gen_fpga.py and tools/run_m4_bench.py import it rather than restating it.
"""

import json
import os

DEFAULT_VARIANTS = [
    "variants/present-80-r16.json",
    "variants/present-80-lin444-297-r7.json",
    "variants/cipher-D.json",
    "variants/cipher-D-lin444-297-r5.json",
    "variants/cipher-D-lin444-297-aes-r5.json",
    "variants/wide/aes.json",
    "variants/wide/aes-lin444-0-8-15.json",
]

# Two variants are benchmarked at a round count their JSON does not declare.
# name in JSON -> (name to report, rounds to run)
VARIANT_OVERRIDES = {
    "aes": ("aes-r5", 5),
    "aes-lin444-0-8-15": ("aes-lin444-0-8-15-r4", 4),
}

# The 128-bit ciphers live in bench/wide_ciphers.h, not src/.
WIDE_VARIANTS = frozenset({"aes", "aes-lin444-0-8-15"})


def _name_of(json_path: str) -> str:
    return json_path.rsplit("/", 1)[-1][: -len(".json")]


def resolve() -> list[tuple[str, str, int]]:
    """Returns (json_path, reported_name, rounds) for each of the seven ciphers.

    Rounds come from VARIANT_OVERRIDES when present, otherwise from the JSON.
    """
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    out = []
    for path in DEFAULT_VARIANTS:
        base = _name_of(path)
        with open(os.path.join(root, path)) as fh:
            declared = json.load(fh)["rounds"]
        name, rounds = VARIANT_OVERRIDES.get(base, (base, declared))
        out.append((path, name, rounds))
    return out


def is_wide(json_path: str) -> bool:
    return _name_of(json_path) in WIDE_VARIANTS
```

- [ ] **Step 4: Re-point gen_fpga.py at the shared module**

Replace lines 22-35 of `tools/gen_fpga.py` (the `DEFAULT_VARIANTS` list and the `FPGA_VARIANT_OVERRIDES` dict) with:

```python
from cipher_set import DEFAULT_VARIANTS, VARIANT_OVERRIDES  # noqa: E402

# Retained under the old name: the rest of this file and its tests refer to it.
FPGA_VARIANT_OVERRIDES = VARIANT_OVERRIDES
```

- [ ] **Step 5: Run tests to verify they pass and nothing regressed**

Run: `python3 -m unittest discover -s tools/tests -t tools -v`
Expected: PASS, 3 tests

Run: `python3 tools/gen_fpga.py generate && git diff --stat fpga/generated/`
Expected: PASS, and **no change** to any file under `fpga/generated/` — this is a pure move.

- [ ] **Step 6: Commit**

```bash
git add tools/cipher_set.py tools/tests/test_cipher_set.py tools/gen_fpga.py
git commit -m "Share the seven-cipher set between FPGA and M4 targets"
```

---

### Task 2: `u32` synthesis backend

Emits every S-box circuit a second time over `uint32_t`. The gate sequence is identical to `u64` — Thumb-2 has `BIC` (`a & ~b`) and `ORN` (`a | ~b`) as single instructions, exactly the ops the `u64` backend's gate set assumes — so this is a type substitution, not a re-synthesis. That is what makes it safe.

**Files:**
- Modify: `tools/sbox_synth.c:78-90` (add `BE_U32`), `:288-300` (accept `--backend u32`), `:314` (usage string)
- Modify: `tools/gen_c.py:36` (`BACKENDS`), `:145-160` (synthesise and emit u32)
- Create: `tests/test_circuits32.c`
- Modify: `Makefile` (add `$(BUILD)/test_circuits32` to `TESTS`)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: in `src/gen/sbox_circuits.h`, `present_circuit_u32_c<N>(uint32_t *o3..*o0, uint32_t x0..x3)` for 4-bit S-boxes and `present_circuit8_u32_c<N>(uint32_t *o7..*o0, uint32_t x0..x7)` for 8-bit ones; the dispatchers `present_circuit_u32_dispatch(int cid, ...)` and `present_circuit8_u32_dispatch(int cid, ...)` with the same argument order after `cid`; and `present_circuit_gates_u32_of(int cid) -> int`.

- [ ] **Step 1: Write the failing test**

The test drives each circuit in bitsliced form over all 32 lanes and checks it against the variant's S-box table. It must hold for every circuit, and the output-complement mask must match `u64`'s, because the round-key correction in `present_core.c` is shared.

```c
/* tests/test_circuits32.c -- the u32 circuits compute the same S-boxes as u64. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "internal.h"
#include "gen/sbox_circuits.h"

static int failures = 0;

/* Evaluate a 4-bit circuit bitsliced over 32 lanes: lane j holds input value j
 * for j < 16, and the circuit must produce S(j) ^ outcomp in every lane. */
static void check4(int cid, const uint8_t *sbox, int outcomp)
{
    uint32_t x[4] = {0, 0, 0, 0}, o[4];
    for (int j = 0; j < 16; j++)
        for (int b = 0; b < 4; b++)
            if ((j >> b) & 1) x[b] |= 1u << j;

    present_circuit_u32_dispatch(cid, &o[3], &o[2], &o[1], &o[0],
                                 x[0], x[1], x[2], x[3]);

    for (int j = 0; j < 16; j++) {
        int got = 0;
        for (int b = 0; b < 4; b++) got |= (int)((o[b] >> j) & 1u) << b;
        int want = sbox[j] ^ outcomp;
        if (got != want) {
            printf("  circuit c%d u32: S(%d) = %d, want %d\n", cid, j, got, want);
            failures++;
            return;
        }
    }
}

static void check8(int cid, const uint8_t *sbox, int outcomp)
{
    /* 256 input values do not fit 32 lanes, so run 8 batches of 32. */
    for (int batch = 0; batch < 8; batch++) {
        uint32_t x[8] = {0}, o[8];
        for (int j = 0; j < 32; j++)
            for (int b = 0; b < 8; b++)
                if (((batch * 32 + j) >> b) & 1) x[b] |= 1u << j;

        present_circuit8_u32_dispatch(cid, &o[7], &o[6], &o[5], &o[4],
                                      &o[3], &o[2], &o[1], &o[0],
                                      x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]);

        for (int j = 0; j < 32; j++) {
            int got = 0;
            for (int b = 0; b < 8; b++) got |= (int)((o[b] >> j) & 1u) << b;
            int want = sbox[batch * 32 + j] ^ outcomp;
            if (got != want) {
                printf("  circuit c%d u32: S(%d) = %d, want %d\n",
                       cid, batch * 32 + j, got, want);
                failures++;
                return;
            }
        }
    }
}

int main(void)
{
    for (int i = 0; i < present_n_variants(); i++) {
        const present_variant_t *v = present_variant_at(i);
        int cid = present_circuit_id_for(v->sbox, v->sbox_bits);
        if (cid < 0) continue;   /* no synthesised circuit for this S-box */

        int outcomp = present_circuit_outcomp_mask(cid);
        if (present_circuit_gates_u32_of(cid) != present_circuit_gates(cid)) {
            printf("  circuit c%d: u32 has %d gates, u64 has %d -- must be identical\n",
                   cid, present_circuit_gates_u32_of(cid), present_circuit_gates(cid));
            failures++;
        }
        if (v->sbox_bits == 4) check4(cid, v->sbox, outcomp);
        else check8(cid, v->sbox, outcomp);
    }

    if (failures) { printf("FAIL: %d circuit mismatches\n", failures); return 1; }
    printf("ok: u32 circuits match u64 for every variant\n");
    return 0;
}
```

If `present_circuit_id_for` does not already exist in `internal.h`, add it there as a lookup over the generated circuit table; it is the same mapping `gen_c.py` builds as `circuit_index`.

- [ ] **Step 2: Run test to verify it fails**

```bash
make generate && make build/test_circuits32
```
Expected: FAIL to compile — `present_circuit_u32_dispatch` and `present_circuit_gates_u32_of` do not exist.

- [ ] **Step 3: Add the `u32` backend to the synthesiser**

In `tools/sbox_synth.c`, directly after the `BE_U64` definition at line 78, add a backend that is `BE_U64` with a narrower type. Copy the remaining fields verbatim from `BE_U64` — the gate set must be identical, since that identity is the correctness argument.

```c
/* Cortex-M4. Thumb-2 has BIC (a & ~b) and ORN (a | ~b) as single instructions,
 * the same assumption BE_U64 makes, so the gate set is unchanged and only the
 * word narrows. Identical gate sequences mean the u32 circuit computes the same
 * boolean function as the u64 one by construction. */
static const backend_t BE_U32 = {
    "u32", "uint32_t", "(uint32_t)0", "~(uint32_t)0",
    /* ...remaining fields copied verbatim from BE_U64 (see backend_t at :71-76)... */
};
```

In the `--backend` parsing at line 298, add:

```c
else if (!strcmp(val, "u32")) be = &BE_U32;
```

and extend the usage string at line 314 to `[--backend u64|u32|avx2]`.

- [ ] **Step 4: Emit u32 circuits from the generator**

In `tools/gen_c.py`, change line 36 to:

```python
BACKENDS = ("u64", "u32", "avx2")
```

In `gen_circuits`, after the `u64` synthesis at line 151, add a third synthesis pinned to the *same* output-complement mask (`mask` is chosen by the avx2 pass at line 147 and imposed on the others):

```python
        code, gates, _ = synth(binary, list(tbl), f"c{cid}", "u32", outcomp=mask)
        codes["u32"].append(code)
        counts["u32"].append(gates)
```

The existing emission loop over `BACKENDS` writes `present_circuit_gates_u32[]` with no further change. Keep the `#include <immintrin.h>` emission keyed on `avx2` only — a `u32` build must not require x86 headers, since it has to compile for ARM.

- [ ] **Step 5: Emit the dispatch helpers**

Append to the circuit-header emission in `tools/gen_c.py`:

```python
    parts.append("static inline int present_circuit_gates_u32_of(int cid)\n"
                 "{ return (cid < 0 || cid >= PRESENT_N_CIRCUITS) ? -1\n"
                 "         : present_circuit_gates_u32[cid]; }\n\n")
```

and emit `present_circuit_u32_dispatch` / `present_circuit8_u32_dispatch` as `static inline` functions containing a `switch (cid)` over the generated per-circuit functions of that width, with `default:` leaving the outputs untouched. Only circuits whose `present_circuit_sbox_bits[cid]` matches the dispatcher's width appear in its switch.

- [ ] **Step 6: Run the test to verify it passes**

```bash
make generate && make build/test_circuits32 && ./build/test_circuits32
```
Expected: PASS — `ok: u32 circuits match u64 for every variant`

- [ ] **Step 7: Verify no host regression**

Run: `make test`
Expected: PASS, all existing tests

- [ ] **Step 8: Commit**

```bash
git add tools/sbox_synth.c tools/gen_c.py tests/test_circuits32.c Makefile src/gen/
git commit -m "Add u32 S-box circuit backend for Cortex-M4"
```

---

### Task 3: 32-bit bitslice implementation

**Files:**
- Create: `src/present_bitslice32.c`
- Modify: `include/present/present.h` (declarations), `Makefile` (`LIB_SRC`, `TESTS`)
- Create: `tests/test_bitslice32.c`

**Interfaces:**
- Consumes: `present_circuit_u32_dispatch` / `present_circuit8_u32_dispatch` (Task 2), `LIN444_SPEC_ONE` from `src/lin444_body.h`, `present_ctx_t`.
- Produces:
  ```c
  #define PRESENT_BITSLICE32_BLOCKS 32
  void present_bitslice32_pack(const uint64_t *in, uint32_t *state);
  void present_bitslice32_unpack(const uint32_t *state, uint64_t *out);
  uint32_t *present_encrypt_bitslice32_bs(const present_ctx_t *ctx, uint32_t *state, uint32_t *scratch);
  void present_encrypt_bitslice32(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out);
  ```
  `state` and `scratch` are each `PRESENT_BLOCK_BITS` (64) `uint32_t` words. As with the u64 path, the round function ping-pongs and *returns* the buffer holding the answer rather than copying it back.

- [ ] **Step 1: Write the failing test**

```c
/* tests/test_bitslice32.c -- bitslice32 agrees with the table path, all variants. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "internal.h"

static uint64_t rng_state = 0xC0FFEEull;
static uint64_t rng_next(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

int main(void)
{
    static present_ctx_t ctx;
    int failures = 0;

    for (int i = 0; i < present_n_variants(); i++) {
        const present_variant_t *v = present_variant_at(i);
        uint8_t key[16];
        for (size_t k = 0; k < sizeof key; k++) key[k] = (uint8_t)rng_next();
        if (present_init(&ctx, v, key, (size_t)v->key_bits / 8) != 0) continue;

        uint64_t in[PRESENT_BITSLICE32_BLOCKS], got[PRESENT_BITSLICE32_BLOCKS];
        for (int b = 0; b < PRESENT_BITSLICE32_BLOCKS; b++) in[b] = rng_next();

        present_encrypt_bitslice32(&ctx, in, got);

        for (int b = 0; b < PRESENT_BITSLICE32_BLOCKS; b++) {
            uint64_t want = present_encrypt_table(&ctx, in[b]);
            if (got[b] != want) {
                printf("  %s block %d: got %016llx want %016llx\n",
                       v->name, b, (unsigned long long)got[b],
                       (unsigned long long)want);
                failures++;
                break;
            }
        }
    }

    /* pack/unpack must round-trip exactly. */
    uint64_t orig[PRESENT_BITSLICE32_BLOCKS], back[PRESENT_BITSLICE32_BLOCKS];
    uint32_t st[PRESENT_BLOCK_BITS];
    for (int b = 0; b < PRESENT_BITSLICE32_BLOCKS; b++) orig[b] = rng_next();
    present_bitslice32_pack(orig, st);
    present_bitslice32_unpack(st, back);
    if (memcmp(orig, back, sizeof orig) != 0) {
        printf("  pack/unpack does not round-trip\n");
        failures++;
    }

    if (failures) { printf("FAIL: %d bitslice32 mismatches\n", failures); return 1; }
    printf("ok: bitslice32 matches the table path for every variant\n");
    return 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
make build/test_bitslice32
```
Expected: FAIL to compile — `present_encrypt_bitslice32` undefined.

- [ ] **Step 3: Implement `src/present_bitslice32.c`**

Model it directly on `src/present_bitslice.c`, which is the same algorithm one word-width up. Three parts:

**(a) lin444 instantiation.** The existing macro is already type-parameterized (that is precisely why `src/lin444_body.h` is a header of macros — see its comment), so this mirrors `present_bitslice.c:76-80` with the type changed:

```c
#include "gen/lin_consts.h"
#include "lin444_body.h"
#include "gen/lin444_bodies.h"

#define U32_XOR(a, b) ((a) ^ (b))

#define SPEC_FWD(TAG, C0, C1, C2) \
    LIN444_SPEC_ONE(bs32_lin444, uint32_t, U32_XOR, TAG, LIN444_FWD_BODY_##TAG)
PRESENT_LIN444_LIST(SPEC_FWD)
#undef SPEC_FWD
```

**(b) pack / unpack.** A 32×64 transpose: 32 blocks of 64 bits become 64 words of 32 bits. Correctness matters more than speed here — write the obvious loop first, and only optimize if Phase 4's numbers show the transpose dominating:

```c
void present_bitslice32_pack(const uint64_t *in, uint32_t *state)
{
    for (int bit = 0; bit < PRESENT_BLOCK_BITS; bit++) {
        uint32_t w = 0;
        for (int blk = 0; blk < PRESENT_BITSLICE32_BLOCKS; blk++)
            w |= (uint32_t)((in[blk] >> bit) & 1u) << blk;
        state[bit] = w;
    }
}

void present_bitslice32_unpack(const uint32_t *state, uint64_t *out)
{
    for (int blk = 0; blk < PRESENT_BITSLICE32_BLOCKS; blk++) {
        uint64_t b = 0;
        for (int bit = 0; bit < PRESENT_BLOCK_BITS; bit++)
            b |= (uint64_t)((state[bit] >> blk) & 1u) << bit;
        out[blk] = b;
    }
}
```

**(c) Round function.** Copy the kernel structure from `present_bitslice.c` (the `SBOX_TO` X-macro expansion over the generated encryption kernels), substituting `uint32_t` for `uint64_t` and the `u32` circuit dispatch for the `u64` one. Round keys come from `ctx->rk_mask_enc[r][i]` truncated to 32 bits: those words are all-ones or all-zeros by construction (see the comment at `include/present/present.h:22-26`), so `(uint32_t)ctx->rk_mask_enc[r][i]` is exact, not a lossy narrowing.

- [ ] **Step 4: Declare the entry points**

Add to `include/present/present.h` after the bitslice block:

```c
/* --- 32-bit bitsliced implementation: 32 blocks at a time, encryption only ---
 * The same circuits and the same linear-layer bodies as the 64-bit path, one
 * word-width down. This is the path used on 32-bit targets (Cortex-M4), where a
 * uint64_t is a register pair and every gate would otherwise cost two
 * instructions. in/out are arrays of 32 blocks. */
#define PRESENT_BITSLICE32_BLOCKS 32
void present_bitslice32_pack(const uint64_t *in, uint32_t *state);
void present_bitslice32_unpack(const uint32_t *state, uint64_t *out);
uint32_t *present_encrypt_bitslice32_bs(const present_ctx_t *ctx, uint32_t *state,
                                        uint32_t *scratch);
void present_encrypt_bitslice32(const present_ctx_t *ctx, const uint64_t *in,
                                uint64_t *out);
```

Add `src/present_bitslice32.c` to `LIB_SRC` and `$(BUILD)/test_bitslice32` to `TESTS` in the `Makefile`.

- [ ] **Step 5: Run the test to verify it passes**

```bash
make build/test_bitslice32 && ./build/test_bitslice32
```
Expected: PASS — `ok: bitslice32 matches the table path for every variant`

- [ ] **Step 6: Verify no host regression**

Run: `make test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/present_bitslice32.c include/present/present.h tests/test_bitslice32.c Makefile
git commit -m "Add 32-bit bitslice implementation for 32-bit targets"
```
