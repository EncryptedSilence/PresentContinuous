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

### Task 2: `u32` circuits by mechanical retype

Derives every S-box circuit a second time over `uint32_t`, by generalizing the retype tool that commit `6fd7341` introduced for NEON rather than by adding a synthesis backend.

The correctness argument is the one `tools/gen_neon_circuits.py` already states: a bitslice circuit is a pure boolean program over `& | ^ ~`, so retyping its word gives the same program at a different width — bit-for-bit identical behaviour by construction, not by assertion. Thumb-2 additionally has `BIC` (`a & ~b`) and `ORN` (`a | ~b`) as single instructions, the same gate set the `u64` circuits were synthesised against, so every gate stays one instruction on Cortex-M4.

**Files:**
- Create: `tools/gen_retyped_circuits.py` (generalized from `tools/gen_neon_circuits.py`)
- Delete: `tools/gen_neon_circuits.py`
- Modify: `Makefile:28,53-56` (`GENERATED_NEON` becomes `GENERATED_RETYPED`, covering both headers)
- Generated: `src/gen/sbox_circuits_u32.h` (new), `src/gen/sbox_circuits_neon.h` (unchanged output)

**Interfaces:**
- Consumes: `src/gen/sbox_circuits.h`, emitted by `tools/gen_c.py`.
- Produces: in `src/gen/sbox_circuits_u32.h`, `present_circuit_u32_c<N>(uint32_t *o3..*o0, uint32_t x0..x3)` for 4-bit S-boxes and `present_circuit8_u32_c<N>(uint32_t *o7..*o0, uint32_t x0..x7)` for 8-bit ones — the same names and argument orders as the `u64` originals with `_u64_c` replaced by `_u32_c`. No guard: unlike the NEON header this is plain C and compiles everywhere.

- [ ] **Step 1: Establish the regression baseline**

The existing NEON header must come out byte-identical after the refactor. That is the whole safety net for this task.

```bash
make generate
cp src/gen/sbox_circuits_neon.h /tmp/neon-before.h
```

- [ ] **Step 2: Generalize the tool**

Rewrite `tools/gen_neon_circuits.py` as `tools/gen_retyped_circuits.py`, driven by a target table. Keep the existing docstring's explanation of *why* a retype is valid — it is the correctness argument for both targets — and extend it to say the same reasoning covers the 32-bit scalar case.

```python
# One entry per derived backend. `guard` is None when the header needs no
# target predicate; `typedef` is None when the C type is already spelled.
TARGETS = {
    "neon": {
        "suffix": "_neon_c",
        "ctype": "u64x2",
        "guard": "__ARM_NEON",
        "typedef": ('/* may_alias: the round functions view a uint64_t bitslice buffer through\n'
                    ' * this type, exactly as the AVX2 path views its buffer as __m256i. */\n'
                    'typedef uint64_t u64x2 __attribute__((vector_size(16), may_alias));\n'),
        "blurb": ("The scalar u64 circuits, retyped onto a 128-bit two-lane vector so each gate\n"
                  "is one NEON op and 128 blocks are bitsliced at once. Only compiled on targets\n"
                  "that actually have NEON; elsewhere the header is empty."),
    },
    "u32": {
        "suffix": "_u32_c",
        "ctype": "uint32_t",
        "guard": None,
        "typedef": None,
        "blurb": ("The scalar u64 circuits, retyped onto a 32-bit word: 32 blocks bitsliced at\n"
                  "once instead of 64. This is the path for 32-bit targets (Cortex-M4), where a\n"
                  "uint64_t is a register pair and every gate would otherwise cost two\n"
                  "instructions. Thumb-2 has BIC and ORN, so the u64 gate set still maps one\n"
                  "gate to one instruction."),
    },
}
```

The extraction logic is unchanged: locate the span from the first `present_circuit*_u64_c*` definition to the `#if defined(__AVX2__)` line, then substitute `_u64_c` → `suffix` and `uint64_t` → `ctype` within it. Emit the include guard from the target name (`PRESENT_SBOX_CIRCUITS_<NAME>_H`), the `guard` block only when it is not `None`, and keep the `n_funcs` count on stderr.

Usage: `tools/gen_retyped_circuits.py <target> [src] [dst]`.

- [ ] **Step 3: Update the Makefile**

```make
GENERATED_RETYPED := $(GEN)/sbox_circuits_neon.h $(GEN)/sbox_circuits_u32.h

$(GEN)/sbox_circuits_neon.h: $(GEN)/sbox_circuits.h tools/gen_retyped_circuits.py
	$(PYTHON) tools/gen_retyped_circuits.py neon $(GEN)/sbox_circuits.h $@

$(GEN)/sbox_circuits_u32.h: $(GEN)/sbox_circuits.h tools/gen_retyped_circuits.py
	$(PYTHON) tools/gen_retyped_circuits.py u32 $(GEN)/sbox_circuits.h $@
```

Replace every other reference to `GENERATED_NEON` (the object-file prerequisite at `:67` and the `clean` rule at `:149`) with `GENERATED_RETYPED`.

- [ ] **Step 4: Verify the NEON header is byte-identical**

```bash
make generate
diff /tmp/neon-before.h src/gen/sbox_circuits_neon.h && echo "NEON header unchanged"
```
Expected: no differences. Any difference means the refactor altered the existing backend and must be fixed before proceeding.

- [ ] **Step 5: Verify the u32 header is a faithful retype**

```bash
# Same number of circuit functions as the u64 source.
grep -c "static inline void present_circuit" src/gen/sbox_circuits_u32.h
grep -c "static inline void present_circuit.*_u64_c" src/gen/sbox_circuits.h
# No 64-bit types survived the substitution.
! grep -n "uint64_t\|u64x2\|__m256i" src/gen/sbox_circuits_u32.h && echo "no 64-bit types remain"
# It compiles standalone, for the host and for the target.
echo '#include "gen/sbox_circuits_u32.h"
int main(void){return 0;}' > /tmp/c32.c
gcc -Isrc -Iinclude -O2 -Wall -Wextra -c /tmp/c32.c -o /dev/null && echo "host compile ok"
arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -Isrc -Iinclude -O2 -Wall -Wextra \
    -ffreestanding -c /tmp/c32.c -o /dev/null && echo "M4 compile ok"
```
Expected: the two counts match, no 64-bit types remain, both compiles succeed.

The M4 compile is the load-bearing check — it is the first proof anything in this repo builds for the target.

- [ ] **Step 6: Verify no host regression**

Run: `make test`
Expected: PASS, all existing tests including the NEON cross-check

- [ ] **Step 7: Commit**

```bash
git add tools/gen_retyped_circuits.py Makefile src/gen/sbox_circuits_u32.h
git rm tools/gen_neon_circuits.py
git commit -m "Generalize circuit retyping and derive u32 circuits for Cortex-M4"
```

---

### Task 3: 32-bit bitslice implementation

**Files:**
- Create: `src/present_bitslice32.c`
- Modify: `include/present/present.h` (declarations), `Makefile` (`LIB_SRC`), `tests/test_impls.c` (cross-check)

**Interfaces:**
- Consumes: `present_circuit_u32_c<N>` / `present_circuit8_u32_c<N>` from `src/gen/sbox_circuits_u32.h` (Task 2), `LIN444_SPEC_ONE` from `src/lin444_body.h`, `present_ctx_t`.
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

Extend `tests/test_impls.c` following the NEON block at `tests/test_impls.c:116-124`: a guarded section inside the existing per-variant loop that compares against the reference oracle. Do not create a standalone test file.

```c
    /* 32-bit bitsliced path: 32 blocks at a time, encryption only.
     * Always available -- it is plain C, unlike the NEON and AVX2 paths. */
    if (present_variant_has_bitslice(var)) {
        static uint64_t pt[PRESENT_BITSLICE32_BLOCKS], ct[PRESENT_BITSLICE32_BLOCKS];
        static uint64_t back[PRESENT_BITSLICE32_BLOCKS];
        static uint32_t st[PRESENT_BLOCK_BITS];

        for (int i = 0; i < PRESENT_BITSLICE32_BLOCKS; i++) pt[i] = rng_next();
        present_encrypt_bitslice32(&ctx, pt, ct);
        for (int i = 0; i < PRESENT_BITSLICE32_BLOCKS; i++)
            CHECK(ct[i] == present_encrypt_ref(&ctx, pt[i]),
                  "%s: bitslice32 encrypt disagrees with ref at block %d", var->name, i);

        /* The transposes must round-trip exactly, independent of the cipher. */
        present_bitslice32_pack(pt, st);
        present_bitslice32_unpack(st, back);
        CHECK(memcmp(pt, back, sizeof pt) == 0,
              "%s: bitslice32 pack/unpack does not round-trip", var->name);
    }
```

Use the file's existing `CHECK` macro and `rng_next()` rather than introducing new ones, and declare the buffers `static` as the NEON block does to keep them off the stack.

- [ ] **Step 2: Run the test to verify it fails**

```bash
make build/test_impls
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

**(c) Round function.** Copy the kernel structure from `present_bitslice.c` (the `SBOX_TO` X-macro expansion over the generated encryption kernels), substituting `uint32_t` for `uint64_t` and the `_u32_c` circuit functions for the `_u64_c` ones. Round keys come from `ctx->rk_mask_enc[r][i]` truncated to 32 bits: those words are all-ones or all-zeros by construction (see the comment at `include/present/present.h:22-26`), so `(uint32_t)ctx->rk_mask_enc[r][i]` is exact, not a lossy narrowing.

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

Add `src/present_bitslice32.c` to `LIB_SRC` in the `Makefile`. No new `TESTS` entry: the cross-check lives in the existing `test_impls` binary.

- [ ] **Step 5: Run the test to verify it passes**

```bash
make build/test_impls && ./build/test_impls
```
Expected: PASS, including the new bitslice32 cross-check for every variant

- [ ] **Step 6: Verify no host regression**

Run: `make test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/present_bitslice32.c include/present/present.h tests/test_impls.c Makefile
git commit -m "Add 32-bit bitslice implementation for 32-bit targets"
```
