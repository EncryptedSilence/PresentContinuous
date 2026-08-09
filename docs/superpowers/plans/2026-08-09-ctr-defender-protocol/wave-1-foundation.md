# Wave 1 — Foundation

Tasks 1, 2 and 3 are independent of each other and may run in three parallel sessions. Task 1 blocks all of Wave 2. See [README.md](README.md) for global constraints, which every task here implicitly includes.

---

## Task 1: CTR harness foundation

Produces the frozen interface every other backend task consumes. Nothing in Wave 2 can start until `bench/ctr_backend.h` is committed.

**Files:**
- Create: `bench/ctr_backend.h`, `bench/ctr_registry.c`, `bench/ctr_bench.c`, `bench/ctr_narrow.c`, `bench/ctr_wide.c`, `tests/test_ctr.c`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `present_init`, `present_encrypt_ref`, `present_encrypt_table`, `present_encrypt_table_x{2,4,8,16}`, `present_variants`, `present_n_variants` from `include/present/present.h` and `include/present/variant.h`; `aes_key_t`, `lin_key_t` and their encrypt functions from `bench/wide_ciphers.h`.
- Produces: the whole of `bench/ctr_backend.h`, plus `ctr_backends_narrow[]`, `ctr_backends_narrow_count`, `ctr_backends_wide[]`, `ctr_backends_wide_count`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ctr.c`:

```c
/* The correctness gate: every registered backend must reproduce ctr-ref's
 * ciphertext byte for byte over the published workload. This is the same check
 * the harness runs before timing; having it here means a broken backend fails
 * `make test` rather than silently producing a fast wrong number. */
#include <string.h>

#include "ctr_backend.h"
#include "testutil.h"

#define WORKLOAD 65536

static uint8_t buf_ref[WORKLOAD];
static uint8_t buf_got[WORKLOAD];
static _Alignas(32) uint8_t state[CTR_MAX_STATE_BYTES];

/* One key buffer long enough for every backend, because key_bytes is not the
 * same for all of them: the cipher-D family's key material IS its round keys,
 * so it asks for 72 or 48 bytes where PRESENT-80 asks for 10. A 16-byte buffer
 * here would be read far past its end. */
static uint8_t key[CTR_MAX_KEY_BYTES];

static void fill_from(uint8_t *p, size_t n, uint64_t seed)
{
    uint64_t x = seed;
    for (size_t i = 0; i < n; i++) {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        p[i] = (uint8_t)(x * 0x2545F4914F6CDD1Dull >> 56);
    }
}

static void fill(uint8_t *p, size_t n) { fill_from(p, n, 0x0123456789ABCDEFull); }

int main(void)
{
    /* A different seed from the plaintext's, so a backend that confused the two
     * buffers would not accidentally agree with the reference. */
    fill_from(key, sizeof key, 0xFEDCBA9876543210ull);

    CHECK(ctr_backend_count() > 0, "no backends registered");

    for (size_t i = 0; i < ctr_backend_count(); i++) {
        const ctr_backend_t *b = ctr_backend_at(i);
        const ctr_backend_t *ref = ctr_backend_reference_for(b->cipher);

        CHECK(ref != NULL, "%s: no ctr-ref backend registered for %s",
              b->name, b->cipher);
        if (!ref) continue;
        if (b->available && !b->available()) continue;

        fill(buf_ref, WORKLOAD);
        memcpy(buf_got, buf_ref, WORKLOAD);

        ref->prepare(state, key, ref->key_bytes);
        ref->run(state, buf_ref, WORKLOAD, 0);

        b->prepare(state, key, b->key_bytes);
        b->run(state, buf_got, WORKLOAD, 0);

        CHECK(memcmp(buf_ref, buf_got, WORKLOAD) == 0,
              "%s (%s): ciphertext differs from ctr-ref", b->name, b->cipher);
    }

    /* A backend that XORs nothing would pass a memcmp against a broken ref, so
     * pin the ref itself: CTR must change the buffer, and must be its own
     * inverse when applied twice. */
    {
        const ctr_backend_t *ref = ctr_backend_reference_for(ctr_backend_at(0)->cipher);
        fill(buf_ref, WORKLOAD);
        memcpy(buf_got, buf_ref, WORKLOAD);
        ref->prepare(state, key, ref->key_bytes);
        ref->run(state, buf_got, WORKLOAD, 0);
        CHECK(memcmp(buf_ref, buf_got, WORKLOAD) != 0,
              "ctr-ref left the buffer unchanged");
        ref->run(state, buf_got, WORKLOAD, 0);
        CHECK(memcmp(buf_ref, buf_got, WORKLOAD) == 0,
              "ctr-ref is not an involution");
    }

    return test_summary("ctr");
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `make build/test_ctr`
Expected: FAIL — `fatal error: ctr_backend.h: No such file or directory`.

- [ ] **Step 3: Write the interface header**

Create `bench/ctr_backend.h`. **This file is frozen once Task 1 is committed.** Tasks 4, 5 and 6 depend on it and must not change it; if one of them needs a change, that is a review conversation, not an edit.

```c
/* One CTR backend: a complete counter-mode pass over a byte buffer.
 *
 * The split between prepare() and run() is the point of this interface.
 * prepare() is key expansion plus any table construction: for a video session
 * that is a once-per-session cost, so it is measured, but separately and never
 * inside run(). run() is the operation the main table reports -- generate
 * counters, encrypt them, materialise the keystream as bytes, XOR into the
 * buffer, store -- and it must contain every step of that, including any
 * transpose a bitsliced backend needs. A backend that assumes its input is
 * already bitsliced measures a kernel ceiling, and kernel ceilings belong in
 * bench/bench_main.c, not here.
 *
 * Counter definition, which ctr-ref establishes and every other backend must
 * reproduce byte for byte: block i is the integer ctr0 + i; its keystream bytes
 * are that block serialised big-endian. For the 128-bit ciphers the counter
 * occupies the low 64 bits of the 16-byte block and the high 64 bits are zero.
 */
#ifndef CTR_BACKEND_H
#define CTR_BACKEND_H

#include <stddef.h>
#include <stdint.h>

/* Large enough for the biggest backend state in the tree: a present_ctx_t
 * (66,056 B with decryption, 33,032 B without) with headroom for a bitsliced
 * round-key expansion. Registration asserts state_bytes against it. */
#define CTR_MAX_STATE_BYTES 262144

/* Large enough for the longest key any registered backend asks for. Sized by the
 * same rule bench/bench_main.c uses, (PRESENT_MAX_ROUNDS + 1) * 8, so a variant
 * added later with more rounds cannot overflow a caller's buffer. The longest
 * key in the current set is cipher-D's 72 bytes -- see key_bytes below. */
#define CTR_MAX_KEY_BYTES 256

typedef struct {
    /* "ctr-ref", "ctr-table-x4", "ctr-bitslice-avx2", ... Unique within a cipher. */
    const char *name;
    /* The reported cipher name, exactly as tools/cipher_set.py resolves it:
     * "present-80-r16", "present-80-lin444-297-r7", "cipher-D",
     * "cipher-D-lin444-297-r5", "cipher-D-lin444-297-aes-r5", "aes-r5",
     * "aes-lin444-0-8-15-r4". */
    const char *cipher;
    /* 8 for the five 64-bit constructions, 16 for the two 128-bit ones. */
    size_t block_bytes;
    /* Key length prepare() expects, which is present_variant_key_bytes(v) for
     * the 64-bit set and 16 for the 128-bit set.
     *
     * This is NOT 10-or-16. Three of the five 64-bit constructions -- cipher-D
     * and the two cipher-D-lin444-297 variants -- declare key_schedule
     * "independent", so their key material IS the round keys: (rounds + 1) * 8
     * bytes, read with no truncation, and present_key_schedule rejects any other
     * length outright. cipher-D at 8 rounds wants 72 bytes; the two r5 variants
     * want 48. Their variant JSONs say key_bits 576 and 384 respectively.
     * bench/bench_main.c sizes its own key buffer at
     * (PRESENT_MAX_ROUNDS + 1) * PRESENT_BLOCK_BITS / 8 for exactly this reason.
     *
     * The same fact is why the spec excludes the cipher-D family from the
     * master-key search kernel: independent round-key material has no master key
     * to search for. */
    size_t key_bytes;
    /* Bytes of backend-private state prepare() writes. <= CTR_MAX_STATE_BYTES. */
    size_t state_bytes;
    /* 1 if this backend can run on this build and this CPU; NULL means always.
     * This is what keeps an AVX2 backend out of an ARM run without an #ifdef at
     * every call site. */
    int (*available)(void);
    /* Key expansion and table construction. Timed, but separately from run(). */
    void (*prepare)(void *state, const uint8_t *key, size_t key_len);
    /* The timed operation. len is a multiple of block_bytes and the XOR is in
     * place. Must not allocate, and must not touch anything outside `state` and
     * buf[0..len). */
    void (*run)(const void *state, uint8_t *buf, size_t len, uint64_t ctr0);
} ctr_backend_t;

/* The registry. bench/ctr_registry.c concatenates the per-ISA groups; these
 * three functions are the only supported way to reach them. */
size_t ctr_backend_count(void);
const ctr_backend_t *ctr_backend_at(size_t i);
/* The ctr-ref backend for `cipher`, or NULL. This is the correctness oracle. */
const ctr_backend_t *ctr_backend_reference_for(const char *cipher);

#endif /* CTR_BACKEND_H */
```

- [ ] **Step 4: Write the narrow backends**

Create `bench/ctr_narrow.c` exporting `ctr_backends_narrow[]` and `ctr_backends_narrow_count`. Private state is a `present_ctx_t`; `prepare` looks the variant up by name in `present_variants` and calls `present_init`. Two `run` bodies serve every table-driven backend:

```c
/* ctr-ref and ctr-table: one block at a time. */
static void run_1(const void *st, uint8_t *buf, size_t len, uint64_t ctr0,
                  uint64_t (*enc)(const present_ctx_t *, uint64_t))
{
    const present_ctx_t *ctx = st;
    for (size_t off = 0; off < len; off += 8) {
        uint64_t ks = enc(ctx, ctr0 + off / 8);
        for (int b = 0; b < 8; b++)      /* big-endian serialisation */
            buf[off + b] ^= (uint8_t)(ks >> (56 - 8 * b));
    }
}

/* ctr-table-xN: N blocks at a time. n <= 16. */
static void run_x(const void *st, uint8_t *buf, size_t len, uint64_t ctr0,
                  void (*enc)(const present_ctx_t *, const uint64_t *, uint64_t *),
                  int n)
{
    const present_ctx_t *ctx = st;
    uint64_t in[16], ks[16];
    for (size_t off = 0; off < len; off += (size_t)n * 8) {
        for (int i = 0; i < n; i++) in[i] = ctr0 + off / 8 + (uint64_t)i;
        enc(ctx, in, ks);
        for (int i = 0; i < n; i++)
            for (int b = 0; b < 8; b++)
                buf[off + 8 * i + b] ^= (uint8_t)(ks[i] >> (56 - 8 * b));
    }
}
```

Each registered backend gets a thin wrapper of the right signature — the `ctr_backend_t.run` field takes no function pointer, so `run_1` and `run_x` are called from per-backend one-line wrappers.

Register, for each of the five 64-bit ciphers: `ctr-ref`, `ctr-table`, `ctr-table-x2`, `ctr-table-x4`, `ctr-table-x8`, `ctr-table-x16`. That is 30 backends.

- [ ] **Step 5: Write the wide backends**

Create `bench/ctr_wide.c` exporting `ctr_backends_wide[]` and `ctr_backends_wide_count`, with the same two `run` shapes over the 16-byte block. Private state is `aes_key_t` for `aes-r5` and `lin_key_t` for `aes-lin444-0-8-15-r4`.

The counter block is 16 bytes: eight zero bytes, then `ctr0 + i` serialised big-endian into bytes 8..15. Round counts come from `tools/cipher_set.py`'s `VARIANT_OVERRIDES` — `aes` at 5 rounds, `aes-lin444-0-8-15` at 4 — and are hardcoded nowhere else.

Register for each: `ctr-ref`, `ctr-table`, `ctr-table-x2`, `ctr-table-x4`, `ctr-table-x8`. That is 10 backends.

- [ ] **Step 6: Write the registry**

Create `bench/ctr_registry.c`. Each Wave 2 task appends one entry to `groups[]`; that line is the only shared edit between the three parallel sessions.

```c
#include <string.h>
#include "ctr_backend.h"

extern const ctr_backend_t ctr_backends_narrow[];
extern const size_t ctr_backends_narrow_count;
extern const ctr_backend_t ctr_backends_wide[];
extern const size_t ctr_backends_wide_count;

static const struct { const ctr_backend_t *v; const size_t *n; } groups[] = {
    { ctr_backends_narrow, &ctr_backends_narrow_count },
    { ctr_backends_wide,   &ctr_backends_wide_count   },
    /* Task 4  appends: { ctr_backends_bitslice,  &ctr_backends_bitslice_count  }, */
    /* Task 4  appends: { ctr_backends_avx2,      &ctr_backends_avx2_count      }, */
    /* Task 5  appends: { ctr_backends_neon,      &ctr_backends_neon_count      }, */
    /* Task 6  appends: { ctr_backends_wide_neon, &ctr_backends_wide_neon_count }, */
};

#define NGROUPS (sizeof groups / sizeof groups[0])

size_t ctr_backend_count(void)
{
    size_t n = 0;
    for (size_t g = 0; g < NGROUPS; g++) n += *groups[g].n;
    return n;
}

const ctr_backend_t *ctr_backend_at(size_t i)
{
    for (size_t g = 0; g < NGROUPS; g++) {
        if (i < *groups[g].n) return &groups[g].v[i];
        i -= *groups[g].n;
    }
    return NULL;
}

const ctr_backend_t *ctr_backend_reference_for(const char *cipher)
{
    for (size_t i = 0; i < ctr_backend_count(); i++) {
        const ctr_backend_t *b = ctr_backend_at(i);
        if (!strcmp(b->name, "ctr-ref") && !strcmp(b->cipher, cipher)) return b;
    }
    return NULL;
}
```

- [ ] **Step 7: Add the Makefile rule and run the test**

Follow the existing `$(BUILD)/test_wide_bitslice32` pattern and add `$(BUILD)/test_ctr` to `TESTS`:

```make
CTR_SRCS = bench/ctr_registry.c bench/ctr_narrow.c bench/ctr_wide.c

$(BUILD)/test_ctr: tests/test_ctr.c $(CTR_SRCS) bench/ctr_backend.h \
                   $(CORE_OBJS) | $(BUILD)
	$(CC) $(CFLAGS) -Ibench -Itests -o $@ $< $(CTR_SRCS) $(CORE_OBJS) $(LDFLAGS)
```

Run: `make build/test_ctr && ./build/test_ctr`
Expected: PASS — `ok   ctr (N checks)` with N ≥ 42.

- [ ] **Step 8: Write the harness**

Create `bench/ctr_bench.c`. Command line:

```
./build/ctr_bench --csv PATH [--size 65536] [--trials 15] [--cipher NAME] [--impl NAME]
```

Behaviour, in this order:

1. Allocate one buffer of `--size` bytes, filled from the same xorshift as the test.
2. **Correctness gate.** For every backend that will be measured, run the same comparison against `ctr-ref` that `tests/test_ctr.c` does. On any mismatch, print the offending backend and `exit(1)` **before writing any CSV row**. A partial CSV is worse than none — that is the failure mode `results/m4-speed.csv`'s header warns about.
3. Time `prepare` over 2000 repetitions, median of `--trials`, into `prepare_ns`.
4. Time `run` over the whole buffer: 3 warmup trials, then `--trials` timed trials with `clock_gettime(CLOCK_MONOTONIC)`, median reported. On x86 also read `__rdtsc` into a secondary column.
5. Emit one CSV row per backend.

CSV header, verbatim:

```
cipher,impl,size_bytes,block_bytes,rounds,mbit_per_sec,ns_median,ns_min,prepare_ns,tsc_per_byte
```

`mbit_per_sec` is `size_bytes * 8 / ns_median * 1000` — decimal megabits, matching how the paper states throughput. `tsc_per_byte` is written as `NA` on targets without a TSC, **never** as a nanosecond count under a cycles heading; that substitution is exactly what made the raw `cycles` column of `results/wide-speed-arm.csv` unusable and had to be discarded in its header.

- [ ] **Step 9: Verify the harness end to end**

Run: `make build/ctr_bench && ./build/ctr_bench --csv /tmp/ctr.csv --size 65536`
Expected: one row per registered backend. `prepare_ns` for the table-driven 64-bit ciphers should land in the hundreds of microseconds — they build 16 KiB of tables, so compare against the `ctxinit` rows of `results/speed.csv` (~207,000 ns there) and expect the same order.

Then deliberately break one backend — change a `^=` to `=` in `run_1` — and confirm the gate refuses to write the CSV at all. Revert.

- [ ] **Step 10: Commit**

```bash
git add bench/ctr_backend.h bench/ctr_registry.c bench/ctr_bench.c \
        bench/ctr_narrow.c bench/ctr_wide.c tests/test_ctr.c Makefile
git commit -m "Measure a complete CTR pass instead of a round function"
```

---

## Task 2: M4 fixed-layout build infrastructure

Independent of the CTR harness: it only changes where code lands.

**Files:**
- Modify: `fw/m4/link/product.ld`, `Makefile`
- Create: `tools/tests/test_m4_layout.py`

**Interfaces:**
- Produces: a `.timed` output section at a fixed flash address, and `tools/tests/test_m4_layout.py` which Task 10 relies on to enforce it across per-cipher images.

- [ ] **Step 1: Write the failing test**

`tools/tests/test_m4_layout.py` runs `arm-none-eabi-nm -n` over every built image under `build/m4/` and asserts the timed entry symbol sits at the expected fixed address in all of them. It skips with a clear message if `arm-none-eabi-nm` is absent, so the host test suite still passes on a machine without the cross toolchain.

- [ ] **Step 2: Run it to verify it fails**

Run: `make m4-bench-fw && python3 -m unittest tools.tests.test_m4_layout -v`
Expected: FAIL — no `.timed` section exists yet, so the symbol is at whatever address the linker chose.

- [ ] **Step 3: Add the section to the linker script**

In `fw/m4/link/product.ld`, **ahead of** `.text`:

```ld
  /* The timed kernel at a fixed address, so a measurement cannot depend on
     which unrelated routine happened to precede it in the image. The repository
     measured up to 7.5% variation from position relative to the 128-bit flash
     fetch boundary; pinning the address is what removes it.

     Placed before .text on purpose, for the same reason sram_noart.ld places
     .ramtext first: ld assigns each input section to the first output section
     whose pattern matches, so with an unqualified *(.text*) first, .timed would
     match nothing and every symbol would stay where it was while the link still
     succeeded. tools/tests/test_m4_layout.py is the guard on that. */
  .timed 0x08010000 : ALIGN(16) { KEEP(*(.timed*)) . = ALIGN(16); } > FLASH
```

- [ ] **Step 4: Mark the kernel and rebuild**

Put `__attribute__((section(".timed"), aligned(16)))` on the timed entry point and on everything inlined into it.

Run: `make m4-bench-fw && python3 -m unittest tools.tests.test_m4_layout -v`
Expected: PASS, with the symbol at `0x08010000` in every image.

- [ ] **Step 5: Confirm the rest of the image still links**

Run: `make m4-bench-fw && arm-none-eabi-size build/m4/*.elf`
Expected: flash usage unchanged to within the alignment padding; the CCM assertion in `product.ld` still holds.

- [ ] **Step 6: Commit**

```bash
git add fw/m4/link/product.ld Makefile tools/tests/test_m4_layout.py fw/m4
git commit -m "Pin the M4 timed kernel to a fixed flash address"
```

---

## Task 3: CUDA attacker split

Fully independent of everything else in the plan.

**Files:**
- Modify: `bench/gpu_bench.cu`, `Makefile`
- Create: `results/v2/cuda/block-eval.csv`, `results/v2/cuda/master-key-search.csv`

**Interfaces:**
- Produces: two CSVs with distinct metrics — `block_evals_per_sec` and `master_key_candidates_per_sec` — that Task 11 wires into the manifest.

- [ ] **Step 1: Rename the existing metric**

The current benchmark is a fixed-key block-evaluation benchmark, with key expansion outside and one pre-expanded key for the whole batch. Name it that. The CSV gains `block_evals_per_sec` alongside `gb_per_sec`, and the 4 h budget column becomes `block_evals_in_4h`.

Run: `grep -rn "tests_per_sec\|tests/s" --include=*.cu --include=*.py --include=*.md --include=*.csv .`
Expected after the change: matches only inside `SUPERSEDED` headers.

- [ ] **Step 2: Write the master-key-search kernel**

Each thread takes its own candidate master key, runs the key schedule, encrypts a known plaintext and compares against a target ciphertext. PRESENT uses the standard 80-bit schedule; AES uses the AES-128 schedule. Matches go to a small output buffer; the host reads only the rare hits.

- [ ] **Step 3: Restrict it to constructions that have a master key**

Only `present-80-r16`, `present-80-lin444-297-r7` and `aes-r5`. The cipher-D family uses independent round-key material, so no comparable master-key schedule exists, and forcing all seven rows into a master-key search would invent a mapping the constructions do not have.

**Write the exclusion and its reason into the CSV header**, not only into the paper's prose:

```
# cipher-D, cipher-D-lin444-297-r5 and cipher-D-lin444-297-aes-r5 are absent by
# construction, not by omission: they use independent round-key material and have
# no master-key schedule, so a master-key candidate rate is undefined for them.
# Their comparable figure is in block-eval.csv.
```

- [ ] **Step 4: Verify the kernel actually finds a planted key**

Plant a known key inside the searched range and confirm the kernel reports exactly that candidate and no other.

Run: the kernel's self-test mode.
Expected: exactly one hit, at the planted index. A search kernel that finds nothing runs at a very attractive speed, and nothing else in the harness would notice.

- [ ] **Step 5: Measure and commit**

The CUDA campaign needs a quiet machine and is serial with the x86 campaign (Wave 4); the code and its self-test land now.

```bash
git add bench/gpu_bench.cu Makefile
git commit -m "Separate block evaluation from master-key search on the GPU"
```
