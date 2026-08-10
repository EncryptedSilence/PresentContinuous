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
/* CTR_STATE_ALIGN, not 32 and not a bare array: bench/ctr_backend.h promises
 * backends that `state` is aligned for the widest vector store they might use,
 * and every caller -- this test included -- is what keeps that promise. */
static _Alignas(CTR_STATE_ALIGN) uint8_t state[CTR_MAX_STATE_BYTES];

/* One key buffer long enough for every backend, because key_bytes is not the
 * same for all of them: the cipher-D family's key material IS its round keys,
 * so it asks for 72 or 48 bytes where PRESENT-80 asks for 10. A 16-byte buffer
 * here would be read far past its end. */
static uint8_t key[CTR_MAX_KEY_BYTES];

/* Two counter origins, for the same reason bench/ctr_bench.c uses two: a
 * backend that ignores ctr0 and starts its own counter at 0, or that keeps the
 * counter in 32-bit SIMD lanes, agrees with ctr-ref everywhere if 0 is the only
 * value ever tried. The second origin carries out of the low 32 bits 128 blocks
 * into the buffer, so both the "ctr0 is dead" and the "counter is 32 bits" bugs
 * produce a mismatch. */
static const uint64_t GATE_CTR0[] = { 0, 0x00000000FFFFFF80ull };
#define N_GATE_CTR0 (sizeof GATE_CTR0 / sizeof GATE_CTR0[0])

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

    /* The registry must describe tools/cipher_set.py's seven ciphers at their
     * round counts and nothing else. A Wave 2 group whose cipher name has a
     * typo would pass every check below -- its own ctr-ref carries the same
     * typo, so it agrees with itself -- and would publish a row under a name no
     * other target in this project has measured. */
    {
        char why[256];
        int bad = ctr_cipher_set_check(why, sizeof why);
        CHECK(bad == 0, "registry disagrees with tools/cipher_set.py: %s", why);
        /* Stop here on failure rather than run the loops below against a
         * registry already known to be malformed: they divide by group_bytes,
         * which is one of the things this check validates as non-zero. CHECK
         * only records a failure, it does not abort. */
        if (bad) return test_summary("ctr");
    }

    for (size_t i = 0; i < ctr_backend_count(); i++) {
        const ctr_backend_t *b = ctr_backend_at(i);
        const ctr_backend_t *ref = ctr_backend_reference_for(b->cipher);

        CHECK(ref != NULL, "%s: no ctr-ref backend registered for %s",
              b->name, b->cipher);
        if (!ref) continue;
        if (b->available && !b->available()) continue;

        /* run() has no partial-group path, so a backend whose group does not
         * divide the workload would write past buf_got. Refuse rather than
         * corrupt: this is the same rule bench/ctr_bench.c applies to --size.
         * The oracle is checked too, since it runs over the same buffer. */
        CHECK(WORKLOAD % b->group_bytes == 0 && WORKLOAD % ref->group_bytes == 0,
              "%s (%s): group_bytes %zu (ctr-ref's %zu) does not divide the "
              "%d-byte workload",
              b->name, b->cipher, b->group_bytes, ref->group_bytes, WORKLOAD);
        if (WORKLOAD % b->group_bytes != 0 || WORKLOAD % ref->group_bytes != 0) continue;

        for (size_t c = 0; c < N_GATE_CTR0; c++) {
            fill(buf_ref, WORKLOAD);
            memcpy(buf_got, buf_ref, WORKLOAD);

            ref->prepare(state, key, ref->key_bytes);
            ref->run(state, buf_ref, WORKLOAD, GATE_CTR0[c]);

            b->prepare(state, key, b->key_bytes);
            b->run(state, buf_got, WORKLOAD, GATE_CTR0[c]);

            CHECK(memcmp(buf_ref, buf_got, WORKLOAD) == 0,
                  "%s (%s) at ctr0=0x%016llx: ciphertext differs from ctr-ref",
                  b->name, b->cipher, (unsigned long long)GATE_CTR0[c]);
        }
    }

    /* A backend that XORs nothing would pass a memcmp against a broken ref, so
     * pin the refs themselves: CTR must change the buffer, and must be its own
     * inverse when applied twice.
     *
     * Every registered ctr-ref, not just the first cipher's. The 128-bit pair
     * needs this most: bench/wide_ciphers.h has one kernel per cipher, so
     * AES-lin444's ctr-ref, ctr-table and all three xN rows run byte-identical
     * code and agree with each other no matter what that code computes. If
     * lin_encrypt_ref emitted zero blocks, all five rows would leave the buffer
     * unchanged, the loop above would pass, and the harness would publish five
     * enormous throughputs for a backend that did nothing. */
    for (size_t i = 0; i < ctr_backend_count(); i++) {
        const ctr_backend_t *ref = ctr_backend_at(i);
        if (strcmp(ref->name, "ctr-ref") != 0) continue;
        if (ref->available && !ref->available()) continue;
        if (WORKLOAD % ref->group_bytes != 0) continue;

        fill(buf_ref, WORKLOAD);
        memcpy(buf_got, buf_ref, WORKLOAD);
        ref->prepare(state, key, ref->key_bytes);
        ref->run(state, buf_got, WORKLOAD, 0);
        CHECK(memcmp(buf_ref, buf_got, WORKLOAD) != 0,
              "ctr-ref (%s) left the buffer unchanged", ref->cipher);
        ref->run(state, buf_got, WORKLOAD, 0);
        CHECK(memcmp(buf_ref, buf_got, WORKLOAD) == 0,
              "ctr-ref (%s) is not an involution", ref->cipher);
    }

    return test_summary("ctr");
}
