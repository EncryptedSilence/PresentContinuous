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
