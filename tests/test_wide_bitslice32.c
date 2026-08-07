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

    /* AMENDED BY THE CONTROLLER AFTER TASK 4: the lin444 oracle below is
     * lin_encrypt_ref, not lin_encrypt1. Task 4 established that lin_encrypt1 is
     * an SSE2 kernel and left it in bench/wide_bench.c, so it is not reachable
     * from a test that includes only wide_ciphers.h + wide_bitslice32.h.
     * lin_encrypt_ref is the portable definition of the cipher and the better
     * oracle regardless. Everything else in this test is unchanged. */

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
        lin_encrypt_ref(&lk, 4, in + b * 16, want);
        if (memcmp(got + b * 16, want, 16) != 0) {
            printf("  aes-lin444 r=4 block %d mismatch\n", b); failures++; break;
        }
    }

    /* Fix round 1: the transpose-free _bs entry points skip pack/unpack and key
     * expansion internally, so doing those by hand around the call has to
     * reproduce the all-in-one wrapper exactly -- the same pattern
     * tests/test_impls.c uses for present_encrypt_bitslice32_bs. Checked
     * directly against the scalar oracle, independent of the wrapper's own
     * "got" above, so a bug shared between the wrapper and the _bs form
     * (rather than only in the wrapper's pack/expand/unpack glue) still shows
     * up here.
     *
     * Fix round 2: both round counts below are checked at rounds=5 (AES) /
     * rounds=4 (lin444) *and* at the opposite parity (AES at 4, lin444 at 5).
     * The _bs kernels ping-pong state and scratch every round, so which
     * buffer holds the result depends on whether the round count is odd or
     * even; mutating "return cur" to "return state" in lin_encrypt_bs32_bs
     * still passed this test when it only ran lin444 at rounds=4 (an even
     * round count, where cur == state on return by coincidence) even though
     * the same mutation is a live bug at odd round counts. Do not collapse
     * this back to one round count per cipher -- that reintroduces exactly
     * the gap a ping-pong-buffer bug can hide behind. */
    {
        uint32_t st[WIDE_BS32_BITS], sc[WIDE_BS32_BITS], km[WIDE_BS32_KM_WORDS];
        uint8_t back[WIDE_BS32_BLOCKS * 16];

        bs32_expand_aes_key(&ak, 5, km);
        wide_bs32_pack(in, st);
        wide_bs32_unpack(aes_encrypt_bs32_bs(km, 5, st, sc), back);
        for (int b = 0; b < WIDE_BS32_BLOCKS; b++) {
            aes_encrypt1(&ak, 5, in + b * 16, want);
            if (memcmp(back + b * 16, want, 16) != 0) {
                printf("  aes-bs32-bs r=5 block %d mismatch\n", b); failures++; break;
            }
        }

        bs32_expand_aes_key(&ak, 4, km);
        wide_bs32_pack(in, st);
        wide_bs32_unpack(aes_encrypt_bs32_bs(km, 4, st, sc), back);
        for (int b = 0; b < WIDE_BS32_BLOCKS; b++) {
            aes_encrypt1(&ak, 4, in + b * 16, want);
            if (memcmp(back + b * 16, want, 16) != 0) {
                printf("  aes-bs32-bs r=4 block %d mismatch\n", b); failures++; break;
            }
        }

        bs32_expand_lin_key(&lk, 4, km);
        wide_bs32_pack(in, st);
        wide_bs32_unpack(lin_encrypt_bs32_bs(&lk, km, 4, st, sc), back);
        for (int b = 0; b < WIDE_BS32_BLOCKS; b++) {
            lin_encrypt_ref(&lk, 4, in + b * 16, want);
            if (memcmp(back + b * 16, want, 16) != 0) {
                printf("  aes-lin444-bs32-bs r=4 block %d mismatch\n", b); failures++; break;
            }
        }

        bs32_expand_lin_key(&lk, 5, km);
        wide_bs32_pack(in, st);
        wide_bs32_unpack(lin_encrypt_bs32_bs(&lk, km, 5, st, sc), back);
        for (int b = 0; b < WIDE_BS32_BLOCKS; b++) {
            lin_encrypt_ref(&lk, 5, in + b * 16, want);
            if (memcmp(back + b * 16, want, 16) != 0) {
                printf("  aes-lin444-bs32-bs r=5 block %d mismatch\n", b); failures++; break;
            }
        }
    }

    if (failures) { printf("FAIL: %d wide bitslice32 mismatches\n", failures); return 1; }
    printf("ok: wide bitslice32 matches the scalar path\n");
    return 0;
}
