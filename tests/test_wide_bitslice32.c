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

    if (failures) { printf("FAIL: %d wide bitslice32 mismatches\n", failures); return 1; }
    printf("ok: wide bitslice32 matches the scalar path\n");
    return 0;
}
