/* tests/test_wide_bitslice_neon.c -- the NEON bitslice for the 128-bit pair
 * (AES and AES-lin444) agrees with the scalar reference in bench/wide_ciphers.h.
 *
 * Modelled on tests/test_wide_bitslice32.c: encrypt 128 known blocks through the
 * scalar reference and through pack -> bitsliced rounds -> unpack, then compare.
 * Covers aes at 5 rounds and aes-lin444-0-8-15 at 4, plus the opposite parity
 * for each (to catch a ping-pong-buffer bug) and a direct lane-layout assertion.
 *
 * On a build without NEON (the x86 stub build) wide_bitslice_neon.h defines no
 * kernel, so the test compiles and skips -- the real red->green cycle runs on the
 * Cortex-A7. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "wide_ciphers.h"
#include "wide_bitslice_neon.h"

int main(void)
{
#if !defined(__ARM_NEON)
    printf("skip: wide bitslice neon requires NEON (built without __ARM_NEON)\n");
    return 0;
#else
    uint8_t key[16], in[WIDE_NEON_BLOCKS * 16];
    uint8_t got[WIDE_NEON_BLOCKS * 16], want[16];
    int failures = 0;

    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (size_t i = 0; i < sizeof in; i++) in[i] = (uint8_t)(i * 31 + 5);

    /* The two round counts the benchmark actually uses: AES at 5, lin444 at 4.
     * lin_encrypt_ref is the portable oracle (lin_encrypt1 is an x86-only kernel
     * that lives in bench/wide_bench.c), exactly as test_wide_bitslice32.c uses. */
    aes_key_t ak; aes_key_schedule(&ak, key);
    wide_aes_encrypt_neon(&ak, 5, in, got);
    for (int b = 0; b < WIDE_NEON_BLOCKS; b++) {
        aes_encrypt1(&ak, 5, in + b * 16, want);
        if (memcmp(got + b * 16, want, 16) != 0) {
            printf("  aes r=5 block %d mismatch\n", b); failures++; break;
        }
    }

    lin_key_t lk; lin_key_schedule(&lk, key);
    wide_lin_encrypt_neon(&lk, 4, in, got);
    for (int b = 0; b < WIDE_NEON_BLOCKS; b++) {
        lin_encrypt_ref(&lk, 4, in + b * 16, want);
        if (memcmp(got + b * 16, want, 16) != 0) {
            printf("  aes-lin444 r=4 block %d mismatch\n", b); failures++; break;
        }
    }

    /* The transpose-free _bs entry points, driven by hand and checked directly
     * against the scalar oracle -- so a bug shared between the wrapper and the
     * _bs form still shows up. Both parities are exercised (AES at 5 and 4,
     * lin444 at 4 and 5): the kernels ping-pong state and scratch every round, so
     * which buffer holds the result depends on the round count's parity, and
     * running only one parity per cipher can hide a "return state" mutation. */
    {
        u64x2 st[WIDE_NEON_BITS], sc[WIDE_NEON_BITS], km[WIDE_NEON_KM_WORDS];
        uint8_t back[WIDE_NEON_BLOCKS * 16];

        bs_neon_expand_aes_key(&ak, 5, km);
        wide_neon_pack(in, st);
        wide_neon_unpack(wide_aes_encrypt_neon_bs(km, 5, st, sc), back);
        for (int b = 0; b < WIDE_NEON_BLOCKS; b++) {
            aes_encrypt1(&ak, 5, in + b * 16, want);
            if (memcmp(back + b * 16, want, 16) != 0) {
                printf("  aes-neon-bs r=5 block %d mismatch\n", b); failures++; break;
            }
        }

        bs_neon_expand_aes_key(&ak, 4, km);
        wide_neon_pack(in, st);
        wide_neon_unpack(wide_aes_encrypt_neon_bs(km, 4, st, sc), back);
        for (int b = 0; b < WIDE_NEON_BLOCKS; b++) {
            aes_encrypt1(&ak, 4, in + b * 16, want);
            if (memcmp(back + b * 16, want, 16) != 0) {
                printf("  aes-neon-bs r=4 block %d mismatch\n", b); failures++; break;
            }
        }

        bs_neon_expand_lin_key(&lk, 4, km);
        wide_neon_pack(in, st);
        wide_neon_unpack(wide_lin_encrypt_neon_bs(&lk, km, 4, st, sc), back);
        for (int b = 0; b < WIDE_NEON_BLOCKS; b++) {
            lin_encrypt_ref(&lk, 4, in + b * 16, want);
            if (memcmp(back + b * 16, want, 16) != 0) {
                printf("  aes-lin444-neon-bs r=4 block %d mismatch\n", b); failures++; break;
            }
        }

        bs_neon_expand_lin_key(&lk, 5, km);
        wide_neon_pack(in, st);
        wide_neon_unpack(wide_lin_encrypt_neon_bs(&lk, km, 5, st, sc), back);
        for (int b = 0; b < WIDE_NEON_BLOCKS; b++) {
            lin_encrypt_ref(&lk, 5, in + b * 16, want);
            if (memcmp(back + b * 16, want, 16) != 0) {
                printf("  aes-lin444-neon-bs r=5 block %d mismatch\n", b); failures++; break;
            }
        }
    }

    /* Lane layout, asserted against its definition rather than inferred from a
     * round trip -- pack composed with unpack cannot see a consistent lane
     * permutation. The contract (same as wide_bitslice32.h, one vector wider):
     *
     *   slice j, block b  ==  bit (j%8) of byte (j/8) of block b,
     *
     * with block b at bit b of the 128-bit vector (lane b/64, bit b%64), the
     * identity lane order. */
    {
        u64x2 st[WIDE_NEON_BITS];
        wide_neon_pack(in, st);
        for (int b = 0; b < WIDE_NEON_BLOCKS; b++) {
            const uint8_t *p = in + b * 16;
            uint64_t lane[2];
            for (int j = 0; j < WIDE_NEON_BITS; j++) {
                memcpy(lane, &st[j], sizeof lane);
                int byte = j / 8, bit = j % 8;
                unsigned got_bit = (unsigned)((lane[b / 64] >> (b % 64)) & 1u);
                unsigned want_bit = (unsigned)((p[byte] >> bit) & 1u);
                if (got_bit != want_bit) {
                    printf("  pack layout wrong at block %d slice %d\n", b, j);
                    failures++;
                    b = WIDE_NEON_BLOCKS; break;
                }
            }
        }
    }

    if (failures) { printf("FAIL: %d wide bitslice neon mismatches\n", failures); return 1; }
    printf("ok: wide bitslice neon matches the scalar path\n");
    return 0;
#endif
}
