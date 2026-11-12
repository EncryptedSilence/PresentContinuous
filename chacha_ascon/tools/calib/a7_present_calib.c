/* Calibration of tools/arm_cycles.py --core a7 against hardware: PRESENT kernels
 * whose Cortex-A7 cycles/byte were MEASURED on an Orange Pi R1 (Allwinner H2+,
 * 1296 MHz; results/speed-arm.csv, mode=throughput, Debian gcc 14 -O3
 * -march=native, i.e. Thumb-2 + NEON). Built here with the same source and
 * equivalent flags (-O3 -mcpu=cortex-a7 -mthumb -mfpu=neon-vfpv4) and run between
 * ca_mark()s under the model. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "present/present.h"
#include "present/variant.h"

void ca_mark(void);
#define WS 4096
static uint64_t in[WS / 8], out[WS / 8];
static present_ctx_t ctx;

int main(void)
{
    const present_variant_t *v = present_variant_by_name("present-80-r16");
    uint8_t key[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    if (!v || present_init(&ctx, v, key, 10)) { printf("init failed\n"); return 1; }
    for (int i = 0; i < WS / 8; i++) in[i] = 0x0123456789abcdefULL * (i + 1);
    printf("REGION 0 - - 0 0 0\n"); ca_mark(); ca_mark();

    printf("REGION 1 present-80-r16 table 1 %d %d\n", WS, WS); ca_mark();
    for (int i = 0; i < WS / 8; i++) out[i] = present_encrypt_table(&ctx, in[i]);
    ca_mark();
    printf("REGION 2 present-80-r16 bitslice 1 %d %d\n", WS, WS); ca_mark();
    for (int g = 0; g < WS / 8 / PRESENT_BITSLICE_BLOCKS; g++)
        present_encrypt_bitslice(&ctx, in + PRESENT_BITSLICE_BLOCKS * g, out + PRESENT_BITSLICE_BLOCKS * g);
    ca_mark();
    printf("REGION 3 present-80-r16 neon 1 %d %d\n", WS, WS); ca_mark();
    for (int g = 0; g < WS / 8 / PRESENT_NEON_BLOCKS; g++)
        present_encrypt_neon(&ctx, in + PRESENT_NEON_BLOCKS * g, out + PRESENT_NEON_BLOCKS * g);
    ca_mark();
    printf("REGION 4 present-80-r16 ref 1 256 256\n"); ca_mark();
    for (int i = 0; i < 256 / 8; i++) out[i] = present_encrypt_ref(&ctx, in[i]);
    ca_mark();
    printf("sum %08lx\n", (unsigned long)(out[3] ^ out[200]));
    return 0;
}
