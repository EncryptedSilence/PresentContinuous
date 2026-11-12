/* Calibration of tools/arm_cycles.py against hardware: PRESENT kernels whose
 * Cortex-M4 cycles/byte were MEASURED on an STM32F407 (results/m4-speed.csv,
 * config `product`), run here the same way as fw/m4/bench_m4_main.c runs them
 * (WS_BYTES of 8-byte blocks, every ciphertext stored), between ca_mark()s, so
 * the model's estimate can be compared with the measurement. 2048-byte
 * working set here (the model has no caches, so the size only sets the
 * per-call overhead share; the hardware bench used a 4 KiB set). */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "present/present.h"
#include "present/variant.h"

void ca_mark(void);
#define WS 2048
static uint64_t in[WS / 8], out[WS / 8];
static present_ctx_t ctx;

int main(void)
{
    const present_variant_t *v = present_variant_by_name("present-80-r16");
    if (!v) v = present_variant_by_name("present-80");
    uint8_t key[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    if (!v || present_init(&ctx, v, key, 10)) { printf("init failed\n"); return 1; }
    for (int i = 0; i < WS / 8; i++) in[i] = 0x0123456789abcdefULL * (i + 1);
    present_table_fn tfix = present_table_fixed_fn(16);
    printf("REGION 0 - - 0 0 0\n"); ca_mark(); ca_mark();

    printf("REGION 1 present-80-r16 table 1 %d %d\n", WS, WS); ca_mark();
    for (int i = 0; i < WS / 8; i++) out[i] = tfix(&ctx, in[i]);
    ca_mark();
    printf("REGION 2 present-80-r16 table-x4 1 %d %d\n", WS, WS); ca_mark();
    for (int g = 0; g < WS / 32; g++) present_encrypt_table_x4(&ctx, in + 4 * g, out + 4 * g);
    ca_mark();
    printf("REGION 3 present-80-r16 bitslice32 1 %d %d\n", WS, WS); ca_mark();
    for (int g = 0; g < WS / 8 / PRESENT_BITSLICE32_BLOCKS; g++)
        present_encrypt_bitslice32(&ctx, in + PRESENT_BITSLICE32_BLOCKS * g, out + PRESENT_BITSLICE32_BLOCKS * g);
    ca_mark();
    printf("REGION 4 present-80-r16 ref 1 256 256\n"); ca_mark();
    for (int i = 0; i < 256 / 8; i++) out[i] = present_encrypt_ref(&ctx, in[i]);
    ca_mark();
    printf("REGION 5 present-80-r16 bitslice64 1 %d %d\n", WS, WS); ca_mark();
    for (int g = 0; g < WS / 8 / 64; g++) present_encrypt_bitslice(&ctx, in + 64 * g, out + 64 * g);
    ca_mark();
    printf("sum %08lx\n", (unsigned long)(out[3] ^ out[200]));
    return 0;
}
