/* Contexts of the bitsliced AES-128/256-CTR kernels (src/aes/aes128_bs.c). */
#ifndef CA_AES128_BS_H
#define CA_AES128_BS_H
#include <stdint.h>
typedef struct {
    uint32_t KM[9][128]; /* round keys 1..9 ^ 0x63.., bit b of byte n at [8n+b], 0 / ~0 */
    uint32_t K10[4];     /* round key 10 ^ 0x63.. as little-endian words */
    uint8_t rk0[16];
} aes128_bs_ctx;
typedef struct {
    uint32_t KM[13][128]; /* round keys 1..13 ^ 0x63.., as above */
    uint32_t K14[4];      /* round key 14 ^ 0x63.. */
    uint8_t rk0[16];
} aes256_bs_ctx;
#endif
