/* RFC 8439 wrapper around chacha20_m4_blocks (chacha20_m4_core.S): state setup,
 * whole blocks in assembly, the final partial block through a 64-byte bounce
 * buffer (so the assembly never touches bytes past len). */
#include <string.h>
#include "chacha20.h"

void chacha20_m4_blocks(uint8_t *out, const uint8_t *in, size_t nblocks, uint32_t state[16]);

void chacha20_xor_m4(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t key[32], const uint8_t nonce[12], uint32_t counter)
{
    uint32_t s[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    memcpy(s + 4, key, 32);
    s[12] = counter;
    memcpy(s + 13, nonce, 12);
    size_t nb = len / 64;
    if (nb) chacha20_m4_blocks(out, in, nb, s);
    size_t t = len % 64;
    if (t) {
        uint8_t b[64] = {0};
        memcpy(b, in + 64 * nb, t);
        chacha20_m4_blocks(b, b, 1, s);
        memcpy(out + 64 * nb, b, t);
    }
}
