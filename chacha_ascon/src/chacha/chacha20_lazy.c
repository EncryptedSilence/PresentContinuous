/* ChaCha20 for 32-bit ARM scalar cores (Cortex-M4, Cortex-A7 integer pipe):
 * "lazy rotation", so that no rotate instruction is ever executed.
 *
 * Every ARM data-processing instruction can rotate its second operand for free
 * (`add a, a, b, ror #20`, `eor d, a, d, ror #24`). The obstacle is that ChaCha's
 * rotated values are each used twice -- d after `d <<<= 16` feeds both `c += d`
 * and the next `d ^= a` -- so a compiler materialises the rotate. Instead keep
 * the b and d rows *unrotated* and remember, at compile time, by how much each
 * stored value still has to be rotated left to give the true value:
 *
 *   true b = rotl(sb, PB),  true d = rotl(sd, PD)        (a, c always exact)
 *
 *   a += rotl(sb, PB)          ; add a, a, sb, ror #(32-PB)
 *   sd  = a ^ rotl(sd, PD)     ; eor sd, a, sd, ror #(32-PD)   -> pending 16
 *   c += rotl(sd, 16)          ; add c, c, sd, ror #16
 *   sb  = c ^ rotl(sb, PB)     ; eor sb, c, sb, ror #(32-PB)   -> pending 12
 *   a += rotl(sb, 12)          ; add a, a, sb, ror #20
 *   sd  = a ^ rotl(sd, 16)     ; eor sd, a, sd, ror #16        -> pending 8
 *   c += rotl(sd, 8)           ; add c, c, sd, ror #24
 *   sb  = c ^ rotl(sb, 12)     ; eor sb, c, sb, ror #20        -> pending 7
 *
 * So a quarter-round is exactly 8 instructions instead of 12, and its output
 * pending rotations are (PB, PD) = (7, 8) whatever they were on input. Words
 * 4..7 are always in the b role and 12..15 always in the d role (column and
 * diagonal rounds alike), so the pending amount is uniform per row: (0, 0)
 * entering the first double round, (7, 8) for the other nine, and the final
 * feed-forward applies the last (7, 8) in its own add -- also free.
 *
 * ARM compilers fold `x op rotl(y, k)` into one shifted-operand instruction
 * whenever the rotate has a single use, which this form guarantees. Plain C, so
 * it is also correct (if pointless) anywhere else; little-endian hosts. */
#include <string.h>
#include "chacha20.h"

#define ROTL(x, n) ((n) == 0 ? (x) : (((x) << ((n) & 31)) | ((x) >> ((32 - (n)) & 31))))

#define QRL(a, b, c, d, PB, PD)       \
    a += ROTL(b, PB);                 \
    d = a ^ ROTL(d, PD);              \
    c += ROTL(d, 16);                 \
    b = c ^ ROTL(b, PB);              \
    a += ROTL(b, 12);                 \
    d = a ^ ROTL(d, 16);              \
    c += ROTL(d, 8);                  \
    b = c ^ ROTL(b, 12)

#define DROUND(PB, PD)                                    \
    QRL(x0, x4, x8, x12, PB, PD);  QRL(x1, x5, x9, x13, PB, PD);   \
    QRL(x2, x6, x10, x14, PB, PD); QRL(x3, x7, x11, x15, PB, PD);  \
    QRL(x0, x5, x10, x15, 7, 8);   QRL(x1, x6, x11, x12, 7, 8);    \
    QRL(x2, x7, x8, x13, 7, 8);    QRL(x3, x4, x9, x14, 7, 8)

static inline uint32_t ld32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static inline void st32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

/* One 64-byte keystream block XORed into out (n == 64), or into a partial tail. */
static void block(uint32_t ks[16], const uint32_t s[16])
{
    uint32_t x0 = s[0], x1 = s[1], x2 = s[2], x3 = s[3];
    uint32_t x4 = s[4], x5 = s[5], x6 = s[6], x7 = s[7];
    uint32_t x8 = s[8], x9 = s[9], x10 = s[10], x11 = s[11];
    uint32_t x12 = s[12], x13 = s[13], x14 = s[14], x15 = s[15];
    DROUND(0, 0);
    for (int r = 1; r < 10; r++) {
        DROUND(7, 8);
    }
    ks[0] = x0 + s[0]; ks[1] = x1 + s[1]; ks[2] = x2 + s[2]; ks[3] = x3 + s[3];
    ks[4] = ROTL(x4, 7) + s[4]; ks[5] = ROTL(x5, 7) + s[5];
    ks[6] = ROTL(x6, 7) + s[6]; ks[7] = ROTL(x7, 7) + s[7];
    ks[8] = x8 + s[8]; ks[9] = x9 + s[9]; ks[10] = x10 + s[10]; ks[11] = x11 + s[11];
    ks[12] = ROTL(x12, 8) + s[12]; ks[13] = ROTL(x13, 8) + s[13];
    ks[14] = ROTL(x14, 8) + s[14]; ks[15] = ROTL(x15, 8) + s[15];
}

void chacha20_xor_lazy(uint8_t *out, const uint8_t *in, size_t len,
                       const uint8_t key[32], const uint8_t nonce[12], uint32_t counter)
{
    uint32_t s[16], ks[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = ld32(key + 4 * i);
    s[12] = counter;
    for (int i = 0; i < 3; i++) s[13 + i] = ld32(nonce + 4 * i);
    while (len >= 64) {
        block(ks, s);
        for (int i = 0; i < 16; i++) st32(out + 4 * i, ld32(in + 4 * i) ^ ks[i]);
        s[12]++;
        in += 64; out += 64; len -= 64;
    }
    if (len) {
        block(ks, s);
        uint8_t k8[64];
        memcpy(k8, ks, 64);
        for (size_t i = 0; i < len; i++) out[i] = in[i] ^ k8[i];
    }
}
