/* Copied unmodified (below this comment) from /home/leo/projects/QalqanSpeed/qalqan.h,
 * QalqanSpeed commit 1813b14 (the user's reference, verified against СТ РК 4009-2025
 * Appendix A). Used here as the reference block function of qalqan-ctr. */
/* qalqan.h - Qalqan-256/128 block cipher, ENCRYPTION only.
 *
 *   Key       : 256-bit (32 bytes)
 *   Block     : 128-bit (16 bytes)
 *   Rounds    : 16 round keys; linear-layer constants c = {1, 17, 14}
 *
 * Portable C (C99/C11): no SIMD, no intrinsics, no platform headers. Endianness-
 * independent (all word<->byte conversions are explicit little-endian), so the
 * output is identical on any CPU. Single-block primitive only -- wire up your own
 * mode of operation (CTR/CFB/OFB only need this encrypt direction).
 */
#ifndef QALQAN_H
#define QALQAN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Expanded key schedule. Treat as opaque; create one per key with qalqan_key_setup. */
typedef struct {
    uint32_t rk[16][4];   /* 16 round keys, each four 32-bit little-endian words */
} qalqan_ctx;

/* Expand a 32-byte key into the round-key schedule. */
void qalqan_key_setup(const uint8_t key[32], qalqan_ctx *ctx);

/* Encrypt one 16-byte block. `in` and `out` may alias (point to the same buffer). */
void qalqan_encrypt_block(const qalqan_ctx *ctx, const uint8_t in[16], uint8_t out[16]);

#ifdef __cplusplus
}
#endif

#endif /* QALQAN_H */
