/* Qalqan-256/128 in counter mode, reference implementation ("ref"): the block
 * function of qalqan.c (the user's reference, copied unmodified) driven one
 * counter block at a time. The context is the reference qalqan_ctx. */
#include "blockctr.h"
#include "qalqan.h"

void qalqan_setup_ref(void *ctx, const uint8_t *key) { qalqan_key_setup(key, ctx); }

void qalqan_ctr_ref(const void *ctx, uint8_t *out, const uint8_t *in, size_t len,
                    const uint8_t nonce[12], uint32_t ctr)
{
    uint8_t blk[16], ks[16];
    for (size_t off = 0; off < len; off += 16, ctr++) {
        bc_counter_block(blk, nonce, ctr);
        qalqan_encrypt_block(ctx, blk, ks);
        size_t n = len - off < 16 ? len - off : 16;
        for (size_t i = 0; i < n; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
    }
}
