/* AES-128-CTR on Cortex-M4 with the Schwabe-Stoffelen assembly ("All the AES You
 * Need on Cortex-M3 and M4", CC0; adapted copies in aes128_ctr_m4ss*.S, the
 * unmodified upstream in third_party_m4/aes-armcortexm/). This file is the thin
 * wrapper that gives them the bc_impl contract (include/blockctr.h):
 *
 *   m4ss-tt[-sram]  T-table, one block per iteration, "counter-mode caching"
 *                   (round 1 and most of round 2 precomputed per 256 counters),
 *                   fully unrolled as upstream; -sram: the 1 KiB table in SRAM
 *                   instead of flash.
 *   m4ss-ttl[-sram] the same with rounds 3..9 rolled into a loop (our change;
 *                   the hot loop then fits the STM32F4's 1 KiB ART cache).
 *                   Context: aes128_tt_ctx (rk[44], FIPS-197 round keys as
 *                   little-endian words) from upstream's key schedule.
 *   m4ss-bs         bitsliced, constant time, two blocks per iteration.
 *                   Context: the 352-byte bitsliced key from upstream's
 *                   bitsliced key schedule.
 *
 * Contract decisions (see the .S headers for the asm-side changes):
 *  - Counter: the kernels take nonce[12] || BE32(ctr) directly (the T-table code
 *    was changed to cache on byte 15 instead of upstream's LE byte 0); the
 *    counter wraps mod 2^32 inside the kernels.
 *  - The kernels only ever process whole blocks (16 B; 32 B for bs) and need
 *    len > 0. The wrapper passes the largest whole-block prefix straight
 *    through (in place and unaligned in/out are fine: single LDR/STR, each
 *    block read before it is written) and does the remaining 1..15 (1..31) bytes
 *    through a zero-padded stack buffer with the counter advanced by the
 *    number of blocks done, then copies back exactly the tail: nothing is ever
 *    written past out + len and nothing read past in + len.
 *  - Nothing in the context is written by xor_fn. */
#include <string.h>
#include "blockctr.h"

#define TT_DECL(sfx)                                                                                  \
    void aes128_m4ss_keyschedule##sfx(const uint8_t *key, uint8_t *rk);                               \
    void aes128_m4ss_ctr##sfx(const uint32_t rk[44], const uint8_t *in, uint8_t *out, uint32_t len,   \
                              uint32_t n0, uint32_t n1, uint32_t n2, uint32_t ctr, const uint32_t *rk_end);
TT_DECL()
TT_DECL(_sram)
TT_DECL(_loop)
TT_DECL(_loop_sram)

typedef struct { uint32_t blk[4]; const uint32_t *rk; } bs_param; /* asm's p */
void aes128_m4ss_bs_keyschedule(const uint8_t *key, uint8_t *rk);
void aes128_m4ss_bs_ctr(bs_param *p, const uint8_t *in, uint8_t *out, uint32_t len);

#define M4SS_CHUNK ((size_t)1 << 30) /* multiple of 32: whole blocks and whole bs pairs */

static uint32_t ld32le(const uint8_t *p) { uint32_t w; memcpy(&w, p, 4); return w; } /* LE host */

/* ---- T-table ---- */
typedef void (*tt_ctr_fn)(const uint32_t *, const uint8_t *, uint8_t *, uint32_t, uint32_t, uint32_t,
                          uint32_t, uint32_t, const uint32_t *);

static void tt_setup(void *vctx, const uint8_t *key, void (*ks)(const uint8_t *, uint8_t *))
{
    aes128_tt_ctx *c = vctx;
    memcpy(c->rk, key, 16);                     /* rk[0..3] = key, 4-byte aligned for LDM */
    ks((const uint8_t *)c->rk, (uint8_t *)(c->rk + 4));
}

static inline void tt_xor(tt_ctr_fn f, const void *vctx, uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t nonce[12], uint32_t ctr, const int nr)
{
    const uint32_t *rk = vctx; /* aes128_tt_ctx.rk[44], or 60 words for AES-256 */
    const uint32_t *rk_end = rk + 4 * nr;
    uint32_t n0 = ld32le(nonce), n1 = ld32le(nonce + 4), n2 = ld32le(nonce + 8);
    size_t full = len & ~(size_t)15, rem = len & 15;
    /* The adapted kernels end their loop on a signed compare (upstream's subs/ble),
     * so a single call must stay below 2^31 bytes: feed them at most 1 GiB at a time. */
    for (size_t done = 0; done < full;) {
        size_t chunk = full - done > M4SS_CHUNK ? M4SS_CHUNK : full - done;
        f(rk, in + done, out + done, (uint32_t)chunk, n0, n1, n2, ctr + (uint32_t)(done / 16), rk_end);
        done += chunk;
    }
    if (rem) {
        uint8_t b[16];
        memset(b, 0, sizeof b);
        memcpy(b, in + full, rem);
        f(rk, b, b, 16, n0, n1, n2, ctr + (uint32_t)(full / 16), rk_end);
        memcpy(out + full, b, rem);
    }
}

#define TT_IMPL(sfx)                                                                                 \
    void aes128_setup_m4ss##sfx(void *ctx, const uint8_t *key) { tt_setup(ctx, key, aes128_m4ss_keyschedule##sfx); } \
    void aes128_ctr_m4ss##sfx(const void *ctx, uint8_t *out, const uint8_t *in, size_t len,           \
                              const uint8_t nonce[12], uint32_t ctr)                                  \
    {                                                                                                \
        tt_xor(aes128_m4ss_ctr##sfx, ctx, out, in, len, nonce, ctr, 10);                                \
    }
TT_IMPL()
TT_IMPL(_sram)
TT_IMPL(_loop)
TT_IMPL(_loop_sram)

/* AES-256: rounds 3..13 rolled (AES_M4SS_AES256 in aes128_ctr_m4ss.S). Context:
 * 60 round-key words from the portable key schedule (aes256_setup_ttable, the
 * same LE-word layout), so the setup is shared with the C T-table. */
void aes256_m4ss_ctr_loop(const uint32_t *, const uint8_t *, uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t,
                          uint32_t, const uint32_t *);
void aes256_m4ss_ctr_loop_sram(const uint32_t *, const uint8_t *, uint8_t *, uint32_t, uint32_t, uint32_t,
                               uint32_t, uint32_t, const uint32_t *);
void aes256_ctr_m4ss_loop(const void *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t nonce[12],
                          uint32_t ctr)
{
    tt_xor(aes256_m4ss_ctr_loop, ctx, out, in, len, nonce, ctr, 14);
}
void aes256_ctr_m4ss_loop_sram(const void *ctx, uint8_t *out, const uint8_t *in, size_t len,
                               const uint8_t nonce[12], uint32_t ctr)
{
    tt_xor(aes256_m4ss_ctr_loop_sram, ctx, out, in, len, nonce, ctr, 14);
}

/* ---- bitsliced ---- */
void aes128_setup_m4ss_bs(void *ctx, const uint8_t *key)
{
    uint32_t k[4];
    memcpy(k, key, 16); /* the key schedule loads the key with LDM */
    aes128_m4ss_bs_keyschedule((const uint8_t *)k, ctx);
}

void aes128_ctr_m4ss_bs(const void *ctx, uint8_t *out, const uint8_t *in, size_t len, const uint8_t nonce[12],
                        uint32_t ctr)
{
    bs_param p;
    memcpy(p.blk, nonce, 12);
    p.blk[3] = __builtin_bswap32(ctr);
    p.rk = ctx;
    size_t full = len & ~(size_t)31, rem = len & 31;
    /* At most 1 GiB per kernel call (signed loop end, see tt_xor). The kernel does not
     * leave a usable counter behind, so it is set explicitly before every call. */
    for (size_t done = 0; done < full;) {
        size_t chunk = full - done > M4SS_CHUNK ? M4SS_CHUNK : full - done;
        p.blk[3] = __builtin_bswap32(ctr + (uint32_t)(done / 16));
        aes128_m4ss_bs_ctr(&p, in + done, out + done, (uint32_t)chunk);
        done += chunk;
    }
    if (rem) {
        uint8_t b[32];
        p.blk[3] = __builtin_bswap32(ctr + (uint32_t)(full / 16));
        memset(b, 0, sizeof b);
        memcpy(b, in + full, rem);
        aes128_m4ss_bs_ctr(&p, b, b, 32);
        memcpy(out + full, b, rem);
    }
}
