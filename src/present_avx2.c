/* AVX2 bitsliced implementation: 256 blocks encrypted in parallel.
 *
 * Same idea as src/present_bitslice.c, four times wider: state bit i of 256 blocks
 * lives in one __m256i, so the whole state is 64 registers' worth (2 KiB, L1
 * resident) and one round is 16 S-box circuits plus the key XOR. Encryption only --
 * this is the throughput path, and it is validated against the reference
 * implementation for every variant.
 *
 * Four things make this faster than 4x the scalar version rather than merely 4x
 * wider. Figures are cycles per byte on an i9-14900HX for PRESENT-80 at 31 rounds,
 * where the whole encryption is 1.33.
 *
 * 1. The pLayer costs *nothing at all*, not even a move: the S-box result is stored
 *    straight to its permuted destination, so the permutation is folded into a
 *    store that had to happen anyway. That only works with the destinations as
 *    immediates, which is why a round function here is specialised on the layer as
 *    well as on the S-box -- see PRESENT_KERNEL_ENC_LIST. Read from v->pbox[]
 *    instead it is a load and an indexed store, 64 of each per round, worth 0.14.
 *    Only a permutation can do this; lin444 runs its XOR chain afterwards.
 *
 * 2. The circuits are synthesised over AVX2's *actual* gate set. AVX2 has vpand,
 *    vpor, vpxor and vpandn but nothing for ~a|b or ~(a^b) -- those need a second
 *    vpxor against an all-ones register. (vpternlogd would cover all of them in one
 *    instruction, but it is AVX-512 and this is not an AVX-512 target.) So
 *    tools/sbox_synth runs a separate search over {AND, OR, XOR, ANDN} and the
 *    result is one instruction per gate.
 *
 * 3. The circuits may leave their output complemented, because a constant XORed
 *    into the state is cancelled once at key setup rather than 16 times a round.
 *    For PRESENT's S-box that is the two NOTs the circuit ends with, 17 gates down
 *    to 15, worth 0.10. See build_key_masks in present_core.c.
 *
 * 4. The 64x64 bit transpose runs on __m256i lanes, so it transposes four groups of
 *    64 blocks for the price of one. Getting the data into that shape needs a 4x4
 *    transpose of 64-bit lanes first, which is 8 shuffles per 4 rows -- far cheaper
 *    than four separate scalar transposes, which is what the naive port would do.
 *
 * What is left is the transposes themselves: a fixed 0.31 per call whatever the
 * round count or the layer, which is 23% of PRESENT-80 and the largest single item
 * remaining. present_encrypt_avx2_bs skips them for a caller that keeps its state
 * bitsliced.
 */

#include <string.h>

#include "internal.h"

#if defined(__AVX2__)

#include <immintrin.h>

#include "gen/sbox_circuits.h"

int present_have_avx2(void) { return 1; }

/* --- getting 256 blocks into and out of bitsliced form ---------------------------
 *
 * Blocks are split into four groups of 64. Group g goes in lane g, so a[k] holds
 * block k of every group and the bit transpose below can run on all four at once.
 * A 4x4 transpose of 64-bit lanes, which is its own inverse, so one routine serves
 * both directions.
 */
static inline void lane_transpose_4x4(const uint64_t *in, __m256i *a)
{
    for (int kk = 0; kk < 64; kk += 4) {
        __m256i r0 = _mm256_loadu_si256((const __m256i *)(in + 0 * 64 + kk));
        __m256i r1 = _mm256_loadu_si256((const __m256i *)(in + 1 * 64 + kk));
        __m256i r2 = _mm256_loadu_si256((const __m256i *)(in + 2 * 64 + kk));
        __m256i r3 = _mm256_loadu_si256((const __m256i *)(in + 3 * 64 + kk));
        __m256i t0 = _mm256_unpacklo_epi64(r0, r1);
        __m256i t1 = _mm256_unpackhi_epi64(r0, r1);
        __m256i t2 = _mm256_unpacklo_epi64(r2, r3);
        __m256i t3 = _mm256_unpackhi_epi64(r2, r3);
        a[kk + 0] = _mm256_permute2x128_si256(t0, t2, 0x20);
        a[kk + 1] = _mm256_permute2x128_si256(t1, t3, 0x20);
        a[kk + 2] = _mm256_permute2x128_si256(t0, t2, 0x31);
        a[kk + 3] = _mm256_permute2x128_si256(t1, t3, 0x31);
    }
}

static inline void lane_transpose_4x4_out(const __m256i *a, uint64_t *out)
{
    for (int kk = 0; kk < 64; kk += 4) {
        __m256i r0 = a[kk + 0], r1 = a[kk + 1], r2 = a[kk + 2], r3 = a[kk + 3];
        __m256i t0 = _mm256_unpacklo_epi64(r0, r1);
        __m256i t1 = _mm256_unpackhi_epi64(r0, r1);
        __m256i t2 = _mm256_unpacklo_epi64(r2, r3);
        __m256i t3 = _mm256_unpackhi_epi64(r2, r3);
        _mm256_storeu_si256((__m256i *)(out + 0 * 64 + kk), _mm256_permute2x128_si256(t0, t2, 0x20));
        _mm256_storeu_si256((__m256i *)(out + 1 * 64 + kk), _mm256_permute2x128_si256(t1, t3, 0x20));
        _mm256_storeu_si256((__m256i *)(out + 2 * 64 + kk), _mm256_permute2x128_si256(t0, t2, 0x31));
        _mm256_storeu_si256((__m256i *)(out + 3 * 64 + kk), _mm256_permute2x128_si256(t1, t3, 0x31));
    }
}

/* The same six-pass recursive block swap as present_transpose64, applied per 64-bit
 * lane so all four groups transpose simultaneously -- but grouped so that the state
 * only crosses L1 twice instead of six times.
 *
 * The trick is which registers each pass touches. Passes with J = 32, 16, 8 only
 * ever pair a[k] with a[k + J], so all three stay inside the set
 * {m, m+8, m+16, ..., m+56} for a fixed m -- eight registers. Passes with J = 4, 2,
 * 1 likewise stay inside {8n, ..., 8n+7}. So each triple of passes can be done with
 * its eight registers held in YMM: 128 loads and 128 stores for the whole
 * transpose, against 384 and 384 for six independent passes over 2 KiB.
 *
 * Both triples have the identical shape -- pair at stride 4, then 2, then 1 -- so
 * one macro serves both; only the shift counts and masks differ. The shifts must be
 * compile-time constants for vpsllq/vpsrlq, which is why this is a macro at all.
 */
#define DSWAP(X, Y, SH, MM)                                                           \
    do {                                                                              \
        __m256i t_ = _mm256_and_si256(                                                \
            _mm256_xor_si256(_mm256_srli_epi64(X, (SH)), Y), MM);                     \
        X = _mm256_xor_si256(X, _mm256_slli_epi64(t_, (SH)));                         \
        Y = _mm256_xor_si256(Y, t_);                                                  \
    } while (0)

#define BT_OCTET(r, S0, M0, S1, M1, S2, M2)                                           \
    do {                                                                              \
        const __m256i m0_ = _mm256_set1_epi64x((long long)(uint64_t)(M0));            \
        const __m256i m1_ = _mm256_set1_epi64x((long long)(uint64_t)(M1));            \
        const __m256i m2_ = _mm256_set1_epi64x((long long)(uint64_t)(M2));            \
        DSWAP(r[0], r[4], S0, m0_); DSWAP(r[1], r[5], S0, m0_);                       \
        DSWAP(r[2], r[6], S0, m0_); DSWAP(r[3], r[7], S0, m0_);                       \
        DSWAP(r[0], r[2], S1, m1_); DSWAP(r[1], r[3], S1, m1_);                       \
        DSWAP(r[4], r[6], S1, m1_); DSWAP(r[5], r[7], S1, m1_);                       \
        DSWAP(r[0], r[1], S2, m2_); DSWAP(r[2], r[3], S2, m2_);                       \
        DSWAP(r[4], r[5], S2, m2_); DSWAP(r[6], r[7], S2, m2_);                       \
    } while (0)

static inline void bit_transpose64x4(__m256i *a)
{
    for (int m = 0; m < 8; m++) {           /* J = 32, 16, 8: stride-8 octets */
        __m256i r[8];
        for (int i = 0; i < 8; i++) r[i] = a[m + 8 * i];
        BT_OCTET(r, 32, 0x00000000FFFFFFFFull,
                    16, 0x0000FFFF0000FFFFull,
                     8, 0x00FF00FF00FF00FFull);
        for (int i = 0; i < 8; i++) a[m + 8 * i] = r[i];
    }
    for (int n = 0; n < 8; n++) {           /* J = 4, 2, 1: contiguous octets */
        __m256i r[8];
        for (int i = 0; i < 8; i++) r[i] = a[8 * n + i];
        BT_OCTET(r, 4, 0x0F0F0F0F0F0F0F0Full,
                    2, 0x3333333333333333ull,
                    1, 0x5555555555555555ull);
        for (int i = 0; i < 8; i++) a[8 * n + i] = r[i];
    }
}

/* --- lin444, four times wider ----------------------------------------------------
 *
 * Same bodies as the scalar backend, instantiated per rotation triple. Baking the
 * constants in matters more here than anywhere else: with them in registers the
 * layer emitted ~600 scalar address instructions against 160 vector XORs, so it
 * was limited by index arithmetic rather than by any of the work it exists to do.
 */
#include "gen/lin_consts.h"
#include "lin444_body.h"
#include "gen/lin444_bodies.h"

#define X4(a, b) _mm256_xor_si256(a, b)

#define SPEC_FWD(TAG, C0, C1, C2) \
    LIN444_SPEC_ONE(av_lin444, __m256i, X4, TAG, LIN444_FWD_BODY_##TAG)
PRESENT_LIN444_LIST(SPEC_FWD)
#undef SPEC_FWD

/* --- rounds ----------------------------------------------------------------------
 *
 * One function per *kernel*: a round function with the S-box circuit and the linear
 * layer both fixed at compile time. Only the pairs some variant actually asks for
 * are instantiated -- tools/gen_c.py works out which -- so this is fewer functions
 * than a circuit x {pbox, lin444} cross product, not more.
 *
 * Fixing the layer is what makes the permutation free. AV_SBOX writes the four
 * circuit outputs straight to their permuted slots, and with the destinations as
 * immediates the pLayer costs not even a move: the store had to happen anyway. Read
 * from v->pbox[] instead it is a load and an indexed store, 64 of each per round,
 * which measured 7% of PRESENT's total -- worth having, and worth not charging to
 * lin444's account, since lin444's rotations are immediates either way.
 *
 * lin444 cannot fold into the store: it writes back in place and then runs its XOR
 * chain into the other buffer.
 */
#define AV_SBOX_TO(CID, BUF, I, D0, D1, D2, D3)                                       \
    {                                                                                 \
        __m256i y0, y1, y2, y3;                                                       \
        present_circuit_avx2_c##CID(&y3, &y2, &y1, &y0,                               \
            X4(cur[4 * (I) + 0], _mm256_set1_epi64x((long long)km[4 * (I) + 0])),     \
            X4(cur[4 * (I) + 1], _mm256_set1_epi64x((long long)km[4 * (I) + 1])),     \
            X4(cur[4 * (I) + 2], _mm256_set1_epi64x((long long)km[4 * (I) + 2])),     \
            X4(cur[4 * (I) + 3], _mm256_set1_epi64x((long long)km[4 * (I) + 3])));    \
        BUF[D0] = y0; BUF[D1] = y1; BUF[D2] = y2; BUF[D3] = y3;                       \
    }

/* The X-macro callback: the permutation list cannot know the circuit id, so it
 * passes one through for us. */
#define AV_SBOX(CID, I, D0, D1, D2, D3) AV_SBOX_TO(CID, alt, I, D0, D1, D2, D3)

/* The whitening key, and then the answer -- which after an odd number of ping-pong
 * swaps sits in the scratch buffer. Returning the pointer rather than copying it
 * back saves a 2 KiB memcpy per call, ~4% of PRESENT's total at 31 rounds. */
#define AV_ENC_TAIL                                                                   \
    { const uint64_t *km = ctx->rk_mask_enc[rounds];                                  \
      for (int i = 0; i < PRESENT_BLOCK_BITS; i++)                                    \
          cur[i] = X4(cur[i], _mm256_set1_epi64x((long long)km[i])); }                \
    return cur;

#define AV_ENC_PBOX(KID, CID, TAG)                                                    \
static __m256i *av_enc_k##KID(const present_ctx_t *ctx, __m256i *cur, __m256i *alt)    \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        const uint64_t *km = ctx->rk_mask_enc[r];                                     \
        PRESENT_PBOX_STORE_##TAG(AV_SBOX, CID)                                        \
        { __m256i *tmp = cur; cur = alt; alt = tmp; }                                 \
    }                                                                                 \
    AV_ENC_TAIL                                                                       \
}

/* The 8-bit circuit needs eight live inputs, eight live outputs and hundreds of
 * temporaries against sixteen architectural registers, so the compiler spills it
 * heavily -- there is no arranging around that at 1100 gates. Kept anyway so the
 * cost is measured rather than argued. */
#define AV_SBOX8_TO(CID, BUF, I, D0, D1, D2, D3, D4, D5, D6, D7)                      \
    {                                                                                 \
        __m256i y0, y1, y2, y3, y4, y5, y6, y7;                                       \
        present_circuit8_avx2_c##CID(&y7, &y6, &y5, &y4, &y3, &y2, &y1, &y0,          \
            X4(cur[8 * (I) + 0], _mm256_set1_epi64x((long long)km[8 * (I) + 0])),     \
            X4(cur[8 * (I) + 1], _mm256_set1_epi64x((long long)km[8 * (I) + 1])),     \
            X4(cur[8 * (I) + 2], _mm256_set1_epi64x((long long)km[8 * (I) + 2])),     \
            X4(cur[8 * (I) + 3], _mm256_set1_epi64x((long long)km[8 * (I) + 3])),     \
            X4(cur[8 * (I) + 4], _mm256_set1_epi64x((long long)km[8 * (I) + 4])),     \
            X4(cur[8 * (I) + 5], _mm256_set1_epi64x((long long)km[8 * (I) + 5])),     \
            X4(cur[8 * (I) + 6], _mm256_set1_epi64x((long long)km[8 * (I) + 6])),     \
            X4(cur[8 * (I) + 7], _mm256_set1_epi64x((long long)km[8 * (I) + 7])));    \
        BUF[D0] = y0; BUF[D1] = y1; BUF[D2] = y2; BUF[D3] = y3;                       \
        BUF[D4] = y4; BUF[D5] = y5; BUF[D6] = y6; BUF[D7] = y7;                       \
    }
#define AV_SBOX8(CID, I, D0, D1, D2, D3, D4, D5, D6, D7)                              \
    AV_SBOX8_TO(CID, alt, I, D0, D1, D2, D3, D4, D5, D6, D7)

#define AV_ENC_PBOX8(KID, CID, TAG)                                                   \
static __m256i *av_enc_k##KID(const present_ctx_t *ctx, __m256i *cur, __m256i *alt)    \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        const uint64_t *km = ctx->rk_mask_enc[r];                                     \
        PRESENT_PBOX_STORE8_##TAG(AV_SBOX8, CID)                                      \
        { __m256i *tmp = cur; cur = alt; alt = tmp; }                                 \
    }                                                                                 \
    AV_ENC_TAIL                                                                       \
}

#define AV_ENC_LIN444(KID, CID, TAG)                                                  \
static __m256i *av_enc_k##KID(const present_ctx_t *ctx, __m256i *cur, __m256i *alt)    \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        const uint64_t *km = ctx->rk_mask_enc[r];                                     \
        for (int i = 0; i < PRESENT_BS_N_SBOXES; i++)                                    \
            AV_SBOX_TO(CID, cur, i, 4 * i + 0, 4 * i + 1, 4 * i + 2, 4 * i + 3)       \
        av_lin444_##TAG(cur, alt);                                                    \
        { __m256i *tmp = cur; cur = alt; alt = tmp; }                                 \
    }                                                                                 \
    AV_ENC_TAIL                                                                       \
}

#define AV_ENC_LIN4448(KID, CID, TAG)                                                 \
static __m256i *av_enc_k##KID(const present_ctx_t *ctx, __m256i *cur, __m256i *alt)    \
{                                                                                     \
    const int rounds = ctx->var->rounds;                                              \
    for (int r = 0; r < rounds; r++) {                                                \
        const uint64_t *km = ctx->rk_mask_enc[r];                                     \
        for (int i = 0; i < PRESENT_BLOCK_BITS / 8; i++)                              \
            AV_SBOX8_TO(CID, cur, i, 8 * i + 0, 8 * i + 1, 8 * i + 2, 8 * i + 3,      \
                        8 * i + 4, 8 * i + 5, 8 * i + 6, 8 * i + 7)                   \
        av_lin444_##TAG(cur, alt);                                                    \
        { __m256i *tmp = cur; cur = alt; alt = tmp; }                                 \
    }                                                                                 \
    AV_ENC_TAIL                                                                       \
}

#define AV_ENC(KID, CID, KIND, TAG) AV_ENC_##KIND(KID, CID, TAG)
PRESENT_KERNEL_ENC_LIST(AV_ENC)
#undef AV_ENC

void present_avx2_pack(const uint64_t *in, uint64_t *state)
{
    __m256i *a = (__m256i *)state;
    lane_transpose_4x4(in, a);
    bit_transpose64x4(a);
}

void present_avx2_unpack(const uint64_t *state, uint64_t *out)
{
    __m256i *a = (__m256i *)state;   /* the transpose is in place and self-inverse */
    bit_transpose64x4(a);
    lane_transpose_4x4_out(a, out);
}

uint64_t *present_encrypt_avx2_bs(const present_ctx_t *ctx, uint64_t *state, uint64_t *scratch)
{
    __m256i *a = (__m256i *)state, *b = (__m256i *)scratch;
    switch (ctx->var->kernel_enc) {
#define CASE_ENC(KID, CID, KIND, TAG) case KID: return (uint64_t *)av_enc_k##KID(ctx, a, b);
    PRESENT_KERNEL_ENC_LIST(CASE_ENC)
#undef CASE_ENC
    default: return state;   /* rejected by present_variant_check */
    }
}

void present_encrypt_avx2(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{
    __m256i a[PRESENT_BLOCK_BITS], b[PRESENT_BLOCK_BITS];

    lane_transpose_4x4(in, a);
    bit_transpose64x4(a);

    __m256i *res;
    switch (ctx->var->kernel_enc) {
#define CASE_ENC(KID, CID, KIND, TAG) case KID: res = av_enc_k##KID(ctx, a, b); break;
    PRESENT_KERNEL_ENC_LIST(CASE_ENC)
#undef CASE_ENC
    default: return;   /* rejected by present_variant_check; nothing to compute */
    }

    bit_transpose64x4(res);
    lane_transpose_4x4_out(res, out);
}

#else /* no AVX2 at compile time */

int present_have_avx2(void) { return 0; }

void present_encrypt_avx2(const present_ctx_t *ctx, const uint64_t *in, uint64_t *out)
{
    (void)ctx; (void)in; (void)out;
}

void present_avx2_pack(const uint64_t *in, uint64_t *state) { (void)in; (void)state; }
void present_avx2_unpack(const uint64_t *state, uint64_t *out) { (void)state; (void)out; }

uint64_t *present_encrypt_avx2_bs(const present_ctx_t *ctx, uint64_t *state, uint64_t *scratch)
{
    (void)ctx; (void)scratch;
    return state;
}

#endif
