/* AES-128 and AES-256 (NR = 10 / 14) in counter mode: bitsliced AVX2 kernel without AES-NI/VAES/GFNI (built
 * with -mno-aes -mno-vaes -mno-gfni -mno-vpclmulqdq -mno-pclmul, see Makefile; only
 * AND/XOR/shift/permute on ymm). Constant time. The counterpart of qalqan-ctr
 * bitslice-avx2-x256 (src/qalqan/qalqan_bs.c), same layout and transposition, so that
 * the two ciphers are compared with the same technique.
 *
 * 256 blocks per batch, one ymm per state bit: X[8n + b] = bit b of state byte n
 * (n = 4 * column + row, FIPS-197 order) of all 256 blocks.
 *   - SubBytes: the Boyar-Peralta depth-16 circuit, 128 gates (aes128_bs_sbox.h,
 *     generated and checked by tools/gen_qalqan_bs_sbox.py), on each byte's 8 planes;
 *     its output constant 0x63 is not computed: SR and MC map the all-0x63 state to
 *     itself, so it is folded into round keys 1..NR.
 *   - ShiftRows: renaming of planes (no instructions).
 *   - MixColumns: b_i = a_i ^ t ^ xtime(a_i ^ a_i+1), t = a0^a1^a2^a3; xtime is a
 *     renaming plus 3 XOR, so 116 XOR per column.
 *   - AddRoundKey: 0 / ~0 dwords broadcast from memory (load-port uops).
 * CTR: bytes 0..11 of the counter block are the nonce, so round 1's SubBytes on them
 * is computed once per call; only bytes 12..15 (= bswap32(ctr + j) ^ rk0 word 3) are
 * bitsliced per batch. The last round key is applied after the output transposition, on
 * word-sliced registers. Tail (< 256 blocks): one more batch into a stack buffer. */
#include <immintrin.h>
#include <string.h>
#define AI static inline __attribute__((always_inline))
#define XOR(a, b) _mm256_xor_si256((a), (b))
#include "blockctr.h"
#include "aes128_bs.h"
#include "aes128_bs_sbox.h"
#include "../bs_avx2.h"

#if defined(__GFNI__) || defined(__AES__) || defined(__VAES__) || defined(__VPCLMULQDQ__)
#error "aes128_bs.c must be built without GFNI/AES/VAES/VPCLMULQDQ (see Makefile)"
#endif

extern const uint8_t aes_sbox[256];

static uint32_t ld32le(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

/* rk: NR+1 FIPS-197 round keys -> KM (rounds 1..NR-1 as planes), Klast, rk0 */
static void setup_keys(const uint8_t (*rk)[16], int nr, uint32_t (*KM)[128], uint32_t Klast[4], uint8_t rk0[16])
{
    for (int r = 1; r < nr; r++)
        for (int n = 0; n < 16; n++)
            for (int b = 0; b < 8; b++) KM[r - 1][8 * n + b] = 0u - (((rk[r][n] ^ 0x63) >> b) & 1);
    uint8_t kl[16];
    for (int n = 0; n < 16; n++) kl[n] = rk[nr][n] ^ 0x63;
    for (int w = 0; w < 4; w++) Klast[w] = ld32le(kl + 4 * w);
    memcpy(rk0, rk[0], 16);
}
void aes128_setup_bs(void *vctx, const uint8_t *key)
{
    aes128_ctx k;
    aes128_key_expand(&k, key);
    aes128_bs_ctx *c = vctx;
    setup_keys(k.rk, 10, c->KM, c->K10, c->rk0);
}
void aes256_setup_bs(void *vctx, const uint8_t *key)
{
    aes256_ctx k;
    aes256_key_expand(&k, key);
    aes256_bs_ctx *c = vctx;
    setup_keys(k.rk, 14, c->KM, c->K14, c->rk0);
}

/* Y = MixColumns(ShiftRows(X)) */
AI void srmc(const __m256i *X, __m256i *Y)
{
#pragma GCC unroll 4
    for (int col = 0; col < 4; col++) {
        const __m256i *a[4];
        for (int i = 0; i < 4; i++) a[i] = X + 8 * (4 * ((col + i) & 3) + i); /* ShiftRows */
        __m256i s[4][8], t[8];
#pragma GCC unroll 8
        for (int b = 0; b < 8; b++) {
            for (int i = 0; i < 4; i++) s[i][b] = XOR(a[i][b], a[(i + 1) & 3][b]);
            t[b] = XOR(s[0][b], s[2][b]);
        }
#pragma GCC unroll 4
        for (int i = 0; i < 4; i++) {
            const __m256i *v = s[i];
            __m256i x[8] = {v[7], XOR(v[0], v[7]), v[1], XOR(v[2], v[7]), XOR(v[3], v[7]), v[4], v[5], v[6]};
            __m256i *y = Y + 8 * (4 * col + i);
#pragma GCC unroll 8
            for (int b = 0; b < 8; b++) y[b] = XOR(XOR(a[i][b], t[b]), x[b]);
        }
    }
}

typedef struct {
    uint32_t A3;     /* rk0 word 3: counter-block word 3 after round 0 = bswap32(ctr) ^ A3 */
    uint32_t S[96];  /* planes of SubBytes(nonce ^ rk0) ^ 0x63 for bytes 0..11, 0 / ~0 */
} aes_bs_call;

static void call_setup(const uint8_t rk0[16], const uint8_t nonce[12], aes_bs_call *k)
{
    for (int n = 0; n < 12; n++) {
        uint8_t v = aes_sbox[nonce[n] ^ rk0[n]] ^ 0x63;
        for (int b = 0; b < 8; b++) k->S[8 * n + b] = 0u - ((v >> b) & 1);
    }
    k->A3 = ld32le(rk0 + 12);
}

AI void batch(const uint32_t (*KM)[128], const uint32_t Klast[4], const int NR, const aes_bs_call *k, uint32_t ctr,
              uint8_t *out, const uint8_t *in)
{
    const __m256i bswap = _mm256_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
                                           3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
    __m256i X[128], Y[128];
    __m256i R[4][8]; /* [p][g] */
    const __m256i a3 = _mm256_set1_epi32((int)k->A3);
    __m256i base = _mm256_add_epi32(_mm256_set1_epi32((int)ctr), _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
    for (int g = 0; g < 8; g++) {
        __m256i q[4];
        for (int j = 0; j < 4; j++) {
            __m256i v = _mm256_add_epi32(base, _mm256_set1_epi32(32 * g + 8 * j));
            q[j] = to_bytecols(XOR(_mm256_shuffle_epi8(v, bswap), a3));
        }
        qt4(q); /* q[p] = byte 12+p of blocks 32g .. 32g+31 */
        for (int p = 0; p < 4; p++) R[p][g] = q[p];
    }
    for (int p = 0; p < 4; p++) {
        bit_transpose(R[p]);
        AES_BS_SBOX(R[p], &X[8 * (12 + p)]);
    }
    for (int i = 0; i < 96; i++) X[i] = _mm256_set1_epi32((int)k->S[i]);
    for (int r = 0; r < NR - 1; r++) {
        srmc(X, Y);
        for (int n = 0; n < 16; n++) {
            __m256i T[8];
            for (int b = 0; b < 8; b++) T[b] = XOR(Y[8 * n + b], _mm256_set1_epi32((int)KM[r][8 * n + b]));
            AES_BS_SBOX(T, &X[8 * n]);
        }
    }
    /* final ShiftRows (renaming into Y), then planes -> bytes */
    for (int col = 0; col < 4; col++)
        for (int row = 0; row < 4; row++)
            for (int b = 0; b < 8; b++) Y[8 * (4 * col + row) + b] = X[8 * (4 * ((col + row) & 3) + row) + b];
    for (int n = 0; n < 16; n++) bit_transpose(&Y[8 * n]); /* Y[8n+g] = byte n of blocks 32g.. */
    __m256i K10[4];
    for (int w = 0; w < 4; w++) K10[w] = _mm256_set1_epi32((int)Klast[w]);
    for (int g = 0; g < 8; g++) {
        __m256i W[4][4]; /* [j][w] */
        for (int w = 0; w < 4; w++) {
            __m256i q[4] = {Y[8 * (4 * w) + g], Y[8 * (4 * w + 1) + g], Y[8 * (4 * w + 2) + g], Y[8 * (4 * w + 3) + g]};
            qt4(q);
            for (int j = 0; j < 4; j++) W[j][w] = XOR(from_bytecols(q[j]), K10[w]);
        }
        for (int j = 0; j < 4; j++) {
            __m256i o[4];
            unslice(W[j], o);
            const size_t off = 512 * (size_t)g + 128 * (size_t)j;
            for (int i = 0; i < 4; i++) {
                const __m256i *src = (const __m256i *)(in + off) + i;
                _mm256_storeu_si256((__m256i *)(out + off) + i, XOR(o[i], _mm256_loadu_si256(src)));
            }
        }
    }
}

AI void ctr_bs(const uint32_t (*KM)[128], const uint32_t Klast[4], const uint8_t rk0[16], const int NR,
               uint8_t *out, const uint8_t *in, size_t len, const uint8_t nonce[12], uint32_t ctr)
{
    aes_bs_call k;
    call_setup(rk0, nonce, &k);
    for (; len >= 4096; len -= 4096, in += 4096, out += 4096, ctr += 256) batch(KM, Klast, NR, &k, ctr, out, in);
    if (len) {
        _Alignas(32) uint8_t ks[4096] = {0};
        batch(KM, Klast, NR, &k, ctr, ks, ks);
        for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(in[i] ^ ks[i]);
    }
}

void aes128_ctr_bs_x256(const void *vctx, uint8_t *out, const uint8_t *in, size_t len,
                        const uint8_t nonce[12], uint32_t ctr)
{
    const aes128_bs_ctx *c = vctx;
    ctr_bs(c->KM, c->K10, c->rk0, 10, out, in, len, nonce, ctr);
}
void aes256_ctr_bs_x256(const void *vctx, uint8_t *out, const uint8_t *in, size_t len,
                        const uint8_t nonce[12], uint32_t ctr)
{
    const aes256_bs_ctx *c = vctx;
    ctr_bs(c->KM, c->K14, c->rk0, 14, out, in, len, nonce, ctr);
}
