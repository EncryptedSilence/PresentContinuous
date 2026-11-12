// Full-round block ciphers in counter mode on a CUDA GPU: AES-128 (10 rounds), AES-256 (14),
// Qalqan-256/128 (15 rounds), PRESENT-80 (31 rounds). Kernels, correctness gate,
// benchmark.
//
// Protocol: the same as ca_gpu.cu's (shared in gpu_harness.cuh): data stays in
// device memory and is XORed in place, key setup (round keys to constant memory,
// tables to global memory) is outside the timed region, 5 warm-up + 15 timed
// launches, median CUDA-event time, working sets of 16 MiB and 256 MiB, SM clock
// recorded inside one extra launch of the same kernel.
//
// CTR contracts:
//   AES-128 / Qalqan (include/blockctr.h): counter block j = nonce[0..11] ||
//     BE32(ctr + j mod 2^32), out = in ^ E_K(block). Qalqan loads the block as four
//     little-endian 32-bit words.
//   PRESENT-80 (bench/ctr_backend.h): 64-bit block i = ctr0 + i (full 64-bit),
//     keystream = E_K(block) serialised big-endian. Here any length is accepted (a
//     partial last block uses the leading keystream bytes), as for the 128-bit ones.
//
// Kernels (all: one counter block per thread per step, ILP = independent blocks per
// thread at a blockDim stride, so every global load/store is coalesced; the
// table kernels loop grid-stride over one wave of resident blocks, so the shared
// table is filled once per resident block, not once per 256 blocks of data):
//   AES-128
//     tt4-smem-xN   4 T-tables (4 KiB) in shared memory; the last round masks the
//                   S-box byte out of the T-tables (no separate S-box)
//     tt1-smem-x2   one T-table (1 KiB) + rotates (funnel shift)
//     tt1-rep32-xN  one T-table replicated per bank (32 KiB): lane l reads only
//                   bank l, so the lookups are conflict-free
//     sbox-rep32-x2 256-byte S-box replicated per bank (8 KiB, conflict-free),
//                   ShiftRows by indexing, MixColumns as packed-byte arithmetic
//   Qalqan
//     sb8-smem-x2   256-byte S-box in shared memory
//     sb32x4-smem-x2  the S-box spread into 4 u32 tables (SB[x] << 8k), 4 KiB
//     sb8-rep32-xN  256-byte S-box replicated per bank (8 KiB), conflict-free
//   PRESENT-80
//     tab8-smem-xN  fused S-box+pLayer tables, 8 x 256 x u64 (16 KiB) in shared
//     bitslice-x32  32 blocks per thread as 64 bit-planes of 32 bits (15-gate
//                   S-box circuit, pLayer folded into register naming), counters
//                   transposed in and keystream transposed out in registers;
//                   rounds fully unrolled (-loop: a rolled round loop)
//
// Correctness: at startup the host oracles (KAT-verified by `make -C .. test`) are
// re-checked against FIPS-197 C.1 / the Qalqan sample / the PRESENT paper vectors,
// and every GPU kernel is run on those single-block known answers. Then, before
// any timing, every kernel's output at every timed shape plus odd lengths and
// counter wrap is compared byte for byte with the host oracle. A mismatch exits
// non-zero before any CSV row is written.
#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <algorithm>
#include <string>
#include <vector>

extern "C" {
#include "blockctr.h"
#include "qalqan.h"
#include "present/present.h"
extern const uint8_t aes_sbox[256];
void aes128_setup_ni(void *, const uint8_t *);
void aes128_ctr_aesni_x8(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);
void aes128_ctr_ref(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);
void aes256_setup_ref(void *, const uint8_t *);
void aes256_ctr_ref(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);
#ifdef HAVE_QALQAN_X86
void qalqan_setup_gfni(void *, const uint8_t *);
void qalqan_ctr_gfni_x16(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);
#define qalqan_setup_host qalqan_setup_gfni
#define qalqan_ctr_host qalqan_ctr_gfni_x16
#else
#define qalqan_setup_host qalqan_setup_ref
#define qalqan_ctr_host qalqan_ctr_ref
#endif
void qalqan_setup_ref(void *, const uint8_t *);
void qalqan_ctr_ref(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);
}

#include "gpu_harness.cuh"

#define TPB 256

// ------------------------------------------------------------ device state
__constant__ uint32_t c_aes_rk[44];     // FIPS-197 w[0..43] as big-endian words
__constant__ uint32_t c_a256_rk[60];    // AES-256 w[0..59], same layout
// round-key word i of AES with NR rounds (10: AES-128, 14: AES-256)
template <int NR> __device__ __forceinline__ uint32_t rkw(int i) { return NR == 10 ? c_aes_rk[i] : c_a256_rk[i]; }
__constant__ uint32_t c_aes_nonce[3];   // nonce as big-endian words
__constant__ uint32_t c_q_rk[16][4];    // Qalqan round keys (little-endian words)
__constant__ uint32_t c_q_nonce[3];     // nonce as little-endian words
__constant__ uint64_t c_p_rk[32];       // PRESENT-80 round keys 0..31
__constant__ uint32_t c_p_rkmask[32 * 64];  // bitsliced round keys (complement-corrected)

__device__ __forceinline__ uint32_t bswap32(uint32_t x) { return __byte_perm(x, 0, 0x0123); }
__device__ __forceinline__ uint32_t rotl(uint32_t x, int n) { return __funnelshift_l(x, x, n); }
__device__ __forceinline__ uint32_t rotr(uint32_t x, int n) { return __funnelshift_r(x, x, n); }
__device__ __forceinline__ uint32_t byte_(uint32_t x, int k) { return (x >> (8 * k)) & 0xff; }
__device__ __forceinline__ unsigned lane_() { return threadIdx.x & 31; }

// XOR 16 keystream bytes (four little-endian words) into block idx of buf[0..len).
__device__ __forceinline__ void xor16(uint8_t *buf, size_t len, size_t idx, const uint32_t ks[4])
{
    size_t off = idx * 16;
    if (off + 16 <= len) {
        uint4 v = *(uint4 *)(buf + off);
        v.x ^= ks[0]; v.y ^= ks[1]; v.z ^= ks[2]; v.w ^= ks[3];
        *(uint4 *)(buf + off) = v;
    } else if (off < len) {
        for (size_t i = off; i < len; i++) buf[i] ^= (uint8_t)(ks[(i - off) >> 2] >> (8 * ((i - off) & 3)));
    }
}

// Generic 128-bit CTR kernel: C supplies a shared-memory struct, its setup from the
// global table, and enc<ILP>(sm, counters, keystream words).
template <class C, int ILP, bool CLK>
__global__ __launch_bounds__(TPB) void k_bc128(uint8_t *buf, size_t len, uint32_t ctr, const void *gtab)
{
    clk_scope<CLK> clk_;
    __shared__ typename C::Smem sm;
    C::setup(sm, gtab);
    __syncthreads();
    const size_t nblk = (len + 15) / 16, step = (size_t)gridDim.x * TPB * ILP;
    for (size_t b0 = (size_t)blockIdx.x * TPB * ILP + threadIdx.x; b0 < nblk; b0 += step) {
        uint32_t c[ILP], ks[ILP][4];
#pragma unroll
        for (int j = 0; j < ILP; j++) c[j] = ctr + (uint32_t)(b0 + (size_t)j * TPB);
        C::template enc<ILP>(sm, c, ks);
#pragma unroll
        for (int j = 0; j < ILP; j++) xor16(buf, len, b0 + (size_t)j * TPB, ks[j]);
    }
}

// ------------------------------------------------------------------- AES-128
// T-table AES on big-endian column words. Te0[x] = (2s, s, s, 3s), Te_k = rotr(Te0, 8k).
// The last round takes S[x] from the byte of a T-table that holds plain s:
// bits 24..31 of Te2/Te3, 16..23 of Te0/Te3, 8..15 of Te0/Te1, 0..7 of Te1/Te2.
template <class T, int NR>
__device__ __forceinline__ void aes_tt_enc(const typename T::Smem &sm, uint32_t &s0, uint32_t &s1, uint32_t &s2,
                                           uint32_t &s3)
{
#pragma unroll
    for (int r = 1; r < NR; r++) {
        uint32_t t0 = T::te(sm, 0, s0 >> 24) ^ T::te(sm, 1, byte_(s1, 2)) ^ T::te(sm, 2, byte_(s2, 1)) ^ T::te(sm, 3, s3 & 0xff) ^ rkw<NR>(4 * r + 0);
        uint32_t t1 = T::te(sm, 0, s1 >> 24) ^ T::te(sm, 1, byte_(s2, 2)) ^ T::te(sm, 2, byte_(s3, 1)) ^ T::te(sm, 3, s0 & 0xff) ^ rkw<NR>(4 * r + 1);
        uint32_t t2 = T::te(sm, 0, s2 >> 24) ^ T::te(sm, 1, byte_(s3, 2)) ^ T::te(sm, 2, byte_(s0, 1)) ^ T::te(sm, 3, s1 & 0xff) ^ rkw<NR>(4 * r + 2);
        uint32_t t3 = T::te(sm, 0, s3 >> 24) ^ T::te(sm, 1, byte_(s0, 2)) ^ T::te(sm, 2, byte_(s1, 1)) ^ T::te(sm, 3, s2 & 0xff) ^ rkw<NR>(4 * r + 3);
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
#define LAST(a, b, c, d, k)                                                                                  \
    ((T::te(sm, 2, (a) >> 24) & 0xff000000u) ^ (T::te(sm, 3, byte_(b, 2)) & 0x00ff0000u) ^                  \
     (T::te(sm, 0, byte_(c, 1)) & 0x0000ff00u) ^ (T::te(sm, 1, (d) & 0xff) & 0xffu) ^ rkw<NR>(4 * NR + (k)))
    uint32_t t0 = LAST(s0, s1, s2, s3, 0), t1 = LAST(s1, s2, s3, s0, 1), t2 = LAST(s2, s3, s0, s1, 2),
             t3 = LAST(s3, s0, s1, s2, 3);
#undef LAST
    s0 = t0; s1 = t1; s2 = t2; s3 = t3;
}

template <class T, int NR = 10> struct AesTT {
    typedef typename T::Smem Smem;
    __device__ static void setup(Smem &sm, const void *g) { T::setup(sm, (const uint32_t *)g); }
    template <int ILP> __device__ static void enc(const Smem &sm, const uint32_t *c, uint32_t (*ks)[4])
    {
        uint32_t s[ILP][4];
#pragma unroll
        for (int j = 0; j < ILP; j++) {
            s[j][0] = c_aes_nonce[0] ^ rkw<NR>(0); s[j][1] = c_aes_nonce[1] ^ rkw<NR>(1);
            s[j][2] = c_aes_nonce[2] ^ rkw<NR>(2); s[j][3] = c[j] ^ rkw<NR>(3);
        }
#pragma unroll
        for (int j = 0; j < ILP; j++) aes_tt_enc<T, NR>(sm, s[j][0], s[j][1], s[j][2], s[j][3]);
#pragma unroll
        for (int j = 0; j < ILP; j++)
#pragma unroll
            for (int w = 0; w < 4; w++) ks[j][w] = bswap32(s[j][w]);
    }
};

struct TT4 {  // 4 tables, 4 KiB
    struct Smem { uint32_t t[4][256]; };
    __device__ static void setup(Smem &sm, const uint32_t *g)
    {
        for (int i = threadIdx.x; i < 256; i += TPB) {
            uint32_t v = g[i];
            sm.t[0][i] = v; sm.t[1][i] = rotr(v, 8); sm.t[2][i] = rotr(v, 16); sm.t[3][i] = rotr(v, 24);
        }
    }
    __device__ static uint32_t te(const Smem &sm, int k, uint32_t x) { return sm.t[k][x]; }
};
struct TT1 {  // 1 table + rotates, 1 KiB
    struct Smem { uint32_t t[256]; };
    __device__ static void setup(Smem &sm, const uint32_t *g)
    {
        for (int i = threadIdx.x; i < 256; i += TPB) sm.t[i] = g[i];
    }
    __device__ static uint32_t te(const Smem &sm, int k, uint32_t x) { return k ? rotr(sm.t[x], 8 * k) : sm.t[x]; }
};
struct TT1R {  // 1 table replicated per bank, 32 KiB: entry x of lane l at word 32x + l
    struct Smem { uint32_t t[256 * 32]; };
    __device__ static void setup(Smem &sm, const uint32_t *g)
    {
        for (int i = threadIdx.x; i < 256 * 32; i += TPB) sm.t[i] = g[i >> 5];
    }
    __device__ static uint32_t te(const Smem &sm, int k, uint32_t x)
    {
        uint32_t v = sm.t[(x << 5) | lane_()];
        return k ? rotr(v, 8 * k) : v;
    }
};

// 256-byte S-box replicated per bank (8 KiB): byte x of lane l at byte offset
// 128*(x>>2) + 4l + (x&3), i.e. always in bank l.
struct SbRep {
    uint32_t w[64 * 32];
    __device__ void fill(const uint8_t *g)
    {
        for (int i = threadIdx.x; i < 64 * 32; i += TPB) {
            int x = (i >> 5) << 2;
            w[i] = g[x] | (g[x + 1] << 8) | (g[x + 2] << 16) | ((uint32_t)g[x + 3] << 24);
        }
    }
    __device__ uint32_t operator()(uint32_t x) const
    {
        return ((const uint8_t *)w)[((x >> 2) << 7) | (lane_() << 2) | (x & 3)];
    }
};

__device__ __forceinline__ uint32_t xtime4(uint32_t u)
{
    return ((u & 0x7f7f7f7fu) << 1) ^ (((u >> 7) & 0x01010101u) * 0x1b);
}

template <int NR = 10> struct AesSbox {  // SubBytes via replicated S-box, ShiftRows by indexing, arithmetic MixColumns
    struct Smem { SbRep sb; };
    __device__ static void setup(Smem &sm, const void *g) { sm.sb.fill((const uint8_t *)g); }
    template <int ILP> __device__ static void enc(const Smem &sm, const uint32_t *c, uint32_t (*ks)[4])
    {
        uint32_t s[ILP][4];
#pragma unroll
        for (int j = 0; j < ILP; j++) {
            s[j][0] = c_aes_nonce[0] ^ rkw<NR>(0); s[j][1] = c_aes_nonce[1] ^ rkw<NR>(1);
            s[j][2] = c_aes_nonce[2] ^ rkw<NR>(2); s[j][3] = c[j] ^ rkw<NR>(3);
        }
#pragma unroll
        for (int r = 1; r <= NR; r++)
#pragma unroll
            for (int j = 0; j < ILP; j++) {
                uint32_t u[4];
#pragma unroll
                for (int col = 0; col < 4; col++)
                    u[col] = (sm.sb(s[j][col] >> 24) << 24) | (sm.sb(byte_(s[j][(col + 1) & 3], 2)) << 16) |
                             (sm.sb(byte_(s[j][(col + 2) & 3], 1)) << 8) | sm.sb(s[j][(col + 3) & 3] & 0xff);
#pragma unroll
                for (int col = 0; col < 4; col++) {
                    uint32_t v = u[col];
                    if (r < NR) {
                        uint32_t r8 = rotl(v, 8);
                        v = xtime4(v ^ r8) ^ r8 ^ rotl(v, 16) ^ rotl(v, 24);
                    }
                    s[j][col] = v ^ rkw<NR>(4 * r + col);
                }
            }
#pragma unroll
        for (int j = 0; j < ILP; j++)
#pragma unroll
            for (int w = 0; w < 4; w++) ks[j][w] = bswap32(s[j][w]);
    }
};

// -------------------------------------------------------------------- Qalqan
// The Qalqan kernels live in bc_gpu_qalqan.cuh, which is not distributed. Without it
// bc_gpu runs AES and PRESENT only.
#if __has_include("bc_gpu_qalqan.cuh")
#include "bc_gpu_qalqan.cuh"
#endif

// ---------------------------------------------------------------- PRESENT-80
__device__ __forceinline__ uint64_t bswap64(uint64_t x)
{
    return ((uint64_t)bswap32((uint32_t)x) << 32) | bswap32((uint32_t)(x >> 32));
}
__device__ __forceinline__ void xor8(uint8_t *buf, size_t len, size_t idx, uint64_t c)
{
    size_t off = idx * 8;
    uint64_t ks = bswap64(c);  // big-endian serialisation, XORed as a little-endian word
    if (off + 8 <= len) {
        *(uint64_t *)(buf + off) ^= ks;
    } else if (off < len) {
        for (size_t i = off; i < len; i++) buf[i] ^= (uint8_t)(ks >> (8 * (i - off)));
    }
}

template <int ILP, bool CLK>
__global__ __launch_bounds__(TPB) void k_present_tab8(uint8_t *buf, size_t len, uint64_t ctr0, const void *gtab)
{
    clk_scope<CLK> clk_;
    __shared__ uint64_t t[8][256];
    for (int i = threadIdx.x; i < 8 * 256; i += TPB) (&t[0][0])[i] = ((const uint64_t *)gtab)[i];
    __syncthreads();
    const size_t nblk = (len + 7) / 8, step = (size_t)gridDim.x * TPB * ILP;
    for (size_t b0 = (size_t)blockIdx.x * TPB * ILP + threadIdx.x; b0 < nblk; b0 += step) {
        uint64_t s[ILP];
#pragma unroll
        for (int j = 0; j < ILP; j++) s[j] = ctr0 + b0 + (size_t)j * TPB;
#pragma unroll
        for (int r = 0; r < 31; r++)
#pragma unroll
            for (int j = 0; j < ILP; j++) {
                uint64_t x = s[j] ^ c_p_rk[r];
                uint32_t lo = (uint32_t)x, hi = (uint32_t)(x >> 32);
                s[j] = t[0][lo & 0xff] ^ t[1][byte_(lo, 1)] ^ t[2][byte_(lo, 2)] ^ t[3][lo >> 24] ^
                       t[4][hi & 0xff] ^ t[5][byte_(hi, 1)] ^ t[6][byte_(hi, 2)] ^ t[7][hi >> 24];
            }
#pragma unroll
        for (int j = 0; j < ILP; j++) xor8(buf, len, b0 + (size_t)j * TPB, s[j] ^ c_p_rk[31]);
    }
}

// Bitsliced PRESENT (after bench/gpu_bench.cu): the 15-gate circuit computes
// S(x) ^ 0xC per nibble; the constant is pushed through the pLayer into the next
// round key on the host (build of c_p_rkmask).
__device__ __forceinline__ void present_sbox_bs(uint32_t &o0, uint32_t &o1, uint32_t &o2, uint32_t &o3, uint32_t x0,
                                                uint32_t x1, uint32_t x2, uint32_t x3)
{
    uint32_t t0 = ~x1 & x2, t1 = x3 ^ t0, t2 = x0 ^ t1, t3 = ~x1 & t1, t4 = x0 | x2, t5 = ~t2 & t4, t6 = t3 | t5;
    uint32_t t7 = x2 ^ t6, t8 = x1 ^ t7, t9 = x2 | x3, t10 = t8 ^ t9, t11 = t3 ^ t10, t12 = x0 ^ t11;
    uint32_t t13 = ~t12 & t8, t14 = t1 ^ t13;
    o0 = t2; o1 = t8; o2 = t14; o3 = t12;
}
// In-place 32x32 bit transpose: afterwards a[i] bit j is the original a[j] bit i.
__device__ __forceinline__ void transpose32(uint32_t *a)
{
    uint32_t m = 0x0000FFFFu;
#pragma unroll
    for (int j = 16; j != 0; j >>= 1) {
#pragma unroll
        for (int k = 0; k < 32; k = (k + j + 1) & ~j) {
            uint32_t t = ((a[k] >> j) ^ a[k + j]) & m;
            a[k] ^= t << j;
            a[k + j] ^= t;
        }
        m ^= m << (j >> 1);
    }
}
#define BS_TPB 128
// UNROLL: 31 rounds fully unrolled (round keys as constant-bank immediates) or a
// rolled round loop (smaller code, key address computed per round).
template <bool UNROLL, bool CLK>
__global__ __launch_bounds__(BS_TPB) void k_present_bs(uint8_t *buf, size_t len, uint64_t ctr0, const void *)
{
    clk_scope<CLK> clk_;
    const size_t nblk = (len + 7) / 8;
    const size_t base = (size_t)blockIdx.x * BS_TPB * 32 + threadIdx.x;
    uint32_t p[64];
    {
        uint32_t lo[32], hi[32];
#pragma unroll
        for (int k = 0; k < 32; k++) {
            uint64_t v = ctr0 + base + (size_t)k * BS_TPB;
            lo[k] = (uint32_t)v; hi[k] = (uint32_t)(v >> 32);
        }
        transpose32(lo);
        transpose32(hi);
#pragma unroll
        for (int b = 0; b < 32; b++) { p[b] = lo[b]; p[32 + b] = hi[b]; }
    }
#pragma unroll(UNROLL ? 31 : 1)
    for (int r = 0; r < 31; r++) {
        uint32_t q[64];
        const uint32_t *km = &c_p_rkmask[64 * r];
#pragma unroll
        for (int i = 0; i < 16; i++) {
            uint32_t y0, y1, y2, y3;
            present_sbox_bs(y0, y1, y2, y3, p[4 * i] ^ km[4 * i], p[4 * i + 1] ^ km[4 * i + 1],
                            p[4 * i + 2] ^ km[4 * i + 2], p[4 * i + 3] ^ km[4 * i + 3]);
#define PD(S) (((S) == 63) ? 63 : (16 * (S)) % 63)
            q[PD(4 * i)] = y0; q[PD(4 * i + 1)] = y1; q[PD(4 * i + 2)] = y2; q[PD(4 * i + 3)] = y3;
#undef PD
        }
#pragma unroll
        for (int b = 0; b < 64; b++) p[b] = q[b];
    }
    {
        uint32_t lo[32], hi[32];
#pragma unroll
        for (int b = 0; b < 32; b++) { lo[b] = p[b] ^ c_p_rkmask[64 * 31 + b]; hi[b] = p[32 + b] ^ c_p_rkmask[64 * 31 + 32 + b]; }
        transpose32(lo);
        transpose32(hi);
#pragma unroll
        for (int k = 0; k < 32; k++) {
            size_t idx = base + (size_t)k * BS_TPB;
            if (idx < nblk) xor8(buf, len, idx, (uint64_t)lo[k] | ((uint64_t)hi[k] << 32));
        }
    }
}

// --------------------------------------------------------------------- host
typedef void (*kfn)(uint8_t *, size_t, uint64_t, const void *);  // PRESENT kernels
typedef void (*kfn32)(uint8_t *, size_t, uint32_t, const void *);  // 128-bit kernels

// One kernel row: two instantiations (timed / clock), threads per block, blocks
// of data per thread per step, and whether it loops grid-stride over one wave.
struct kdesc {
    const char *name;
    const void *k, *kc;
    int tpb, ilp, unit;  // unit = bytes per cipher block
    bool gridstride;
    const char *note;
    int maxgrid;
};

static unsigned grid_for(const kdesc &d, size_t len)
{
    size_t nblk = (len + d.unit - 1) / d.unit, per = (size_t)d.tpb * d.ilp;
    size_t g = (nblk + per - 1) / per;
    if (d.gridstride && g > (size_t)d.maxgrid) g = d.maxgrid;
    return (unsigned)std::max<size_t>(g, 1);
}

static void launch(const kdesc &d, bool clk, uint8_t *buf, size_t len, uint64_t ctr, const void *gtab)
{
    unsigned g = grid_for(d, len);
    const void *f = clk ? d.kc : d.k;
    if (d.unit == 16) ((kfn32)f)<<<g, d.tpb>>>(buf, len, (uint32_t)ctr, gtab);
    else ((kfn)f)<<<g, d.tpb>>>(buf, len, ctr, gtab);
}

#define K128(n, C, ILP, note) {n, (const void *)k_bc128<C, ILP, false>, (const void *)k_bc128<C, ILP, true>, TPB, ILP, 16, true, note, 0}
static kdesc aes_k[] = {
    K128("tt4-smem-x1", AesTT<TT4>, 1, "4 T-tables (4 KiB) in shared"),
    K128("tt4-smem-x2", AesTT<TT4>, 2, "4 T-tables (4 KiB) in shared"),
    K128("tt1-smem-x2", AesTT<TT1>, 2, "1 T-table (1 KiB) in shared + rotates"),
    K128("tt1-rep32-x1", AesTT<TT1R>, 1, "1 T-table replicated per bank (32 KiB), conflict-free"),
    K128("tt1-rep32-x2", AesTT<TT1R>, 2, "1 T-table replicated per bank (32 KiB), conflict-free"),
    K128("sbox-rep32-x2", AesSbox<>, 2, "S-box replicated per bank (8 KiB) + arithmetic MixColumns"),
};
typedef AesTT<TT4, 14> A256TT4;
typedef AesTT<TT1, 14> A256TT1;
typedef AesTT<TT1R, 14> A256TT1R;
static kdesc a256_k[] = {
    K128("tt4-smem-x1", A256TT4, 1, "4 T-tables (4 KiB) in shared"),
    K128("tt4-smem-x2", A256TT4, 2, "4 T-tables (4 KiB) in shared"),
    K128("tt1-smem-x2", A256TT1, 2, "1 T-table (1 KiB) in shared + rotates"),
    K128("tt1-rep32-x1", A256TT1R, 1, "1 T-table replicated per bank (32 KiB), conflict-free"),
    K128("tt1-rep32-x2", A256TT1R, 2, "1 T-table replicated per bank (32 KiB), conflict-free"),
    K128("sbox-rep32-x2", AesSbox<14>, 2, "S-box replicated per bank (8 KiB) + arithmetic MixColumns"),
};
#ifdef QAL_KERNELS
static kdesc qal_k[] = {QAL_KERNELS};
#define QAL_NK NK(qal_k)
#else
static kdesc qal_k[1];
#define QAL_NK 0
#endif
static kdesc pre_k[] = {
    {"tab8-smem-x1", (const void *)k_present_tab8<1, false>, (const void *)k_present_tab8<1, true>, TPB, 1, 8, true,
     "fused S+P tables 8x256xu64 (16 KiB) in shared", 0},
    {"tab8-smem-x2", (const void *)k_present_tab8<2, false>, (const void *)k_present_tab8<2, true>, TPB, 2, 8, true,
     "fused S+P tables 8x256xu64 (16 KiB) in shared", 0},
    {"bitslice-x32", (const void *)k_present_bs<true, false>, (const void *)k_present_bs<true, true>, BS_TPB, 32, 8, false,
     "bitsliced, 32 blocks/thread, transposes in registers, rounds unrolled", 0},
    {"bitslice-x32-loop", (const void *)k_present_bs<false, false>, (const void *)k_present_bs<false, true>, BS_TPB, 32, 8,
     false, "bitsliced, 32 blocks/thread, transposes in registers, round loop", 0},
};
#define NK(a) (sizeof a / sizeof a[0])

static void set_maxgrid(kdesc *ks, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        int per_sm = 0;
        CK(cudaOccupancyMaxActiveBlocksPerMultiprocessor(&per_sm, ks[i].k, ks[i].tpb, 0));
        ks[i].maxgrid = per_sm * prop.multiProcessorCount;
    }
}

// --- host-side key setup and oracles
static uint8_t aes_key[16], q_key[32], nonce[12];
static uint8_t p_key[10];
alignas(64) static uint8_t a256_ctx[4096];
static uint8_t a256_key[32];
alignas(64) static uint8_t aes_ctx[4096], q_ctx[4096], q_ref_ctx[4096];
static present_ctx_t pctx;
static present_table_fn p_enc;
static uint32_t *d_te0;
static uint8_t *d_aes_sb, *d_q_sb;
static uint64_t *d_ptab;
// Qalqan S-box, copied from src/qalqan/qalqan.c (static there). A copying error
// cannot pass: the sample vector and the CTR gate run every Qalqan kernel on it.
static const uint8_t qalqan_sb[256] = {
    0xd1,0xb5,0xa6,0x74,0x2f,0xb2,0x03,0x77,0xae,0xb3,0x60,0x95,0xfd,0xf8,0xc7,0xf0,
    0x2b,0xce,0xa5,0x91,0x4c,0x6f,0xf3,0x4f,0x82,0x01,0x45,0x76,0x9f,0xed,0x41,0xfb,
    0xac,0x4e,0x5e,0x04,0xeb,0xf9,0xf1,0x3a,0x1f,0xe2,0x8e,0xe7,0x85,0x35,0xdb,0x52,
    0x78,0xa1,0xfc,0xa2,0xde,0x68,0x02,0x4d,0xf6,0xdd,0xcf,0xa3,0xdc,0x6b,0x81,0x44,
    0x2a,0x5d,0x1e,0xe0,0x53,0x71,0x3b,0xc1,0xcc,0x9d,0x80,0xd5,0x84,0x00,0x24,0x4b,
    0xb6,0x83,0x0d,0x87,0x7e,0x86,0xca,0x96,0xbe,0x5a,0xe6,0xd0,0xd4,0xd8,0x55,0xc0,
    0x05,0xe5,0xe9,0x5b,0x47,0xe4,0x2d,0x34,0x13,0x88,0x48,0x32,0x38,0xb9,0xda,0xc9,
    0x42,0x29,0xd7,0xf2,0x9b,0x6d,0xe8,0x8d,0x12,0x7c,0x8c,0x3f,0xbc,0x3c,0x1b,0xc5,
    0x69,0x22,0x97,0xaa,0x73,0x0a,0x0c,0x8a,0x90,0x31,0xc4,0x33,0xe1,0x8b,0x9c,0x63,
    0x5f,0xf5,0xf7,0xff,0x79,0x49,0xd3,0xc6,0x7b,0x1a,0x39,0xc8,0x6e,0x72,0xd9,0xc3,
    0x62,0x28,0xbd,0xbb,0xfa,0x2e,0xbf,0x43,0x06,0x0b,0x7a,0x64,0x5c,0x92,0x37,0x3d,
    0x66,0x26,0x51,0xef,0x0f,0xa9,0x14,0x70,0x16,0x17,0x10,0x19,0x93,0x09,0x59,0x15,
    0xfe,0x4a,0xcb,0x2c,0xcd,0xb8,0x94,0xab,0xdf,0xa7,0x0e,0x30,0xaf,0x56,0x23,0xb1,
    0xb0,0x58,0x7d,0xc2,0x1d,0x50,0x20,0x61,0x25,0x89,0xa0,0x6c,0x11,0x54,0x98,0xb7,
    0x18,0x21,0xad,0x3e,0xd2,0xea,0x40,0xd6,0xf4,0xa4,0x8f,0xa8,0x08,0x57,0xba,0xee,
    0x75,0x6a,0x07,0x99,0x7f,0x1c,0xe3,0x46,0x67,0xec,0x27,0x36,0xb4,0x65,0x9e,0x9a
};

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

static void aes_setkey(const uint8_t key[16], const uint8_t n[12])
{
    aes128_setup_ni(aes_ctx, key);
    const aes128_ctx *c = (const aes128_ctx *)aes_ctx;
    uint32_t rk[44], nw[3];
    for (int i = 0; i < 44; i++) rk[i] = be32(&c->rk[i / 4][4 * (i % 4)]);
    for (int i = 0; i < 3; i++) nw[i] = be32(n + 4 * i);
    CK(cudaMemcpyToSymbol(c_aes_rk, rk, sizeof rk));
    CK(cudaMemcpyToSymbol(c_aes_nonce, nw, sizeof nw));
}
static void a256_setkey(const uint8_t key[32])
{
    aes256_setup_ref(a256_ctx, key);
    const aes256_ctx *c = (const aes256_ctx *)a256_ctx;
    uint32_t rk[60];
    for (int i = 0; i < 60; i++) rk[i] = be32(&c->rk[i / 4][4 * (i % 4)]);
    CK(cudaMemcpyToSymbol(c_a256_rk, rk, sizeof rk));  // nonce: c_aes_nonce, set by aes_setkey
}
static void q_setkey(const uint8_t key[32], const uint8_t n[12])
{
    qalqan_setup_host(q_ctx, key);
    qalqan_setup_ref(q_ref_ctx, key);
    uint32_t nw[3];
    for (int i = 0; i < 3; i++) nw[i] = le32(n + 4 * i);
    CK(cudaMemcpyToSymbol(c_q_rk, ((const qalqan_ctx *)q_ref_ctx)->rk, sizeof(uint32_t) * 64));
    CK(cudaMemcpyToSymbol(c_q_nonce, nw, sizeof nw));
}
static void p_setkey(const uint8_t key[10])
{
    const present_variant_t *v = present_variant_by_name("present-80");
    if (!v || v->rounds != 31 || present_init(&pctx, v, key, 10)) { fprintf(stderr, "present-80 init failed\n"); exit(1); }
    p_enc = present_table_fixed_fn(31);
    if (!p_enc) { fprintf(stderr, "no 31-round table kernel\n"); exit(1); }
    CK(cudaMemcpyToSymbol(c_p_rk, pctx.rk, 32 * sizeof(uint64_t)));
    // bitsliced keys: the S-box circuit's output complement 0xC per nibble, pushed
    // through the linear layer, cancelled in every key after the first
    uint64_t corr = 0;
    for (int i = 0; i < 64; i++)
        if ((0xCCCCCCCCCCCCCCCCull >> i) & 1) corr ^= v->lin_col[i];
    std::vector<uint32_t> km(32 * 64);
    for (int r = 0; r <= 31; r++) {
        uint64_t k = pctx.rk[r] ^ (r ? corr : 0);
        for (int b = 0; b < 64; b++) km[64 * r + b] = ((k >> b) & 1) ? 0xffffffffu : 0;
    }
    CK(cudaMemcpyToSymbol(c_p_rkmask, km.data(), km.size() * 4));
    CK(cudaMemcpy(d_ptab, pctx.enc_tab, sizeof pctx.enc_tab, cudaMemcpyHostToDevice));
}
static void p_ctr_host(uint8_t *out, const uint8_t *in, size_t len, uint64_t ctr0)
{
    for (size_t off = 0; off < len; off += 8) {
        uint64_t ks = p_enc(&pctx, ctr0 + off / 8);
        for (size_t b = 0; b < 8 && off + b < len; b++) out[off + b] = in[off + b] ^ (uint8_t)(ks >> (56 - 8 * b));
    }
}

enum { AES, QAL, PRE, A256, NCIPH };
static const char *cname[] = {"aes128-ctr", "qalqan-ctr", "present80-r31-ctr", "aes256-ctr"};
static kdesc *kset[] = {aes_k, qal_k, pre_k, a256_k};
static size_t kcount[] = {NK(aes_k), QAL_NK, NK(pre_k), NK(a256_k)};
static const void *gtab_for(int c, const kdesc &d)
{
    if ((c == AES || c == A256) && !strncmp(d.name, "sbox", 4)) return d_aes_sb;
    return c == AES || c == A256 ? (const void *)d_te0 : c == QAL ? (const void *)d_q_sb : (const void *)d_ptab;
}
static void oracle(int c, uint8_t *out, const uint8_t *in, size_t len, uint64_t ctr)
{
    if (c == AES) aes128_ctr_aesni_x8(aes_ctx, out, in, len, nonce, (uint32_t)ctr);
    else if (c == A256) aes256_ctr_ref(a256_ctx, out, in, len, nonce, (uint32_t)ctr);
    else if (c == QAL) qalqan_ctr_host(q_ctx, out, in, len, nonce, (uint32_t)ctr);
    else p_ctr_host(out, in, len, ctr);
}

static void fail(const char *what) { fprintf(stderr, "FAIL %s\n", what); exit(1); }

// Run kernel d on `len` zero bytes at counter ctr and return the first 16/8 bytes.
static void gpu_ks(int c, const kdesc &d, uint8_t *dbuf, size_t len, uint64_t ctr, uint8_t *out)
{
    CK(cudaMemset(dbuf, 0, len));
    launch(d, false, dbuf, len, ctr, gtab_for(c, d));
    CK(cudaGetLastError());
    CK(cudaMemcpy(out, dbuf, len, cudaMemcpyDeviceToHost));
}

static void hexto(const char *h, uint8_t *o) { for (size_t i = 0; i < strlen(h) / 2; i++) sscanf(h + 2 * i, "%2hhx", &o[i]); }

static void known_answers(uint8_t *dbuf)
{
    uint8_t out[16], exp[16];
    // AES-128 FIPS-197 C.1
    uint8_t k[16], pt[16];
    hexto("000102030405060708090a0b0c0d0e0f", k);
    hexto("00112233445566778899aabbccddeeff", pt);
    hexto("69c4e0d86a7b0430d8cdb78070b4c55a", exp);
    aes128_ctx rc;
    aes128_key_expand(&rc, k);
    aes128_encrypt_block_ref(&rc, pt, out);
    if (memcmp(out, exp, 16)) fail("AES FIPS-197 C.1 host");
    aes_setkey(k, pt);  // nonce = pt[0..11], ctr = BE32(pt[12..15])  ->  keystream block 0 = E(pt)
    memcpy(nonce, pt, 12);
    for (size_t i = 0; i < kcount[AES]; i++) {
        gpu_ks(AES, aes_k[i], dbuf, 16, be32(pt + 12), out);
        if (memcmp(out, exp, 16)) fail("AES FIPS-197 C.1 on GPU");
    }
    // AES-256 FIPS-197 C.3 (nonce/ctr = pt as above, set by aes_setkey)
    {
        uint8_t k32[32];
        for (int i = 0; i < 32; i++) k32[i] = (uint8_t)i;
        hexto("8ea2b7ca516745bfeafc49904b496089", exp);
        aes256_ctx r2;
        aes256_key_expand(&r2, k32);
        aes256_encrypt_block_ref(&r2, pt, out);
        if (memcmp(out, exp, 16)) fail("AES-256 FIPS-197 C.3 host");
        a256_setkey(k32);
        for (size_t i = 0; i < kcount[A256]; i++) {
            gpu_ks(A256, a256_k[i], dbuf, 16, be32(pt + 12), out);
            if (memcmp(out, exp, 16)) fail("AES-256 FIPS-197 C.3 on GPU");
        }
    }
    // Qalqan sample: key 00..1f, pt 00 10 .. f0
    uint8_t qk[32];
    for (int i = 0; i < 32; i++) qk[i] = (uint8_t)i;
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(16 * i);
    hexto("de71b5f8646a6a5d77fdb1fa285a3889", exp);
    qalqan_ctx qc;
    qalqan_key_setup(qk, &qc);
    qalqan_encrypt_block(&qc, pt, out);
    if (memcmp(out, exp, 16)) fail("Qalqan sample vector host");
    q_setkey(qk, pt);
    for (size_t i = 0; i < kcount[QAL]; i++) {
        gpu_ks(QAL, qal_k[i], dbuf, 16, be32(pt + 12), out);
        if (memcmp(out, exp, 16)) fail("Qalqan sample vector on GPU");
    }
    // PRESENT-80 paper vectors (Bogdanov et al., CHES 2007, Appendix I)
    struct { uint8_t key; uint64_t pt, ct; } pv[] = {{0x00, 0, 0x5579c1387b228445ull},
                                                    {0xff, 0, 0xe72c46c0f5945049ull},
                                                    {0x00, ~0ull, 0xa112ffc72f68417bull},
                                                    {0xff, ~0ull, 0x3333dcd3213210d2ull}};
    for (auto &v : pv) {
        uint8_t pk[10];
        memset(pk, v.key, 10);
        p_setkey(pk);
        if (present_encrypt_ref(&pctx, v.pt) != v.ct || p_enc(&pctx, v.pt) != v.ct) fail("PRESENT-80 paper vector host");
        for (size_t i = 0; i < kcount[PRE]; i++) {
            gpu_ks(PRE, pre_k[i], dbuf, 8, v.pt, out);
            for (int b = 0; b < 8; b++)
                if (out[b] != (uint8_t)(v.ct >> (56 - 8 * b))) fail("PRESENT-80 paper vector on GPU");
        }
    }
    // table == bit-by-bit reference on random blocks, under the paper key
    uint64_t x = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < 100000; i++) {
        x = x * 6364136223846793005ull + 1442695040888963407ull;
        if (p_enc(&pctx, x) != present_encrypt_ref(&pctx, x)) fail("PRESENT table vs ref");
    }
}

// The benchmark keys (not the KAT ones).
static void bench_keys(void)
{
    for (int i = 0; i < 16; i++) aes_key[i] = (uint8_t)(7 * i + 1);
    for (int i = 0; i < 32; i++) q_key[i] = (uint8_t)(11 * i + 5);
    for (int i = 0; i < 10; i++) p_key[i] = (uint8_t)(13 * i + 3);
    for (int i = 0; i < 32; i++) a256_key[i] = (uint8_t)(9 * i + 4);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(5 * i + 2);
    aes_setkey(aes_key, nonce);
    a256_setkey(a256_key);
    q_setkey(q_key, nonce);
    p_setkey(p_key);
}

static const uint64_t TIMED_CTR = 7;

static void gate(size_t big, uint8_t *dbuf, uint8_t *h_in, uint8_t *h_out, uint8_t *h_ref)
{
    // second-opinion check of the fast host oracles against the reference CTR code
    {
        const size_t L = 70003;
        std::vector<uint8_t> a(L), b(L);
        for (uint32_t ctr : {7u, 0xfffffff0u}) {
            aes128_ctr_aesni_x8(aes_ctx, a.data(), h_in, L, nonce, ctr);
            aes128_ctr_ref(aes_ctx, b.data(), h_in, L, nonce, ctr);
            if (a != b) fail("aesni-x8 vs ref host oracle");
            qalqan_ctr_host(q_ctx, a.data(), h_in, L, nonce, ctr);
            qalqan_ctr_ref(q_ref_ctx, b.data(), h_in, L, nonce, ctr);
            if (a != b) fail("qalqan gfni-x16 vs ref host oracle");
        }
    }
    struct tcase { size_t len; uint64_t ctr; };
    const size_t odd[] = {1, 15, 16, 17, 4095, 1000003};
    for (int c = AES; c < NCIPH; c++) {
        std::vector<tcase> cases;
        for (size_t l : odd) cases.push_back({l, TIMED_CTR});
        cases.push_back({(size_t)16 << 20, TIMED_CTR});
        cases.push_back({big, TIMED_CTR});
        if (c != PRE) {  // 32-bit counter wraps mod 2^32
            for (size_t l : {(size_t)4095, (size_t)1000003}) cases.push_back({l, 0xfffffff0u});
            cases.push_back({(size_t)16 << 20, 0xffff0000u});
        } else {  // 64-bit counter: carries across bytes 0..3, 4..7, and wrap mod 2^64
            for (uint64_t c0 : {0ull, 0xffffff80ull, 0x00ffffffffffff00ull, 0xfffffffffffffff0ull})
                for (size_t l : {(size_t)4095, (size_t)1000003}) cases.push_back({l, c0});
            cases.push_back({(size_t)16 << 20, 0x00000000fffff000ull});
        }
        for (const tcase &t : cases) {
            oracle(c, h_ref, h_in, t.len, t.ctr);
            for (size_t i = 0; i < kcount[c]; i++) {
                const kdesc &d = kset[c][i];
                CK(cudaMemcpy(dbuf, h_in, t.len, cudaMemcpyHostToDevice));
                launch(d, false, dbuf, t.len, t.ctr, gtab_for(c, d));
                CK(cudaGetLastError());
                CK(cudaMemcpy(h_out, dbuf, t.len, cudaMemcpyDeviceToHost));
                if (memcmp(h_out, h_ref, t.len)) {
                    fprintf(stderr, "FAIL %s %s len=%zu ctr=0x%llx\n", cname[c], d.name, t.len, (unsigned long long)t.ctr);
                    exit(1);
                }
            }
        }
        if (!kcount[c]) { printf("%s: no GPU kernels in this build\n", cname[c]); continue; }
        printf("%s: all %zu kernels match the KAT-verified host implementation on %zu cases\n", cname[c], kcount[c],
               cases.size());
    }
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : NULL;
    const char *only = argc > 2 ? argv[2] : NULL;  // optional: time only ciphers whose name contains this
    CK(cudaGetDeviceProperties(&prop, 0));
    int rt, drv;
    cudaRuntimeGetVersion(&rt);
    cudaDriverGetVersion(&drv);
    printf("gpu: %s, cc %d.%d, %d SMs, L2 %d KiB\n", prop.name, prop.major, prop.minor, prop.multiProcessorCount,
           prop.l2CacheSize / 1024);
    CK(cudaMalloc(&d_sink, sizeof(int)));
    size_t big = (size_t)256 << 20;
    uint8_t *dbuf;
    CK(cudaMalloc(&dbuf, big));
    // tables (global; every kernel copies what it needs to shared memory)
    {
        uint32_t te0[256];
        for (int x = 0; x < 256; x++) {
            uint32_t s = aes_sbox[x], s2 = ((s << 1) ^ ((s >> 7) * 0x1b)) & 0xff, s3 = s2 ^ s;
            te0[x] = s2 << 24 | s << 16 | s << 8 | s3;
        }
        CK(cudaMalloc(&d_te0, sizeof te0));
        CK(cudaMemcpy(d_te0, te0, sizeof te0, cudaMemcpyHostToDevice));
        CK(cudaMalloc(&d_aes_sb, 256));
        CK(cudaMemcpy(d_aes_sb, aes_sbox, 256, cudaMemcpyHostToDevice));
        CK(cudaMalloc(&d_q_sb, 256));
        CK(cudaMemcpy(d_q_sb, qalqan_sb, 256, cudaMemcpyHostToDevice));
        CK(cudaMalloc(&d_ptab, sizeof pctx.enc_tab));
    }
    for (int c = AES; c < NCIPH; c++) set_maxgrid(kset[c], kcount[c]);
    known_answers(dbuf);
    printf("known answers: FIPS-197 C.1 and C.3, Qalqan sample, 4 PRESENT-80 paper vectors pass on host and every GPU kernel\n");
    bench_keys();
    uint8_t *h_in = (uint8_t *)malloc(big), *h_out = (uint8_t *)malloc(big), *h_ref = (uint8_t *)malloc(big);
    for (size_t i = 0; i < big; i++) h_in[i] = (uint8_t)(i * 2654435761u >> 13);
    gate(big, dbuf, h_in, h_out, h_ref);
    free(h_in); free(h_out); free(h_ref);

    if (path) {  // opened only after the whole gate has passed
        csv = fopen(path, "w");
        if (!csv) { perror(path); return 1; }
        time_t now = time(NULL);
        char ts[64];
        strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
        fprintf(csv, "# produced_by: build/ca/cuda/bc_gpu (chacha_ascon/cuda/bc_gpu.cu)\n# generated_utc: %s\n", ts);
        fprintf(csv, "# gpu: %s (compute capability %d.%d, %d SMs, L2 %d KiB)\n# cuda_runtime: %d, cuda_driver: %d\n",
                prop.name, prop.major, prop.minor, prop.multiProcessorCount, prop.l2CacheSize / 1024, rt, drv);
        fprintf(csv, "# ciphers: AES-128 (10 rounds), AES-256 (14 rounds), Qalqan-256/128 (15 rounds), PRESENT-80 (31 rounds), CTR, XOR in place\n");
        fprintf(csv, "# trials: 15 timed, 5 warm-up, median reported; table kernels 256 threads/block grid-stride over one\n"
                     "#   resident wave, bitslice 128 threads/block; key setup and table upload outside timing\n");
        fprintf(csv, "# sm_mhz_kernel: median over SMs of clock64 cycles / %%globaltimer ns over each SM's span,\n"
                     "#   recorded in one extra launch of the same kernel right after the timed ones; sms_seen = SMs\n"
                     "#   that reported. probe_mhz_before/after: a clock64() spin kernel around the row (context only).\n"
                     "# bytes_per_sm_cycle = throughput / (sm_mhz_kernel x SM count). Scaling it to another clock is a\n"
                     "#   compute-bound estimate only; memory bandwidth and latency do not scale with the SM clock.\n");
        fprintf(csv, "target,cipher,kernel,msg_bytes,total_bytes,median_ms,gb_per_sec,gbit_per_sec,sm_mhz_kernel,sms_seen,probe_mhz_before,"
                     "probe_mhz_after,bytes_per_sm_cycle,note\n");
    }
    printf("SM clock now: %.0f MHz\n", sm_mhz());
    std::vector<std::string> best;
    for (int c = AES; c < NCIPH; c++)
        if ((!only || strstr(cname[c], only)) && kcount[c])
        for (size_t total : {(size_t)16 << 20, big}) {
            float bms = 1e30f;
            const char *bname = "";
            for (size_t i = 0; i < kcount[c]; i++) {
                const kdesc &d = kset[c][i];
                const void *g = gtab_for(c, d);
                float ms = time_kernel([&] { launch(d, false, dbuf, total, TIMED_CTR, g); },
                                       [&] { launch(d, true, dbuf, total, TIMED_CTR, g); });
                report(cname[c], d.name, total, total, ms, d.note);
                if (ms < bms) bms = ms, bname = d.name;
            }
            char line[160];
            snprintf(line, sizeof line, "# fastest: %s %zu MiB: %s (%.2f GB/s)", cname[c], total >> 20, bname,
                     total / (bms * 1e-3) / 1e9);
            best.push_back(line);
        }
    for (auto &l : best) {
        printf("%s\n", l.c_str() + 2);
        if (csv) fprintf(csv, "%s\n", l.c_str());
    }
    if (csv) fclose(csv);
    CK(cudaFree(dbuf));
    return 0;
}
