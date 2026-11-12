// ChaCha20 and Ascon-AEAD128 on a CUDA GPU: kernels, correctness gate, benchmark.
//
// Protocol, the same as bench/gpu_bench.cu's for PRESENT (docs/gpu-optimizations.md):
// data stays in device memory, key/nonce setup is outside the timed region, 5
// warm-up launches then 15 timed launches, median CUDA-event time reported. Two
// working-set sizes per row, repeated over the same buffer: 16 MiB, which fits
// nominally in the RTX 5070 Laptop's 32 MB L2, and 256 MiB, which cannot. No
// cache-residency or memory-traffic counters are read, so the two are reported
// as small/large working sets, not as "cipher-only" vs "memory-bound".
//
// ChaCha20 -- one buffer, one key/nonce, 32-bit block counter (RFC 8439). Kernels:
//   xor-1      one 64-byte block per thread, its 64 bytes read/written as 4 x uint4
//   xor-2      two consecutive blocks per thread (more ILP, half the threads)
//   xor-smem   one block per thread, keystream staged through shared memory so a
//              warp's 2 KiB of loads and stores are fully coalesced
//   ks-1       keystream only (store, no load): the generation rate, the analogue of
//              PRESENT's "block evaluation" rows
// Ascon-AEAD128 -- many independent messages, one per thread (a duplex cannot be
// split across threads), each with its own key and nonce, ciphertext||tag written
// in place over a (mlen + 16)-byte slot. Message size is swept, because on a GPU
// the number of concurrent messages IS the parallelism: 16 MiB of 64 KiB messages
// is only 256 threads.
//   u64        straightforward 64-bit code; nvcc splits it into 32-bit halves, fuses
//              the S-box's xor/andnot/xor into LOP3 and does each rotate as two SHF
//   u64-smem   the same, with each warp's next 16-byte blocks staged through shared
//              memory in coalesced 128-byte rows
//
// Correctness: at startup oracle_gate.c checks the linked host oracles against the
// KAT files; then, before any timing, every kernel's output for every timed launch
// shape (and odd lengths that exercise tails) is compared byte for byte with them.
// A mismatch aborts the run with a non-zero exit; nothing is reported for it.
#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <algorithm>
#include <vector>

extern "C" {
#include "ascon_aead.h"
#include "chacha20.h"
void chacha20_xor_avx2_x8(uint8_t *, const uint8_t *, size_t, const uint8_t[32], const uint8_t[12], uint32_t);
void ascon_multi_avx2_x8(const ascon_job *, size_t, size_t, size_t);
int oracle_gate(void);
}

#include "gpu_harness.cuh"  // CK, clk_scope<CLK>, k_spin, kernel_clock, time_kernel, sm_mhz, report

// ------------------------------------------------------------------- ChaCha20
struct chacha_key { uint32_t k[8], n[3]; };

__device__ __forceinline__ uint32_t rotl(uint32_t x, int n) { return __funnelshift_l(x, x, n); }
#define ROT16(x) __byte_perm((x), 0, 0x1032)
#define ROT8(x) __byte_perm((x), 0, 0x2103)
#define QR(a, b, c, d)                          \
    a += b; d ^= a; d = ROT16(d);               \
    c += d; b ^= c; b = rotl(b, 12);            \
    a += b; d ^= a; d = ROT8(d);                \
    c += d; b ^= c; b = rotl(b, 7)

__device__ __forceinline__ void chacha_block(uint32_t out[16], const chacha_key &K, uint32_t ctr)
{
    uint32_t x[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                      K.k[0], K.k[1], K.k[2], K.k[3], K.k[4], K.k[5], K.k[6], K.k[7],
                      ctr, K.n[0], K.n[1], K.n[2]};
#pragma unroll
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    out[0] = x[0] + 0x61707865; out[1] = x[1] + 0x3320646e;
    out[2] = x[2] + 0x79622d32; out[3] = x[3] + 0x6b206574;
#pragma unroll
    for (int i = 0; i < 8; i++) out[4 + i] = x[4 + i] + K.k[i];
    out[12] = x[12] + ctr;
#pragma unroll
    for (int i = 0; i < 3; i++) out[13 + i] = x[13 + i] + K.n[i];
}

// Byte-wise XOR of a final partial block (len % 64 bytes) -- one thread, once.
__device__ void xor_tail(uint8_t *p, size_t n, const uint32_t ks[16])
{
    for (size_t i = 0; i < n; i++) p[i] ^= (uint8_t)(ks[i / 4] >> (8 * (i % 4)));
}

template <bool CLK = false>
__global__ void __launch_bounds__(256) k_chacha_xor1(uint8_t *buf, size_t len, chacha_key K, uint32_t ctr0)
{
    clk_scope<CLK> clk_;
    size_t blk = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    size_t off = blk * 64;
    if (off >= len) return;
    uint32_t ks[16];
    chacha_block(ks, K, ctr0 + (uint32_t)blk);
    if (off + 64 <= len) {
        uint4 *p = (uint4 *)(buf + off);
#pragma unroll
        for (int i = 0; i < 4; i++) {
            uint4 v = p[i];
            v.x ^= ks[4 * i]; v.y ^= ks[4 * i + 1]; v.z ^= ks[4 * i + 2]; v.w ^= ks[4 * i + 3];
            p[i] = v;
        }
    } else {
        xor_tail(buf + off, len - off, ks);
    }
}

template <bool CLK = false>
__global__ void __launch_bounds__(256) k_chacha_xor2(uint8_t *buf, size_t len, chacha_key K, uint32_t ctr0)
{
    clk_scope<CLK> clk_;
    size_t pair = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    size_t blk = pair * 2;
    if (blk * 64 >= len) return;
    uint32_t ka[16], kb[16];
    chacha_block(ka, K, ctr0 + (uint32_t)blk);
    chacha_block(kb, K, ctr0 + (uint32_t)blk + 1);
    for (int h = 0; h < 2; h++) {
        const uint32_t *ks = h ? kb : ka;
        size_t off = (blk + h) * 64;
        if (off >= len) break;
        if (off + 64 <= len) {
            uint4 *p = (uint4 *)(buf + off);
#pragma unroll
            for (int i = 0; i < 4; i++) {
                uint4 v = p[i];
                v.x ^= ks[4 * i]; v.y ^= ks[4 * i + 1]; v.z ^= ks[4 * i + 2]; v.w ^= ks[4 * i + 3];
                p[i] = v;
            }
        } else {
            xor_tail(buf + off, len - off, ks);
        }
    }
}

// Keystream staged in shared memory: thread t writes its block's 16 words into the
// warp's 2 KiB tile; then the warp walks the tile as 4 rows of 32 x uint4, so every
// global load/store instruction covers 512 contiguous bytes. +1 uint4 of padding per
// 4 avoids 4-way bank conflicts on the column writes.
template <bool CLK = false>
__global__ void __launch_bounds__(256) k_chacha_xor_smem(uint8_t *buf, size_t len, chacha_key K, uint32_t ctr0)
{
    clk_scope<CLK> clk_;
    __shared__ uint4 tile[8][32 * 5];
    const int lane = threadIdx.x & 31, w = threadIdx.x >> 5;
    size_t warp_blk0 = ((size_t)blockIdx.x * blockDim.x) + (size_t)w * 32;
    size_t blk = warp_blk0 + lane;
    uint32_t ks[16];
    chacha_block(ks, K, ctr0 + (uint32_t)blk);
#pragma unroll
    for (int i = 0; i < 4; i++)
        tile[w][lane * 5 + i] = make_uint4(ks[4 * i], ks[4 * i + 1], ks[4 * i + 2], ks[4 * i + 3]);
    __syncwarp();
    size_t base = warp_blk0 * 64;
    if (base + 2048 <= len) {
        uint4 *p = (uint4 *)(buf + base);
#pragma unroll
        for (int r = 0; r < 4; r++) {
            int idx = r * 32 + lane;           // uint4 index within the warp's 2 KiB
            uint4 k = tile[w][(idx >> 2) * 5 + (idx & 3)];
            uint4 v = p[idx];
            v.x ^= k.x; v.y ^= k.y; v.z ^= k.z; v.w ^= k.w;
            p[idx] = v;
        }
    } else {
        size_t off = blk * 64;
        if (off < len) {
            if (off + 64 <= len) {
                uint4 *p = (uint4 *)(buf + off);
                for (int i = 0; i < 4; i++) {
                    uint4 v = p[i];
                    v.x ^= ks[4 * i]; v.y ^= ks[4 * i + 1]; v.z ^= ks[4 * i + 2]; v.w ^= ks[4 * i + 3];
                    p[i] = v;
                }
            } else {
                xor_tail(buf + off, len - off, ks);
            }
        }
    }
}

template <bool CLK = false>
__global__ void __launch_bounds__(256) k_chacha_ks1(uint8_t *buf, size_t len, chacha_key K, uint32_t ctr0)
{
    clk_scope<CLK> clk_;
    size_t blk = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    size_t off = blk * 64;
    if (off >= len) return;
    uint32_t ks[16];
    chacha_block(ks, K, ctr0 + (uint32_t)blk);
    if (off + 64 <= len) {
        uint4 *p = (uint4 *)(buf + off);
#pragma unroll
        for (int i = 0; i < 4; i++) p[i] = make_uint4(ks[4 * i], ks[4 * i + 1], ks[4 * i + 2], ks[4 * i + 3]);
    } else {
        for (size_t i = 0; i < len - off; i++) buf[off + i] = (uint8_t)(ks[i / 4] >> (8 * (i % 4)));
    }
}

// ---------------------------------------------------------------------- Ascon
#define IV_AEAD128 0x00001000808c0001ULL
__device__ __forceinline__ uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

__device__ __forceinline__ void ascon_round(uint64_t &x0, uint64_t &x1, uint64_t &x2, uint64_t &x3,
                                            uint64_t &x4, uint64_t c)
{
    x2 ^= c;
    x0 ^= x4; x4 ^= x3; x2 ^= x1;
    uint64_t t0 = x0 ^ (~x1 & x2);
    uint64_t t2 = x2 ^ (~x3 & x4);
    uint64_t t4 = x4 ^ (~x0 & x1);
    uint64_t t1 = x1 ^ (~x2 & x3);
    uint64_t t3 = x3 ^ (~x4 & x0);
    t1 ^= t0; t3 ^= t2; t0 ^= t4;
    x0 = t0 ^ ror64(t0, 19) ^ ror64(t0, 28);
    x1 = t1 ^ ror64(t1, 61) ^ ror64(t1, 39);
    x2 = ~(t2 ^ ror64(t2, 1) ^ ror64(t2, 6));
    x3 = t3 ^ ror64(t3, 10) ^ ror64(t3, 17);
    x4 = t4 ^ ror64(t4, 7) ^ ror64(t4, 41);
}
#define P12() _Pragma("unroll") for (int r_ = 0; r_ < 12; r_++) ascon_round(x0, x1, x2, x3, x4, 0xf0 - 0x0f * r_)
#define P8()  _Pragma("unroll") for (int r_ = 4; r_ < 12; r_++) ascon_round(x0, x1, x2, x3, x4, 0xf0 - 0x0f * r_)

struct ascon_kn { uint64_t k0, k1, n0, n1; };

__device__ __forceinline__ uint64_t ld64u(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

// Final partial block (n = 0..15 bytes): absorb padded, emit n bytes. Byte-wise,
// since the slot is not 16-byte aligned in general.
__device__ __forceinline__ void ascon_last(uint8_t *p, size_t n, uint64_t &x0, uint64_t &x1)
{
    uint8_t b[16];
#pragma unroll
    for (int i = 0; i < 16; i++) b[i] = 0;
    for (size_t i = 0; i < n; i++) b[i] = p[i];
    b[n] = 1;
    x0 ^= ld64u(b);
    x1 ^= ld64u(b + 8);
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)((i < 8 ? x0 >> (8 * i) : x1 >> (8 * (i - 8))));
}

// One message per thread. Slot i of `buf` is [stride * i, stride * i + mlen + 16).
// Full blocks use 16-byte vector accesses when the slot is 16-byte aligned
// (stride % 16 == 0), byte accesses otherwise.
template <bool CLK = false>
__global__ void __launch_bounds__(256) k_ascon_u64(uint8_t *buf, size_t nmsg, size_t mlen, size_t stride,
                                                   const ascon_kn *kn)
{
    clk_scope<CLK> clk_;
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= nmsg) return;
    uint8_t *p = buf + i * stride;
    ascon_kn K = kn[i];
    uint64_t x0 = IV_AEAD128, x1 = K.k0, x2 = K.k1, x3 = K.n0, x4 = K.n1;
    P12();
    x3 ^= K.k0; x4 ^= K.k1;
    x4 ^= 0x8000000000000000ULL;  // no associated data: domain separation only
    size_t off = 0;
    const bool vec = (stride % 16) == 0;
    for (; off + 16 <= mlen; off += 16) {
        if (vec) {
            ulonglong2 v = *(ulonglong2 *)(p + off);
            x0 ^= v.x; x1 ^= v.y;
            *(ulonglong2 *)(p + off) = make_ulonglong2(x0, x1);
        } else {
            uint64_t a = ld64u(p + off), b = ld64u(p + off + 8);
            x0 ^= a; x1 ^= b;
            for (int j = 0; j < 8; j++) { p[off + j] = (uint8_t)(x0 >> (8 * j)); p[off + 8 + j] = (uint8_t)(x1 >> (8 * j)); }
        }
        P8();
    }
    ascon_last(p + off, mlen - off, x0, x1);
    x2 ^= K.k0; x3 ^= K.k1;
    P12();
    x3 ^= K.k0; x4 ^= K.k1;
    for (int j = 0; j < 8; j++) { p[mlen + j] = (uint8_t)(x3 >> (8 * j)); p[mlen + 8 + j] = (uint8_t)(x4 >> (8 * j)); }
}

// Staged variant: a warp holds its 32 messages' next 128 bytes (8 blocks each) in
// shared memory. Loading the tile is 32 rows of 128 contiguous bytes, done as
// 8 x uint4 per thread with consecutive lanes on consecutive uint4 of one row --
// i.e. each instruction touches 4 full 128-byte lines instead of 32 partial ones.
// The staged part needs stride % 16 == 0 (else the whole message takes the direct
// path); the part of the message past the last whole 128 bytes is done directly.
template <bool CLK = false>
__global__ void __launch_bounds__(256) k_ascon_u64_smem(uint8_t *buf, size_t nmsg, size_t mlen, size_t stride,
                                                        const ascon_kn *kn)
{
    clk_scope<CLK> clk_;
    __shared__ uint4 tile[8][32 * 9];  // per warp: 32 messages x 8 uint4, padded to 9
    const int lane = threadIdx.x & 31, w = threadIdx.x >> 5;
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    size_t wbase = i - lane;           // first message of this warp
    bool active = i < nmsg;
    uint8_t *p = buf + (active ? i : 0) * stride;
    ascon_kn K = kn[active ? i : 0];
    uint64_t x0 = IV_AEAD128, x1 = K.k0, x2 = K.k1, x3 = K.n0, x4 = K.n1;
    P12();
    x3 ^= K.k0; x4 ^= K.k1;
    x4 ^= 0x8000000000000000ULL;
    size_t off = 0;
    const bool vec = (stride % 16) == 0;  // warp-uniform
    for (; vec && off + 128 <= mlen; off += 128) {
        // cooperative coalesced load: element e = r*32 + lane, message m = e / 8, uint4 q = e % 8
#pragma unroll
        for (int r = 0; r < 8; r++) {
            int e = r * 32 + lane, m = e >> 3, q = e & 7;
            tile[w][m * 9 + q] = wbase + m < nmsg ? *(const uint4 *)(buf + (wbase + m) * stride + off + 16 * q)
                                                  : make_uint4(0, 0, 0, 0);  // inactive lane: defined input
        }
        __syncwarp();
#pragma unroll
        for (int q = 0; q < 8; q++) {
            uint4 v = tile[w][lane * 9 + q];
            x0 ^= ((uint64_t)v.y << 32) | v.x;
            x1 ^= ((uint64_t)v.w << 32) | v.z;
            tile[w][lane * 9 + q] = make_uint4((uint32_t)x0, (uint32_t)(x0 >> 32), (uint32_t)x1, (uint32_t)(x1 >> 32));
            P8();
        }
        __syncwarp();
#pragma unroll
        for (int r = 0; r < 8; r++) {
            int e = r * 32 + lane, m = e >> 3, q = e & 7;
            if (wbase + m < nmsg)
                *(uint4 *)(buf + (wbase + m) * stride + off + 16 * q) = tile[w][m * 9 + q];
        }
        __syncwarp();
    }
    if (!active) return;
    for (; off + 16 <= mlen; off += 16) {
        if (vec) {
            ulonglong2 v = *(ulonglong2 *)(p + off);
            x0 ^= v.x; x1 ^= v.y;
            *(ulonglong2 *)(p + off) = make_ulonglong2(x0, x1);
        } else {
            uint64_t a = ld64u(p + off), b = ld64u(p + off + 8);
            x0 ^= a; x1 ^= b;
            for (int j = 0; j < 8; j++) { p[off + j] = (uint8_t)(x0 >> (8 * j)); p[off + 8 + j] = (uint8_t)(x1 >> (8 * j)); }
        }
        P8();
    }
    ascon_last(p + off, mlen - off, x0, x1);
    x2 ^= K.k0; x3 ^= K.k1;
    P12();
    x3 ^= K.k0; x4 ^= K.k1;
    for (int j = 0; j < 8; j++) { p[mlen + j] = (uint8_t)(x3 >> (8 * j)); p[mlen + 8 + j] = (uint8_t)(x4 >> (8 * j)); }
}

static uint64_t le64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

typedef void (*chacha_kernel)(uint8_t *, size_t, chacha_key, uint32_t);
struct ck_desc { const char *name; chacha_kernel k, kc; int blocks_per_thread; bool ks_only; };

static void chacha_suite(size_t big)
{
#define CKD(n, f, b, o) {n, f<false>, f<true>, b, o}
    const ck_desc ks[] = {CKD("xor-1", k_chacha_xor1, 1, false), CKD("xor-2", k_chacha_xor2, 2, false),
                          CKD("xor-smem", k_chacha_xor_smem, 1, false), CKD("ks-1", k_chacha_ks1, 1, true)};
    uint8_t key[32], nonce[12];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(3 * i + 1);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(5 * i + 2);
    chacha_key K;
    memcpy(K.k, key, 32);
    memcpy(K.n, nonce, 12);
    uint8_t *h_in = (uint8_t *)malloc(big), *h_out = (uint8_t *)malloc(big), *h_ref = (uint8_t *)malloc(big);
    for (size_t i = 0; i < big; i++) h_in[i] = (uint8_t)(i * 2654435761u >> 13);
    uint8_t *d;
    CK(cudaMalloc(&d, big));
    // correctness: odd lengths (tail paths, partial last warp) and the full timed size
    const size_t lens[] = {1, 63, 64, 65, 2047, 2048, 2049, 1000003, 16u << 20, big};
    const uint32_t ctr0 = 7;
    for (const ck_desc &c : ks)
        for (size_t len : lens) {
            if (len > big) continue;
            CK(cudaMemcpy(d, h_in, len, cudaMemcpyHostToDevice));
            size_t threads = (len + 64 * c.blocks_per_thread - 1) / (64 * c.blocks_per_thread);
            c.k<<<(unsigned)((threads + 255) / 256), 256>>>(d, len, K, ctr0);
            CK(cudaGetLastError());
            CK(cudaMemcpy(h_out, d, len, cudaMemcpyDeviceToHost));
            if (c.ks_only) memset(h_ref, 0, len), chacha20_xor_avx2_x8(h_ref, h_ref, len, key, nonce, ctr0);
            else chacha20_xor_avx2_x8(h_ref, h_in, len, key, nonce, ctr0);
            if (memcmp(h_out, h_ref, len)) {
                fprintf(stderr, "FAIL chacha20 %s len=%zu\n", c.name, len);
                exit(1);
            }
        }
    printf("chacha20: all %zu kernels match the KAT-verified host implementation\n", sizeof ks / sizeof ks[0]);
    for (size_t total : {(size_t)16 << 20, big})
        for (const ck_desc &c : ks) {
            size_t threads = total / (64 * c.blocks_per_thread);
            unsigned g = (unsigned)((threads + 255) / 256);
            float ms = time_kernel([&] { c.k<<<g, 256>>>(d, total, K, 0); }, [&] { c.kc<<<g, 256>>>(d, total, K, 0); });
            report("chacha20", c.name, total, total, ms, c.ks_only ? "keystream-only (write)" : "xor in place (read+write)");
        }
    CK(cudaFree(d));
    free(h_in); free(h_out); free(h_ref);
}

typedef void (*ascon_kernel)(uint8_t *, size_t, size_t, size_t, const ascon_kn *);

static void ascon_suite(size_t big)
{
    struct { const char *name; ascon_kernel k, kc; } ks[] = {{"u64", k_ascon_u64<false>, k_ascon_u64<true>},
                                                            {"u64-smem", k_ascon_u64_smem<false>, k_ascon_u64_smem<true>}};
    const size_t msizes[] = {256, 1024, 4096, 16384, 65536};
    size_t maxmsgs = big / 256;
    std::vector<uint8_t> keys(maxmsgs * 16), nonces(maxmsgs * 16);
    for (size_t i = 0; i < maxmsgs * 16; i++) { keys[i] = (uint8_t)(i * 7 + 3); nonces[i] = (uint8_t)(i * 13 + 11); }
    std::vector<ascon_kn> kn(maxmsgs);
    for (size_t i = 0; i < maxmsgs; i++)
        kn[i] = {le64(&keys[16 * i]), le64(&keys[16 * i + 8]), le64(&nonces[16 * i]), le64(&nonces[16 * i + 8])};
    ascon_kn *d_kn;
    CK(cudaMalloc(&d_kn, maxmsgs * sizeof(ascon_kn)));
    CK(cudaMemcpy(d_kn, kn.data(), maxmsgs * sizeof(ascon_kn), cudaMemcpyHostToDevice));
    size_t cap = big + (big / 256) * 16 + 4096;
    uint8_t *d, *h = (uint8_t *)malloc(cap), *h_out = (uint8_t *)malloc(cap), *h_ref = (uint8_t *)malloc(cap);
    CK(cudaMalloc(&d, cap));
    // correctness: odd message sizes (byte path, partial last block, partial warp)
    // and every timed configuration, all messages checked.
    std::vector<std::pair<size_t, size_t>> check;  // (mlen, nmsg)
    for (size_t m : {0, 1, 15, 16, 17, 100, 128, 129, 1000}) check.push_back({m, 3001});  // partial warp/block
    for (size_t total : {(size_t)16 << 20, big})
        for (size_t m : msizes) check.push_back({m, total / m});  // exactly the timed launches
    for (auto &kd : ks)
        for (auto [mlen, nmsg] : check) {
            size_t stride = mlen + 16;
            for (size_t i = 0; i < nmsg * stride; i++) h[i] = (uint8_t)(i * 2654435761u >> 11);
            CK(cudaMemcpy(d, h, nmsg * stride, cudaMemcpyHostToDevice));
            kd.k<<<(unsigned)((nmsg + 255) / 256), 256>>>(d, nmsg, mlen, stride, d_kn);
            CK(cudaGetLastError());
            CK(cudaMemcpy(h_out, d, nmsg * stride, cudaMemcpyDeviceToHost));
            std::vector<ascon_job> jobs(nmsg);
            for (size_t i = 0; i < nmsg; i++)
                jobs[i] = {h_ref + i * stride, h + i * stride, nullptr, &nonces[16 * i], &keys[16 * i]};
            ascon_multi_avx2_x8(jobs.data(), nmsg, mlen, 0);
            for (size_t i = 0; i < nmsg; i++)
                if (memcmp(h_out + i * stride, h_ref + i * stride, mlen + 16)) {
                    fprintf(stderr, "FAIL ascon %s mlen=%zu msg=%zu\n", kd.name, mlen, i);
                    exit(1);
                }
        }
    printf("ascon: all %zu kernels match, every timed (size, count) launch checked in full; the KAT-verified host implementation\n", sizeof ks / sizeof ks[0]);
    for (size_t total : {(size_t)16 << 20, big})
        for (size_t mlen : msizes)
            for (auto &kd : ks) {
                size_t nmsg = total / mlen, stride = mlen + 16;
                unsigned g = (unsigned)((nmsg + 255) / 256);
                float ms = time_kernel([&] { kd.k<<<g, 256>>>(d, nmsg, mlen, stride, d_kn); },
                                       [&] { kd.kc<<<g, 256>>>(d, nmsg, mlen, stride, d_kn); });
                char note[96];
                snprintf(note, sizeof note, "%zu messages, one per thread, AEAD encrypt+tag in place", nmsg);
                report("ascon128", kd.name, mlen, nmsg * mlen, ms, note);
            }
    CK(cudaFree(d));
    CK(cudaFree(d_kn));
    free(h); free(h_out); free(h_ref);
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : NULL;
    CK(cudaGetDeviceProperties(&prop, 0));
    int rt, drv;
    cudaRuntimeGetVersion(&rt);
    cudaDriverGetVersion(&drv);
    printf("gpu: %s, cc %d.%d, %d SMs, L2 %d KiB\n", prop.name, prop.major, prop.minor, prop.multiProcessorCount,
           prop.l2CacheSize / 1024);
    if (path) {
        csv = fopen(path, "w");
        if (!csv) { perror(path); return 1; }
        time_t now = time(NULL);
        char ts[64];
        strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
        fprintf(csv, "# produced_by: build/ca/cuda/ca_gpu (chacha_ascon/cuda/ca_gpu.cu)\n# generated_utc: %s\n", ts);
        fprintf(csv, "# gpu: %s (compute capability %d.%d, %d SMs, L2 %d KiB)\n# cuda_runtime: %d, cuda_driver: %d\n",
                prop.name, prop.major, prop.minor, prop.multiProcessorCount, prop.l2CacheSize / 1024, rt, drv);
        fprintf(csv, "# trials: 15 timed, 5 warm-up, median reported; 256 threads per block\n");
        fprintf(csv, "# total_bytes is payload bytes encrypted per launch (Ascon tags excluded).\n");
        fprintf(csv, "# sm_mhz_kernel: median over SMs of clock64 cycles / %%globaltimer ns over each SM's span,\n"
                     "#   recorded in one extra launch of the same kernel right after the timed ones; sms_seen = SMs\n"
                     "#   that reported. probe_mhz_before/after: a clock64() spin kernel around the row (context only).\n"
                     "# bytes_per_sm_cycle = throughput / (sm_mhz_kernel x SM count). Scaling it to another clock is a\n"
                     "#   compute-bound estimate only; memory bandwidth and latency do not scale with the SM clock.\n");
        fprintf(csv, "target,cipher,kernel,msg_bytes,total_bytes,median_ms,gb_per_sec,gbit_per_sec,sm_mhz_kernel,sms_seen,probe_mhz_before,"
                     "probe_mhz_after,bytes_per_sm_cycle,note\n");
    }
    printf("oracle gate: %d KAT vectors pass on the linked host oracles\n", oracle_gate());
    CK(cudaMalloc(&d_sink, sizeof(int)));
    printf("SM clock now: %.0f MHz\n", sm_mhz());
    size_t big = (size_t)256 << 20;
    chacha_suite(big);
    ascon_suite(big);
    if (csv) fclose(csv);
    return 0;
}
