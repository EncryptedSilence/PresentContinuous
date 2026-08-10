/* CUDA attacker-side throughput experiments.
 *
 * This is intentionally standalone. The CPU library is C and 64-bit-block oriented,
 * while the GPU experiments need both the PRESENT-like 64-bit variants and the
 * 128-bit AES/AES-lin444 rows. The variant S-boxes are still read from the checked-in
 * JSON files, so the cipher definitions remain auditable.
 *
 * Timed work is encryption only with pre-expanded round keys. That matches the GPU
 * attacker question: how much round-function throughput can the device buy for each
 * cipher once there are many independent blocks/keys in flight?
 */

#include <cuda_runtime.h>

#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>

/* The seven ciphers and their round counts, from tools/cipher_set.py, by way of
 * the same generated header bench/ctr_narrow.c and bench/ctr_wide.c expand. No
 * cipher name and no round count is typed into this file: the v2 measurement
 * modes below are driven entirely by CTR_CIPHER_LIST, so adding a cipher to
 * tools/cipher_set.py breaks this build rather than silently omitting a row. */
#include "gen/ctr_cipher_set.h"

/* The CPU library, for the master-key self-test. The GPU key schedule is checked
 * against present_key_schedule() and the GPU ciphertext against
 * present_encrypt_ref() -- against the implementation the test suite already
 * exercises, that is, rather than against a second copy of the schedule written
 * here, which would agree with itself no matter what either of them computed. */
extern "C" {
#include "present/present.h"
}

#define TRIALS 15
#define WARMUP 5
#ifndef THREADS
#define THREADS 256
#endif
#define MAX_ROUNDS 32

enum Lin64Kind {
    LIN64_PRESENT_PBOX = 0,
    LIN64_CIPHERD_TRANSPOSE = 1,
    LIN64_LIN444_16 = 2
};

struct Variant64 {
    const char *name;
    const char *json_path;
    int rounds;
    int sbox_bits;
    Lin64Kind lin;
    int c0[3];
};

struct Variant128 {
    const char *name;
    int rounds;
    bool lin444;
    int c0[3];
};

struct __align__(16) U128 {
    uint32_t w[4];
};

__constant__ uint8_t c_sbox[256];
__constant__ uint64_t c_rk64[MAX_ROUNDS + 1];
__constant__ U128 c_rk128[MAX_ROUNDS + 1];
__constant__ uint32_t c_aes_te[4][256];
/* Round keys splatted one bit per word for the bitsliced kernel: entry 64*r + b
 * is all-ones when bit b of round key r is set. */
__constant__ uint32_t c_rkmask64[(MAX_ROUNDS + 1) * 64];

static uint64_t rng_state = 0x123456789abcdefULL;
static uint64_t rng_next()
{
    uint64_t x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;
    return x * 0x2545f4914f6cdd1dULL;
}

static void die_cuda(cudaError_t err, const char *what)
{
    if (err == cudaSuccess) return;
    std::fprintf(stderr, "CUDA error at %s: %s\n", what, cudaGetErrorString(err));
    std::exit(1);
}

#define CUDA_CHECK(call) die_cuda((call), #call)

static std::vector<int> read_json_sbox(const char *path)
{
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "cannot open %s\n", path);
        std::exit(1);
    }
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    size_t key = s.find("\"sbox\"");
    size_t open = s.find('[', key);
    size_t close = s.find(']', open);
    if (key == std::string::npos || open == std::string::npos || close == std::string::npos) {
        std::fprintf(stderr, "cannot find sbox array in %s\n", path);
        std::exit(1);
    }
    std::vector<int> out;
    int val = 0;
    bool have = false;
    for (size_t i = open + 1; i < close; i++) {
        char ch = s[i];
        if (ch >= '0' && ch <= '9') {
            val = 10 * val + (ch - '0');
            have = true;
        } else if (have) {
            out.push_back(val);
            val = 0;
            have = false;
        }
    }
    if (have) out.push_back(val);
    if (out.empty() || out.size() > 256) {
        std::fprintf(stderr, "bad sbox length %zu in %s\n", out.size(), path);
        std::exit(1);
    }
    return out;
}

static uint8_t xtime8(uint8_t a)
{
    return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b));
}

static uint32_t rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t rotl32_host(uint32_t x, int n)
{
    n &= 31;
    return n ? ((x << n) | (x >> (32 - n))) : x;
}

static uint16_t rotl16_host(uint16_t x, int n)
{
    n &= 15;
    return n ? (uint16_t)((x << n) | (x >> (16 - n))) : x;
}

static uint64_t apply_sbox64_host(uint64_t s, const std::vector<int> &sbox, int bits)
{
    uint64_t out = 0;
    if (bits == 4) {
        for (int i = 0; i < 16; i++) out |= (uint64_t)sbox[(s >> (4 * i)) & 15] << (4 * i);
    } else {
        for (int i = 0; i < 8; i++) out |= (uint64_t)sbox[(s >> (8 * i)) & 255] << (8 * i);
    }
    return out;
}

static uint64_t lin64_host(uint64_t s, Lin64Kind kind, const int c0[3])
{
    if (kind == LIN64_PRESENT_PBOX) {
        uint64_t out = 0;
        for (int i = 0; i < 64; i++) {
            int dst = (i == 63) ? 63 : (16 * i) % 63;
            out |= ((s >> i) & 1ULL) << dst;
        }
        return out;
    }
    if (kind == LIN64_CIPHERD_TRANSPOSE) {
        uint64_t out = 0;
        for (int i = 0; i < 64; i++) {
            int dst = i / 8 + 8 * (i % 8);
            out |= ((s >> i) & 1ULL) << dst;
        }
        return out;
    }
    uint16_t w[4];
    for (int i = 0; i < 4; i++) w[i] = (uint16_t)(s >> (16 * i));
    uint16_t o0 = w[0] ^ rotl16_host(w[1], c0[0]) ^ rotl16_host(w[2], c0[1])
                ^ rotl16_host(w[3], c0[2]);
    uint16_t o1 = w[1] ^ rotl16_host(w[2], c0[0]) ^ rotl16_host(w[3], c0[1])
                ^ rotl16_host(o0, c0[2]);
    uint16_t o2 = w[2] ^ rotl16_host(w[3], c0[0]) ^ rotl16_host(o0, c0[1])
                ^ rotl16_host(o1, c0[2]);
    uint16_t o3 = w[3] ^ rotl16_host(o0, c0[0]) ^ rotl16_host(o1, c0[1])
                ^ rotl16_host(o2, c0[2]);
    return (uint64_t)o0 | ((uint64_t)o1 << 16) | ((uint64_t)o2 << 32) | ((uint64_t)o3 << 48);
}

static uint64_t encrypt64_host(uint64_t s, const std::vector<int> &sbox, int bits,
                               Lin64Kind lin, const int c0[3], const uint64_t *rk,
                               int rounds)
{
    for (int r = 0; r < rounds; r++) {
        s ^= rk[r];
        s = apply_sbox64_host(s, sbox, bits);
        s = lin64_host(s, lin, c0);
    }
    return s ^ rk[rounds];
}

static void build_table64(std::vector<uint64_t> &tab, const std::vector<int> &sbox,
                          int bits, Lin64Kind lin, const int c0[3])
{
    if (bits == 4) {
        tab.assign(16 * 16, 0);
        for (int nib = 0; nib < 16; nib++) {
            for (int v = 0; v < 16; v++) {
                uint64_t s = (uint64_t)sbox[v] << (4 * nib);
                tab[nib * 16 + v] = lin64_host(s, lin, c0);
            }
        }
    } else {
        tab.assign(8 * 256, 0);
        for (int byte = 0; byte < 8; byte++) {
            for (int v = 0; v < 256; v++) {
                uint64_t s = (uint64_t)sbox[v] << (8 * byte);
                tab[byte * 256 + v] = lin64_host(s, lin, c0);
            }
        }
    }
}

/* Fuse two PRESENT nibbles per lookup. Eight 256-entry rows have the same 16 KiB
 * shape as an 8-bit S-box table and halve PRESENT's dependent loads per round. */
static void build_table64_byte(std::vector<uint64_t> &tab, const std::vector<int> &sbox,
                               int bits, Lin64Kind lin, const int c0[3])
{
    tab.assign(8 * 256, 0);
    for (int byte = 0; byte < 8; byte++) {
        for (int v = 0; v < 256; v++) {
            uint64_t substituted;
            if (bits == 4) {
                substituted = (uint64_t)sbox[v & 15]
                            | ((uint64_t)sbox[v >> 4] << 4);
            } else {
                substituted = (uint64_t)sbox[v];
            }
            tab[byte * 256 + v] =
                lin64_host(substituted << (8 * byte), lin, c0);
        }
    }
}

static void lin444_128_host(uint32_t w[4], const int c0[3])
{
    uint32_t o0 = w[0] ^ rotl32_host(w[1], c0[0]) ^ rotl32_host(w[2], c0[1])
                ^ rotl32_host(w[3], c0[2]);
    uint32_t o1 = w[1] ^ rotl32_host(w[2], c0[0]) ^ rotl32_host(w[3], c0[1])
                ^ rotl32_host(o0, c0[2]);
    uint32_t o2 = w[2] ^ rotl32_host(w[3], c0[0]) ^ rotl32_host(o0, c0[1])
                ^ rotl32_host(o1, c0[2]);
    uint32_t o3 = w[3] ^ rotl32_host(o0, c0[0]) ^ rotl32_host(o1, c0[1])
                ^ rotl32_host(o2, c0[2]);
    w[0] = o0; w[1] = o1; w[2] = o2; w[3] = o3;
}

static U128 encrypt_lin128_host(U128 s, const std::vector<int> &sbox, const int c0[3],
                                const U128 *rk, int rounds)
{
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < 4; i++) s.w[i] ^= rk[r].w[i];
        for (int i = 0; i < 4; i++) {
            uint32_t v = 0;
            for (int b = 0; b < 4; b++)
                v |= (uint32_t)sbox[(s.w[i] >> (8 * b)) & 255] << (8 * b);
            s.w[i] = v;
        }
        lin444_128_host(s.w, c0);
    }
    for (int i = 0; i < 4; i++) s.w[i] ^= rk[rounds].w[i];
    return s;
}

static void build_lin128_table(std::vector<U128> &tab, const std::vector<int> &sbox,
                               const int c0[3])
{
    tab.assign(16 * 256, {});
    for (int byte = 0; byte < 16; byte++) {
        for (int v = 0; v < 256; v++) {
            uint32_t w[4] = {0, 0, 0, 0};
            w[byte / 4] = (uint32_t)sbox[v] << (8 * (byte % 4));
            lin444_128_host(w, c0);
            for (int i = 0; i < 4; i++) tab[byte * 256 + v].w[i] = w[i];
        }
    }
}

static void aes_tables(std::vector<uint32_t> &te)
{
    std::vector<int> sbox = read_json_sbox("variants/wide/aes.json");
    te.assign(4 * 256, 0);
    for (int x = 0; x < 256; x++) {
        uint8_t s = (uint8_t)sbox[x], s2 = xtime8(s), s3 = (uint8_t)(s2 ^ s);
        uint32_t t0 = ((uint32_t)s2 << 24) | ((uint32_t)s << 16) | ((uint32_t)s << 8) | s3;
        te[0 * 256 + x] = t0;
        te[1 * 256 + x] = rotr32(t0, 8);
        te[2 * 256 + x] = rotr32(t0, 16);
        te[3 * 256 + x] = rotr32(t0, 24);
    }
}

static U128 encrypt_aes_host(U128 s, const std::vector<int> &sbox,
                             const std::vector<uint32_t> &te, const U128 *rk,
                             int rounds)
{
    for (int i = 0; i < 4; i++) s.w[i] ^= rk[0].w[i];
    for (int r = 1; r < rounds; r++) {
        U128 t;
        t.w[0] = te[0 * 256 + (s.w[0] >> 24)]
               ^ te[1 * 256 + ((s.w[1] >> 16) & 255)]
               ^ te[2 * 256 + ((s.w[2] >> 8) & 255)]
               ^ te[3 * 256 + (s.w[3] & 255)] ^ rk[r].w[0];
        t.w[1] = te[0 * 256 + (s.w[1] >> 24)]
               ^ te[1 * 256 + ((s.w[2] >> 16) & 255)]
               ^ te[2 * 256 + ((s.w[3] >> 8) & 255)]
               ^ te[3 * 256 + (s.w[0] & 255)] ^ rk[r].w[1];
        t.w[2] = te[0 * 256 + (s.w[2] >> 24)]
               ^ te[1 * 256 + ((s.w[3] >> 16) & 255)]
               ^ te[2 * 256 + ((s.w[0] >> 8) & 255)]
               ^ te[3 * 256 + (s.w[1] & 255)] ^ rk[r].w[2];
        t.w[3] = te[0 * 256 + (s.w[3] >> 24)]
               ^ te[1 * 256 + ((s.w[0] >> 16) & 255)]
               ^ te[2 * 256 + ((s.w[1] >> 8) & 255)]
               ^ te[3 * 256 + (s.w[2] & 255)] ^ rk[r].w[3];
        s = t;
    }
    U128 t;
    t.w[0] = ((uint32_t)sbox[s.w[0] >> 24] << 24)
           | ((uint32_t)sbox[(s.w[1] >> 16) & 255] << 16)
           | ((uint32_t)sbox[(s.w[2] >> 8) & 255] << 8)
           | (uint32_t)sbox[s.w[3] & 255];
    t.w[1] = ((uint32_t)sbox[s.w[1] >> 24] << 24)
           | ((uint32_t)sbox[(s.w[2] >> 16) & 255] << 16)
           | ((uint32_t)sbox[(s.w[3] >> 8) & 255] << 8)
           | (uint32_t)sbox[s.w[0] & 255];
    t.w[2] = ((uint32_t)sbox[s.w[2] >> 24] << 24)
           | ((uint32_t)sbox[(s.w[3] >> 16) & 255] << 16)
           | ((uint32_t)sbox[(s.w[0] >> 8) & 255] << 8)
           | (uint32_t)sbox[s.w[1] & 255];
    t.w[3] = ((uint32_t)sbox[s.w[3] >> 24] << 24)
           | ((uint32_t)sbox[(s.w[0] >> 16) & 255] << 16)
           | ((uint32_t)sbox[(s.w[1] >> 8) & 255] << 8)
           | (uint32_t)sbox[s.w[2] & 255];
    for (int i = 0; i < 4; i++) t.w[i] ^= rk[rounds].w[i];
    return t;
}

static void make_keys64(uint64_t *rk, int rounds)
{
    for (int r = 0; r <= rounds; r++) rk[r] = rng_next();
}

static void make_keys128(U128 *rk, int rounds)
{
    for (int r = 0; r <= rounds; r++)
        for (int i = 0; i < 4; i++) rk[r].w[i] = (uint32_t)rng_next();
}

__device__ __forceinline__ uint32_t rotl32_dev(uint32_t x, int n)
{
    n &= 31;
    return n ? ((x << n) | (x >> (32 - n))) : x;
}

__device__ __forceinline__ uint16_t rotl16_dev(uint16_t x, int n)
{
    n &= 15;
    return n ? (uint16_t)((x << n) | (x >> (16 - n))) : x;
}

__device__ __forceinline__ uint64_t sbox64_dev(uint64_t s, int bits)
{
    uint64_t out = 0;
    if (bits == 4) {
        #pragma unroll
        for (int i = 0; i < 16; i++) out |= (uint64_t)c_sbox[(s >> (4 * i)) & 15] << (4 * i);
    } else {
        #pragma unroll
        for (int i = 0; i < 8; i++) out |= (uint64_t)c_sbox[(s >> (8 * i)) & 255] << (8 * i);
    }
    return out;
}

__device__ __forceinline__ uint64_t lin64_dev(uint64_t s, int lin, int c0, int c1, int c2)
{
    if (lin == LIN64_PRESENT_PBOX) {
        uint64_t out = 0;
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            int dst = (i == 63) ? 63 : (16 * i) % 63;
            out |= ((s >> i) & 1ULL) << dst;
        }
        return out;
    }
    if (lin == LIN64_CIPHERD_TRANSPOSE) {
        uint64_t out = 0;
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            int dst = i / 8 + 8 * (i % 8);
            out |= ((s >> i) & 1ULL) << dst;
        }
        return out;
    }
    uint16_t w0 = (uint16_t)s, w1 = (uint16_t)(s >> 16);
    uint16_t w2 = (uint16_t)(s >> 32), w3 = (uint16_t)(s >> 48);
    uint16_t o0 = w0 ^ rotl16_dev(w1, c0) ^ rotl16_dev(w2, c1) ^ rotl16_dev(w3, c2);
    uint16_t o1 = w1 ^ rotl16_dev(w2, c0) ^ rotl16_dev(w3, c1) ^ rotl16_dev(o0, c2);
    uint16_t o2 = w2 ^ rotl16_dev(w3, c0) ^ rotl16_dev(o0, c1) ^ rotl16_dev(o1, c2);
    uint16_t o3 = w3 ^ rotl16_dev(o0, c0) ^ rotl16_dev(o1, c1) ^ rotl16_dev(o2, c2);
    return (uint64_t)o0 | ((uint64_t)o1 << 16) | ((uint64_t)o2 << 32) | ((uint64_t)o3 << 48);
}

__device__ __forceinline__ uint64_t round64_table(const uint64_t *tab, uint64_t s, int bits)
{
    uint64_t t = 0;
    if (bits == 4) {
        #pragma unroll
        for (int b = 0; b < 16; b++)
            t ^= tab[b * 16 + ((s >> (4 * b)) & 15)];
    } else {
        #pragma unroll
        for (int b = 0; b < 8; b++)
            t ^= tab[b * 256 + ((s >> (8 * b)) & 255)];
    }
    return t;
}

__global__ void enc64_direct_kernel(uint64_t *out, const uint64_t *in, size_t n,
                                    int rounds, int bits, int lin, int c0, int c1, int c2)
{
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    uint64_t s = in[i];
    for (int r = 0; r < rounds; r++) {
        s ^= c_rk64[r];
        s = sbox64_dev(s, bits);
        s = lin64_dev(s, lin, c0, c1, c2);
    }
    out[i] = s ^ c_rk64[rounds];
}

__global__ void enc64_table_kernel(uint64_t *out, const uint64_t *in, const uint64_t *tab,
                                   size_t n, int rounds, int bits)
{
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    uint64_t s = in[i];
    for (int r = 0; r < rounds; r++) {
        s ^= c_rk64[r];
        s = round64_table(tab, s, bits);
    }
    out[i] = s ^ c_rk64[rounds];
}

__global__ void enc64_table_ilp4_kernel(uint64_t *out, const uint64_t *in, const uint64_t *tab,
                                        size_t n, int rounds, int bits)
{
    size_t base = ((size_t)blockIdx.x * blockDim.x + threadIdx.x) * 4;
    if (base >= n) return;
    uint64_t s0 = in[base + 0];
    uint64_t s1 = (base + 1 < n) ? in[base + 1] : 0;
    uint64_t s2 = (base + 2 < n) ? in[base + 2] : 0;
    uint64_t s3 = (base + 3 < n) ? in[base + 3] : 0;
    for (int r = 0; r < rounds; r++) {
        uint64_t k = c_rk64[r];
        s0 = round64_table(tab, s0 ^ k, bits);
        s1 = round64_table(tab, s1 ^ k, bits);
        s2 = round64_table(tab, s2 ^ k, bits);
        s3 = round64_table(tab, s3 ^ k, bits);
    }
    uint64_t k = c_rk64[rounds];
    out[base + 0] = s0 ^ k;
    if (base + 1 < n) out[base + 1] = s1 ^ k;
    if (base + 2 < n) out[base + 2] = s2 ^ k;
    if (base + 3 < n) out[base + 3] = s3 ^ k;
}

template<int ROUNDS, int BITS, int LIN, int C0, int C1, int C2>
__global__ __launch_bounds__(THREADS)
void enc64_direct_ct_kernel(uint64_t *__restrict__ out,
                            const uint64_t *__restrict__ in, size_t n)
{
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    uint64_t s = in[i];
    #pragma unroll
    for (int r = 0; r < ROUNDS; r++) {
        s = sbox64_dev(s ^ c_rk64[r], BITS);
        s = lin64_dev(s, LIN, C0, C1, C2);
    }
    out[i] = s ^ c_rk64[ROUNDS];
}

__device__ __forceinline__ uint64_t round64_byte_table(const uint64_t *tab, uint64_t s)
{
    uint64_t t = 0;
    #pragma unroll
    for (int b = 0; b < 8; b++)
        t ^= tab[b * 256 + ((s >> (8 * b)) & 255)];
    return t;
}

__device__ __forceinline__ uint64_t sbox64_shared(uint64_t s, const uint8_t *sbox,
                                                  int bits)
{
    uint64_t out = 0;
    if (bits == 4) {
        #pragma unroll
        for (int i = 0; i < 16; i++)
            out |= (uint64_t)sbox[(s >> (4 * i)) & 15] << (4 * i);
    } else {
        #pragma unroll
        for (int i = 0; i < 8; i++)
            out |= (uint64_t)sbox[(s >> (8 * i)) & 255] << (8 * i);
    }
    return out;
}

template<int ROUNDS, int BITS, int LIN, int C0, int C1, int C2, int ILP>
__global__ __launch_bounds__(THREADS)
void enc64_shared_sbox_kernel(uint64_t *__restrict__ out,
                              const uint64_t *__restrict__ in,
                              const uint8_t *__restrict__ global_sbox, size_t n)
{
    __shared__ uint8_t sbox[256];
    for (int i = threadIdx.x; i < 256; i += blockDim.x) sbox[i] = global_sbox[i];
    __syncthreads();

    /* Interleave by blockDim, not by ILP: consecutive lanes must touch consecutive
     * blocks or each of the ILP loads is a strided gather. */
    size_t base = (size_t)blockIdx.x * blockDim.x * ILP + threadIdx.x;
    uint64_t s[ILP];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        size_t idx = base + (size_t)j * blockDim.x;
        s[j] = (idx < n) ? in[idx] : 0;
    }
    #pragma unroll
    for (int r = 0; r < ROUNDS; r++) {
        uint64_t k = c_rk64[r];
        #pragma unroll
        for (int j = 0; j < ILP; j++) {
            s[j] = sbox64_shared(s[j] ^ k, sbox, BITS);
            s[j] = lin64_dev(s[j], LIN, C0, C1, C2);
        }
    }
    uint64_t k = c_rk64[ROUNDS];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        size_t idx = base + (size_t)j * blockDim.x;
        if (idx < n) out[idx] = s[j] ^ k;
    }
}

template<int ROUNDS, int ILP, bool USE_SHARED>
__global__ __launch_bounds__(THREADS)
void enc64_byte_table_ct_kernel(uint64_t *__restrict__ out,
                                const uint64_t *__restrict__ in,
                                const uint64_t *__restrict__ global_tab, size_t n)
{
    __shared__ uint64_t shared_tab[8 * 256];
    const uint64_t *tab = global_tab;
    if (USE_SHARED) {
        for (int i = threadIdx.x; i < 8 * 256; i += blockDim.x)
            shared_tab[i] = global_tab[i];
        __syncthreads();
        tab = shared_tab;
    }

    size_t base = (size_t)blockIdx.x * blockDim.x * ILP + threadIdx.x;
    uint64_t s[ILP];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        size_t idx = base + (size_t)j * blockDim.x;
        s[j] = (idx < n) ? in[idx] : 0;
    }

    #pragma unroll
    for (int r = 0; r < ROUNDS; r++) {
        uint64_t k = c_rk64[r];
        #pragma unroll
        for (int j = 0; j < ILP; j++)
            s[j] = round64_byte_table(tab, s[j] ^ k);
    }

    uint64_t k = c_rk64[ROUNDS];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        size_t idx = base + (size_t)j * blockDim.x;
        if (idx < n) out[idx] = s[j] ^ k;
    }
}

template<int ROUNDS, int BITS, bool USE_SHARED>
__global__ __launch_bounds__(THREADS)
void enc64_native_table_ct_kernel(uint64_t *__restrict__ out,
                                  const uint64_t *__restrict__ in,
                                  const uint64_t *__restrict__ global_tab, size_t n)
{
    constexpr int TABLE_ENTRIES = (BITS == 4) ? 16 * 16 : 8 * 256;
    __shared__ uint64_t shared_tab[TABLE_ENTRIES];
    const uint64_t *tab = global_tab;
    if (USE_SHARED) {
        for (int i = threadIdx.x; i < TABLE_ENTRIES; i += blockDim.x)
            shared_tab[i] = global_tab[i];
        __syncthreads();
        tab = shared_tab;
    }

    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    uint64_t s = in[i];
    #pragma unroll
    for (int r = 0; r < ROUNDS; r++)
        s = round64_table(tab, s ^ c_rk64[r], BITS);
    out[i] = s ^ c_rk64[ROUNDS];
}

/* ---- bitsliced PRESENT ---------------------------------------------------
 *
 * The table kernels above spend a dependent shared-memory load per S-box: 256 of
 * them for PRESENT-r16, which is why the baseline sat at 40 GB/s while every
 * modified cipher got a specialised win. Bitslicing removes the lookups entirely.
 * PRESENT's S-box is 15 gates (src/gen/sbox_circuits.h, circuit c4) and its bit
 * permutation is a renaming of the bit-planes, so it costs nothing at all.
 *
 * Each thread holds 32 blocks as 64 bit-planes of 32 bits. Loads and stores stay
 * coalesced because lane l of a warp takes block base + l + 32k. The transpose in
 * and out is the price; at 16 rounds it is well under the lookups it replaces.
 */

/* Circuit c4 of src/gen/sbox_circuits.h, x0/o0 the nibble LSB. It computes
 * S(x) ^ 0xC (present_circuit_outcomp[4]); the complement is cancelled in the
 * round keys, exactly as src/present_core.c does on the CPU side. Both facts are
 * checked against the S-box read from JSON before any kernel runs. */
#define PRESENT_BS_OUTCOMP 0xC

__device__ __host__ __forceinline__
void present_sbox_bitslice(uint32_t &o0, uint32_t &o1, uint32_t &o2, uint32_t &o3,
                           uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3)
{
    uint32_t t0 = ~x1 & x2;
    uint32_t t1 = x3 ^ t0;
    uint32_t t2 = x0 ^ t1;
    uint32_t t3 = ~x1 & t1;
    uint32_t t4 = x0 | x2;
    uint32_t t5 = ~t2 & t4;
    uint32_t t6 = t3 | t5;
    uint32_t t7 = x2 ^ t6;
    uint32_t t8 = x1 ^ t7;
    uint32_t t9 = x2 | x3;
    uint32_t t10 = t8 ^ t9;
    uint32_t t11 = t3 ^ t10;
    uint32_t t12 = x0 ^ t11;
    uint32_t t13 = ~t12 & t8;
    uint32_t t14 = t1 ^ t13;
    o0 = t2; o1 = t8; o2 = t14; o3 = t12;
}

/* In-place 32x32 bit transpose by recursive block swap: afterwards a[i] bit j is
 * the original a[j] bit i. Verified at startup on random input. */
__device__ __host__ __forceinline__ void transpose32(uint32_t *a)
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

/* Circuit c2 of src/gen/sbox_circuits.h: Boyar and Peralta's AES S-box, 132 gates
 * against the 1107 a BDD synthesiser lands on for cipher-D's unstructured table.
 * That gap is why this kernel exists for the AES-S-box variants and not for
 * cipher-D itself. present_circuit_outcomp[2] is 0, so there is nothing to cancel.
 * Lifted verbatim from the generated header, uint64_t narrowed to uint32_t, and
 * checked against all 256 table entries before any kernel runs. */
__device__ __host__ __forceinline__
void aes_sbox_bitslice(uint32_t &o0, uint32_t &o1, uint32_t &o2, uint32_t &o3,
                       uint32_t &o4, uint32_t &o5, uint32_t &o6, uint32_t &o7,
                       uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
                       uint32_t x4, uint32_t x5, uint32_t x6, uint32_t x7)
{
    uint32_t t[132];
    t[0] = x7 ^ x4;
    t[1] = x7 ^ x2;
    t[2] = x7 ^ x1;
    t[3] = x4 ^ x2;
    t[4] = x3 ^ x1;
    t[5] = t[0] ^ t[4];
    t[6] = x6 ^ x5;
    t[7] = x0 ^ t[5];
    t[8] = x0 ^ t[6];
    t[9] = t[5] ^ t[6];
    t[10] = x6 ^ x2;
    t[11] = x5 ^ x2;
    t[12] = t[2] ^ t[3];
    t[13] = t[5] ^ t[10];
    t[14] = t[4] ^ t[10];
    t[15] = t[4] ^ t[11];
    t[16] = t[8] ^ t[15];
    t[17] = x4 ^ x0;
    t[18] = t[6] ^ t[17];
    t[19] = t[0] ^ t[18];
    t[20] = x1 ^ x0;
    t[21] = t[6] ^ t[20];
    t[22] = t[1] ^ t[21];
    t[23] = t[1] ^ t[9];
    t[24] = t[19] ^ t[16];
    t[25] = t[2] ^ t[15];
    t[26] = t[0] ^ t[11];
    t[27] = t[12] & t[5];
    t[28] = t[22] & t[7];
    t[29] = t[13] ^ t[27];
    t[30] = t[18] & x0;
    t[31] = t[30] ^ t[27];
    t[32] = t[2] & t[15];
    t[33] = t[21] & t[8];
    t[34] = t[25] ^ t[32];
    t[35] = t[19] & t[16];
    t[36] = t[35] ^ t[32];
    t[37] = t[0] & t[14];
    t[38] = t[3] & t[26];
    t[39] = t[38] ^ t[37];
    t[40] = t[1] & t[9];
    t[41] = t[40] ^ t[37];
    t[42] = t[29] ^ t[28];
    t[43] = t[31] ^ t[23];
    t[44] = t[34] ^ t[33];
    t[45] = t[36] ^ t[41];
    t[46] = t[42] ^ t[39];
    t[47] = t[43] ^ t[41];
    t[48] = t[44] ^ t[39];
    t[49] = t[45] ^ t[24];
    t[50] = t[48] ^ t[49];
    t[51] = t[48] & t[46];
    t[52] = t[47] ^ t[51];
    t[53] = t[46] ^ t[47];
    t[54] = t[49] ^ t[51];
    t[55] = t[54] & t[53];
    t[56] = t[52] & t[50];
    t[57] = t[46] & t[49];
    t[58] = t[53] & t[57];
    t[59] = t[53] ^ t[51];
    t[60] = t[47] & t[48];
    t[61] = t[50] & t[60];
    t[62] = t[50] ^ t[51];
    t[63] = t[47] ^ t[55];
    t[64] = t[58] ^ t[59];
    t[65] = t[49] ^ t[56];
    t[66] = t[61] ^ t[62];
    t[67] = t[64] ^ t[66];
    t[68] = t[63] ^ t[65];
    t[69] = t[63] ^ t[64];
    t[70] = t[65] ^ t[66];
    t[71] = t[68] ^ t[67];
    t[72] = t[70] & t[5];
    t[73] = t[66] & t[7];
    t[74] = t[65] & x0;
    t[75] = t[69] & t[15];
    t[76] = t[64] & t[8];
    t[77] = t[63] & t[16];
    t[78] = t[68] & t[14];
    t[79] = t[71] & t[26];
    t[80] = t[67] & t[9];
    t[81] = t[70] & t[12];
    t[82] = t[66] & t[22];
    t[83] = t[65] & t[18];
    t[84] = t[69] & t[2];
    t[85] = t[64] & t[21];
    t[86] = t[63] & t[19];
    t[87] = t[68] & t[0];
    t[88] = t[71] & t[3];
    t[89] = t[67] & t[1];
    t[90] = t[87] ^ t[88];
    t[91] = t[76] ^ t[82];
    t[92] = t[72] ^ t[74];
    t[93] = t[73] ^ t[81];
    t[94] = t[80] ^ t[84];
    t[95] = t[75] ^ t[87];
    t[96] = t[88] ^ t[95];
    t[97] = t[72] ^ t[93];
    t[98] = t[77] ^ t[85];
    t[99] = t[78] ^ t[79];
    t[100] = t[79] ^ t[94];
    t[101] = t[86] ^ t[92];
    t[102] = t[74] ^ t[77];
    t[103] = t[76] ^ t[90];
    t[104] = t[78] ^ t[87];
    t[105] = t[81] ^ t[91];
    t[106] = t[82] ^ t[90];
    t[107] = t[83] ^ t[91];
    t[108] = t[84] ^ t[98];
    t[109] = t[89] ^ t[94];
    t[110] = t[90] ^ t[91];
    t[111] = t[91] ^ t[97];
    t[112] = t[93] ^ t[102];
    t[113] = t[108] ^ t[92];
    t[114] = t[105] ^ t[99];
    t[115] = t[96] ^ t[100];
    t[116] = t[97] ^ t[99];
    t[117] = t[98] ^ t[100];
    t[118] = t[101] ^ t[104];
    t[119] = t[101] ^ t[107];
    t[120] = t[96] ^ t[114];
    t[121] = t[106] ^ t[116];
    t[122] = t[109] ^ t[118];
    t[123] = t[96] ^ t[111];
    t[124] = t[110] ^ t[112];
    t[125] = t[115] ^ t[119];
    t[126] = t[103] ^ t[117];
    t[127] = t[96] ^ t[113];
    t[128] = ~t[121];
    t[129] = ~t[122];
    t[130] = ~t[126];
    t[131] = ~t[127];
    o0 = t[131];
    o1 = t[130];
    o2 = t[125];
    o3 = t[124];
    o4 = t[123];
    o5 = t[129];
    o6 = t[128];
    o7 = t[120];
}

/* Which gate circuit a variant's S-box is served by. Anything else keeps the table
 * kernels: a BDD-synthesised 8-bit circuit is 1107 gates and loses to a lookup. */
enum BsSboxKind { BS_SBOX_PRESENT = 0, BS_SBOX_AES = 1 };

template<int SBOX, int LIN, int C0, int C1, int C2>
__device__ __forceinline__ void present_bs_round(uint32_t *p, const uint32_t *km)
{
    #pragma unroll
    for (int b = 0; b < 64; b++) p[b] ^= km[b];

    uint32_t q[64];
    if (SBOX == BS_SBOX_PRESENT) {
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            uint32_t y0, y1, y2, y3;
            present_sbox_bitslice(y0, y1, y2, y3, p[4 * i + 0], p[4 * i + 1],
                                  p[4 * i + 2], p[4 * i + 3]);
            if (LIN == LIN64_PRESENT_PBOX) {
                /* the permutation is the store */
                #define PBOX_DST(SRC) (((SRC) == 63) ? 63 : (16 * (SRC)) % 63)
                q[PBOX_DST(4 * i + 0)] = y0; q[PBOX_DST(4 * i + 1)] = y1;
                q[PBOX_DST(4 * i + 2)] = y2; q[PBOX_DST(4 * i + 3)] = y3;
                #undef PBOX_DST
            } else {
                q[4 * i + 0] = y0; q[4 * i + 1] = y1;
                q[4 * i + 2] = y2; q[4 * i + 3] = y3;
            }
        }
    } else {
        /* The AES-S-box variants here are all lin444, so no permutation to fold. */
        #pragma unroll
        for (int i = 0; i < 8; i++)
            aes_sbox_bitslice(q[8 * i + 0], q[8 * i + 1], q[8 * i + 2], q[8 * i + 3],
                              q[8 * i + 4], q[8 * i + 5], q[8 * i + 6], q[8 * i + 7],
                              p[8 * i + 0], p[8 * i + 1], p[8 * i + 2], p[8 * i + 3],
                              p[8 * i + 4], p[8 * i + 5], p[8 * i + 6], p[8 * i + 7]);
    }

    if (LIN == LIN64_PRESENT_PBOX) {
        #pragma unroll
        for (int b = 0; b < 64; b++) p[b] = q[b];
    } else {
        /* lin444 on four 16-bit words; every rotation is plane-index arithmetic */
        #define BSW(J, K) q[16 * (J) + ((K) & 15)]
        #pragma unroll
        for (int k = 0; k < 16; k++)
            p[k] = BSW(0, k) ^ BSW(1, k - C0) ^ BSW(2, k - C1) ^ BSW(3, k - C2);
        #pragma unroll
        for (int k = 0; k < 16; k++)
            p[16 + k] = BSW(1, k) ^ BSW(2, k - C0) ^ BSW(3, k - C1) ^ p[(k - C2) & 15];
        #pragma unroll
        for (int k = 0; k < 16; k++)
            p[32 + k] = BSW(2, k) ^ BSW(3, k - C0) ^ p[(k - C1) & 15]
                      ^ p[16 + ((k - C2) & 15)];
        #pragma unroll
        for (int k = 0; k < 16; k++)
            p[48 + k] = BSW(3, k) ^ p[(k - C0) & 15] ^ p[16 + ((k - C1) & 15)]
                      ^ p[32 + ((k - C2) & 15)];
        #undef BSW
    }
}

/* 64 planes plus temporaries is around 190 registers, so the occupancy ceiling is
 * about 340 threads per SM whatever the block size. Small blocks pack that budget
 * better; 512 spills. */
#define BITSLICE_THREADS 128

template<int ROUNDS, int SBOX, int LIN, int C0, int C1, int C2>
__global__ __launch_bounds__(BITSLICE_THREADS)
void enc64_bitslice_kernel(uint64_t *__restrict__ out, const uint64_t *__restrict__ in,
                           size_t n)
{
    size_t base = (size_t)blockIdx.x * blockDim.x * 32 + threadIdx.x;
    uint32_t lo[32], hi[32];
    #pragma unroll
    for (int k = 0; k < 32; k++) {
        size_t idx = base + (size_t)k * blockDim.x;
        uint64_t v = (idx < n) ? in[idx] : 0;
        lo[k] = (uint32_t)v;
        hi[k] = (uint32_t)(v >> 32);
    }
    transpose32(lo);
    transpose32(hi);

    uint32_t p[64];
    #pragma unroll
    for (int b = 0; b < 32; b++) { p[b] = lo[b]; p[32 + b] = hi[b]; }

    #pragma unroll
    for (int r = 0; r < ROUNDS; r++)
        present_bs_round<SBOX, LIN, C0, C1, C2>(p, &c_rkmask64[64 * r]);
    #pragma unroll
    for (int b = 0; b < 64; b++) p[b] ^= c_rkmask64[64 * ROUNDS + b];

    #pragma unroll
    for (int b = 0; b < 32; b++) { lo[b] = p[b]; hi[b] = p[32 + b]; }
    transpose32(lo);
    transpose32(hi);
    #pragma unroll
    for (int k = 0; k < 32; k++) {
        size_t idx = base + (size_t)k * blockDim.x;
        if (idx < n) out[idx] = (uint64_t)lo[k] | ((uint64_t)hi[k] << 32);
    }
}

/* Only two S-boxes here have a gate circuit worth using. Anything else -- notably
 * cipher-D's own table, which a BDD synthesiser turns into 1107 gates -- returns
 * -1 and keeps the table kernels. */
static int bitslice_sbox_kind(const std::vector<int> &sbox)
{
    static const int present[16] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                                    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};
    if (sbox.size() == 16) {
        for (int i = 0; i < 16; i++)
            if (sbox[i] != present[i]) return -1;
        return BS_SBOX_PRESENT;
    }
    if (sbox.size() == 256) {
        /* AES S-box: inversion in GF(2^8) then the 0x1F/0x63 affine map. Derived
         * rather than tabulated so this cannot drift from the JSON silently. */
        for (int v = 0; v < 256; v++) {
            int inv = 0;
            if (v != 0) {
                for (int c = 1; c < 256; c++) {
                    int a = v, b = c, prod = 0;
                    for (int k = 0; k < 8; k++) {
                        if (b & 1) prod ^= a;
                        b >>= 1;
                        a = (a << 1) ^ ((a & 0x80) ? 0x11B : 0);
                    }
                    if ((prod & 0xFF) == 1) { inv = c; break; }
                }
            }
            int y = inv;
            for (int k = 0; k < 4; k++) y ^= ((inv << (k + 1)) | (inv >> (7 - k))) & 0xFF;
            if ((y ^ 0x63) != sbox[v]) return -1;
        }
        return BS_SBOX_AES;
    }
    return -1;
}

/* Evaluate the gate circuit on splatted words and confirm it reproduces the table
 * the JSON actually defines, complement included. A transcription error cannot
 * reach a timed kernel. */
static void verify_bitslice_circuit(const std::vector<int> &sbox, int kind)
{
    if (kind == BS_SBOX_PRESENT) {
        for (int v = 0; v < 16; v++) {
            uint32_t o0, o1, o2, o3;
            present_sbox_bitslice(o0, o1, o2, o3,
                                  0u - (uint32_t)((v >> 0) & 1), 0u - (uint32_t)((v >> 1) & 1),
                                  0u - (uint32_t)((v >> 2) & 1), 0u - (uint32_t)((v >> 3) & 1));
            int got = (int)((o0 & 1) | ((o1 & 1) << 1) | ((o2 & 1) << 2) | ((o3 & 1) << 3));
            got ^= PRESENT_BS_OUTCOMP;
            if (got != sbox[v]) {
                std::fprintf(stderr,
                             "bitslice S-box circuit disagrees with the table at %d: %x vs %x\n",
                             v, got, sbox[v]);
                std::exit(1);
            }
        }
        return;
    }
    for (int v = 0; v < 256; v++) {
        uint32_t o[8], x[8];
        for (int b = 0; b < 8; b++) x[b] = 0u - (uint32_t)((v >> b) & 1);
        aes_sbox_bitslice(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7],
                          x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]);
        int got = 0;
        for (int b = 0; b < 8; b++) got |= (int)(o[b] & 1) << b;
        if (got != sbox[v]) {
            std::fprintf(stderr,
                         "AES bitslice circuit disagrees with the table at %d: %02x vs %02x\n",
                         v, got, sbox[v]);
            std::exit(1);
        }
    }
}

static void verify_transpose32()
{
    uint32_t a[32], b[32];
    for (uint32_t &x : a) x = (uint32_t)rng_next();
    std::memcpy(b, a, sizeof(a));
    transpose32(b);
    for (int i = 0; i < 32; i++)
        for (int j = 0; j < 32; j++)
            if (((b[i] >> j) & 1) != ((a[j] >> i) & 1)) {
                std::fprintf(stderr, "transpose32 is wrong at %d,%d\n", i, j);
                std::exit(1);
            }
}

/* PRESENT's circuit emits S(x) ^ splat(0xC) (the AES one has no complement). The
 * layer is GF(2)-linear, so that constant passes straight through it and is
 * cancelled in the next round's key -- the trick src/present_core.c uses. */
static void build_rkmask64(std::vector<uint32_t> &km, const uint64_t *rk, int rounds,
                           Lin64Kind lin, const int c0[3], int kind)
{
    uint64_t splat = 0;
    if (kind == BS_SBOX_PRESENT)
        for (int i = 0; i < 16; i++) splat |= (uint64_t)PRESENT_BS_OUTCOMP << (4 * i);
    const uint64_t corr = lin64_host(splat, lin, c0);
    km.assign((MAX_ROUNDS + 1) * 64, 0);
    for (int r = 0; r <= rounds; r++) {
        const uint64_t k = rk[r] ^ (r ? corr : 0);
        for (int b = 0; b < 64; b++) km[64 * r + b] = ((k >> b) & 1) ? 0xffffffffu : 0u;
    }
}

__device__ __forceinline__ U128 u128_xor(U128 a, U128 b)
{
    U128 r;
    r.w[0] = a.w[0] ^ b.w[0]; r.w[1] = a.w[1] ^ b.w[1];
    r.w[2] = a.w[2] ^ b.w[2]; r.w[3] = a.w[3] ^ b.w[3];
    return r;
}

__device__ __forceinline__ void lin444_128_dev(U128 &s, int c0, int c1, int c2)
{
    uint32_t o0 = s.w[0] ^ rotl32_dev(s.w[1], c0) ^ rotl32_dev(s.w[2], c1)
                ^ rotl32_dev(s.w[3], c2);
    uint32_t o1 = s.w[1] ^ rotl32_dev(s.w[2], c0) ^ rotl32_dev(s.w[3], c1)
                ^ rotl32_dev(o0, c2);
    uint32_t o2 = s.w[2] ^ rotl32_dev(s.w[3], c0) ^ rotl32_dev(o0, c1)
                ^ rotl32_dev(o1, c2);
    uint32_t o3 = s.w[3] ^ rotl32_dev(o0, c0) ^ rotl32_dev(o1, c1)
                ^ rotl32_dev(o2, c2);
    s.w[0] = o0; s.w[1] = o1; s.w[2] = o2; s.w[3] = o3;
}

__device__ __forceinline__ U128 lin128_round_table(const U128 *tab, U128 s)
{
    U128 t = {{0, 0, 0, 0}};
    #pragma unroll
    for (int byte = 0; byte < 16; byte++) {
        U128 v = tab[byte * 256 + ((s.w[byte / 4] >> (8 * (byte % 4))) & 255)];
        t.w[0] ^= v.w[0]; t.w[1] ^= v.w[1]; t.w[2] ^= v.w[2]; t.w[3] ^= v.w[3];
    }
    return t;
}

__device__ __forceinline__ void subbytes128_dev(U128 &s)
{
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        uint32_t v = 0;
        #pragma unroll
        for (int b = 0; b < 4; b++)
            v |= (uint32_t)c_sbox[(s.w[i] >> (8 * b)) & 255] << (8 * b);
        s.w[i] = v;
    }
}

__global__ void lin128_direct_kernel(U128 *out, const U128 *in, size_t n,
                                     int rounds, int c0, int c1, int c2)
{
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    U128 s = in[i];
    for (int r = 0; r < rounds; r++) {
        s = u128_xor(s, c_rk128[r]);
        subbytes128_dev(s);
        lin444_128_dev(s, c0, c1, c2);
    }
    out[i] = u128_xor(s, c_rk128[rounds]);
}

__global__ void lin128_table_kernel(U128 *out, const U128 *in, const U128 *tab,
                                    size_t n, int rounds)
{
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    U128 s = in[i];
    for (int r = 0; r < rounds; r++) {
        s = u128_xor(s, c_rk128[r]);
        s = lin128_round_table(tab, s);
    }
    out[i] = u128_xor(s, c_rk128[rounds]);
}

__global__ void lin128_table_ilp4_kernel(U128 *out, const U128 *in, const U128 *tab,
                                         size_t n, int rounds)
{
    size_t base = ((size_t)blockIdx.x * blockDim.x + threadIdx.x) * 4;
    if (base >= n) return;
    U128 s[4];
    #pragma unroll
    for (int j = 0; j < 4; j++) {
        s[j].w[0] = 0; s[j].w[1] = 0; s[j].w[2] = 0; s[j].w[3] = 0;
        if (base + j < n) s[j] = in[base + j];
    }
    for (int r = 0; r < rounds; r++) {
        U128 k = c_rk128[r];
        #pragma unroll
        for (int j = 0; j < 4; j++) s[j] = lin128_round_table(tab, u128_xor(s[j], k));
    }
    U128 k = c_rk128[rounds];
    #pragma unroll
    for (int j = 0; j < 4; j++)
        if (base + j < n) out[base + j] = u128_xor(s[j], k);
}

__device__ __forceinline__ uint32_t aes_round_word(const uint32_t *te, uint32_t s0,
                                                   uint32_t s1, uint32_t s2, uint32_t s3,
                                                   int which)
{
    if (which == 0)
        return te[0 * 256 + (s0 >> 24)]
             ^ te[1 * 256 + ((s1 >> 16) & 255)]
             ^ te[2 * 256 + ((s2 >> 8) & 255)]
             ^ te[3 * 256 + (s3 & 255)];
    if (which == 1)
        return te[0 * 256 + (s1 >> 24)]
             ^ te[1 * 256 + ((s2 >> 16) & 255)]
             ^ te[2 * 256 + ((s3 >> 8) & 255)]
             ^ te[3 * 256 + (s0 & 255)];
    if (which == 2)
        return te[0 * 256 + (s2 >> 24)]
             ^ te[1 * 256 + ((s3 >> 16) & 255)]
             ^ te[2 * 256 + ((s0 >> 8) & 255)]
             ^ te[3 * 256 + (s1 & 255)];
    return te[0 * 256 + (s3 >> 24)]
         ^ te[1 * 256 + ((s0 >> 16) & 255)]
         ^ te[2 * 256 + ((s1 >> 8) & 255)]
         ^ te[3 * 256 + (s2 & 255)];
}

__device__ __forceinline__ U128 aes_encrypt_dev(U128 s, int rounds)
{
    s = u128_xor(s, c_rk128[0]);
    for (int r = 1; r < rounds; r++) {
        U128 t;
        t.w[0] = aes_round_word(&c_aes_te[0][0], s.w[0], s.w[1], s.w[2], s.w[3], 0) ^ c_rk128[r].w[0];
        t.w[1] = aes_round_word(&c_aes_te[0][0], s.w[0], s.w[1], s.w[2], s.w[3], 1) ^ c_rk128[r].w[1];
        t.w[2] = aes_round_word(&c_aes_te[0][0], s.w[0], s.w[1], s.w[2], s.w[3], 2) ^ c_rk128[r].w[2];
        t.w[3] = aes_round_word(&c_aes_te[0][0], s.w[0], s.w[1], s.w[2], s.w[3], 3) ^ c_rk128[r].w[3];
        s = t;
    }
    U128 t;
    t.w[0] = ((uint32_t)c_sbox[s.w[0] >> 24] << 24)
           | ((uint32_t)c_sbox[(s.w[1] >> 16) & 255] << 16)
           | ((uint32_t)c_sbox[(s.w[2] >> 8) & 255] << 8)
           | c_sbox[s.w[3] & 255];
    t.w[1] = ((uint32_t)c_sbox[s.w[1] >> 24] << 24)
           | ((uint32_t)c_sbox[(s.w[2] >> 16) & 255] << 16)
           | ((uint32_t)c_sbox[(s.w[3] >> 8) & 255] << 8)
           | c_sbox[s.w[0] & 255];
    t.w[2] = ((uint32_t)c_sbox[s.w[2] >> 24] << 24)
           | ((uint32_t)c_sbox[(s.w[3] >> 16) & 255] << 16)
           | ((uint32_t)c_sbox[(s.w[0] >> 8) & 255] << 8)
           | c_sbox[s.w[1] & 255];
    t.w[3] = ((uint32_t)c_sbox[s.w[3] >> 24] << 24)
           | ((uint32_t)c_sbox[(s.w[0] >> 16) & 255] << 16)
           | ((uint32_t)c_sbox[(s.w[1] >> 8) & 255] << 8)
           | c_sbox[s.w[2] & 255];
    return u128_xor(t, c_rk128[rounds]);
}

__global__ void aes_table_kernel(U128 *out, const U128 *in, size_t n, int rounds)
{
    size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) out[i] = aes_encrypt_dev(in[i], rounds);
}

__global__ void aes_table_ilp4_kernel(U128 *out, const U128 *in, size_t n, int rounds)
{
    size_t base = ((size_t)blockIdx.x * blockDim.x + threadIdx.x) * 4;
    if (base >= n) return;
    #pragma unroll
    for (int j = 0; j < 4; j++)
        if (base + j < n) out[base + j] = aes_encrypt_dev(in[base + j], rounds);
}

template<int C0, int C1, int C2>
__device__ __forceinline__ void lin444_128_ct(U128 &s)
{
    uint32_t o0 = s.w[0] ^ rotl32_dev(s.w[1], C0) ^ rotl32_dev(s.w[2], C1)
                ^ rotl32_dev(s.w[3], C2);
    uint32_t o1 = s.w[1] ^ rotl32_dev(s.w[2], C0) ^ rotl32_dev(s.w[3], C1)
                ^ rotl32_dev(o0, C2);
    uint32_t o2 = s.w[2] ^ rotl32_dev(s.w[3], C0) ^ rotl32_dev(o0, C1)
                ^ rotl32_dev(o1, C2);
    uint32_t o3 = s.w[3] ^ rotl32_dev(o0, C0) ^ rotl32_dev(o1, C1)
                ^ rotl32_dev(o2, C2);
    s.w[0] = o0; s.w[1] = o1; s.w[2] = o2; s.w[3] = o3;
}

__device__ __forceinline__ void subbytes128_shared(U128 &s, const uint8_t *sbox)
{
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        uint32_t x = s.w[i];
        s.w[i] = (uint32_t)sbox[x & 255]
               | ((uint32_t)sbox[(x >> 8) & 255] << 8)
               | ((uint32_t)sbox[(x >> 16) & 255] << 16)
               | ((uint32_t)sbox[x >> 24] << 24);
    }
}

template<int ROUNDS, int ILP, int C0, int C1, int C2>
__global__ __launch_bounds__(THREADS)
void lin128_shared_sbox_kernel(U128 *__restrict__ out, const U128 *__restrict__ in,
                               const uint8_t *__restrict__ global_sbox, size_t n)
{
    __shared__ uint8_t sbox[256];
    for (int i = threadIdx.x; i < 256; i += blockDim.x) sbox[i] = global_sbox[i];
    __syncthreads();

    size_t base = (size_t)blockIdx.x * blockDim.x * ILP + threadIdx.x;
    U128 s[ILP];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        s[j].w[0] = s[j].w[1] = s[j].w[2] = s[j].w[3] = 0;
        size_t idx = base + (size_t)j * blockDim.x;
        if (idx < n) s[j] = in[idx];
    }

    #pragma unroll
    for (int r = 0; r < ROUNDS; r++) {
        U128 k = c_rk128[r];
        #pragma unroll
        for (int j = 0; j < ILP; j++) {
            s[j] = u128_xor(s[j], k);
            subbytes128_shared(s[j], sbox);
            lin444_128_ct<C0, C1, C2>(s[j]);
        }
    }

    U128 k = c_rk128[ROUNDS];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        size_t idx = base + (size_t)j * blockDim.x;
        if (idx < n) out[idx] = u128_xor(s[j], k);
    }
}

template<int ROUNDS, int ILP, bool USE_SHARED>
__global__ __launch_bounds__(THREADS)
void lin128_table_ct_kernel(U128 *__restrict__ out, const U128 *__restrict__ in,
                            const U128 *__restrict__ global_tab, size_t n)
{
    extern __shared__ U128 shared_tab[];
    const U128 *tab = global_tab;
    if (USE_SHARED) {
        for (int i = threadIdx.x; i < 16 * 256; i += blockDim.x)
            shared_tab[i] = global_tab[i];
        __syncthreads();
        tab = shared_tab;
    }

    size_t base = (size_t)blockIdx.x * blockDim.x * ILP + threadIdx.x;
    U128 s[ILP];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        s[j].w[0] = s[j].w[1] = s[j].w[2] = s[j].w[3] = 0;
        size_t idx = base + (size_t)j * blockDim.x;
        if (idx < n) s[j] = in[idx];
    }
    #pragma unroll
    for (int r = 0; r < ROUNDS; r++) {
        U128 k = c_rk128[r];
        #pragma unroll
        for (int j = 0; j < ILP; j++)
            s[j] = lin128_round_table(tab, u128_xor(s[j], k));
    }
    U128 k = c_rk128[ROUNDS];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        size_t idx = base + (size_t)j * blockDim.x;
        if (idx < n) out[idx] = u128_xor(s[j], k);
    }
}

__device__ __forceinline__ uint32_t aes_round_word_table(const uint32_t *te,
                                                          uint32_t s0, uint32_t s1,
                                                          uint32_t s2, uint32_t s3,
                                                          int which)
{
    return aes_round_word(te, s0, s1, s2, s3, which);
}

template<int ROUNDS, int ILP>
__global__ __launch_bounds__(THREADS)
void aes_shared_table_kernel(U128 *__restrict__ out, const U128 *__restrict__ in,
                             const uint32_t *__restrict__ global_te,
                             const uint8_t *__restrict__ global_sbox, size_t n)
{
    __shared__ uint32_t te[4 * 256];
    __shared__ uint8_t sbox[256];
    for (int i = threadIdx.x; i < 4 * 256; i += blockDim.x) te[i] = global_te[i];
    for (int i = threadIdx.x; i < 256; i += blockDim.x) sbox[i] = global_sbox[i];
    __syncthreads();

    size_t base = (size_t)blockIdx.x * blockDim.x * ILP + threadIdx.x;
    U128 s[ILP];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        s[j].w[0] = s[j].w[1] = s[j].w[2] = s[j].w[3] = 0;
        size_t idx = base + (size_t)j * blockDim.x;
        if (idx < n) s[j] = u128_xor(in[idx], c_rk128[0]);
    }

    #pragma unroll
    for (int r = 1; r < ROUNDS; r++) {
        U128 k = c_rk128[r];
        #pragma unroll
        for (int j = 0; j < ILP; j++) {
            U128 t;
            t.w[0] = aes_round_word_table(te, s[j].w[0], s[j].w[1], s[j].w[2], s[j].w[3], 0) ^ k.w[0];
            t.w[1] = aes_round_word_table(te, s[j].w[0], s[j].w[1], s[j].w[2], s[j].w[3], 1) ^ k.w[1];
            t.w[2] = aes_round_word_table(te, s[j].w[0], s[j].w[1], s[j].w[2], s[j].w[3], 2) ^ k.w[2];
            t.w[3] = aes_round_word_table(te, s[j].w[0], s[j].w[1], s[j].w[2], s[j].w[3], 3) ^ k.w[3];
            s[j] = t;
        }
    }

    U128 k = c_rk128[ROUNDS];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        U128 t;
        t.w[0] = ((uint32_t)sbox[s[j].w[0] >> 24] << 24)
               | ((uint32_t)sbox[(s[j].w[1] >> 16) & 255] << 16)
               | ((uint32_t)sbox[(s[j].w[2] >> 8) & 255] << 8)
               | sbox[s[j].w[3] & 255];
        t.w[1] = ((uint32_t)sbox[s[j].w[1] >> 24] << 24)
               | ((uint32_t)sbox[(s[j].w[2] >> 16) & 255] << 16)
               | ((uint32_t)sbox[(s[j].w[3] >> 8) & 255] << 8)
               | sbox[s[j].w[0] & 255];
        t.w[2] = ((uint32_t)sbox[s[j].w[2] >> 24] << 24)
               | ((uint32_t)sbox[(s[j].w[3] >> 16) & 255] << 16)
               | ((uint32_t)sbox[(s[j].w[0] >> 8) & 255] << 8)
               | sbox[s[j].w[1] & 255];
        t.w[3] = ((uint32_t)sbox[s[j].w[3] >> 24] << 24)
               | ((uint32_t)sbox[(s[j].w[0] >> 16) & 255] << 16)
               | ((uint32_t)sbox[(s[j].w[1] >> 8) & 255] << 8)
               | sbox[s[j].w[2] & 255];
        size_t idx = base + (size_t)j * blockDim.x;
        if (idx < n) out[idx] = u128_xor(t, k);
    }
}

static double median(std::vector<float> ms)
{
    std::sort(ms.begin(), ms.end());
    return ms[ms.size() / 2];
}

template <typename Launch>
static double time_kernel(Launch launch)
{
    std::vector<float> ms;
    cudaEvent_t start, stop;
    CUDA_CHECK(cudaEventCreate(&start));
    CUDA_CHECK(cudaEventCreate(&stop));
    for (int t = -WARMUP; t < TRIALS; t++) {
        CUDA_CHECK(cudaEventRecord(start));
        launch();
        CUDA_CHECK(cudaEventRecord(stop));
        CUDA_CHECK(cudaEventSynchronize(stop));
        CUDA_CHECK(cudaGetLastError());
        if (t >= 0) {
            float elapsed = 0.0f;
            CUDA_CHECK(cudaEventElapsedTime(&elapsed, start, stop));
            ms.push_back(elapsed);
        }
    }
    CUDA_CHECK(cudaEventDestroy(start));
    CUDA_CHECK(cudaEventDestroy(stop));
    return median(ms);
}

/* The attacker budget the block-evaluation table quotes, in seconds. */
#define BUDGET_SECONDS 14400.0

/* Two CSV shapes behind one writer.
 *
 * `legacy` is what results/gpu-speed.csv, results/gpu-speed-optimized.csv and
 * results/gpu-speed-16m.csv were built from and what docs/gpu-optimizations.md
 * compares against; its column list is kept byte for byte so `make gpu-bench`
 * still reproduces those files.
 *
 * `v2` is results/v2/cuda/block-eval.csv. It adds the two columns the
 * measurement protocol asks for and drops nothing, because the rate and the
 * budget are the same measurement as gb_per_sec presented in the unit the
 * attacker table actually wants:
 *
 *   block_evals_per_sec  blocks / elapsed. Key expansion is NOT in the timed
 *                        region and one pre-expanded key is shared by the whole
 *                        batch, so this is a block-evaluation rate and not a
 *                        key-search rate. The two are separated on purpose; the
 *                        key-search rate is master-key-search.csv's own column.
 *   block_evals_in_4h    the same figure times BUDGET_SECONDS. Derived, not
 *                        measured, and derived here rather than by hand. */
/* A v2 sink buffers its rows in memory and writes nothing until the whole run has
 * succeeded, then writes a temporary file and rename()s it into place. bench/ctr_bench.c
 * reached the same arrangement for the same reason: these files carry header text
 * asserting that checks passed, so a run that dies half way through must leave no file
 * at all rather than a short one wearing that assertion. The legacy sink keeps writing
 * as it goes, because its format is frozen and it makes no such claim. */
struct CsvSink {
    FILE *fp;                        /* legacy only */
    bool v2;
    std::vector<std::string> *rows;  /* v2 only */
};

/* Which (cipher, impl) pairs actually produced a row, so the portfolio gaps can be
 * derived from the run rather than maintained by hand. See emit_portfolio_gaps(). */
struct BlockEvalRow {
    std::string cipher;
    std::string impl;
    int rounds;
    int block_bits;
};
static std::vector<BlockEvalRow> g_block_eval_rows;

static void emit(const CsvSink *csv, const char *cipher, const char *impl, int rounds,
                 int block_bits, size_t blocks, double ms)
{
    double bytes = (double)blocks * (block_bits / 8);
    double gbps = bytes / (ms * 1.0e6);
    double ns_block = ms * 1.0e6 / (double)blocks;
    double evals_per_sec = (double)blocks / (ms * 1.0e-3);
    std::printf("  %-28s %-12s r=%-3d %8.2f GB/s %8.3f ns/block %10.3e evals/s\n",
                cipher, impl, rounds, gbps, ns_block, evals_per_sec);
    if (!csv) return;
    if (csv->v2) {
        if (!csv->rows) return;
        char line[512];
        std::snprintf(line, sizeof line, "%s,%s,%d,%d,%zu,%.6f,%.6f,%.6e,%.6e,measured,\n",
                      cipher, impl, rounds, block_bits, blocks, gbps, ns_block,
                      evals_per_sec, evals_per_sec * BUDGET_SECONDS);
        csv->rows->push_back(line);
        g_block_eval_rows.push_back(BlockEvalRow{cipher, impl, rounds, block_bits});
    } else if (csv->fp) {
        std::fprintf(csv->fp, "%s,%s,%d,%d,%zu,%.6f,%.6f\n",
                     cipher, impl, rounds, block_bits, blocks, gbps, ns_block);
    }
}

static void check64(const Variant64 &v, const std::vector<int> &sbox, const uint64_t *rk,
                    uint64_t *d_in, uint64_t *d_out, const uint64_t *d_tab)
{
    uint64_t in[4], got[4];
    for (uint64_t &x : in) x = rng_next();
    CUDA_CHECK(cudaMemcpy(d_in, in, sizeof(in), cudaMemcpyHostToDevice));
    enc64_direct_kernel<<<1, 32>>>(d_out, d_in, 4, v.rounds, v.sbox_bits, v.lin,
                                   v.c0[0], v.c0[1], v.c0[2]);
    CUDA_CHECK(cudaMemcpy(got, d_out, sizeof(got), cudaMemcpyDeviceToHost));
    for (int i = 0; i < 4; i++) {
        uint64_t want = encrypt64_host(in[i], sbox, v.sbox_bits, v.lin, v.c0, rk, v.rounds);
        if (got[i] != want) {
            std::fprintf(stderr, "%s direct mismatch at %d\n", v.name, i);
            std::exit(1);
        }
    }
    enc64_table_kernel<<<1, 32>>>(d_out, d_in, d_tab, 4, v.rounds, v.sbox_bits);
    CUDA_CHECK(cudaMemcpy(got, d_out, sizeof(got), cudaMemcpyDeviceToHost));
    for (int i = 0; i < 4; i++) {
        uint64_t want = encrypt64_host(in[i], sbox, v.sbox_bits, v.lin, v.c0, rk, v.rounds);
        if (got[i] != want) {
            std::fprintf(stderr, "%s table mismatch at %d\n", v.name, i);
            std::exit(1);
        }
    }
    enc64_table_ilp4_kernel<<<1, 32>>>(d_out, d_in, d_tab, 4, v.rounds, v.sbox_bits);
    CUDA_CHECK(cudaMemcpy(got, d_out, sizeof(got), cudaMemcpyDeviceToHost));
    for (int i = 0; i < 4; i++) {
        uint64_t want = encrypt64_host(in[i], sbox, v.sbox_bits, v.lin, v.c0, rk, v.rounds);
        if (got[i] != want) {
            std::fprintf(stderr, "%s table-ilp4 mismatch at %d\n", v.name, i);
            std::exit(1);
        }
    }
}

template<int ROUNDS, int BITS, int LIN, int C0, int C1, int C2>
static void check64_optimized(const Variant64 &v, const std::vector<int> &sbox,
                              const uint64_t *rk, uint64_t *d_in, uint64_t *d_out,
                              const uint64_t *d_byte_tab, const uint64_t *d_native_tab,
                              const uint8_t *d_sbox)
{
    uint64_t in[4], got[4];
    for (uint64_t &x : in) x = rng_next();
    CUDA_CHECK(cudaMemcpy(d_in, in, sizeof(in), cudaMemcpyHostToDevice));

#define CHECK_OPT64(LABEL, LAUNCH) do {                                                \
    LAUNCH;                                                                            \
    CUDA_CHECK(cudaMemcpy(got, d_out, sizeof(got), cudaMemcpyDeviceToHost));            \
    for (int i = 0; i < 4; i++) {                                                      \
        uint64_t want = encrypt64_host(in[i], sbox, BITS, (Lin64Kind)LIN, v.c0, rk,     \
                                       ROUNDS);                                         \
        if (got[i] != want) {                                                          \
            std::fprintf(stderr, "%s %s mismatch at %d: got %016llx want %016llx\n",  \
                         v.name, LABEL, i, (unsigned long long)got[i],                  \
                         (unsigned long long)want);                                     \
            std::exit(1);                                                              \
        }                                                                              \
    }                                                                                  \
} while (0)

    CHECK_OPT64("direct-ct",
        (enc64_direct_ct_kernel<ROUNDS, BITS, LIN, C0, C1, C2><<<1, THREADS>>>
            (d_out, d_in, 4)));
    CHECK_OPT64("byte-global",
        (enc64_byte_table_ct_kernel<ROUNDS, 1, false><<<1, THREADS>>>
            (d_out, d_in, d_byte_tab, 4)));
    CHECK_OPT64("byte-global-x2",
        (enc64_byte_table_ct_kernel<ROUNDS, 2, false><<<1, THREADS>>>
            (d_out, d_in, d_byte_tab, 4)));
    CHECK_OPT64("byte-shared",
        (enc64_byte_table_ct_kernel<ROUNDS, 1, true><<<1, THREADS>>>
            (d_out, d_in, d_byte_tab, 4)));
    CHECK_OPT64("byte-shared-x2",
        (enc64_byte_table_ct_kernel<ROUNDS, 2, true><<<1, THREADS>>>
            (d_out, d_in, d_byte_tab, 4)));
    CHECK_OPT64("shared-sbox",
        (enc64_shared_sbox_kernel<ROUNDS, BITS, LIN, C0, C1, C2, 1><<<1, THREADS>>>
            (d_out, d_in, d_sbox, 4)));
    CHECK_OPT64("shared-sbox-x2",
        (enc64_shared_sbox_kernel<ROUNDS, BITS, LIN, C0, C1, C2, 2><<<1, THREADS>>>
            (d_out, d_in, d_sbox, 4)));
    CHECK_OPT64("shared-sbox-x4",
        (enc64_shared_sbox_kernel<ROUNDS, BITS, LIN, C0, C1, C2, 4><<<1, THREADS>>>
            (d_out, d_in, d_sbox, 4)));
    if constexpr (BITS == 4) {
        CHECK_OPT64("nibble-global-ct",
            (enc64_native_table_ct_kernel<ROUNDS, BITS, false><<<1, THREADS>>>
                (d_out, d_in, d_native_tab, 4)));
        CHECK_OPT64("nibble-shared-ct",
            (enc64_native_table_ct_kernel<ROUNDS, BITS, true><<<1, THREADS>>>
                (d_out, d_in, d_native_tab, 4)));
    }
#undef CHECK_OPT64
}

template<int ROUNDS, int BITS, int LIN, int C0, int C1, int C2>
static void bench64(const CsvSink *csv, const Variant64 &v, size_t blocks)
{
    std::vector<int> sbox = read_json_sbox(v.json_path);
    uint8_t sbox256[256] = {};
    for (size_t i = 0; i < sbox.size(); i++) sbox256[i] = (uint8_t)sbox[i];
    CUDA_CHECK(cudaMemcpyToSymbol(c_sbox, sbox256, sizeof(sbox256)));

    uint64_t rk[MAX_ROUNDS + 1] = {};
    make_keys64(rk, v.rounds);
    CUDA_CHECK(cudaMemcpyToSymbol(c_rk64, rk, sizeof(rk)));

    std::vector<uint64_t> tab;
    build_table64(tab, sbox, v.sbox_bits, v.lin, v.c0);
    std::vector<uint64_t> byte_tab;
    build_table64_byte(byte_tab, sbox, v.sbox_bits, v.lin, v.c0);

    uint64_t *d_in = nullptr, *d_out = nullptr, *d_tab = nullptr, *d_byte_tab = nullptr;
    uint8_t *d_sbox = nullptr;
    CUDA_CHECK(cudaMalloc(&d_in, blocks * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(&d_out, blocks * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(&d_tab, tab.size() * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(&d_byte_tab, byte_tab.size() * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(&d_sbox, sizeof(sbox256)));
    std::vector<uint64_t> host(blocks);
    for (uint64_t &x : host) x = rng_next();
    CUDA_CHECK(cudaMemcpy(d_in, host.data(), blocks * sizeof(uint64_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_tab, tab.data(), tab.size() * sizeof(uint64_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_byte_tab, byte_tab.data(), byte_tab.size() * sizeof(uint64_t),
                          cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_sbox, sbox256, sizeof(sbox256), cudaMemcpyHostToDevice));

    check64(v, sbox, rk, d_in, d_out, d_tab);
    check64_optimized<ROUNDS, BITS, LIN, C0, C1, C2>(v, sbox, rk, d_in, d_out,
                                                     d_byte_tab, d_tab, d_sbox);

    /* The bitsliced kernel needs PRESENT's own S-box circuit. Where it applies,
     * check it over enough blocks to exercise every lane of the transpose and
     * more than one thread block, not just the four blocks the table kernels use. */
    const int bs_kind = bitslice_sbox_kind(sbox);
    /* The AES-S-box variants here are all lin444; a pLayer+AES combination would
     * need the permutation folded into the byte-wide store and is not generated. */
    const bool bitslice_ok = (bs_kind == BS_SBOX_PRESENT)
                          || (bs_kind == BS_SBOX_AES && LIN == LIN64_LIN444_16);
    if (bitslice_ok) {
        /* check64 and check64_optimized scribble their own vectors over the head of
         * d_in; put the benchmark input back before comparing against host. */
        CUDA_CHECK(cudaMemcpy(d_in, host.data(), blocks * sizeof(uint64_t),
                              cudaMemcpyHostToDevice));
        verify_bitslice_circuit(sbox, bs_kind);
        verify_transpose32();
        std::vector<uint32_t> km;
        build_rkmask64(km, rk, v.rounds, v.lin, v.c0, bs_kind);
        CUDA_CHECK(cudaMemcpyToSymbol(c_rkmask64, km.data(), km.size() * sizeof(uint32_t)));

        const size_t nchk = std::min<size_t>(blocks, 32 * BITSLICE_THREADS * 3 + 17);
        const unsigned gchk =
            (unsigned)((nchk + 32 * BITSLICE_THREADS - 1) / (32 * BITSLICE_THREADS));
        if (bs_kind == BS_SBOX_PRESENT)
            enc64_bitslice_kernel<ROUNDS, BS_SBOX_PRESENT, LIN, C0, C1, C2>
                <<<gchk, BITSLICE_THREADS>>>(d_out, d_in, nchk);
        else
            enc64_bitslice_kernel<ROUNDS, BS_SBOX_AES, LIN, C0, C1, C2>
                <<<gchk, BITSLICE_THREADS>>>(d_out, d_in, nchk);
        std::vector<uint64_t> got(nchk);
        CUDA_CHECK(cudaMemcpy(got.data(), d_out, nchk * sizeof(uint64_t),
                              cudaMemcpyDeviceToHost));
        for (size_t i = 0; i < nchk; i++) {
            uint64_t want = encrypt64_host(host[i], sbox, BITS, (Lin64Kind)LIN, v.c0, rk,
                                           ROUNDS);
            if (got[i] != want) {
                std::fprintf(stderr, "%s bitslice mismatch at %zu: got %016llx want %016llx\n",
                             v.name, i, (unsigned long long)got[i], (unsigned long long)want);
                std::exit(1);
            }
        }
    }

    dim3 block(THREADS);
    dim3 grid((unsigned)((blocks + THREADS - 1) / THREADS));
    dim3 grid4((unsigned)(((blocks + 3) / 4 + THREADS - 1) / THREADS));
    dim3 grid2((unsigned)(((blocks + 1) / 2 + THREADS - 1) / THREADS));

    double ms = time_kernel([&] {
        enc64_direct_kernel<<<grid, block>>>(d_out, d_in, blocks, v.rounds, v.sbox_bits, v.lin,
                                             v.c0[0], v.c0[1], v.c0[2]);
    });
    emit(csv, v.name, "direct", v.rounds, 64, blocks, ms);

    ms = time_kernel([&] {
        enc64_table_kernel<<<grid, block>>>(d_out, d_in, d_tab, blocks, v.rounds, v.sbox_bits);
    });
    emit(csv, v.name, "table", v.rounds, 64, blocks, ms);

    ms = time_kernel([&] {
        enc64_table_ilp4_kernel<<<grid4, block>>>(d_out, d_in, d_tab, blocks, v.rounds,
                                                  v.sbox_bits);
    });
    emit(csv, v.name, "table-ilp4", v.rounds, 64, blocks, ms);

    ms = time_kernel([&] {
        enc64_direct_ct_kernel<ROUNDS, BITS, LIN, C0, C1, C2><<<grid, block>>>
            (d_out, d_in, blocks);
    });
    emit(csv, v.name, "direct-ct", v.rounds, 64, blocks, ms);

    ms = time_kernel([&] {
        enc64_byte_table_ct_kernel<ROUNDS, 1, false><<<grid, block>>>
            (d_out, d_in, d_byte_tab, blocks);
    });
    emit(csv, v.name, "byte-global", v.rounds, 64, blocks, ms);
    ms = time_kernel([&] {
        enc64_byte_table_ct_kernel<ROUNDS, 2, false><<<grid2, block>>>
            (d_out, d_in, d_byte_tab, blocks);
    });
    emit(csv, v.name, "byte-global-x2", v.rounds, 64, blocks, ms);
    ms = time_kernel([&] {
        enc64_byte_table_ct_kernel<ROUNDS, 1, true><<<grid, block>>>
            (d_out, d_in, d_byte_tab, blocks);
    });
    emit(csv, v.name, "byte-shared", v.rounds, 64, blocks, ms);
    ms = time_kernel([&] {
        enc64_byte_table_ct_kernel<ROUNDS, 2, true><<<grid2, block>>>
            (d_out, d_in, d_byte_tab, blocks);
    });
    emit(csv, v.name, "byte-shared-x2", v.rounds, 64, blocks, ms);
    ms = time_kernel([&] {
        enc64_shared_sbox_kernel<ROUNDS, BITS, LIN, C0, C1, C2, 1><<<grid, block>>>
            (d_out, d_in, d_sbox, blocks);
    });
    emit(csv, v.name, "shared-sbox", v.rounds, 64, blocks, ms);
    ms = time_kernel([&] {
        enc64_shared_sbox_kernel<ROUNDS, BITS, LIN, C0, C1, C2, 2><<<grid2, block>>>
            (d_out, d_in, d_sbox, blocks);
    });
    emit(csv, v.name, "shared-sbox-x2", v.rounds, 64, blocks, ms);
    ms = time_kernel([&] {
        enc64_shared_sbox_kernel<ROUNDS, BITS, LIN, C0, C1, C2, 4><<<grid4, block>>>
            (d_out, d_in, d_sbox, blocks);
    });
    emit(csv, v.name, "shared-sbox-x4", v.rounds, 64, blocks, ms);
    if constexpr (BITS == 4) {
        ms = time_kernel([&] {
            enc64_native_table_ct_kernel<ROUNDS, BITS, false><<<grid, block>>>
                (d_out, d_in, d_tab, blocks);
        });
        emit(csv, v.name, "nibble-global-ct", v.rounds, 64, blocks, ms);
        ms = time_kernel([&] {
            enc64_native_table_ct_kernel<ROUNDS, BITS, true><<<grid, block>>>
                (d_out, d_in, d_tab, blocks);
        });
        emit(csv, v.name, "nibble-shared-ct", v.rounds, 64, blocks, ms);
    }
    if (bitslice_ok) {
        const size_t per_block = 32 * BITSLICE_THREADS;
        dim3 grid_bs((unsigned)((blocks + per_block - 1) / per_block));
        if (bs_kind == BS_SBOX_PRESENT) {
            ms = time_kernel([&] {
                enc64_bitslice_kernel<ROUNDS, BS_SBOX_PRESENT, LIN, C0, C1, C2>
                    <<<grid_bs, BITSLICE_THREADS>>>(d_out, d_in, blocks);
            });
        } else {
            ms = time_kernel([&] {
                enc64_bitslice_kernel<ROUNDS, BS_SBOX_AES, LIN, C0, C1, C2>
                    <<<grid_bs, BITSLICE_THREADS>>>(d_out, d_in, blocks);
            });
        }
        emit(csv, v.name, "bitslice-x32", v.rounds, 64, blocks, ms);
    }

    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
    CUDA_CHECK(cudaFree(d_tab));
    CUDA_CHECK(cudaFree(d_byte_tab));
    CUDA_CHECK(cudaFree(d_sbox));
}

static void check_lin128(const Variant128 &v, const std::vector<int> &sbox, const U128 *rk,
                         U128 *d_in, U128 *d_out, const U128 *d_tab)
{
    U128 in[4], got[4];
    for (U128 &x : in)
        for (uint32_t &w : x.w) w = (uint32_t)rng_next();
    CUDA_CHECK(cudaMemcpy(d_in, in, sizeof(in), cudaMemcpyHostToDevice));
    lin128_direct_kernel<<<1, 32>>>(d_out, d_in, 4, v.rounds, v.c0[0], v.c0[1], v.c0[2]);
    CUDA_CHECK(cudaMemcpy(got, d_out, sizeof(got), cudaMemcpyDeviceToHost));
    for (int i = 0; i < 4; i++) {
        U128 want = encrypt_lin128_host(in[i], sbox, v.c0, rk, v.rounds);
        if (std::memcmp(&got[i], &want, sizeof(U128)) != 0) {
            std::fprintf(stderr, "%s direct mismatch at %d\n", v.name, i);
            std::exit(1);
        }
    }
    lin128_table_kernel<<<1, 32>>>(d_out, d_in, d_tab, 4, v.rounds);
    CUDA_CHECK(cudaMemcpy(got, d_out, sizeof(got), cudaMemcpyDeviceToHost));
    for (int i = 0; i < 4; i++) {
        U128 want = encrypt_lin128_host(in[i], sbox, v.c0, rk, v.rounds);
        if (std::memcmp(&got[i], &want, sizeof(U128)) != 0) {
            std::fprintf(stderr, "%s table mismatch at %d\n", v.name, i);
            std::exit(1);
        }
    }
}

static void check_aes128(const Variant128 &v, const std::vector<int> &sbox,
                         const std::vector<uint32_t> &te, const U128 *rk,
                         U128 *d_in, U128 *d_out)
{
    U128 in[4], got[4];
    for (U128 &x : in)
        for (uint32_t &w : x.w) w = (uint32_t)rng_next();
    CUDA_CHECK(cudaMemcpy(d_in, in, sizeof(in), cudaMemcpyHostToDevice));
    aes_table_kernel<<<1, 32>>>(d_out, d_in, 4, v.rounds);
    CUDA_CHECK(cudaMemcpy(got, d_out, sizeof(got), cudaMemcpyDeviceToHost));
    for (int i = 0; i < 4; i++) {
        U128 want = encrypt_aes_host(in[i], sbox, te, rk, v.rounds);
        if (std::memcmp(&got[i], &want, sizeof(U128)) != 0) {
            std::fprintf(stderr, "%s table mismatch at %d\n", v.name, i);
            std::exit(1);
        }
    }
    aes_table_ilp4_kernel<<<1, 32>>>(d_out, d_in, 4, v.rounds);
    CUDA_CHECK(cudaMemcpy(got, d_out, sizeof(got), cudaMemcpyDeviceToHost));
    for (int i = 0; i < 4; i++) {
        U128 want = encrypt_aes_host(in[i], sbox, te, rk, v.rounds);
        if (std::memcmp(&got[i], &want, sizeof(U128)) != 0) {
            std::fprintf(stderr, "%s table-ilp4 mismatch at %d\n", v.name, i);
            std::exit(1);
        }
    }
}

template<int ROUNDS, int C0, int C1, int C2>
static void check_lin128_optimized(const Variant128 &v, const std::vector<int> &sbox,
                                   const U128 *rk, U128 *d_in, U128 *d_out,
                                   const U128 *d_tab, const uint8_t *d_sbox,
                                   bool large_shared)
{
    U128 in[4], got[4];
    for (U128 &x : in)
        for (uint32_t &w : x.w) w = (uint32_t)rng_next();
    CUDA_CHECK(cudaMemcpy(d_in, in, sizeof(in), cudaMemcpyHostToDevice));

#define CHECK_OPTLIN(LABEL, LAUNCH) do {                                               \
    LAUNCH;                                                                            \
    CUDA_CHECK(cudaMemcpy(got, d_out, sizeof(got), cudaMemcpyDeviceToHost));            \
    for (int i = 0; i < 4; i++) {                                                      \
        U128 want = encrypt_lin128_host(in[i], sbox, v.c0, rk, ROUNDS);                 \
        if (std::memcmp(&got[i], &want, sizeof(U128)) != 0) {                          \
            std::fprintf(stderr, "%s %s mismatch at %d\n", v.name, LABEL, i);         \
            std::exit(1);                                                              \
        }                                                                              \
    }                                                                                  \
} while (0)

    CHECK_OPTLIN("shared-sbox",
        (lin128_shared_sbox_kernel<ROUNDS, 1, C0, C1, C2><<<1, THREADS>>>
            (d_out, d_in, d_sbox, 4)));
    CHECK_OPTLIN("shared-sbox-x2",
        (lin128_shared_sbox_kernel<ROUNDS, 2, C0, C1, C2><<<1, THREADS>>>
            (d_out, d_in, d_sbox, 4)));
    CHECK_OPTLIN("table-global-ct",
        (lin128_table_ct_kernel<ROUNDS, 1, false><<<1, THREADS>>>
            (d_out, d_in, d_tab, 4)));
    CHECK_OPTLIN("table-global-x2",
        (lin128_table_ct_kernel<ROUNDS, 2, false><<<1, THREADS>>>
            (d_out, d_in, d_tab, 4)));
    if (large_shared) {
        CHECK_OPTLIN("table-shared-x4",
            (lin128_table_ct_kernel<ROUNDS, 4, true><<<1, THREADS,
                16 * 256 * sizeof(U128)>>>(d_out, d_in, d_tab, 4)));
    }
#undef CHECK_OPTLIN
}

template<int ROUNDS>
static void check_aes128_optimized(const Variant128 &v, const std::vector<int> &sbox,
                                   const std::vector<uint32_t> &te, const U128 *rk,
                                   U128 *d_in, U128 *d_out, const uint32_t *d_te,
                                   const uint8_t *d_sbox)
{
    U128 in[4], got[4];
    for (U128 &x : in)
        for (uint32_t &w : x.w) w = (uint32_t)rng_next();
    CUDA_CHECK(cudaMemcpy(d_in, in, sizeof(in), cudaMemcpyHostToDevice));

#define CHECK_OPTAES(LABEL, ILP) do {                                                  \
    aes_shared_table_kernel<ROUNDS, ILP><<<1, THREADS>>>                              \
        (d_out, d_in, d_te, d_sbox, 4);                                               \
    CUDA_CHECK(cudaMemcpy(got, d_out, sizeof(got), cudaMemcpyDeviceToHost));            \
    for (int i = 0; i < 4; i++) {                                                      \
        U128 want = encrypt_aes_host(in[i], sbox, te, rk, ROUNDS);                     \
        if (std::memcmp(&got[i], &want, sizeof(U128)) != 0) {                          \
            std::fprintf(stderr, "%s %s mismatch at %d\n", v.name, LABEL, i);         \
            std::exit(1);                                                              \
        }                                                                              \
    }                                                                                  \
} while (0)

    CHECK_OPTAES("shared-table", 1);
    CHECK_OPTAES("shared-table-x2", 2);
    CHECK_OPTAES("shared-table-x4", 4);
#undef CHECK_OPTAES
}

template<int ROUNDS, bool LIN444, int C0, int C1, int C2>
static void bench_aes(const CsvSink *csv, const Variant128 &v, size_t blocks)
{
    std::vector<int> sbox = read_json_sbox("variants/wide/aes.json");
    uint8_t sbox256[256] = {};
    for (size_t i = 0; i < sbox.size(); i++) sbox256[i] = (uint8_t)sbox[i];
    CUDA_CHECK(cudaMemcpyToSymbol(c_sbox, sbox256, sizeof(sbox256)));

    U128 rk[MAX_ROUNDS + 1] = {};
    make_keys128(rk, v.rounds);
    CUDA_CHECK(cudaMemcpyToSymbol(c_rk128, rk, sizeof(rk)));

    U128 *d_in = nullptr, *d_out = nullptr;
    uint8_t *d_sbox = nullptr;
    CUDA_CHECK(cudaMalloc(&d_in, blocks * sizeof(U128)));
    CUDA_CHECK(cudaMalloc(&d_out, blocks * sizeof(U128)));
    CUDA_CHECK(cudaMalloc(&d_sbox, sizeof(sbox256)));
    std::vector<U128> host(blocks);
    for (U128 &x : host)
        for (uint32_t &w : x.w) w = (uint32_t)rng_next();
    CUDA_CHECK(cudaMemcpy(d_in, host.data(), blocks * sizeof(U128), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_sbox, sbox256, sizeof(sbox256), cudaMemcpyHostToDevice));

    dim3 block(THREADS);
    dim3 grid((unsigned)((blocks + THREADS - 1) / THREADS));
    dim3 grid4((unsigned)(((blocks + 3) / 4 + THREADS - 1) / THREADS));
    dim3 grid2((unsigned)(((blocks + 1) / 2 + THREADS - 1) / THREADS));

    if constexpr (!LIN444) {
        std::vector<uint32_t> te;
        aes_tables(te);
        CUDA_CHECK(cudaMemcpyToSymbol(c_aes_te, te.data(), te.size() * sizeof(uint32_t)));
        uint32_t *d_te = nullptr;
        CUDA_CHECK(cudaMalloc(&d_te, te.size() * sizeof(uint32_t)));
        CUDA_CHECK(cudaMemcpy(d_te, te.data(), te.size() * sizeof(uint32_t),
                              cudaMemcpyHostToDevice));
        check_aes128(v, sbox, te, rk, d_in, d_out);
        check_aes128_optimized<ROUNDS>(v, sbox, te, rk, d_in, d_out, d_te, d_sbox);
        double ms = time_kernel([&] {
            aes_table_kernel<<<grid, block>>>(d_out, d_in, blocks, v.rounds);
        });
        emit(csv, v.name, "t-table", v.rounds, 128, blocks, ms);
        ms = time_kernel([&] {
            aes_table_ilp4_kernel<<<grid4, block>>>(d_out, d_in, blocks, v.rounds);
        });
        emit(csv, v.name, "t-table-ilp4", v.rounds, 128, blocks, ms);
        ms = time_kernel([&] {
            aes_shared_table_kernel<ROUNDS, 1><<<grid, block>>>
                (d_out, d_in, d_te, d_sbox, blocks);
        });
        emit(csv, v.name, "shared-table", v.rounds, 128, blocks, ms);
        ms = time_kernel([&] {
            aes_shared_table_kernel<ROUNDS, 2><<<grid2, block>>>
                (d_out, d_in, d_te, d_sbox, blocks);
        });
        emit(csv, v.name, "shared-table-x2", v.rounds, 128, blocks, ms);
        ms = time_kernel([&] {
            aes_shared_table_kernel<ROUNDS, 4><<<grid4, block>>>
                (d_out, d_in, d_te, d_sbox, blocks);
        });
        emit(csv, v.name, "shared-table-x4", v.rounds, 128, blocks, ms);
        CUDA_CHECK(cudaFree(d_te));
    } else {
        std::vector<U128> tab;
        build_lin128_table(tab, sbox, v.c0);
        U128 *d_tab = nullptr;
        CUDA_CHECK(cudaMalloc(&d_tab, tab.size() * sizeof(U128)));
        CUDA_CHECK(cudaMemcpy(d_tab, tab.data(), tab.size() * sizeof(U128), cudaMemcpyHostToDevice));
        check_lin128(v, sbox, rk, d_in, d_out, d_tab);

        cudaDeviceProp prop;
        CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
        const int large_shared_bytes = 16 * 256 * (int)sizeof(U128);
        bool large_shared = prop.sharedMemPerBlockOptin >= large_shared_bytes;
        if (large_shared) {
            CUDA_CHECK(cudaFuncSetAttribute(lin128_table_ct_kernel<ROUNDS, 4, true>,
                                            cudaFuncAttributeMaxDynamicSharedMemorySize,
                                            large_shared_bytes));
        }
        check_lin128_optimized<ROUNDS, C0, C1, C2>(v, sbox, rk, d_in, d_out, d_tab,
                                                   d_sbox, large_shared);

        double ms = time_kernel([&] {
            lin128_direct_kernel<<<grid, block>>>(d_out, d_in, blocks, v.rounds,
                                                  v.c0[0], v.c0[1], v.c0[2]);
        });
        emit(csv, v.name, "direct", v.rounds, 128, blocks, ms);
        ms = time_kernel([&] {
            lin128_table_kernel<<<grid, block>>>(d_out, d_in, d_tab, blocks, v.rounds);
        });
        emit(csv, v.name, "table", v.rounds, 128, blocks, ms);
        ms = time_kernel([&] {
            lin128_table_ilp4_kernel<<<grid4, block>>>(d_out, d_in, d_tab, blocks, v.rounds);
        });
        emit(csv, v.name, "table-ilp4", v.rounds, 128, blocks, ms);
        ms = time_kernel([&] {
            lin128_shared_sbox_kernel<ROUNDS, 1, C0, C1, C2><<<grid, block>>>
                (d_out, d_in, d_sbox, blocks);
        });
        emit(csv, v.name, "shared-sbox", v.rounds, 128, blocks, ms);
        ms = time_kernel([&] {
            lin128_shared_sbox_kernel<ROUNDS, 2, C0, C1, C2><<<grid2, block>>>
                (d_out, d_in, d_sbox, blocks);
        });
        emit(csv, v.name, "shared-sbox-x2", v.rounds, 128, blocks, ms);
        ms = time_kernel([&] {
            lin128_table_ct_kernel<ROUNDS, 1, false><<<grid, block>>>
                (d_out, d_in, d_tab, blocks);
        });
        emit(csv, v.name, "table-global-ct", v.rounds, 128, blocks, ms);
        ms = time_kernel([&] {
            lin128_table_ct_kernel<ROUNDS, 2, false><<<grid2, block>>>
                (d_out, d_in, d_tab, blocks);
        });
        emit(csv, v.name, "table-global-x2", v.rounds, 128, blocks, ms);
        if (large_shared) {
            ms = time_kernel([&] {
                lin128_table_ct_kernel<ROUNDS, 4, true><<<grid4, block,
                    large_shared_bytes>>>(d_out, d_in, d_tab, blocks);
            });
            emit(csv, v.name, "table-shared-x4", v.rounds, 128, blocks, ms);
        }
        CUDA_CHECK(cudaFree(d_tab));
    }

    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
    CUDA_CHECK(cudaFree(d_sbox));
}

/* ===================================================================================
 * Master-key search
 *
 * Everything above evaluates blocks under one pre-expanded key that the whole batch
 * shares, with key expansion outside the timed region. That is a real attacker
 * quantity and it is what this file has always measured, but it is not key search,
 * and the two must not be quoted as one number.
 *
 * This is key search. Each thread takes its own candidate master key, runs the
 * construction's own key schedule *inside* the timed region, encrypts a known
 * plaintext and compares the result against a target ciphertext. Hits go to a small
 * output buffer that the host reads back; a search over a 2^64-block cipher produces
 * one hit in the planted case and none otherwise, so the buffer never fills.
 *
 * The candidate space is a contiguous run of the low 64 bits of the master key, the
 * high bits held at a fixed prefix. That is a slice of a real search rather than a
 * whole one -- the point is the rate, and the rate does not depend on which slice.
 *
 * Which constructions are here, and which are not, is not a matter of effort: see the
 * comment block MK_EXCLUSION_NOTE below, which is also written into the CSV.
 * =================================================================================== */

#define MK_MAX_HITS 8

struct MkResult {
    unsigned count;
    unsigned long long idx[MK_MAX_HITS];
};

/* --- PRESENT-80 ------------------------------------------------------------------
 * The 80-bit key register is carried as (hi:lo), 16 bits over 64, because the device
 * has no 128-bit integer unit. src/keyschedule.c's schedule80() carries the same
 * register in an `unsigned __int128`; present80_dump_kernel below exists to prove the
 * two agree round key for round key rather than by inspection. */

__device__ __forceinline__ uint64_t present80_rk(uint64_t lo, uint32_t hi)
{
    return (lo >> 16) | ((uint64_t)hi << 48);
}

/* One step of the register: rotate left 61 over 80 bits, S-box the top nibble with
 * the variant's own S-box (c_sbox), XOR the round counter into bits 19..15. */
__device__ __forceinline__ void present80_step(uint64_t &lo, uint32_t &hi, int counter)
{
    uint64_t nlo = (lo >> 19) | ((uint64_t)hi << 45) | (lo << 61);
    uint32_t nhi = (uint32_t)((lo & 0x7FFFFULL) >> 3);
    nhi = (uint32_t)((nhi & 0x0FFFu) | ((uint32_t)c_sbox[(nhi >> 12) & 0xFu] << 12));
    nlo ^= ((uint64_t)(unsigned)counter) << 15;
    lo = nlo;
    hi = nhi;
}

/* Schedule and encrypt under one candidate. rk_out is nullptr on the timed path, so
 * the stores vanish and the timed kernel and the verified kernel are the same code
 * rather than two copies that could drift apart. */
template<int ROUNDS, int LIN, int C0, int C1, int C2>
__device__ __forceinline__ uint64_t present80_master_encrypt(uint64_t plain,
                                                             uint64_t lo, uint32_t hi,
                                                             const uint64_t *tab,
                                                             uint64_t *rk_out)
{
    uint64_t s = plain;
    #pragma unroll
    for (int r = 0; r < ROUNDS; r++) {
        uint64_t rk = present80_rk(lo, hi);
        if (rk_out) rk_out[r] = rk;
        s = round64_table(tab, s ^ rk, 4);
        present80_step(lo, hi, r + 1);
    }
    uint64_t rk = present80_rk(lo, hi);
    if (rk_out) rk_out[ROUNDS] = rk;
    return s ^ rk;
}

template<int ROUNDS, int LIN, int C0, int C1, int C2>
__global__ __launch_bounds__(THREADS)
void present80_search_kernel(const uint64_t *__restrict__ global_tab,
                             uint64_t base_lo, uint32_t base_hi,
                             uint64_t plain, uint64_t target,
                             unsigned long long n, MkResult *out)
{
    __shared__ uint64_t tab[16 * 16];
    for (int i = threadIdx.x; i < 16 * 16; i += blockDim.x) tab[i] = global_tab[i];
    __syncthreads();

    unsigned long long i = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;

    uint64_t lo = base_lo + i;
    uint32_t hi = (uint32_t)((base_hi + (lo < base_lo ? 1u : 0u)) & 0xFFFFu);

    uint64_t c = present80_master_encrypt<ROUNDS, LIN, C0, C1, C2>(plain, lo, hi, tab,
                                                                   nullptr);
    if (c == target) {
        unsigned slot = atomicAdd(&out->count, 1u);
        if (slot < MK_MAX_HITS) out->idx[slot] = i;
    }
}

/* One candidate, round keys and ciphertext both returned: the self-test's window into
 * the device function the search kernel runs. */
template<int ROUNDS, int LIN, int C0, int C1, int C2>
__global__ void present80_dump_kernel(const uint64_t *__restrict__ global_tab,
                                      uint64_t lo, uint32_t hi, uint64_t plain,
                                      uint64_t *rk_out, uint64_t *ct_out)
{
    *ct_out = present80_master_encrypt<ROUNDS, LIN, C0, C1, C2>(plain, lo, hi,
                                                                global_tab, rk_out);
}

/* --- AES-128 ---------------------------------------------------------------------
 * FIPS-197 5.2 in rolling form: w0..w3 hold round key r on entry and round key r+1 on
 * exit. bench/wide_ciphers.h's aes_key_schedule() writes the same recurrence out into
 * an array; this keeps four words live instead, which is what lets a search thread
 * carry its schedule in registers. */
__device__ __forceinline__ void aes128_step(uint32_t &w0, uint32_t &w1, uint32_t &w2,
                                            uint32_t &w3, uint32_t &rcon,
                                            const uint8_t *sbox)
{
    uint32_t t = (w3 << 8) | (w3 >> 24);
    t = ((uint32_t)sbox[(t >> 24) & 0xffu] << 24) | ((uint32_t)sbox[(t >> 16) & 0xffu] << 16)
      | ((uint32_t)sbox[(t >> 8) & 0xffu] << 8) | (uint32_t)sbox[t & 0xffu];
    w0 ^= t ^ rcon;
    w1 ^= w0;
    w2 ^= w1;
    w3 ^= w2;
    uint32_t rb = (rcon >> 24) & 0xffu;
    rb = ((rb << 1) ^ (((rb >> 7) & 1u) * 0x1bu)) & 0xffu;
    rcon = rb << 24;
}

template<int ROUNDS>
__device__ __forceinline__ U128 aes128_master_encrypt(U128 plain,
                                                      uint32_t w0, uint32_t w1,
                                                      uint32_t w2, uint32_t w3,
                                                      const uint32_t *te,
                                                      const uint8_t *sbox,
                                                      uint32_t *rk_out)
{
    uint32_t rcon = 0x01000000u;
    if (rk_out) { rk_out[0] = w0; rk_out[1] = w1; rk_out[2] = w2; rk_out[3] = w3; }

    U128 s;
    s.w[0] = plain.w[0] ^ w0;
    s.w[1] = plain.w[1] ^ w1;
    s.w[2] = plain.w[2] ^ w2;
    s.w[3] = plain.w[3] ^ w3;

    #pragma unroll
    for (int r = 1; r < ROUNDS; r++) {
        aes128_step(w0, w1, w2, w3, rcon, sbox);
        if (rk_out) {
            rk_out[4 * r + 0] = w0; rk_out[4 * r + 1] = w1;
            rk_out[4 * r + 2] = w2; rk_out[4 * r + 3] = w3;
        }
        U128 t;
        t.w[0] = aes_round_word_table(te, s.w[0], s.w[1], s.w[2], s.w[3], 0) ^ w0;
        t.w[1] = aes_round_word_table(te, s.w[0], s.w[1], s.w[2], s.w[3], 1) ^ w1;
        t.w[2] = aes_round_word_table(te, s.w[0], s.w[1], s.w[2], s.w[3], 2) ^ w2;
        t.w[3] = aes_round_word_table(te, s.w[0], s.w[1], s.w[2], s.w[3], 3) ^ w3;
        s = t;
    }

    aes128_step(w0, w1, w2, w3, rcon, sbox);
    if (rk_out) {
        rk_out[4 * ROUNDS + 0] = w0; rk_out[4 * ROUNDS + 1] = w1;
        rk_out[4 * ROUNDS + 2] = w2; rk_out[4 * ROUNDS + 3] = w3;
    }
    U128 t;
    t.w[0] = ((uint32_t)sbox[s.w[0] >> 24] << 24)
           | ((uint32_t)sbox[(s.w[1] >> 16) & 255] << 16)
           | ((uint32_t)sbox[(s.w[2] >> 8) & 255] << 8)
           | (uint32_t)sbox[s.w[3] & 255];
    t.w[1] = ((uint32_t)sbox[s.w[1] >> 24] << 24)
           | ((uint32_t)sbox[(s.w[2] >> 16) & 255] << 16)
           | ((uint32_t)sbox[(s.w[3] >> 8) & 255] << 8)
           | (uint32_t)sbox[s.w[0] & 255];
    t.w[2] = ((uint32_t)sbox[s.w[2] >> 24] << 24)
           | ((uint32_t)sbox[(s.w[3] >> 16) & 255] << 16)
           | ((uint32_t)sbox[(s.w[0] >> 8) & 255] << 8)
           | (uint32_t)sbox[s.w[1] & 255];
    t.w[3] = ((uint32_t)sbox[s.w[3] >> 24] << 24)
           | ((uint32_t)sbox[(s.w[0] >> 16) & 255] << 16)
           | ((uint32_t)sbox[(s.w[1] >> 8) & 255] << 8)
           | (uint32_t)sbox[s.w[2] & 255];
    t.w[0] ^= w0; t.w[1] ^= w1; t.w[2] ^= w2; t.w[3] ^= w3;
    return t;
}

template<int ROUNDS>
__global__ __launch_bounds__(THREADS)
void aes128_search_kernel(const uint32_t *__restrict__ global_te,
                          const uint8_t *__restrict__ global_sbox,
                          uint32_t k0, uint32_t k1, uint64_t base_low,
                          U128 plain, U128 target,
                          unsigned long long n, MkResult *out)
{
    __shared__ uint32_t te[4 * 256];
    __shared__ uint8_t sbox[256];
    for (int i = threadIdx.x; i < 4 * 256; i += blockDim.x) te[i] = global_te[i];
    for (int i = threadIdx.x; i < 256; i += blockDim.x) sbox[i] = global_sbox[i];
    __syncthreads();

    unsigned long long i = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;

    uint64_t low = base_low + i;
    U128 c = aes128_master_encrypt<ROUNDS>(plain, k0, k1, (uint32_t)(low >> 32),
                                           (uint32_t)low, te, sbox, nullptr);
    if (c.w[0] == target.w[0] && c.w[1] == target.w[1]
        && c.w[2] == target.w[2] && c.w[3] == target.w[3]) {
        unsigned slot = atomicAdd(&out->count, 1u);
        if (slot < MK_MAX_HITS) out->idx[slot] = i;
    }
}

template<int ROUNDS>
__global__ void aes128_dump_kernel(const uint32_t *__restrict__ global_te,
                                   const uint8_t *__restrict__ global_sbox,
                                   uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3,
                                   U128 plain, uint32_t *rk_out, U128 *ct_out)
{
    *ct_out = aes128_master_encrypt<ROUNDS>(plain, k0, k1, k2, k3, global_te,
                                            global_sbox, rk_out);
}

/* --- host side -------------------------------------------------------------------- */

static void mk_fail(const char *what)
{
    std::fprintf(stderr, "gpu_bench: master-key self-test FAILED: %s\n", what);
    std::exit(1);
}

static void mk_require(bool ok, const char *what)
{
    if (!ok) mk_fail(what);
}

/* The exclusion note, written into results/v2/cuda/master-key-search.csv. The first
 * paragraph is the one the measurement protocol specifies verbatim. The second is
 * here because without it the note would explain three of the four constructions that
 * are absent, and a reader would have to guess about the fourth -- which is the exact
 * failure this note exists to prevent. */
static const char *const MK_EXCLUSION_NOTE =
"# cipher-D, cipher-D-lin444-297-r5 and cipher-D-lin444-297-aes-r5 are absent by\n"
"# construction, not by omission: they use independent round-key material and have\n"
"# no master-key schedule, so a master-key candidate rate is undefined for them.\n"
"# Their comparable figure is in block-eval.csv.\n"
"#\n"
"# aes-lin444-0-8-15-r4 is absent for a related but distinct reason. It has a\n"
"# 16-byte key, but the map from that key to its round keys is not a designed key\n"
"# schedule: bench/wide_ciphers.h expands it with a xorshift128+ stream precisely\n"
"# because the construction has no schedule of its own to preserve. Searching it\n"
"# would time that expansion, not a cipher. Its comparable figure is also in\n"
"# block-eval.csv.\n"
"#\n"
"# One thing the aes-r5 row does NOT mean. variants/wide/aes.json declares\n"
"# key_schedule=independent with 640 key bits: the differential bound quoted for\n"
"# aes-r5 elsewhere in this repository is computed in the independent-round-key\n"
"# model, as every bound here is. The row below is the other key model -- AES-128's\n"
"# own schedule (FIPS-197 5.2) truncated to 5 rounds, which is what an attacker\n"
"# searching a real 128-bit AES key would run. Both are correct for their own\n"
"# question; they are not the same question, and a reader comparing this rate\n"
"# against that bound is comparing across two key models.\n";

/* key_model is a column and not a comment on purpose. `aes-r5, key_bits=128` is a true
 * statement about the object searched here and a false one about the object every
 * differential bound in this repository was computed for: variants/wide/aes.json
 * declares key_schedule=independent with 640 key bits. A reader that strips '#' lines --
 * which is what a table generator does -- would otherwise see a 128-bit AES key rate
 * sitting next to a bound computed for a 640-bit independent-key object, with nothing in
 * the data to say they are different questions. The prose below says so too; this makes
 * it survive the trip. */
static void mk_emit(const CsvSink *csv, const char *cipher, int rounds, int key_bits,
                    const char *key_model, unsigned long long candidates, double ms)
{
    double per_sec = (double)candidates / (ms * 1.0e-3);
    std::printf("  %-28s r=%-3d key=%-4d %-14s %10.3e master-key candidates/s\n",
                cipher, rounds, key_bits, key_model, per_sec);
    if (csv && csv->v2 && csv->rows) {
        char line[512];
        std::snprintf(line, sizeof line, "%s,%d,%d,%s,%llu,%.6e,%.6e\n",
                      cipher, rounds, key_bits, key_model, candidates, per_sec,
                      per_sec * BUDGET_SECONDS);
        csv->rows->push_back(line);
    }
}

/* Upload one variant's S-box to c_sbox and its fused round table to the device. */
static void mk_upload_present_tables(const char *json_path, Lin64Kind lin, const int c0[3],
                                     uint64_t **d_tab)
{
    std::vector<int> sbox = read_json_sbox(json_path);
    uint8_t sbox256[256] = {};
    for (size_t i = 0; i < sbox.size(); i++) sbox256[i] = (uint8_t)sbox[i];
    CUDA_CHECK(cudaMemcpyToSymbol(c_sbox, sbox256, sizeof(sbox256)));

    std::vector<uint64_t> tab;
    build_table64(tab, sbox, 4, lin, c0);
    CUDA_CHECK(cudaMalloc(d_tab, tab.size() * sizeof(uint64_t)));
    CUDA_CHECK(cudaMemcpy(*d_tab, tab.data(), tab.size() * sizeof(uint64_t),
                          cudaMemcpyHostToDevice));
}

static void mk_key_bytes(uint64_t lo, uint32_t hi, uint8_t key[10])
{
    key[0] = (uint8_t)(hi >> 8);
    key[1] = (uint8_t)hi;
    for (int i = 0; i < 8; i++) key[2 + i] = (uint8_t)(lo >> (8 * (7 - i)));
}

/* The four PRESENT-80 vectors from the specification, the same ones
 * tests/test_vectors.c holds for the CPU library. Checked against the *unreduced*
 * cipher, because a reduced-round variant has no published vector and a schedule
 * that is wrong only past round 7 would sail through one that did. */
struct Present80Kat { const char *key_hex; uint64_t pt; uint64_t ct; };
static const Present80Kat kPresent80Kats[] = {
    {"00000000000000000000", 0x0000000000000000ull, 0x5579C1387B228445ull},
    {"FFFFFFFFFFFFFFFFFFFF", 0x0000000000000000ull, 0xE72C46C0F5945049ull},
    {"00000000000000000000", 0xFFFFFFFFFFFFFFFFull, 0xA112FFC72F68417Bull},
    {"FFFFFFFFFFFFFFFFFFFF", 0xFFFFFFFFFFFFFFFFull, 0x3333DCD3213210D2ull},
};
#define PRESENT80_SPEC_ROUNDS 31

static void mk_selftest_present80_published()
{
    const present_variant_t *v = present_variant_by_name("present-80");
    mk_require(v != nullptr, "variant present-80 not found in the CPU library");
    mk_require(v->rounds == PRESENT80_SPEC_ROUNDS,
               "variants/present-80.json is no longer at the specification's round count");

    uint64_t *d_tab = nullptr, *d_rk = nullptr, *d_ct = nullptr;
    const int c0[3] = {0, 0, 0};
    mk_upload_present_tables("variants/present-80.json", LIN64_PRESENT_PBOX, c0, &d_tab);
    CUDA_CHECK(cudaMalloc(&d_rk, (PRESENT80_SPEC_ROUNDS + 1) * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(&d_ct, sizeof(uint64_t)));

    for (const Present80Kat &kat : kPresent80Kats) {
        uint8_t key[10] = {};
        for (int i = 0; i < 10; i++) {
            unsigned byte = 0;
            std::sscanf(kat.key_hex + 2 * i, "%2x", &byte);
            key[i] = (uint8_t)byte;
        }
        uint32_t hi = (uint32_t)(((unsigned)key[0] << 8) | key[1]);
        uint64_t lo = 0;
        for (int i = 0; i < 8; i++) lo = (lo << 8) | key[2 + i];

        present_ctx_t ctx;
        mk_require(present_init(&ctx, v, key, sizeof(key)) == 0,
                   "present_init rejected a specification key");
        const uint64_t *cpu_rk = ctx.rk;

        present80_dump_kernel<PRESENT80_SPEC_ROUNDS, LIN64_PRESENT_PBOX, 0, 0, 0>
            <<<1, 1>>>(d_tab, lo, hi, kat.pt, d_rk, d_ct);
        CUDA_CHECK(cudaDeviceSynchronize());

        uint64_t gpu_rk[PRESENT80_SPEC_ROUNDS + 1] = {}, gpu_ct = 0;
        CUDA_CHECK(cudaMemcpy(gpu_rk, d_rk, sizeof(gpu_rk), cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(&gpu_ct, d_ct, sizeof(gpu_ct), cudaMemcpyDeviceToHost));

        for (int r = 0; r <= PRESENT80_SPEC_ROUNDS; r++) {
            if (gpu_rk[r] != cpu_rk[r]) {
                std::fprintf(stderr,
                             "  key %s round key %d: GPU %016llx, CPU %016llx\n",
                             kat.key_hex, r, (unsigned long long)gpu_rk[r],
                             (unsigned long long)cpu_rk[r]);
                mk_fail("GPU PRESENT-80 schedule disagrees with src/keyschedule.c");
            }
        }
        if (gpu_ct != kat.ct) {
            std::fprintf(stderr, "  key %s pt %016llx: GPU %016llx, specification %016llx\n",
                         kat.key_hex, (unsigned long long)kat.pt,
                         (unsigned long long)gpu_ct, (unsigned long long)kat.ct);
            mk_fail("GPU PRESENT-80 does not reproduce the specification's test vector");
        }
    }
    std::printf("  present-80 (r=%d): %zu specification vectors reproduced, "
                "%d round keys each identical to src/keyschedule.c\n",
                PRESENT80_SPEC_ROUNDS,
                sizeof(kPresent80Kats) / sizeof(kPresent80Kats[0]),
                PRESENT80_SPEC_ROUNDS + 1);
    CUDA_CHECK(cudaFree(d_tab));
    CUDA_CHECK(cudaFree(d_rk));
    CUDA_CHECK(cudaFree(d_ct));
}

/* FIPS-197 C.1. The ciphertext is the published one; round keys 0 and 1 are the
 * published expansion of that key. */
static const uint8_t kAesKat128Key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint32_t kAesKatPt[4] = {0x00112233u, 0x44556677u, 0x8899aabbu, 0xccddeeffu};
static const uint32_t kAesKatCt[4] = {0x69c4e0d8u, 0x6a7b0430u, 0xd8cdb780u, 0x70b4c55au};
static const uint32_t kAesKatRk1[4] = {0xd6aa74fdu, 0xd2af72fau, 0xdaa678f1u, 0xd6ab76feu};
#define AES_SPEC_ROUNDS 10

/* Timed and verified AES rows share these device-side tables. */
struct MkAesTables { uint32_t *d_te; uint8_t *d_sbox; };

static MkAesTables mk_upload_aes_tables()
{
    std::vector<int> sbox = read_json_sbox("variants/wide/aes.json");
    uint8_t sbox256[256] = {};
    for (size_t i = 0; i < sbox.size(); i++) sbox256[i] = (uint8_t)sbox[i];
    std::vector<uint32_t> te;
    aes_tables(te);

    MkAesTables t = {nullptr, nullptr};
    CUDA_CHECK(cudaMalloc(&t.d_te, te.size() * sizeof(uint32_t)));
    CUDA_CHECK(cudaMalloc(&t.d_sbox, sizeof(sbox256)));
    CUDA_CHECK(cudaMemcpy(t.d_te, te.data(), te.size() * sizeof(uint32_t),
                          cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(t.d_sbox, sbox256, sizeof(sbox256), cudaMemcpyHostToDevice));
    return t;
}

static void mk_selftest_aes128_published(const MkAesTables &tabs)
{
    uint32_t *d_rk = nullptr;
    U128 *d_ct = nullptr;
    CUDA_CHECK(cudaMalloc(&d_rk, 4 * (AES_SPEC_ROUNDS + 1) * sizeof(uint32_t)));
    CUDA_CHECK(cudaMalloc(&d_ct, sizeof(U128)));

    uint32_t k[4];
    for (int i = 0; i < 4; i++)
        k[i] = ((uint32_t)kAesKat128Key[4 * i] << 24) | ((uint32_t)kAesKat128Key[4 * i + 1] << 16)
             | ((uint32_t)kAesKat128Key[4 * i + 2] << 8) | kAesKat128Key[4 * i + 3];
    U128 pt;
    for (int i = 0; i < 4; i++) pt.w[i] = kAesKatPt[i];

    aes128_dump_kernel<AES_SPEC_ROUNDS><<<1, 1>>>(tabs.d_te, tabs.d_sbox,
                                                  k[0], k[1], k[2], k[3], pt, d_rk, d_ct);
    CUDA_CHECK(cudaDeviceSynchronize());

    uint32_t gpu_rk[4 * (AES_SPEC_ROUNDS + 1)] = {};
    U128 gpu_ct;
    CUDA_CHECK(cudaMemcpy(gpu_rk, d_rk, sizeof(gpu_rk), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(&gpu_ct, d_ct, sizeof(gpu_ct), cudaMemcpyDeviceToHost));

    for (int i = 0; i < 4; i++) {
        mk_require(gpu_rk[i] == k[i], "AES round key 0 is not the master key");
        mk_require(gpu_rk[4 + i] == kAesKatRk1[i],
                   "AES round key 1 disagrees with the FIPS-197 key expansion");
        if (gpu_ct.w[i] != kAesKatCt[i]) {
            std::fprintf(stderr, "  word %d: GPU %08x, FIPS-197 %08x\n",
                         i, gpu_ct.w[i], kAesKatCt[i]);
            mk_fail("GPU AES-128 does not reproduce the FIPS-197 C.1 vector");
        }
    }
    std::printf("  aes (r=%d): FIPS-197 C.1 vector reproduced, round keys 0 and 1 "
                "match the published expansion\n", AES_SPEC_ROUNDS);
    CUDA_CHECK(cudaFree(d_rk));
    CUDA_CHECK(cudaFree(d_ct));
}

/* Plant a known key in the searched range and require the kernel to report exactly
 * it. A search kernel that finds nothing runs at a very attractive speed. */
template<int ROUNDS, int LIN, int C0, int C1, int C2>
static void mk_bench_present80(const CsvSink *csv, const char *name, const char *json_path,
                               unsigned long long candidates)
{
    const present_variant_t *v = present_variant_by_name(name);
    mk_require(v != nullptr, "variant not found in the CPU library");
    mk_require(v->rounds == ROUNDS, "CPU variant round count disagrees with cipher_set.py");
    mk_require(v->key_schedule == PRESENT_KS_80, "variant is not on the PRESENT-80 schedule");

    /* The host table and the device kernel take their linear layer from the same
     * template arguments, so there is no second place for the two to disagree. */
    uint64_t *d_tab = nullptr;
    const int c0[3] = {C0, C1, C2};
    mk_upload_present_tables(json_path, (Lin64Kind)LIN, c0, &d_tab);

    /* An arbitrary but fixed prefix and offset: the rate does not depend on which
     * slice of the key space is searched, and a fixed one keeps the run reproducible. */
    const uint32_t base_hi = 0xA5C3u;
    const uint64_t base_lo = 0x0123456789ABCDEFull;
    const uint64_t plain = 0x0123456789ABCDEFull;
    const unsigned long long plant = candidates / 3 + 7;

    uint64_t plant_lo = base_lo + plant;
    uint32_t plant_hi = (uint32_t)((base_hi + (plant_lo < base_lo ? 1u : 0u)) & 0xFFFFu);
    uint8_t key[10];
    mk_key_bytes(plant_lo, plant_hi, key);

    present_ctx_t ctx;
    mk_require(present_init(&ctx, v, key, sizeof(key)) == 0, "present_init rejected the key");
    const uint64_t target = present_encrypt_ref(&ctx, plain);

    /* 1. the schedule, round key by round key, against src/keyschedule.c. */
    uint64_t *d_rk = nullptr, *d_ct = nullptr;
    CUDA_CHECK(cudaMalloc(&d_rk, (ROUNDS + 1) * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(&d_ct, sizeof(uint64_t)));
    present80_dump_kernel<ROUNDS, LIN, C0, C1, C2><<<1, 1>>>(d_tab, plant_lo, plant_hi,
                                                             plain, d_rk, d_ct);
    CUDA_CHECK(cudaDeviceSynchronize());
    uint64_t gpu_rk[ROUNDS + 1] = {}, gpu_ct = 0;
    CUDA_CHECK(cudaMemcpy(gpu_rk, d_rk, sizeof(gpu_rk), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(&gpu_ct, d_ct, sizeof(gpu_ct), cudaMemcpyDeviceToHost));
    for (int r = 0; r <= ROUNDS; r++) {
        if (gpu_rk[r] != ctx.rk[r]) {
            std::fprintf(stderr, "  %s round key %d: GPU %016llx, CPU %016llx\n",
                         name, r, (unsigned long long)gpu_rk[r],
                         (unsigned long long)ctx.rk[r]);
            mk_fail("GPU key schedule disagrees with src/keyschedule.c");
        }
    }
    /* 2. the ciphertext, against present_encrypt_ref. */
    if (gpu_ct != target) {
        std::fprintf(stderr, "  %s: GPU %016llx, present_encrypt_ref %016llx\n",
                     name, (unsigned long long)gpu_ct, (unsigned long long)target);
        mk_fail("GPU encryption under a derived key disagrees with present_encrypt_ref");
    }

    /* 3. the search itself: exactly one hit, at the planted index. */
    MkResult *d_res = nullptr;
    CUDA_CHECK(cudaMalloc(&d_res, sizeof(MkResult)));
    CUDA_CHECK(cudaMemset(d_res, 0, sizeof(MkResult)));
    dim3 block(THREADS);
    dim3 grid((unsigned)((candidates + THREADS - 1) / THREADS));
    present80_search_kernel<ROUNDS, LIN, C0, C1, C2><<<grid, block>>>
        (d_tab, base_lo, base_hi, plain, target, candidates, d_res);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaGetLastError());
    MkResult res;
    CUDA_CHECK(cudaMemcpy(&res, d_res, sizeof(res), cudaMemcpyDeviceToHost));
    if (res.count != 1 || res.idx[0] != plant) {
        std::fprintf(stderr, "  %s: %u hit(s), first at %llu, planted at %llu\n",
                     name, res.count, res.count ? res.idx[0] : 0ull, plant);
        mk_fail("planted key was not the unique hit");
    }
    /* Printed so the vector can be checked outside this binary as well:
     *   build/present-cli encrypts under the same variant and key. */
    std::printf("  %-28s planted key found, uniquely, at candidate %llu of %llu\n",
                name, plant, candidates);
    std::printf("  %-28s vector: key=", name);
    for (size_t i = 0; i < sizeof(key); i++) std::printf("%02x", key[i]);
    std::printf(" pt=%016llx ct=%016llx\n",
                (unsigned long long)plain, (unsigned long long)target);

    /* Only now, with the kernel shown to compute the right thing, time it. The
     * timed launch searches the same range with no planted key present, so the
     * hit path is never taken and the rate is the search rate. */
    CUDA_CHECK(cudaMemset(d_res, 0, sizeof(MkResult)));
    const uint64_t no_such_target = ~target;
    double ms = time_kernel([&] {
        present80_search_kernel<ROUNDS, LIN, C0, C1, C2><<<grid, block>>>
            (d_tab, base_lo, base_hi, plain, no_such_target, candidates, d_res);
    });
    /* The PRESENT-80 schedule is the one the variant JSON declares (key_schedule:
     * present80) and the one every bound for these variants assumes, so here the
     * searched object and the analysed object are the same. */
    mk_emit(csv, name, ROUNDS, 80, "present-80", candidates, ms);

    CUDA_CHECK(cudaFree(d_tab));
    CUDA_CHECK(cudaFree(d_rk));
    CUDA_CHECK(cudaFree(d_ct));
    CUDA_CHECK(cudaFree(d_res));
}

template<int ROUNDS>
static void mk_bench_aes128(const CsvSink *csv, const char *name, const MkAesTables &tabs,
                            unsigned long long candidates)
{
    const uint32_t k0 = 0x2b7e1516u, k1 = 0x28aed2a6u;
    const uint64_t base_low = 0xabf7158809cf4f3cull;
    const unsigned long long plant = candidates / 5 + 11;
    const uint64_t plant_low = base_low + plant;

    U128 pt;
    pt.w[0] = 0x6bc1bee2u; pt.w[1] = 0x2e409f96u;
    pt.w[2] = 0xe93d7e11u; pt.w[3] = 0x7393172au;

    /* The target comes from the device function itself, run once for the planted key
     * -- which is only legitimate because that function has already reproduced
     * FIPS-197 C.1 at the full round count, and because the ciphertext is
     * independently checked against encrypt_aes_host() below. */
    uint32_t *d_rk = nullptr;
    U128 *d_ct = nullptr;
    CUDA_CHECK(cudaMalloc(&d_rk, 4 * (ROUNDS + 1) * sizeof(uint32_t)));
    CUDA_CHECK(cudaMalloc(&d_ct, sizeof(U128)));
    aes128_dump_kernel<ROUNDS><<<1, 1>>>(tabs.d_te, tabs.d_sbox, k0, k1,
                                         (uint32_t)(plant_low >> 32), (uint32_t)plant_low,
                                         pt, d_rk, d_ct);
    CUDA_CHECK(cudaDeviceSynchronize());
    uint32_t gpu_rk[4 * (ROUNDS + 1)] = {};
    U128 target;
    CUDA_CHECK(cudaMemcpy(gpu_rk, d_rk, sizeof(gpu_rk), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(&target, d_ct, sizeof(target), cudaMemcpyDeviceToHost));

    /* The round keys the device derived, fed to this file's existing host reference
     * -- the same encrypt_aes_host() check_aes128 uses -- must give the same block.
     * That separates "the schedule is right" from "the round function is right":
     * the published vector above covers the pair, this covers the encryption alone. */
    {
        std::vector<int> sbox = read_json_sbox("variants/wide/aes.json");
        std::vector<uint32_t> te;
        aes_tables(te);
        U128 rk[MAX_ROUNDS + 1] = {};
        for (int r = 0; r <= ROUNDS; r++)
            for (int i = 0; i < 4; i++) rk[r].w[i] = gpu_rk[4 * r + i];
        U128 host_ct = encrypt_aes_host(pt, sbox, te, rk, ROUNDS);
        for (int i = 0; i < 4; i++) {
            if (host_ct.w[i] != target.w[i]) {
                std::fprintf(stderr, "  %s word %d: GPU %08x, encrypt_aes_host %08x\n",
                             name, i, target.w[i], host_ct.w[i]);
                mk_fail("GPU encryption under GPU-derived round keys disagrees with "
                        "this file's host AES");
            }
        }
    }

    MkResult *d_res = nullptr;
    CUDA_CHECK(cudaMalloc(&d_res, sizeof(MkResult)));
    CUDA_CHECK(cudaMemset(d_res, 0, sizeof(MkResult)));
    dim3 block(THREADS);
    dim3 grid((unsigned)((candidates + THREADS - 1) / THREADS));
    aes128_search_kernel<ROUNDS><<<grid, block>>>(tabs.d_te, tabs.d_sbox, k0, k1,
                                                  base_low, pt, target, candidates, d_res);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaGetLastError());
    MkResult res;
    CUDA_CHECK(cudaMemcpy(&res, d_res, sizeof(res), cudaMemcpyDeviceToHost));
    if (res.count != 1 || res.idx[0] != plant) {
        std::fprintf(stderr, "  %s: %u hit(s), first at %llu, planted at %llu\n",
                     name, res.count, res.count ? res.idx[0] : 0ull, plant);
        mk_fail("planted key was not the unique hit");
    }
    /* Printed so the vector can be checked outside this binary as well:
     *   build/m4_kat_oracle aes <rounds> <key> <plaintext>
     * runs the same AES from bench/wide_ciphers.h that the Cortex-M4 KATs use. */
    std::printf("  %-28s planted key found, uniquely, at candidate %llu of %llu\n",
                name, plant, candidates);
    std::printf("  %-28s vector: key=%08x%08x%08x%08x pt=%08x%08x%08x%08x "
                "ct=%08x%08x%08x%08x\n",
                name, k0, k1, (uint32_t)(plant_low >> 32), (uint32_t)plant_low,
                pt.w[0], pt.w[1], pt.w[2], pt.w[3],
                target.w[0], target.w[1], target.w[2], target.w[3]);

    CUDA_CHECK(cudaMemset(d_res, 0, sizeof(MkResult)));
    U128 no_such_target = target;
    no_such_target.w[0] = ~no_such_target.w[0];
    double ms = time_kernel([&] {
        aes128_search_kernel<ROUNDS><<<grid, block>>>(tabs.d_te, tabs.d_sbox, k0, k1,
                                                      base_low, pt, no_such_target,
                                                      candidates, d_res);
    });
    /* NOT the key model variants/wide/aes.json declares (independent, 640 bits), which
     * is the one this repository's differential bound for aes-r5 was computed in. This
     * row searches AES-128's own FIPS-197 5.2 schedule truncated to 5 rounds. */
    mk_emit(csv, name, ROUNDS, 128, "fips197-aes128", candidates, ms);

    CUDA_CHECK(cudaFree(d_rk));
    CUDA_CHECK(cudaFree(d_ct));
    CUDA_CHECK(cudaFree(d_res));
}

/* --- the two v2 measurement drivers ------------------------------------------------
 *
 * Both are expanded from CTR_CIPHER_LIST, so the cipher names and round counts below
 * come from tools/cipher_set.py and nowhere else. What the generated header does not
 * carry -- which S-box JSON a row reads, how wide its S-box is, which linear layer it
 * runs and with which rotation constants -- is GPU kernel parameterisation rather than
 * cipher-set membership, and is spelled out here keyed on the header's slug, the same
 * way fw/m4/gen/ciphers.mk keys M4_ONE_VARIANT_<slug>. Adding a cipher to
 * tools/cipher_set.py therefore fails this build with an undefined macro rather than
 * silently dropping a row from the table. */

#define GPU_BLOCK_BYTES_present_80_r16 8
#define GPU_BLOCK_BYTES_present_80_lin444_297_r7 8
#define GPU_BLOCK_BYTES_cipher_D 8
#define GPU_BLOCK_BYTES_cipher_D_lin444_297_r5 8
#define GPU_BLOCK_BYTES_cipher_D_lin444_297_aes_r5 8
#define GPU_BLOCK_BYTES_aes_r5 16
#define GPU_BLOCK_BYTES_aes_lin444_0_8_15_r4 16

/* A cipher moving between the 64-bit and the 128-bit kernels would otherwise be a
 * silently mislabelled block_bits column. */
#define X(slug, nm, rounds, bb) \
    static_assert((bb) == GPU_BLOCK_BYTES_##slug, \
                  "block width for " nm " disagrees with tools/cipher_set.py");
CTR_CIPHER_LIST(X)
#undef X

#define GPU_BLOCK_EVAL_present_80_r16(SINK, NM, R, N) \
    bench64<R, 4, LIN64_PRESENT_PBOX, 0, 0, 0>( \
        SINK, Variant64{NM, "variants/present-80-r16.json", R, 4, LIN64_PRESENT_PBOX, \
                        {0, 0, 0}}, N)
#define GPU_BLOCK_EVAL_present_80_lin444_297_r7(SINK, NM, R, N) \
    bench64<R, 4, LIN64_LIN444_16, 2, 9, 7>( \
        SINK, Variant64{NM, "variants/present-80-lin444-297-r7.json", R, 4, \
                        LIN64_LIN444_16, {2, 9, 7}}, N)
#define GPU_BLOCK_EVAL_cipher_D(SINK, NM, R, N) \
    bench64<R, 8, LIN64_CIPHERD_TRANSPOSE, 0, 0, 0>( \
        SINK, Variant64{NM, "variants/cipher-D.json", R, 8, LIN64_CIPHERD_TRANSPOSE, \
                        {0, 0, 0}}, N)
#define GPU_BLOCK_EVAL_cipher_D_lin444_297_r5(SINK, NM, R, N) \
    bench64<R, 8, LIN64_LIN444_16, 2, 9, 7>( \
        SINK, Variant64{NM, "variants/cipher-D-lin444-297-r5.json", R, 8, \
                        LIN64_LIN444_16, {2, 9, 7}}, N)
#define GPU_BLOCK_EVAL_cipher_D_lin444_297_aes_r5(SINK, NM, R, N) \
    bench64<R, 8, LIN64_LIN444_16, 2, 9, 7>( \
        SINK, Variant64{NM, "variants/cipher-D-lin444-297-aes-r5.json", R, 8, \
                        LIN64_LIN444_16, {2, 9, 7}}, N)
#define GPU_BLOCK_EVAL_aes_r5(SINK, NM, R, N) \
    bench_aes<R, false, 0, 0, 0>(SINK, Variant128{NM, R, false, {0, 0, 0}}, N)
#define GPU_BLOCK_EVAL_aes_lin444_0_8_15_r4(SINK, NM, R, N) \
    bench_aes<R, true, 0, 8, 15>(SINK, Variant128{NM, R, true, {0, 8, 15}}, N)

static void run_block_eval(const CsvSink *csv, size_t blocks)
{
#define X(slug, nm, rounds, bb) GPU_BLOCK_EVAL_##slug(csv, nm, rounds, blocks);
    CTR_CIPHER_LIST(X)
#undef X
}

/* --- portfolio gaps ----------------------------------------------------------------
 *
 * The seven constructions are not benchmarked with the same set of kernels, and until
 * this was written the file did not say so. That matters more than it sounds: a table
 * that takes the best row per cipher credits each cipher for whichever kernels somebody
 * happened to write for it, and reports the difference as a property of the cipher.
 *
 * So every kernel family that a construction does NOT have is emitted as its own row,
 * with no timing figures and one of two statuses:
 *
 *   inapplicable  the family cannot exist for this construction, for a structural
 *                 reason given in the note -- usually because the family is defined by
 *                 some other construction's S-box width or linear layer, and this one
 *                 reaches the same idea under a different name.
 *   unwritten     the family could exist and nobody has implemented it. The gap is
 *                 ours, not the cipher's, and a comparison must not charge the cipher
 *                 for it.
 *
 * The gap set is derived from the run, not maintained by hand: it is the union of the
 * families that appeared for the construction's own block width, minus the ones this
 * construction produced. The 64-bit and 128-bit kernels are separate code with separate
 * names, so the union is taken per block width; comparing an `impl` string across the
 * two widths would be meaningless.
 *
 * The classification below is the only hand-maintained part, and an unclassified gap is
 * a hard error rather than a silent omission -- so adding a kernel for one cipher forces
 * a decision about every other cipher that lacks it. */
struct ImplGap {
    const char *cipher;
    const char *impl;
    const char *status;
    const char *note;
};

static const ImplGap kImplGaps[] = {
    /* cipher-D's S-box is 8 bits wide, so a nibble-indexed table cannot be built for
     * it at all; the byte-indexed family is the same idea at its own width, and it has
     * that. Structural, and not a gap in the comparison. */
    {"cipher-D", "nibble-global-ct", "inapplicable",
     "nibble-indexed table needs a 4-bit S-box; this S-box is 8-bit and byte-global is the same kernel at its width"},
    {"cipher-D", "nibble-shared-ct", "inapplicable",
     "as nibble-global-ct; byte-shared is the same kernel at this S-box width"},
    {"cipher-D-lin444-297-r5", "nibble-global-ct", "inapplicable",
     "nibble-indexed table needs a 4-bit S-box; this S-box is 8-bit and byte-global is the same kernel at its width"},
    {"cipher-D-lin444-297-r5", "nibble-shared-ct", "inapplicable",
     "as nibble-global-ct; byte-shared is the same kernel at this S-box width"},
    {"cipher-D-lin444-297-aes-r5", "nibble-global-ct", "inapplicable",
     "nibble-indexed table needs a 4-bit S-box; this S-box is 8-bit and byte-global is the same kernel at its width"},
    {"cipher-D-lin444-297-aes-r5", "nibble-shared-ct", "inapplicable",
     "as nibble-global-ct; byte-shared is the same kernel at this S-box width"},

    /* This one is ours. bitslice_sbox_kind() recognises PRESENT's 4-bit S-box and the
     * AES S-box and nothing else, so cipher-D's own 8-bit table has no bitsliced
     * circuit -- while its AES-S-box sibling does, and that is that cipher's
     * second-fastest row. A circuit for cipher-D's table is synthesisable (this
     * repository's own BDD synthesis finds roughly 1100 gates for it, against 132 for
     * the AES S-box, so it would probably lose) but it has not been built, and until it
     * is, the missing row is an absence of work and not a property of the cipher. */
    {"cipher-D", "bitslice-x32", "unwritten",
     "no bitsliced circuit is generated for this S-box; synthesisable but not built -- this gap is ours not the cipher's"},
    {"cipher-D-lin444-297-r5", "bitslice-x32", "unwritten",
     "no bitsliced circuit is generated for this S-box; synthesisable but not built -- this gap is ours not the cipher's"},

    /* The two 128-bit constructions were implemented as two independent code paths that
     * named the same ideas differently, so most of these are naming, not absence: each
     * has a fused substitution-and-linear table kernel and a shared-memory variant of
     * it. AES's T-table fuses SubBytes, ShiftRows and MixColumns and exists only because
     * of AES's particular linear layer; lin444's rotate layer admits no such fusion and
     * gets substitute-then-linear kernels instead. Neither can run the other's. */
    {"aes-r5", "table", "inapplicable",
     "lin444's fused substitution-and-linear table; AES's equivalent is t-table"},
    {"aes-r5", "table-ilp4", "inapplicable",
     "as table; AES's equivalent is t-table-ilp4"},
    {"aes-r5", "shared-sbox", "inapplicable",
     "lin444 substitutes then applies its rotate layer; AES's shared-memory equivalent is shared-table"},
    {"aes-r5", "shared-sbox-x2", "inapplicable",
     "as shared-sbox; AES's equivalent is shared-table-x2"},
    {"aes-r5", "table-shared-x4", "inapplicable",
     "as shared-sbox; AES's equivalent is shared-table-x4"},
    {"aes-lin444-0-8-15-r4", "t-table", "inapplicable",
     "AES's SubBytes+ShiftRows+MixColumns fusion -- which this linear layer does not admit; its equivalent is table"},
    {"aes-lin444-0-8-15-r4", "t-table-ilp4", "inapplicable",
     "as t-table; this cipher's equivalent is table-ilp4"},
    {"aes-lin444-0-8-15-r4", "shared-table", "inapplicable",
     "as t-table; this cipher's equivalent is shared-sbox"},
    {"aes-lin444-0-8-15-r4", "shared-table-x2", "inapplicable",
     "as t-table; this cipher's equivalent is shared-sbox-x2"},
    {"aes-lin444-0-8-15-r4", "shared-table-x4", "inapplicable",
     "as t-table; this cipher's equivalent is table-shared-x4"},

    /* These three are ours as well. A byte-wise non-table AES kernel is perfectly
     * definable and the 64-bit ciphers all have one; nobody wrote it for AES on the GPU.
     * The two global-memory placement variants were swept for lin444 and not for AES.
     * aes-r5's five rows against aes-lin444-0-8-15-r4's eight is partly this. */
    {"aes-r5", "direct", "unwritten",
     "a byte-wise non-table AES kernel is definable; none was written for the GPU"},
    {"aes-r5", "table-global-ct", "unwritten",
     "global-memory table placement variant; swept for lin444 and not for AES"},
    {"aes-r5", "table-global-x2", "unwritten",
     "global-memory table placement variant; swept for lin444 and not for AES"},
};

static void emit_portfolio_gaps(const CsvSink *csv)
{
    if (!csv || !csv->v2 || !csv->rows) return;

    /* The union of families seen at each block width, in first-seen order. */
    std::vector<std::pair<int, std::string>> families;
    for (const BlockEvalRow &r : g_block_eval_rows) {
        std::pair<int, std::string> key(r.block_bits, r.impl);
        if (std::find(families.begin(), families.end(), key) == families.end())
            families.push_back(key);
    }

    /* Each construction, in tools/cipher_set.py's order. */
    std::vector<std::pair<std::string, std::pair<int, int>>> ciphers;  /* name -> (rounds, bits) */
    for (const BlockEvalRow &r : g_block_eval_rows) {
        bool seen = false;
        for (const auto &c : ciphers) if (c.first == r.cipher) { seen = true; break; }
        if (!seen)
            ciphers.push_back({r.cipher, {r.rounds, r.block_bits}});
    }

    int gaps = 0;
    for (const auto &c : ciphers) {
        for (const auto &fam : families) {
            if (fam.first != c.second.second) continue;  /* other block width */
            bool have = false;
            for (const BlockEvalRow &r : g_block_eval_rows)
                if (r.cipher == c.first && r.impl == fam.second) { have = true; break; }
            if (have) continue;

            const ImplGap *cls = nullptr;
            for (const ImplGap &g : kImplGaps)
                if (c.first == g.cipher && fam.second == g.impl) { cls = &g; break; }
            if (!cls) {
                std::fprintf(stderr,
                             "gpu_bench: %s has no '%s' row and no classification for that\n"
                             "  gap. Add it to kImplGaps as `inapplicable` (with the structural\n"
                             "  reason) or `unwritten` (nobody implemented it). Refusing to write\n"
                             "  a cross-construction file with an unexplained portfolio gap.\n",
                             c.first.c_str(), fam.second.c_str());
                std::exit(1);
            }

            /* `note` is the last field of an unquoted CSV row, so a comma in it would
             * silently split into a twelfth column. Caught here rather than by whoever
             * parses the file later. */
            if (std::strchr(cls->note, ',') != nullptr) {
                std::fprintf(stderr,
                             "gpu_bench: kImplGaps note for (%s, %s) contains a comma, "
                             "which would split the CSV row\n",
                             cls->cipher, cls->impl);
                std::exit(1);
            }
            if (std::strcmp(cls->status, "inapplicable") != 0
                && std::strcmp(cls->status, "unwritten") != 0) {
                std::fprintf(stderr,
                             "gpu_bench: kImplGaps status for (%s, %s) is '%s'; only "
                             "'inapplicable' and 'unwritten' are meaningful\n",
                             cls->cipher, cls->impl, cls->status);
                std::exit(1);
            }

            char line[768];
            std::snprintf(line, sizeof line, "%s,%s,%d,%d,,,,,,%s,%s\n",
                          c.first.c_str(), fam.second.c_str(), c.second.first,
                          c.second.second, cls->status, cls->note);
            csv->rows->push_back(line);
            gaps++;
        }
    }
    std::printf("  portfolio: %d absent (cipher, kernel) pairs recorded and classified\n",
                gaps);
}

/* The master-key comparison, keyed on the slug exactly as the block-evaluation one is,
 * and expanded from the same CTR_CIPHER_LIST -- but every construction either names a
 * master-key kernel here or expands to nothing *with its reason attached*. There is no
 * default and no fall-through, so a cipher added to tools/cipher_set.py fails this
 * build until someone decides which of the two it is, rather than quietly appearing in
 * one table and quietly missing from the other.
 *
 * `tabs` below is captured by name from run_master_key_search's scope: the AES tables
 * are uploaded once and shared, and the X macro's parameter list is fixed. */
#define GPU_MK_present_80_r16(SINK, NM, R, N) \
    mk_bench_present80<R, LIN64_PRESENT_PBOX, 0, 0, 0>( \
        SINK, NM, "variants/present-80-r16.json", N)
#define GPU_MK_present_80_lin444_297_r7(SINK, NM, R, N) \
    mk_bench_present80<R, LIN64_LIN444_16, 2, 9, 7>( \
        SINK, NM, "variants/present-80-lin444-297-r7.json", N)
#define GPU_MK_aes_r5(SINK, NM, R, N) mk_bench_aes128<R>(SINK, NM, tabs, N)

/* Independent round-key material: the key *is* the round keys, so there is no master
 * key to search for. See MK_EXCLUSION_NOTE. */
#define GPU_MK_cipher_D(SINK, NM, R, N)                   ((void)0)
#define GPU_MK_cipher_D_lin444_297_r5(SINK, NM, R, N)     ((void)0)
#define GPU_MK_cipher_D_lin444_297_aes_r5(SINK, NM, R, N) ((void)0)
/* A 16-byte key, but expanded by a xorshift128+ stream this benchmark invented rather
 * than by a designed schedule. See MK_EXCLUSION_NOTE. */
#define GPU_MK_aes_lin444_0_8_15_r4(SINK, NM, R, N)       ((void)0)

static void run_master_key_search(const CsvSink *csv, unsigned long long candidates)
{
    MkAesTables tabs = mk_upload_aes_tables();
    mk_selftest_aes128_published(tabs);
#define X(slug, nm, rounds, bb) GPU_MK_##slug(csv, nm, rounds, candidates);
    CTR_CIPHER_LIST(X)
#undef X
    CUDA_CHECK(cudaFree(tabs.d_te));
    CUDA_CHECK(cudaFree(tabs.d_sbox));
}

/* Every v2 CSV opens with this. The marker is machine-readable and is written by the
 * binary, not by hand: `--campaign` is the only way to get CAMPAIGN out of it, so a
 * smoke run cannot be left behind wearing a campaign's label because someone forgot to
 * edit a comment. A consumer that cares should refuse any file whose first line is not
 * `# provenance: CAMPAIGN`. */
static void write_provenance(FILE *fp, const char *role, bool campaign,
                             const cudaDeviceProp &prop, const char *params)
{
    char host[256];
    if (gethostname(host, sizeof host - 1) != 0) std::strcpy(host, "unknown");
    host[sizeof host - 1] = '\0';

    char when[64] = "unknown";
    std::time_t now = std::time(nullptr);
    std::tm tm_utc;
    if (gmtime_r(&now, &tm_utc)) std::strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

    int runtime_version = 0, driver_version = 0;
    cudaRuntimeGetVersion(&runtime_version);
    cudaDriverGetVersion(&driver_version);

    std::fprintf(fp, "# provenance: %s\n", campaign ? "CAMPAIGN" : "SMOKE-RUN");
    if (!campaign)
        std::fprintf(fp,
"# NOT A MEASUREMENT RESULT, and not a candidate for one. This file was produced by\n"
"# a correctness smoke run on a loaded, shared desktop -- the same machine that is\n"
"# simultaneously the build machine, the x86 benchmark target and someone's desktop\n"
"# session -- at the default short trial count. Its purpose is to show that the\n"
"# columns are well formed and that the kernels behind them passed their self-test.\n"
"# No number in this file may be quoted, plotted, averaged or cited, and no paper\n"
"# table may be built from it. The CUDA measurement campaign runs later, on a quiet\n"
"# machine, and overwrites this file with `# provenance: CAMPAIGN` on the first\n"
"# line. Until that line reads CAMPAIGN, treat this file as absent.\n");
    std::fprintf(fp, "#\n");
    std::fprintf(fp, "# role: %s\n", role);
    std::fprintf(fp, "# produced_by: build/gpu_bench (bench/gpu_bench.cu)\n");
    std::fprintf(fp, "# generated_utc: %s\n", when);
    std::fprintf(fp, "# host: %s\n", host);
    std::fprintf(fp, "# gpu: %s (compute capability %d.%d, %d SMs)\n",
                 prop.name, prop.major, prop.minor, prop.multiProcessorCount);
    std::fprintf(fp, "# cuda_runtime: %d, cuda_driver: %d\n", runtime_version, driver_version);
    std::fprintf(fp, "# trials: %d timed, %d warm-up, median reported\n", TRIALS, WARMUP);
    std::fprintf(fp, "# %s\n", params);
    std::fprintf(fp, "# cipher set: tools/cipher_set.py, via bench/gen/ctr_cipher_set.h\n");
    std::fprintf(fp, "#\n");
}

static const char *const BLOCK_EVAL_NOTE =
"# What this measures, under its correct name. Every row is a BLOCK EVALUATION rate:\n"
"# one key, expanded once on the host before the timed region, shared by every block\n"
"# in the batch. That is the right number for a throughput question and it is what\n"
"# this benchmark has always measured -- it was previously reported as `tests/s`,\n"
"# which read as a key-search rate and is not one. Key search is a different\n"
"# measurement with a key schedule inside the timed region, and it has its own file,\n"
"# results/v2/cuda/master-key-search.csv. The two rates must not be compared or\n"
"# substituted for one another.\n"
"#\n"
"# block_evals_per_sec is blocks / elapsed. block_evals_in_4h is that times 14400 s\n"
"# and is DERIVED, not measured -- derived here rather than by hand.\n"
"#\n"
"# WHAT THIS FILE IS AND IS NOT COMPARABLE ACROSS. Block evaluation is defined for all\n"
"# seven constructions and all seven appear. It is NOT, however, a comparison of seven\n"
"# ciphers under one implementation: it is a comparison across the kernels that happen\n"
"# to exist, and those differ per construction. Taking the best row per cipher and\n"
"# calling the difference a property of the cipher would be wrong, because part of the\n"
"# difference is which kernels somebody wrote.\n"
"#\n"
"# So the gaps are in the data rather than left to be noticed. Every kernel family a\n"
"# construction does not have is present as its own row, with empty timing fields and\n"
"# a status:\n"
"#\n"
"#   measured      a real timed row.\n"
"#   inapplicable  that family cannot exist for this construction; `note` gives the\n"
"#                 structural reason, and usually names the kernel that is the same\n"
"#                 idea under this construction's own naming.\n"
"#   unwritten     that family could exist and nobody implemented it. The gap is ours,\n"
"#                 not the cipher's, and a fair comparison must not charge the cipher\n"
"#                 for it.\n"
"#\n"
"# Read `status == measured` for the timing rows. Read the other two before drawing any\n"
"# conclusion about one construction being faster than another. In particular: two of\n"
"# the three cipher-D variants have no bitsliced kernel while the third does, and that\n"
"# is `unwritten`, not a property of those ciphers; and neither 128-bit construction has\n"
"# a bitsliced kernel at all, since the GPU bitslice path is 64-bit only.\n"
"#\n"
"# The 64-bit and 128-bit kernels are separate code with separate names, so an `impl`\n"
"# string is only comparable within one block_bits.\n"
"#\n";

static const char *const MASTER_KEY_NOTE =
"# Each thread takes its own candidate master key, runs the construction's own key\n"
"# schedule INSIDE the timed region, encrypts a known plaintext and compares against\n"
"# a target ciphertext. That is what makes this a key-search rate and not the block\n"
"# evaluation rate in block-eval.csv, which shares one pre-expanded key across the\n"
"# whole batch. master_key_candidates_in_4h is DERIVED: the rate times 14400 s.\n"
"#\n"
"# WHAT WAS VERIFIED, exactly, before any of these timings was taken. Three different\n"
"# things are true for the three rows, and no row below has a published test vector of\n"
"# its own -- all three are reduced-round, and one is a modified construction -- so the\n"
"# published vectors anchor the FAMILY at its full round count and the per-row checks\n"
"# are against this repository's CPU implementations at the round count actually timed.\n"
"#\n"
"#   family anchor, PRESENT-80: all four test vectors from the PRESENT specification\n"
"#     reproduced at 31 rounds, with all 32 round keys identical to schedule80() in\n"
"#     src/keyschedule.c. These are the same vectors tests/test_vectors.c holds.\n"
"#   family anchor, AES-128: the FIPS-197 C.1 vector reproduced at 10 rounds, with\n"
"#     round key 0 equal to the master key and round key 1 equal to the published\n"
"#     expansion. src/keyschedule.c contains no AES and is not involved here.\n"
"#\n"
"#   present-80-r16 and present-80-lin444-297-r7: at the round count in the rounds\n"
"#     column, every round key identical to present_init()/src/keyschedule.c for the\n"
"#     same key, and the ciphertext identical to present_encrypt_ref().\n"
"#   aes-r5: at 5 rounds, the round keys the GPU derived were fed to this file's host\n"
"#     reference encrypt_aes_host() -- the one check_aes128 already uses -- and\n"
"#     reproduced the GPU's ciphertext. That separates the schedule from the round\n"
"#     function; the schedule itself is covered by the FIPS-197 anchor above.\n"
"#\n"
"#   all three rows: a known key was planted inside the searched range and the kernel\n"
"#     was required to report exactly that candidate and no other. A search kernel that\n"
"#     finds nothing runs at a very attractive speed.\n"
"#\n"
"# The verification runs the same __device__ function the timed kernel runs, so there is\n"
"# no second copy of a key schedule that could drift from the measured one.\n"
"#\n";

/* Write a finished v2 file: temp path, then rename() onto the real one.
 *
 * Called only after the whole run has succeeded, which is the point. These headers
 * assert that verification passed, so the file must not exist at all until it has --
 * `fopen(path, "w")` up front truncates any previous good file and leaves a short one
 * behind wearing that assertion when a kernel check calls exit(). bench/ctr_bench.c
 * settled on this same shape ("No partial CSV, ever") for the same reason. */
static int write_v2_csv(const char *path, const char *role, bool campaign,
                        const cudaDeviceProp &prop, const char *params,
                        const char *note, const char *columns,
                        const std::vector<std::string> &rows)
{
    std::string tmp = std::string(path) + ".tmp";
    FILE *fp = std::fopen(tmp.c_str(), "w");
    if (!fp) { std::perror(tmp.c_str()); return 1; }

    write_provenance(fp, role, campaign, prop, params);
    std::fputs(note, fp);
    std::fprintf(fp, "%s\n", columns);
    for (const std::string &row : rows) std::fputs(row.c_str(), fp);

    /* Both conditions evaluated: fclose must run even when ferror already failed. */
    int failed = std::ferror(fp) != 0;
    if (std::fclose(fp) != 0) failed = 1;
    if (failed) {
        std::fprintf(stderr, "gpu_bench: writing %s failed\n", tmp.c_str());
        std::remove(tmp.c_str());
        return 1;
    }
    if (std::rename(tmp.c_str(), path) != 0) {
        std::perror(path);
        std::remove(tmp.c_str());
        return 1;
    }
    std::printf("  wrote %s (%zu rows)\n", path, rows.size());
    return 0;
}

int main(int argc, char **argv)
{
    size_t blocks = 1u << 20;
    unsigned long long candidates = 1ull << 24;
    const char *csv_path = nullptr;
    const char *block_eval_path = nullptr;
    const char *master_key_path = nullptr;
    bool self_test_only = false;
    bool campaign = false;

    for (int i = 1; i < argc; i++) {
        if (!std::strcmp(argv[i], "--blocks") && i + 1 < argc) {
            blocks = (size_t)std::strtoull(argv[++i], nullptr, 0);
        } else if (!std::strcmp(argv[i], "--candidates") && i + 1 < argc) {
            candidates = std::strtoull(argv[++i], nullptr, 0);
        } else if (!std::strcmp(argv[i], "--csv") && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (!std::strcmp(argv[i], "--block-eval-csv") && i + 1 < argc) {
            block_eval_path = argv[++i];
        } else if (!std::strcmp(argv[i], "--master-key-csv") && i + 1 < argc) {
            master_key_path = argv[++i];
        } else if (!std::strcmp(argv[i], "--self-test")) {
            self_test_only = true;
        } else if (!std::strcmp(argv[i], "--campaign")) {
            campaign = true;
        } else {
            std::fprintf(stderr,
                         "usage: %s [--blocks N] [--candidates N] [--campaign]\n"
                         "          [--csv PATH]              legacy block-evaluation CSV\n"
                         "          [--block-eval-csv PATH]   v2 block-evaluation CSV\n"
                         "          [--master-key-csv PATH]   v2 master-key-search CSV\n"
                         "          [--self-test]             kernels only, no CSV\n",
                         argv[0]);
            return 2;
        }
    }
    if (blocks < 1024) blocks = 1024;
    if (candidates < THREADS) candidates = THREADS;

    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    CUDA_CHECK(cudaSetDevice(0));
    if (self_test_only)
        std::printf("GPU: %s, cc %d.%d, %llu candidates per self-test search\n",
                    prop.name, prop.major, prop.minor, candidates);
    else
        std::printf("GPU: %s, cc %d.%d, %zu blocks per timed row\n",
                    prop.name, prop.major, prop.minor, blocks);

    /* The self-test is not an optional extra mode: nothing here writes a master-key
     * number without having first reproduced the specification's own vectors. A search
     * kernel that finds nothing is extremely fast. */
    if (self_test_only || master_key_path) {
        std::puts("master-key self-test:");
        mk_selftest_present80_published();
    }

    if (self_test_only) {
        CsvSink none = {nullptr, true, nullptr};
        run_master_key_search(&none, candidates);
        std::puts("master-key self-test: OK");
        return 0;
    }

    /* No output file named: run the legacy block-evaluation sweep to stdout, which is
     * what this binary did before it grew modes. */
    const bool legacy_run = csv_path || (!block_eval_path && !master_key_path);

    char params[256];

    if (legacy_run || block_eval_path) {
        /* The legacy shape keeps the two extra reference round counts (aes-r10,
         * aes-lin444-0-8-15-r5) that results/gpu-speed*.csv and
         * docs/gpu-optimizations.md were built from. The v2 shape carries exactly the
         * seven ciphers tools/cipher_set.py defines and nothing else, because it is
         * the file a cross-construction table is built from. */
        std::vector<std::string> rows;
        CsvSink legacy = {nullptr, false, nullptr};
        CsvSink v2 = {nullptr, true, &rows};

        if (csv_path) {
            legacy.fp = std::fopen(csv_path, "w");
            if (!legacy.fp) { std::perror(csv_path); return 1; }
            std::fprintf(legacy.fp,
                         "cipher,impl,rounds,block_bits,blocks,gb_per_sec,ns_per_block\n");
        }

        if (legacy_run) {
            std::puts("block evaluation (legacy shape):");
            Variant64 v64[] = {
                {"present-80-r16", "variants/present-80-r16.json", 16, 4,
                 LIN64_PRESENT_PBOX, {0, 0, 0}},
                {"present-80-lin444-297-r7", "variants/present-80-lin444-297-r7.json", 7, 4,
                 LIN64_LIN444_16, {2, 9, 7}},
                {"cipher-D-r8", "variants/cipher-D.json", 8, 8,
                 LIN64_CIPHERD_TRANSPOSE, {0, 0, 0}},
                {"cipher-D-lin444-297-r5", "variants/cipher-D-lin444-297-r5.json", 5, 8,
                 LIN64_LIN444_16, {2, 9, 7}},
                {"cipher-D-AES-lin444-297-r5", "variants/cipher-D-lin444-297-aes-r5.json", 5, 8,
                 LIN64_LIN444_16, {2, 9, 7}},
            };
            Variant128 v128[] = {
                {"aes-r5", 5, false, {0, 0, 0}},
                {"aes-lin444-0-8-15-r4", 4, true, {0, 8, 15}},
                {"aes-r10", 10, false, {0, 0, 0}},
                {"aes-lin444-0-8-15-r5", 5, true, {0, 8, 15}},
            };
            bench64<16, 4, LIN64_PRESENT_PBOX, 0, 0, 0>(&legacy, v64[0], blocks);
            bench64<7, 4, LIN64_LIN444_16, 2, 9, 7>(&legacy, v64[1], blocks);
            bench64<8, 8, LIN64_CIPHERD_TRANSPOSE, 0, 0, 0>(&legacy, v64[2], blocks);
            bench64<5, 8, LIN64_LIN444_16, 2, 9, 7>(&legacy, v64[3], blocks);
            bench64<5, 8, LIN64_LIN444_16, 2, 9, 7>(&legacy, v64[4], blocks);
            bench_aes<5, false, 0, 0, 0>(&legacy, v128[0], blocks);
            bench_aes<4, true, 0, 8, 15>(&legacy, v128[1], blocks);
            bench_aes<10, false, 0, 0, 0>(&legacy, v128[2], blocks);
            bench_aes<5, true, 0, 8, 15>(&legacy, v128[3], blocks);
            if (legacy.fp) std::fclose(legacy.fp);
        }
        if (block_eval_path) {
            std::puts("block evaluation (the seven constructions):");
            run_block_eval(&v2, blocks);
            emit_portfolio_gaps(&v2);
            std::snprintf(params, sizeof params, "blocks_per_row: %zu", blocks);
            if (write_v2_csv(block_eval_path,
                             "CUDA block evaluation, all seven constructions",
                             campaign, prop, params, BLOCK_EVAL_NOTE,
                             "cipher,impl,rounds,block_bits,blocks,gb_per_sec,ns_per_block,"
                             "block_evals_per_sec,block_evals_in_4h,status,note",
                             rows) != 0)
                return 1;
        }
    }

    if (master_key_path) {
        std::vector<std::string> rows;
        CsvSink v2 = {nullptr, true, &rows};
        std::puts("master-key search:");
        run_master_key_search(&v2, candidates);

        /* Only now, with every check passed and every row measured, does the file come
         * into existence. See write_v2_csv(). */
        std::string note = std::string(MASTER_KEY_NOTE) + MK_EXCLUSION_NOTE + "#\n";
        std::snprintf(params, sizeof params, "candidates_per_row: %llu", candidates);
        if (write_v2_csv(master_key_path, "CUDA master-key search", campaign, prop,
                         params, note.c_str(),
                         "cipher,rounds,key_bits,key_model,candidates,"
                         "master_key_candidates_per_sec,master_key_candidates_in_4h",
                         rows) != 0)
            return 1;
    }

    return 0;
}
