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

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

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

    size_t base = ((size_t)blockIdx.x * blockDim.x + threadIdx.x) * ILP;
    uint64_t s[ILP];
    #pragma unroll
    for (int j = 0; j < ILP; j++)
        s[j] = (base + j < n) ? in[base + j] : 0;
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
    for (int j = 0; j < ILP; j++)
        if (base + j < n) out[base + j] = s[j] ^ k;
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

    size_t base = ((size_t)blockIdx.x * blockDim.x + threadIdx.x) * ILP;
    uint64_t s[ILP];
    #pragma unroll
    for (int j = 0; j < ILP; j++)
        s[j] = (base + j < n) ? in[base + j] : 0;

    #pragma unroll
    for (int r = 0; r < ROUNDS; r++) {
        uint64_t k = c_rk64[r];
        #pragma unroll
        for (int j = 0; j < ILP; j++)
            s[j] = round64_byte_table(tab, s[j] ^ k);
    }

    uint64_t k = c_rk64[ROUNDS];
    #pragma unroll
    for (int j = 0; j < ILP; j++)
        if (base + j < n) out[base + j] = s[j] ^ k;
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

    size_t base = ((size_t)blockIdx.x * blockDim.x + threadIdx.x) * ILP;
    U128 s[ILP];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        s[j].w[0] = s[j].w[1] = s[j].w[2] = s[j].w[3] = 0;
        if (base + j < n) s[j] = in[base + j];
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
    for (int j = 0; j < ILP; j++)
        if (base + j < n) out[base + j] = u128_xor(s[j], k);
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

    size_t base = ((size_t)blockIdx.x * blockDim.x + threadIdx.x) * ILP;
    U128 s[ILP];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        s[j].w[0] = s[j].w[1] = s[j].w[2] = s[j].w[3] = 0;
        if (base + j < n) s[j] = in[base + j];
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
    for (int j = 0; j < ILP; j++)
        if (base + j < n) out[base + j] = u128_xor(s[j], k);
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

    size_t base = ((size_t)blockIdx.x * blockDim.x + threadIdx.x) * ILP;
    U128 s[ILP];
    #pragma unroll
    for (int j = 0; j < ILP; j++) {
        s[j].w[0] = s[j].w[1] = s[j].w[2] = s[j].w[3] = 0;
        if (base + j < n) s[j] = u128_xor(in[base + j], c_rk128[0]);
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
        if (base + j < n) out[base + j] = u128_xor(t, k);
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

static void emit(FILE *csv, const char *cipher, const char *impl, int rounds,
                 int block_bits, size_t blocks, double ms)
{
    double bytes = (double)blocks * (block_bits / 8);
    double gbps = bytes / (ms * 1.0e6);
    double ns_block = ms * 1.0e6 / (double)blocks;
    std::printf("  %-28s %-12s r=%-3d %8.2f GB/s %8.3f ns/block\n",
                cipher, impl, rounds, gbps, ns_block);
    if (csv)
        std::fprintf(csv, "%s,%s,%d,%d,%zu,%.6f,%.6f\n",
                     cipher, impl, rounds, block_bits, blocks, gbps, ns_block);
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
static void bench64(FILE *csv, const Variant64 &v, size_t blocks)
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
static void bench_aes(FILE *csv, const Variant128 &v, size_t blocks)
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

int main(int argc, char **argv)
{
    size_t blocks = 1u << 20;
    const char *csv_path = nullptr;
    for (int i = 1; i < argc; i++) {
        if (!std::strcmp(argv[i], "--blocks") && i + 1 < argc) {
            blocks = (size_t)std::strtoull(argv[++i], nullptr, 0);
        } else if (!std::strcmp(argv[i], "--csv") && i + 1 < argc) {
            csv_path = argv[++i];
        } else {
            std::fprintf(stderr, "usage: %s [--blocks N] [--csv PATH]\n", argv[0]);
            return 2;
        }
    }
    if (blocks < 1024) blocks = 1024;

    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    CUDA_CHECK(cudaSetDevice(0));
    std::printf("GPU: %s, cc %d.%d, %zu blocks per timed row\n",
                prop.name, prop.major, prop.minor, blocks);

    FILE *csv = nullptr;
    if (csv_path) {
        csv = std::fopen(csv_path, "w");
        if (!csv) {
            std::perror(csv_path);
            return 1;
        }
        std::fprintf(csv, "cipher,impl,rounds,block_bits,blocks,gb_per_sec,ns_per_block\n");
    }

    Variant64 v64[] = {
        {"present-80-r16", "variants/present-80-r16.json", 16, 4, LIN64_PRESENT_PBOX, {0, 0, 0}},
        {"present-80-lin444-297-r7", "variants/present-80-lin444-297-r7.json", 7, 4, LIN64_LIN444_16, {2, 9, 7}},
        {"cipher-D-r8", "variants/cipher-D.json", 8, 8, LIN64_CIPHERD_TRANSPOSE, {0, 0, 0}},
        {"cipher-D-lin444-297-r5", "variants/cipher-D-lin444-297-r5.json", 5, 8, LIN64_LIN444_16, {2, 9, 7}},
        {"cipher-D-AES-lin444-297-r5", "variants/cipher-D-lin444-297-aes-r5.json", 5, 8, LIN64_LIN444_16, {2, 9, 7}},
    };
    Variant128 v128[] = {
        {"aes-r5", 5, false, {0, 0, 0}},
        {"aes-lin444-0-8-15-r4", 4, true, {0, 8, 15}},
        {"aes-r10", 10, false, {0, 0, 0}},
        {"aes-lin444-0-8-15-r5", 5, true, {0, 8, 15}},
    };

    std::puts("64-bit candidates:");
    bench64<16, 4, LIN64_PRESENT_PBOX, 0, 0, 0>(csv, v64[0], blocks);
    bench64<7, 4, LIN64_LIN444_16, 2, 9, 7>(csv, v64[1], blocks);
    bench64<8, 8, LIN64_CIPHERD_TRANSPOSE, 0, 0, 0>(csv, v64[2], blocks);
    bench64<5, 8, LIN64_LIN444_16, 2, 9, 7>(csv, v64[3], blocks);
    bench64<5, 8, LIN64_LIN444_16, 2, 9, 7>(csv, v64[4], blocks);
    std::puts("128-bit candidates:");
    bench_aes<5, false, 0, 0, 0>(csv, v128[0], blocks);
    bench_aes<4, true, 0, 8, 15>(csv, v128[1], blocks);
    bench_aes<10, false, 0, 0, 0>(csv, v128[2], blocks);
    bench_aes<5, true, 0, 8, 15>(csv, v128[3], blocks);

    if (csv) std::fclose(csv);
    return 0;
}
