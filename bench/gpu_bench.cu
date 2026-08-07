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
