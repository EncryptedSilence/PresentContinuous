// Shared CUDA benchmark harness: error check, in-kernel SM clock record, SM clock
// probe, warm-up/timed launch loop with median CUDA-event time, and the CSV/console
// row writer. Included (once, as a header-only translation-unit part) by ca_gpu.cu
// (ChaCha20/Ascon) and bc_gpu.cu (AES-128/Qalqan/PRESENT-80 CTR), so both report
// with the same protocol and the same CSV columns.
#ifndef GPU_HARNESS_CUH
#define GPU_HARNESS_CUH
#include <cuda_runtime.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>

#define CK(x)                                                                            \
    do {                                                                                 \
        cudaError_t e_ = (x);                                                            \
        if (e_ != cudaSuccess) {                                                         \
            fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, #x, cudaGetErrorString(e_)); \
            exit(1);                                                                     \
        }                                                                                \
    } while (0)

// ---------------------------------------------------- in-kernel clock record
// For the SM clock *during encryption*: when g_clk is set (one extra launch per
// row, after the timed ones), lane 0 of every warp folds clock64() and
// %globaltimer at entry/exit into per-SM min/max. clock64() is a per-SM counter,
// so each SM's span gives (cycles, ns) on that SM; %smid identifies it. Every
// kernel is a template on CLK: the timed launches use <false>, which compiles
// to exactly the uninstrumented code (an RAII guard in it was measured to push
// ChaCha's keystream array onto the stack); the clock launch uses <true>.
struct clk_rec { unsigned long long c0, c1, g0, g1; };
__device__ clk_rec *g_clk;
__device__ __forceinline__ unsigned smid_() { unsigned r; asm volatile("mov.u32 %0, %%smid;" : "=r"(r)); return r; }
__device__ __forceinline__ unsigned long long gtimer_()
{
    unsigned long long t;
    asm volatile("mov.u64 %0, %%globaltimer;" : "=l"(t));
    return t;
}
template <bool CLK> struct clk_scope {};  // timed launches: nothing at all
template <> struct clk_scope<true> {
    clk_rec *r = nullptr;
    __device__ clk_scope()
    {
        if ((threadIdx.x & 31) == 0 && g_clk) {
            r = g_clk + smid_();
            atomicMin(&r->g0, gtimer_());
            atomicMin(&r->c0, (unsigned long long)clock64());
        }
    }
    __device__ ~clk_scope()
    {
        if (r) {
            atomicMax(&r->c1, (unsigned long long)clock64());
            atomicMax(&r->g1, gtimer_());
        }
    }
};

// SM clock probe: one block per SM spins for a fixed number of SM cycles; the
// event-timed duration gives the clock the SMs actually ran at. Needed because a
// laptop GPU's clock is whatever its power management decides (see the CSV note).
__global__ void k_spin(long long cycles, int *sink)
{
    long long t0 = clock64();
    while (clock64() - t0 < cycles) {}
    if (threadIdx.x == 0 && blockIdx.x == 0) *sink = 1;
}

// ------------------------------------------------------------------ harness
static FILE *csv;
static cudaDeviceProp prop;
static double mhz_before, kern_mhz;
static int kern_sms;
static double sm_mhz(void);

// One extra launch with g_clk set: per-SM (cycles / ns) over that SM's active
// span, median over the SMs that ran any warp.
template <class F>
static void kernel_clock(F launch)
{
    const int maxsm = 1024;
    std::vector<clk_rec> h(maxsm, clk_rec{~0ULL, 0, ~0ULL, 0});
    clk_rec *d;
    CK(cudaMalloc(&d, maxsm * sizeof(clk_rec)));
    CK(cudaMemcpy(d, h.data(), maxsm * sizeof(clk_rec), cudaMemcpyHostToDevice));
    CK(cudaMemcpyToSymbol(g_clk, &d, sizeof d));
    launch();
    CK(cudaDeviceSynchronize());
    clk_rec *null = nullptr;
    CK(cudaMemcpyToSymbol(g_clk, &null, sizeof null));
    CK(cudaMemcpy(h.data(), d, maxsm * sizeof(clk_rec), cudaMemcpyDeviceToHost));
    CK(cudaFree(d));
    std::vector<double> mhz;
    for (const clk_rec &r : h)
        if (r.c1 > r.c0 && r.g1 > r.g0 + 2000)  // >= 2 us of span: globaltimer granularity
            mhz.push_back((double)(r.c1 - r.c0) / (double)(r.g1 - r.g0) * 1e3);
    kern_sms = (int)mhz.size();
    kern_mhz = mhz.empty() ? NAN : (std::sort(mhz.begin(), mhz.end()), mhz[mhz.size() / 2]);
}

static float median_ms(std::vector<float> v)
{
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

template <class F, class G>
static float time_kernel(F launch, G launch_clk)
{
    mhz_before = sm_mhz();
    cudaEvent_t a, b;
    CK(cudaEventCreate(&a));
    CK(cudaEventCreate(&b));
    for (int i = 0; i < 5; i++) launch();
    CK(cudaDeviceSynchronize());
    std::vector<float> t;
    for (int i = 0; i < 15; i++) {
        CK(cudaEventRecord(a));
        launch();
        CK(cudaEventRecord(b));
        CK(cudaEventSynchronize(b));
        float ms;
        CK(cudaEventElapsedTime(&ms, a, b));
        t.push_back(ms);
    }
    CK(cudaGetLastError());
    cudaEventDestroy(a);
    cudaEventDestroy(b);
    kernel_clock(launch_clk);
    return median_ms(t);
}

static int *d_sink;
static double sm_mhz(void)
{
    const long long cyc = 20000000;
    cudaEvent_t a, b;
    CK(cudaEventCreate(&a));
    CK(cudaEventCreate(&b));
    CK(cudaEventRecord(a));
    k_spin<<<prop.multiProcessorCount, 32>>>(cyc, d_sink);
    CK(cudaEventRecord(b));
    CK(cudaEventSynchronize(b));
    float ms;
    CK(cudaEventElapsedTime(&ms, a, b));
    cudaEventDestroy(a);
    cudaEventDestroy(b);
    return cyc / (ms * 1e3);
}

static void report(const char *cipher, const char *kernel, size_t msg_bytes, size_t total, float ms, const char *note)
{
    double gbs = total / (ms * 1e-3) / 1e9, mhz_after = sm_mhz();
    /* bytes per SM-cycle per SM, with the clock measured inside this kernel */
    double bpc = total / (ms * 1e-3) / (kern_mhz * 1e6) / prop.multiProcessorCount;
    printf("%-9s %-10s msg=%-9zu total=%-10zu %9.3f ms  %8.2f GB/s  %9.1f Gbit/s  SM(kernel) %4.0f MHz on %d SMs"
           "  probe %4.0f/%4.0f  %7.3f B/SM-cycle  %s\n",
           cipher, kernel, msg_bytes, total, ms, gbs, gbs * 8, kern_mhz, kern_sms, mhz_before, mhz_after, bpc, note);
    if (csv)
        fprintf(csv, "cuda,%s,%s,%zu,%zu,%.5f,%.3f,%.2f,%.0f,%d,%.0f,%.0f,%.4f,%s\n", cipher, kernel, msg_bytes, total, ms,
                gbs, gbs * 8, kern_mhz, kern_sms, mhz_before, mhz_after, bpc, note);
    fflush(stdout);
}

#endif
