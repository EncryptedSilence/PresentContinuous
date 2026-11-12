/* Implementations available on the x86-64 host build. */
#include "ascon_aead.h"
#include "blockctr.h"
#include "chacha20.h"
#include "qalqan.h"
#ifdef HAVE_QALQAN_X86 /* accelerated Qalqan kernels, not distributed */
#include "qalqan_x86.h"
#endif
#include "aes/aes128_bs.h"

static int have_avx2(void) { return __builtin_cpu_supports("avx2"); }

void chacha20_xor_avx2_x8(uint8_t *, const uint8_t *, size_t, const uint8_t[32],
                          const uint8_t[12], uint32_t);

const chacha20_impl chacha20_impls[] = {
    {"ref", chacha20_xor_ref, 0, 1},
    {"avx2-x8", chacha20_xor_avx2_x8, have_avx2, 8},
    {0, 0, 0, 0},
};

#define ASCON_C(v)                                                                     \
    int ascon_c_##v##_encrypt(unsigned char *, unsigned long long *, const unsigned char *, \
                              unsigned long long, const unsigned char *, unsigned long long, \
                              const unsigned char *, const unsigned char *,                  \
                              const unsigned char *);                                        \
    int ascon_c_##v##_decrypt(unsigned char *, unsigned long long *, unsigned char *,         \
                              const unsigned char *, unsigned long long,                     \
                              const unsigned char *, unsigned long long,                     \
                              const unsigned char *, const unsigned char *);
ASCON_C(ref)
ASCON_C(opt64)
ASCON_C(opt64_lowsize)
ASCON_C(opt32)
ASCON_C(bi32)
void ascon_multi_avx2_x4(const ascon_job *, size_t, size_t, size_t);
void ascon_multi_avx2_x8(const ascon_job *, size_t, size_t, size_t);
void ascon_multi_scalar_x1(const ascon_job *, size_t, size_t, size_t);
void ascon_multi_scalar_x2(const ascon_job *, size_t, size_t, size_t);
void ascon_multi_scalar_x4(const ascon_job *, size_t, size_t, size_t);

#define SINGLE(v) {"ascon-c/" #v, ascon_c_##v##_encrypt, ascon_c_##v##_decrypt, 0, 0, 1}
const ascon_impl ascon_impls[] = {
    SINGLE(ref),
    SINGLE(opt64),
    SINGLE(opt64_lowsize),
    SINGLE(opt32),
    SINGLE(bi32),
    {"avx2-x4", 0, 0, ascon_multi_avx2_x4, have_avx2, 4},
    {"avx2-x8", 0, 0, ascon_multi_avx2_x8, have_avx2, 8},
    {"scalar64-x1", 0, 0, ascon_multi_scalar_x1, 0, 1},
    {"scalar64-x2", 0, 0, ascon_multi_scalar_x2, 0, 2},
    {"scalar64-x4", 0, 0, ascon_multi_scalar_x4, 0, 4},
    {0, 0, 0, 0, 0, 0},
};

/* ---- 128-bit block ciphers in CTR mode (include/blockctr.h) ---- */
static int have_aesni(void) { return __builtin_cpu_supports("aes") && __builtin_cpu_supports("sse4.1"); }
static int have_vaes(void) { return __builtin_cpu_supports("vaes") && __builtin_cpu_supports("avx2"); }
static int have_gfni(void) { return __builtin_cpu_supports("gfni") && __builtin_cpu_supports("avx2"); }

#define BC_DECL(f) void f(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);
void aes128_setup_ref(void *, const uint8_t *);
void aes128_setup_ttable(void *, const uint8_t *);
void aes128_setup_ni(void *, const uint8_t *);
void aes128_setup_bs(void *, const uint8_t *);
void aes256_setup_ref(void *, const uint8_t *);
void aes256_setup_ni(void *, const uint8_t *);
void aes256_setup_bs(void *, const uint8_t *);
void qalqan_setup_ref(void *, const uint8_t *);
BC_DECL(aes128_ctr_ref)
BC_DECL(aes128_ctr_ttable)
BC_DECL(aes128_ctr_bs_x256)
BC_DECL(aes128_ctr_aesni_x8)
BC_DECL(aes128_ctr_vaes_x8)
BC_DECL(aes128_ctr_vaes_x12)
BC_DECL(aes128_ctr_vaes_x16)
BC_DECL(aes256_ctr_ref)
BC_DECL(aes256_ctr_bs_x256)
BC_DECL(aes256_ctr_aesni_x8)
BC_DECL(aes256_ctr_vaes_x8)
BC_DECL(aes256_ctr_vaes_x12)
BC_DECL(aes256_ctr_vaes_x16)
BC_DECL(qalqan_ctr_ref)
#ifdef HAVE_QALQAN_X86
void qalqan_setup_ttable(void *, const uint8_t *);
void qalqan_setup_gfni(void *, const uint8_t *);
void qalqan_setup_bitslice(void *, const uint8_t *);
BC_DECL(qalqan_ctr_ttable_x8)
BC_DECL(qalqan_ctr_bitslice_x64)
BC_DECL(qalqan_ctr_bitslice_x256)
BC_DECL(qalqan_ctr_gfni_x8)
BC_DECL(qalqan_ctr_gfni_x16)
BC_DECL(qalqan_ctr_gfni_x24)
BC_DECL(qalqan_ctr_gfni_x32)
#endif

const bc_impl bc_impls[] = {
    {"aes128-ctr", "ref", 1, 16, sizeof(aes128_ctx), aes128_setup_ref, aes128_ctr_ref, 0},
    {"aes128-ctr", "ttable", 1, 16, sizeof(aes128_tt_ctx), aes128_setup_ttable, aes128_ctr_ttable, 0},
    {"aes128-ctr", "bitslice-avx2-x256", 256, 16, sizeof(aes128_bs_ctx), aes128_setup_bs, aes128_ctr_bs_x256, have_avx2},
    {"aes128-ctr", "aesni-x8", 8, 16, sizeof(aes128_ctx), aes128_setup_ni, aes128_ctr_aesni_x8, have_aesni},
    {"aes128-ctr", "vaes-x8", 8, 16, sizeof(aes128_ctx), aes128_setup_ni, aes128_ctr_vaes_x8, have_vaes},
    {"aes128-ctr", "vaes-x12", 12, 16, sizeof(aes128_ctx), aes128_setup_ni, aes128_ctr_vaes_x12, have_vaes},
    {"aes128-ctr", "vaes-x16", 16, 16, sizeof(aes128_ctx), aes128_setup_ni, aes128_ctr_vaes_x16, have_vaes},
    {"aes256-ctr", "ref", 1, 32, sizeof(aes256_ctx), aes256_setup_ref, aes256_ctr_ref, 0},
    {"aes256-ctr", "bitslice-avx2-x256", 256, 32, sizeof(aes256_bs_ctx), aes256_setup_bs, aes256_ctr_bs_x256, have_avx2},
    {"aes256-ctr", "aesni-x8", 8, 32, sizeof(aes256_ctx), aes256_setup_ni, aes256_ctr_aesni_x8, have_aesni},
    {"aes256-ctr", "vaes-x8", 8, 32, sizeof(aes256_ctx), aes256_setup_ni, aes256_ctr_vaes_x8, have_vaes},
    {"aes256-ctr", "vaes-x12", 12, 32, sizeof(aes256_ctx), aes256_setup_ni, aes256_ctr_vaes_x12, have_vaes},
    {"aes256-ctr", "vaes-x16", 16, 32, sizeof(aes256_ctx), aes256_setup_ni, aes256_ctr_vaes_x16, have_vaes},
    {"qalqan-ctr", "ref", 1, 32, sizeof(qalqan_ctx), qalqan_setup_ref, qalqan_ctr_ref, 0},
#ifdef HAVE_QALQAN_X86
    {"qalqan-ctr", "ttable64k-x8", 8, 32, sizeof(qt_ctx), qalqan_setup_ttable, qalqan_ctr_ttable_x8, 0},
    {"qalqan-ctr", "bitslice-avx2-x64", 64, 32, sizeof(qb_ctx), qalqan_setup_bitslice, qalqan_ctr_bitslice_x64, have_avx2},
    {"qalqan-ctr", "bitslice-avx2-x256", 256, 32, sizeof(qb_ctx), qalqan_setup_bitslice, qalqan_ctr_bitslice_x256, have_avx2},
    {"qalqan-ctr", "gfni-x8", 8, 32, sizeof(qg_ctx), qalqan_setup_gfni, qalqan_ctr_gfni_x8, have_gfni},
    {"qalqan-ctr", "gfni-x16", 16, 32, sizeof(qg_ctx), qalqan_setup_gfni, qalqan_ctr_gfni_x16, have_gfni},
    {"qalqan-ctr", "gfni-x24", 24, 32, sizeof(qg_ctx), qalqan_setup_gfni, qalqan_ctr_gfni_x24, have_gfni},
    {"qalqan-ctr", "gfni-x32", 32, 32, sizeof(qg_ctx), qalqan_setup_gfni, qalqan_ctr_gfni_x32, have_gfni},
#endif
    {0, 0, 0, 0, 0, 0, 0, 0},
};
