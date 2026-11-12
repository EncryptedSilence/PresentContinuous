/* Implementations in the 32-bit ARM builds (arm/Makefile): CA_M4 (Cortex-M4,
 * ARMv7E-M Thumb-2) or CA_A7 (Cortex-A7, ARMv7-A + NEON). The ascon-c entries
 * are the designers' implementations compiled unmodified; the list per target is
 * the set whose `architectures` file admits it and that builds for that ISA. */
#include "ascon_aead.h"
#include "blockctr.h"
#include "chacha20.h"
#include "qalqan.h"

void chacha20_xor_lazy(uint8_t *, const uint8_t *, size_t, const uint8_t[32], const uint8_t[12], uint32_t);
#ifdef CA_M4
void chacha20_xor_m4(uint8_t *, const uint8_t *, size_t, const uint8_t[32], const uint8_t[12], uint32_t);
#endif
#ifdef CA_A7
void chacha20_xor_neon_x4(uint8_t *, const uint8_t *, size_t, const uint8_t[32], const uint8_t[12], uint32_t);
#endif

const chacha20_impl chacha20_impls[] = {
    {"ref", chacha20_xor_ref, 0, 1},
    {"lazy-rot", chacha20_xor_lazy, 0, 1},
#ifdef CA_M4
    {"m4-asm", chacha20_xor_m4, 0, 1},
#endif
#ifdef CA_A7
    {"neon-x4", chacha20_xor_neon_x4, 0, 4},
#endif
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
#define SINGLE(v) {"ascon-c/" #v, ascon_c_##v##_encrypt, ascon_c_##v##_decrypt, 0, 0, 1},

/* ASCON_C_LIST is passed by the Makefile as X(name) X(name) ... */
#define X(v) ASCON_C(v)
ASCON_C_LIST
#undef X

void ascon_multi_scalar_x1(const ascon_job *, size_t, size_t, size_t);
void ascon_multi_scalar_x2(const ascon_job *, size_t, size_t, size_t);
#ifdef CA_A7
void ascon_multi_neon_x2(const ascon_job *, size_t, size_t, size_t);
#endif

const ascon_impl ascon_impls[] = {
#define X(v) SINGLE(v)
    ASCON_C_LIST
#undef X
    {"scalar64-x1", 0, 0, ascon_multi_scalar_x1, 0, 1},
    {"scalar64-x2", 0, 0, ascon_multi_scalar_x2, 0, 2},
#ifdef CA_A7
    {"neon-x2", 0, 0, ascon_multi_neon_x2, 0, 2},
#endif
    {0, 0, 0, 0, 0, 0},
};

/* ---- 128-bit block ciphers in CTR mode (include/blockctr.h) ----
 * Portable C for now; Cortex-M4 / Cortex-A7 kernels go here under CA_M4 / CA_A7,
 * as for ChaCha20 above. */
#define BC_DECL(f) void f(const void *, uint8_t *, const uint8_t *, size_t, const uint8_t[12], uint32_t);
void aes128_setup_ref(void *, const uint8_t *);
void aes128_setup_ttable(void *, const uint8_t *);
void qalqan_setup_ref(void *, const uint8_t *);
BC_DECL(aes128_ctr_ref)
BC_DECL(aes128_ctr_ttable)
BC_DECL(qalqan_ctr_ref)
void aes256_setup_ref(void *, const uint8_t *);
void aes256_setup_ttable(void *, const uint8_t *);
BC_DECL(aes256_ctr_ref)
BC_DECL(aes256_ctr_ttable)
#ifdef HAVE_QALQAN_ARM
BC_DECL(qalqan_ctr_cunroll) /* portable C, src/qalqan/qalqan_cfast.c (not distributed) */
#endif
#ifdef CA_M4
/* Schwabe-Stoffelen Thumb-2 AES (src/aes/aes128_m4ss.c, third_party_m4/) and
 * the Qalqan Thumb-2 kernels (src/qalqan/qalqan_m4.c, qalqan_m4_core.S) */
void aes128_setup_m4ss(void *, const uint8_t *);
void aes128_setup_m4ss_sram(void *, const uint8_t *);
void aes128_setup_m4ss_loop(void *, const uint8_t *);
void aes128_setup_m4ss_loop_sram(void *, const uint8_t *);
void aes128_setup_m4ss_bs(void *, const uint8_t *);
BC_DECL(aes128_ctr_m4ss)
BC_DECL(aes128_ctr_m4ss_sram)
BC_DECL(aes128_ctr_m4ss_loop)
BC_DECL(aes128_ctr_m4ss_loop_sram)
BC_DECL(aes128_ctr_m4ss_bs)
BC_DECL(aes256_ctr_m4ss_loop)
BC_DECL(aes256_ctr_m4ss_loop_sram)
#ifdef HAVE_QALQAN_M4
BC_DECL(qalqan_ctr_m4_x1)
BC_DECL(qalqan_ctr_m4_x1_flash)
BC_DECL(qalqan_ctr_m4_x1_unr)
BC_DECL(qalqan_ctr_m4_x2)
#endif
#define AES_M4SS_BS_CTX 352 /* 11 bitsliced round keys x 32 B */
#endif

const bc_impl bc_impls[] = {
    {"aes128-ctr", "ref", 1, 16, sizeof(aes128_ctx), aes128_setup_ref, aes128_ctr_ref, 0},
    {"aes128-ctr", "ttable", 1, 16, sizeof(aes128_tt_ctx), aes128_setup_ttable, aes128_ctr_ttable, 0},
    /* CA_M4 / CA_A7 AES-128-CTR kernels: here */
#ifdef CA_M4
    {"aes128-ctr", "m4ss-tt", 1, 16, sizeof(aes128_tt_ctx), aes128_setup_m4ss, aes128_ctr_m4ss, 0},
    {"aes128-ctr", "m4ss-tt-sram", 1, 16, sizeof(aes128_tt_ctx), aes128_setup_m4ss_sram, aes128_ctr_m4ss_sram, 0},
    {"aes128-ctr", "m4ss-ttl", 1, 16, sizeof(aes128_tt_ctx), aes128_setup_m4ss_loop, aes128_ctr_m4ss_loop, 0},
    {"aes128-ctr", "m4ss-ttl-sram", 1, 16, sizeof(aes128_tt_ctx), aes128_setup_m4ss_loop_sram, aes128_ctr_m4ss_loop_sram, 0},
    {"aes128-ctr", "m4ss-bs", 2, 16, AES_M4SS_BS_CTX, aes128_setup_m4ss_bs, aes128_ctr_m4ss_bs, 0},
    {"aes256-ctr", "m4ss-ttl", 1, 32, 60 * sizeof(uint32_t), aes256_setup_ttable, aes256_ctr_m4ss_loop, 0},
    {"aes256-ctr", "m4ss-ttl-sram", 1, 32, 60 * sizeof(uint32_t), aes256_setup_ttable, aes256_ctr_m4ss_loop_sram, 0},
#endif
    {"aes256-ctr", "ref", 1, 32, sizeof(aes256_ctx), aes256_setup_ref, aes256_ctr_ref, 0},
    {"aes256-ctr", "ttable", 1, 32, 60 * sizeof(uint32_t), aes256_setup_ttable, aes256_ctr_ttable, 0},
    {"qalqan-ctr", "ref", 1, 32, sizeof(qalqan_ctx), qalqan_setup_ref, qalqan_ctr_ref, 0},
    /* accelerated Qalqan-CTR kernels (not distributed): registered when built */
#ifdef HAVE_QALQAN_ARM
    {"qalqan-ctr", "c-unroll", 1, 32, sizeof(qalqan_ctx), qalqan_setup_ref, qalqan_ctr_cunroll, 0},
#endif
#ifdef HAVE_QALQAN_M4
    {"qalqan-ctr", "m4-x1", 1, 32, sizeof(qalqan_ctx), qalqan_setup_ref, qalqan_ctr_m4_x1, 0},
    {"qalqan-ctr", "m4-x1-flash", 1, 32, sizeof(qalqan_ctx), qalqan_setup_ref, qalqan_ctr_m4_x1_flash, 0},
    {"qalqan-ctr", "m4-x1-unr", 1, 32, sizeof(qalqan_ctx), qalqan_setup_ref, qalqan_ctr_m4_x1_unr, 0},
    {"qalqan-ctr", "m4-x2", 2, 32, sizeof(qalqan_ctx), qalqan_setup_ref, qalqan_ctr_m4_x2, 0},
#endif
    {0, 0, 0, 0, 0, 0, 0, 0},
};
