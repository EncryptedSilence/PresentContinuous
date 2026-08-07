/* Variant descriptor: what makes one PRESENT-like cipher differ from another.
 *
 * Descriptors are generated from variants/ *.json by tools/gen_variants.py, so the
 * C implementations and the SAT analysis always agree on what a variant is.
 */
#ifndef PRESENT_VARIANT_H
#define PRESENT_VARIANT_H

#include <stddef.h>
#include <stdint.h>

#define PRESENT_BLOCK_BITS 64
#define PRESENT_MAX_ROUNDS 31

/* The S-box width is per variant: 4 bits for PRESENT and its relatives, 8 for a
 * byte-oriented design such as cipher-D. The descriptor carries the table at full
 * width and says how much of it is meaningful. */
#define PRESENT_MAX_SBOX_BITS 8
#define PRESENT_MAX_SBOX_ENTRIES (1 << PRESENT_MAX_SBOX_BITS)

/* The nibble-oriented bitsliced kernels are hard-wired to 4-bit S-boxes: their
 * generated bodies index the state as 4 * i + k. They are only ever instantiated for
 * variants of that width, and a variant the synthesiser cannot handle carries
 * kernel_enc = PRESENT_NO_KERNEL instead. */
#define PRESENT_BS_SBOX_BITS 4
#define PRESENT_BS_N_SBOXES (PRESENT_BLOCK_BITS / PRESENT_BS_SBOX_BITS)
#define PRESENT_NO_KERNEL (-1)

typedef enum {
    PRESENT_KS_80 = 0,
    PRESENT_KS_128 = 1,
    /* No schedule at all: the caller supplies (rounds + 1) * 64 bits of key material
     * and each round key is read off directly. */
    PRESENT_KS_INDEPENDENT = 2
} present_ks_t;

/* How the linear layer is built. Both kinds are described by lin_col below; the
 * kind only selects which specialised code path the bitsliced implementation uses,
 * since there a permutation is free (register renaming) and lin444 is not. */
typedef enum {
    PRESENT_LIN_PBOX = 0,   /* a bit permutation: pbox[] is meaningful */
    PRESENT_LIN_444 = 1     /* the ShiftGen2 lin444_r1 XOR-rotate layer */
} present_lin_t;

/* lin444 reads the state as PRESENT_LIN444_WORDS words of PRESENT_LIN444_WORD_BITS
 * bits; word w bit k is state bit w * PRESENT_LIN444_WORD_BITS + k. */
#define PRESENT_LIN444_WORDS 4
#define PRESENT_LIN444_WORD_BITS (PRESENT_BLOCK_BITS / PRESENT_LIN444_WORDS)

typedef struct {
    const char *name;
    const char *description;

    /* sbox[x] is the S-box; sbox_inv is its inverse. Both generated. Only the first
     * 1 << sbox_bits entries are meaningful; the rest are zero. */
    int sbox_bits;
    int n_sboxes;                  /* PRESENT_BLOCK_BITS / sbox_bits */
    uint8_t sbox[PRESENT_MAX_SBOX_ENTRIES];
    uint8_t sbox_inv[PRESENT_MAX_SBOX_ENTRIES];

    /* pbox[i] is the destination of state bit i (bit 0 = LSB); pbox_inv its inverse.
     * Meaningful only when lin_kind == PRESENT_LIN_PBOX; otherwise the identity. */
    uint8_t pbox[PRESENT_BLOCK_BITS];
    uint8_t pbox_inv[PRESENT_BLOCK_BITS];

    present_lin_t lin_kind;
    /* Rotation constants, lin444 only. */
    int lin_c0[3];
    /* Column form of the linear layer, filled for every kind: input bit i
     * contributes lin_col[i] to the output, so L(x) is the XOR of the columns
     * selected by the set bits of x. For a permutation each column is a single
     * bit, which is why one code path serves both. */
    uint64_t lin_col[PRESENT_BLOCK_BITS];
    uint64_t lin_col_inv[PRESENT_BLOCK_BITS];

    int rounds;
    int key_bits;
    present_ks_t key_schedule;

    /* Index into the generated bitslice circuit table, for sbox and sbox_inv, or
     * PRESENT_NO_KERNEL when no circuit was synthesised for this S-box. */
    int circuit_enc;
    int circuit_dec;

    /* Index into the generated bitsliced kernel tables, or PRESENT_NO_KERNEL. A kernel
     * is a whole round function with the S-box circuit *and* the linear layer fixed at
     * compile time, so every register index in it is an immediate. See
     * PRESENT_KERNEL_ENC_LIST. */
    int kernel_enc;
    int kernel_dec;
} present_variant_t;

/* Registry, defined in the generated src/gen/variants_gen.c */
extern const present_variant_t present_variants[];
extern const int present_n_variants;

const present_variant_t *present_variant_by_name(const char *name);

/* Returns 0 if the descriptor is self-consistent (permutations, inverses, key size),
 * otherwise a negative error code. Used by the test suite and by present_init. */
int present_variant_check(const present_variant_t *v);

/* Key bytes present_init expects for this variant. */
size_t present_variant_key_bytes(const present_variant_t *v);

/* Whether the bitsliced and AVX2 backends have a round function for this variant.
 * False when no S-box circuit could be synthesised -- the table and reference paths
 * still work. Callers must check rather than silently getting a wrong answer.
 *
 * Two predicates, because not every bitsliced backend has both directions. The
 * plain form requires an encrypt *and* a decrypt kernel and is what a caller of
 * present_encrypt_bitslice / present_decrypt_bitslice needs. The _enc form requires
 * only the encrypt kernel and is what the encryption-only backends need --
 * bitslice32 and AVX2. Gating an encryption-only path on the plain predicate is a
 * silent loss of coverage: a variant with a kernel_enc but no kernel_dec would skip
 * its cross-check against the reference cipher rather than fail it. No such variant
 * exists today (every generated variant has both), which is exactly why the
 * distinction has to be in the API rather than in a caller's head.
 *
 * The _enc form is `static inline` here rather than a second function in
 * src/variant.c on purpose. --gc-sections runs at object granularity in the
 * firmware build (there is no -ffunction-sections), so an unreferenced function in
 * variant.c is linked anyway: adding one moved every subsequent address in the
 * Cortex-M4 images and changed all three ELF sha256 recorded in
 * results/m4-speed.csv, which is a republished benchmark for a predicate the
 * firmware never calls. Inline in the header, it costs nothing where it is not
 * used. */
int present_variant_has_bitslice(const present_variant_t *v);

static inline int present_variant_has_bitslice_enc(const present_variant_t *v)
{
    return v && v->kernel_enc != PRESENT_NO_KERNEL;
}

#endif /* PRESENT_VARIANT_H */
