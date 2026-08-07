/* fw/m4/kat.c -- the on-device correctness gate. See kat.h for the contract.
 *
 * Two things this file is careful about, both of which would otherwise show up
 * as a KAT failure and send the reader after the wrong bug:
 *
 *   Stack. Task 5 measured the all-in-one wide entry points (aes_encrypt_bs32,
 *   lin_encrypt_bs32) at 11,960 B and 12,296 B of stack -- they hold two
 *   128-word plane arrays and a 2,688-word expanded key schedule as locals --
 *   against 176 B and 520 B for the transpose-free _bs forms. Both forms are
 *   checked here, because Phase 4 reports both as separate rows and a gate that
 *   ran one call twice would clear two rows having told them apart in no way.
 *   The expensive form is confined to one noinline function per cipher and
 *   everything else -- state, scratch, expanded round keys, contexts, blocks --
 *   is static CCM storage, and fw/m4/kat_main.c reports the peak stack that
 *   resulted rather than an estimate. A bare-metal target with no MMU gives no
 *   warning when the stack grows into .bss; it just produces wrong answers,
 *   which in this file would look exactly like a KAT failure.
 *
 *   Ping-pong. present_encrypt_bitslice32_bs and the wide _bs kernels swap
 *   state and scratch every round and *return* the buffer holding the answer,
 *   which is `scratch` for an odd number of swaps. Every call below unpacks
 *   from the returned pointer, never from the buffer it passed in.
 *
 * Everything the gate needs lives in CCM RAM alongside the cipher context, in
 * the same memory the Phase 4 harness measures out of.
 */
#include "kat.h"

#include <stdint.h>
#include <string.h>

#include "present/present.h"
#include "semihost.h"
#include "wide_ciphers.h"
#include "wide_bitslice32.h"

#include "gen/kat_vectors.h"

/* Zero wait states, no DMA contention -- and the section the linker script
 * asserts a 64 KiB budget on. Nothing here may have an initialiser: .ccm is
 * NOLOAD and the reset handler does not zero it, so every buffer below is
 * written before it is read. */
#define CCM __attribute__((section(".ccmram")))

/* --- the (cipher, implementation) matrix ---------------------------------- */

enum { IMPL_REF, IMPL_TABLE, IMPL_TABLE_X4, IMPL_BS32, IMPL_BS32_BS,
       IMPL_BS64, IMPL_BS64_BS, N_IMPLS };

static const char *const IMPL_NAME[N_IMPLS] = {
    "ref", "table", "table-x4", "bitslice32", "bitslice32-bs",
    "bitslice64", "bitslice64-bs"
};

enum { ST_NOT_RUN = 0, ST_NA, ST_PASS, ST_FAIL };

/* Sized for the seven ciphers tools/cipher_set.py names, with room to spare;
 * an overflow is reported as a failure rather than truncating the run. */
#define MAX_CIPHERS 16

typedef struct {
    const char *name;
    int rounds;
    int block_bytes;
    int first;              /* index of this cipher's first row in KATS */
    int n;                  /* how many rows it has */
    uint8_t status[N_IMPLS];
} cipher_rec_t;

static cipher_rec_t ciphers[MAX_CIPHERS];
static int n_ciphers;
static int n_failures;
static int have_run;

/* --- working buffers, all static (see the file comment) ------------------- */

CCM static present_ctx_t ctx;
CCM static uint8_t keybuf[(PRESENT_MAX_ROUNDS + 1) * (PRESENT_BLOCK_BITS / 8)];
/* Sized for the wider of the two 64-bit-block bitslice paths: the u32 kernel
 * takes 32 blocks at a time, the u64 kernel 64. One pair of block buffers serves
 * both, the u32 checks using the first half. */
CCM static uint64_t in64[PRESENT_BITSLICE_BLOCKS];
CCM static uint64_t out64[PRESENT_BITSLICE_BLOCKS];
CCM static uint8_t in128[WIDE_BS32_BLOCKS * 16];
CCM static uint8_t out128[WIDE_BS32_BLOCKS * 16];
CCM static uint32_t bs_state[WIDE_BS32_BITS];
CCM static uint32_t bs_scratch[WIDE_BS32_BITS];
/* The u64 path's planes: PRESENT_BLOCK_BITS words of 64 bits, twice the width of
 * bs_state/bs_scratch above and holding twice as many blocks. Separate buffers
 * rather than a union, because a union would make the two paths' checks depend on
 * the order they run in. */
CCM static uint64_t bs64_state[PRESENT_BLOCK_BITS];
CCM static uint64_t bs64_scratch[PRESENT_BLOCK_BITS];
CCM static uint32_t bs_km[WIDE_BS32_KM_WORDS];
CCM static aes_key_t akey;
CCM static lin_key_t lkey;

/* --- key material ---------------------------------------------------------
 *
 * A kat_t carries a 16-byte key, which is what the two 128-bit ciphers take
 * directly. The 64-bit ciphers need anything from 10 bytes (PRESENT-80) to 72
 * (cipher-D's raw 576-bit independent round keys), so both this file and
 * tools/gen_m4_kats.py derive those from the same seed by the same rule:
 * SplitMix64, seeded from both halves of the key, emitting each 64-bit word
 * most significant byte first. The two implementations must never diverge --
 * if they do, every 64-bit cipher fails its KAT at once, which is the loud
 * failure rather than the quiet one.
 *
 * Why not simply repeat the seed: an independent-schedule variant reads its
 * round keys straight out of these bytes, and a repeating pattern would give
 * near-identical round keys, so a bug that mixed two round keys up could still
 * produce the expected ciphertext.
 */
static void kat_expand_key(const uint8_t seed[16], uint8_t *out, unsigned n)
{
    uint64_t s0 = 0, s1 = 0;
    for (int i = 0; i < 8; i++) s0 = (s0 << 8) | seed[i];
    for (int i = 0; i < 8; i++) s1 = (s1 << 8) | seed[8 + i];

    uint64_t st = s0 ^ (s1 + 0x9E3779B97F4A7C15ull);
    unsigned i = 0;
    while (i < n) {
        st += 0x9E3779B97F4A7C15ull;
        uint64_t z = st;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z ^= z >> 31;
        for (int k = 0; k < 8 && i < n; k++, i++)
            out[i] = (uint8_t)(z >> (8 * (7 - k)));
    }
}

/* --- block conventions ----------------------------------------------------
 *
 * A 64-bit cipher's block is a uint64_t; the vector table holds it big-endian
 * in bytes 0..7 (pt[0] is bits 63..56), which is the order present-cli's
 * --block hex string reads in, so a vector can be checked against the host by
 * eye. The 128-bit ciphers' blocks are byte arrays already.
 */
static uint64_t be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* --- result bookkeeping --------------------------------------------------- */

static void mark(cipher_rec_t *c, int impl, int ok)
{
    c->status[impl] = ok ? ST_PASS : ST_FAIL;
    if (!ok) n_failures++;
}

/* Used when a cipher cannot even be set up: nothing about it is proven, so
 * every implementation of it is a failure rather than a skip. */
static void fail_all(cipher_rec_t *c)
{
    for (int i = 0; i < N_IMPLS; i++)
        if (c->status[i] != ST_FAIL) { c->status[i] = ST_FAIL; n_failures++; }
}

/* --- the 64-bit ciphers --------------------------------------------------- */

static void run_src(cipher_rec_t *c)
{
    const present_variant_t *v = present_variant_by_name(c->name);
    /* A round-count mismatch means the vectors were generated for a different
     * cipher than the one this firmware would time. Never encrypt at the
     * variant's own round count and call it a pass. */
    if (!v || v->rounds != c->rounds) { fail_all(c); return; }

    unsigned kb = (unsigned)present_variant_key_bytes(v);
    if (kb == 0 || kb > sizeof keybuf) { fail_all(c); return; }
    kat_expand_key(KATS[c->first].key, keybuf, kb);
    if (present_init(&ctx, v, keybuf, kb) != 0) { fail_all(c); return; }

    int ok = 1;
    for (int j = 0; j < c->n; j++) {
        const kat_t *k = &KATS[c->first + j];
        if (present_encrypt_ref(&ctx, be64(k->pt)) != be64(k->ct)) ok = 0;
    }
    mark(c, IMPL_REF, ok);

    ok = 1;
    for (int j = 0; j < c->n; j++) {
        const kat_t *k = &KATS[c->first + j];
        if (present_encrypt_table(&ctx, be64(k->pt)) != be64(k->ct)) ok = 0;
    }
    mark(c, IMPL_TABLE, ok);

    /* Four independent blocks at once: the four vectors are exactly what this
     * kernel wants, so each lane carries a different plaintext and a lane mixup
     * cannot pass. */
    for (int j = 0; j < 4; j++) in64[j] = be64(KATS[c->first + (j % c->n)].pt);
    present_encrypt_table_x4(&ctx, in64, out64);
    ok = 1;
    for (int j = 0; j < 4; j++)
        if (out64[j] != be64(KATS[c->first + (j % c->n)].ct)) ok = 0;
    mark(c, IMPL_TABLE_X4, ok);

    if (v->kernel_enc == PRESENT_NO_KERNEL) {
        c->status[IMPL_BS32] = ST_NA;
        c->status[IMPL_BS32_BS] = ST_NA;
        c->status[IMPL_BS64] = ST_NA;
        c->status[IMPL_BS64_BS] = ST_NA;
        return;
    }

    /* 32 blocks, cycling through the vectors, so every slice of the transpose
     * carries real data rather than 32 copies of one block. */
    for (int b = 0; b < PRESENT_BITSLICE32_BLOCKS; b++)
        in64[b] = be64(KATS[c->first + (b % c->n)].pt);

    present_encrypt_bitslice32(&ctx, in64, out64);
    ok = 1;
    for (int b = 0; b < PRESENT_BITSLICE32_BLOCKS; b++)
        if (out64[b] != be64(KATS[c->first + (b % c->n)].ct)) ok = 0;
    mark(c, IMPL_BS32, ok);

    present_bitslice32_pack(in64, bs_state);
    /* The kernel returns the buffer holding the answer -- unpack from that. */
    present_bitslice32_unpack(present_encrypt_bitslice32_bs(&ctx, bs_state, bs_scratch),
                              out64);
    ok = 1;
    for (int b = 0; b < PRESENT_BITSLICE32_BLOCKS; b++)
        if (out64[b] != be64(KATS[c->first + (b % c->n)].ct)) ok = 0;
    mark(c, IMPL_BS32_BS, ok);

    /* The u64 path, the same two forms one word width up: 64 blocks per call
     * rather than 32, the same circuits, the same linear-layer bodies and the
     * same round-key masks out of ctx. Checked here for the same reason the u32
     * pair is -- Task 12a publishes "bitslice64" and "bitslice64-bs" rows, and a
     * gate that never ran them would clear two rows it had told apart in no way.
     * Note that present_encrypt_bitslice holds two 512-byte plane arrays as
     * locals; that is 1 KB of stack, an order of magnitude below the wide
     * all-in-one kernels this file already calls, so it needs no noinline
     * confinement of its own. */
    for (int b = 0; b < PRESENT_BITSLICE_BLOCKS; b++)
        in64[b] = be64(KATS[c->first + (b % c->n)].pt);

    present_encrypt_bitslice(&ctx, in64, out64);
    ok = 1;
    for (int b = 0; b < PRESENT_BITSLICE_BLOCKS; b++)
        if (out64[b] != be64(KATS[c->first + (b % c->n)].ct)) ok = 0;
    mark(c, IMPL_BS64, ok);

    /* present_transpose64 is its own inverse, which is why it stands in for both
     * the pack and the unpack the u32 path spells with two functions. The kernel
     * ping-pongs and returns the buffer holding the answer, so the second
     * transpose reads the returned pointer and never bs64_state. */
    present_transpose64(in64, bs64_state);
    present_transpose64(present_encrypt_bitslice_bs(&ctx, bs64_state, bs64_scratch),
                        out64);
    ok = 1;
    for (int b = 0; b < PRESENT_BITSLICE_BLOCKS; b++)
        if (out64[b] != be64(KATS[c->first + (b % c->n)].ct)) ok = 0;
    mark(c, IMPL_BS64_BS, ok);
}

/* --- the 128-bit ciphers -------------------------------------------------- */

/* Fill in128 with 32 blocks cycling through this cipher's vectors. */
static void fill_wide_input(const cipher_rec_t *c)
{
    for (int b = 0; b < WIDE_BS32_BLOCKS; b++)
        memcpy(in128 + b * 16, KATS[c->first + (b % c->n)].pt, 16);
}

static int check_wide_blocks(const cipher_rec_t *c, int nblocks)
{
    for (int b = 0; b < nblocks; b++)
        if (memcmp(out128 + b * 16, KATS[c->first + (b % c->n)].ct, 16) != 0) return 0;
    return 1;
}

/* The "bitslice32" row: the all-in-one entry points, blocks in and blocks out,
 * which are what phase-4-measure.md names for that row and what the 77%-transpose
 * figure was measured on. They are the expensive ones -- 11,960 B (aes) and
 * 12,296 B (lin) of stack, since both plane arrays and the 2,688-word expanded
 * schedule are locals -- so they are called from a noinline function whose frame
 * is entered and left once per cipher rather than being inlined into the middle
 * of kat_check_all(). fw/m4/kat_main.c paints free SRAM and reports the peak that
 * actually resulted; on this board .bss ends at 0x200011e4 and the stack starts
 * at 0x20020000, so there is ~123 KiB below it and the measured peak has room to
 * spare. Checking these matters: without it Task 9 would publish "bitslice32" and
 * "bitslice32-bs" rows for AES and AES-lin444 that no on-device test told apart. */
__attribute__((noinline))
static int run_wide_bs32_allinone(const cipher_rec_t *c, int is_lin)
{
    fill_wide_input(c);
    if (is_lin) lin_encrypt_bs32(&lkey, c->rounds, in128, out128);
    else        aes_encrypt_bs32(&akey, c->rounds, in128, out128);
    return check_wide_blocks(c, WIDE_BS32_BLOCKS);
}

/* The "bitslice32-bs" row: the transpose-free form, with the round keys expanded
 * once and the state, scratch and key material in static CCM storage -- 176 B
 * (aes) and 520 B (lin) of stack. This is the pattern the harness uses when it
 * hoists the transpose and the key expansion out of the timed region, and the
 * ping-pong contract is why the unpack reads the returned pointer rather than
 * bs_state. */
static int run_wide_bs32_bs(const cipher_rec_t *c, int is_lin)
{
    fill_wide_input(c);
    if (is_lin) {
        bs32_expand_lin_key(&lkey, c->rounds, bs_km);
        wide_bs32_pack(in128, bs_state);
        wide_bs32_unpack(lin_encrypt_bs32_bs(&lkey, bs_km, c->rounds, bs_state, bs_scratch),
                         out128);
    } else {
        bs32_expand_aes_key(&akey, c->rounds, bs_km);
        wide_bs32_pack(in128, bs_state);
        wide_bs32_unpack(aes_encrypt_bs32_bs(bs_km, c->rounds, bs_state, bs_scratch),
                         out128);
    }
    return check_wide_blocks(c, WIDE_BS32_BLOCKS);
}

static void run_wide(cipher_rec_t *c, int is_lin)
{
    const uint8_t *key = KATS[c->first].key;
    if (c->rounds < 1 || c->rounds > MAX_ROUNDS) { fail_all(c); return; }

    int ok;
    if (is_lin) {
        lin_key_schedule(&lkey, key);
        lkey.nr = c->rounds;

        ok = 1;
        for (int j = 0; j < c->n; j++) {
            const kat_t *k = &KATS[c->first + j];
            lin_encrypt_ref(&lkey, c->rounds, k->pt, out128);
            if (memcmp(out128, k->ct, 16) != 0) ok = 0;
        }
        mark(c, IMPL_REF, ok);
        /* The fused-table lin444 kernels are SSE2 and stayed in
         * bench/wide_bench.c; there is nothing to time here under those names. */
        c->status[IMPL_TABLE] = ST_NA;
        c->status[IMPL_TABLE_X4] = ST_NA;
    } else {
        aes_key_schedule(&akey, key);
        akey.nr = c->rounds;

        ok = 1;
        for (int j = 0; j < c->n; j++) {
            const kat_t *k = &KATS[c->first + j];
            aes_encrypt1(&akey, c->rounds, k->pt, out128);
            if (memcmp(out128, k->ct, 16) != 0) ok = 0;
        }
        mark(c, IMPL_TABLE, ok);

        fill_wide_input(c);
        aes_encrypt4(&akey, c->rounds, in128, out128);
        mark(c, IMPL_TABLE_X4, check_wide_blocks(c, 4));

        /* AES's scalar kernel is the T-table one; there is no separate "ref". */
        c->status[IMPL_REF] = ST_NA;
    }

    mark(c, IMPL_BS32, run_wide_bs32_allinone(c, is_lin));
    mark(c, IMPL_BS32_BS, run_wide_bs32_bs(c, is_lin));

    /* No u64 form exists for the 128-bit ciphers: bench/wide_bitslice32.h is a
     * 32-bit-word bitslice and there is no 64-bit-word counterpart to run. Not an
     * omission, and recorded as not-applicable rather than as a pass -- kat_ok()
     * refuses ST_NA, so the harness cannot publish a bitslice64 row for them. */
    c->status[IMPL_BS64] = ST_NA;
    c->status[IMPL_BS64_BS] = ST_NA;
}

/* --- driver --------------------------------------------------------------- */

/* Group the vector table into ciphers. The generator emits a cipher's rows
 * consecutively, so a run ends where the name changes. */
static int group_vectors(void)
{
    n_ciphers = 0;
    for (unsigned i = 0; i < N_KATS; i++) {
        if (n_ciphers > 0 && strcmp(ciphers[n_ciphers - 1].name, KATS[i].cipher) == 0) {
            ciphers[n_ciphers - 1].n++;
            continue;
        }
        if (n_ciphers == MAX_CIPHERS) return -1;
        cipher_rec_t *c = &ciphers[n_ciphers++];
        c->name = KATS[i].cipher;
        c->rounds = KATS[i].rounds;
        c->block_bytes = KATS[i].block_bytes;
        c->first = (int)i;
        c->n = 1;
        for (int k = 0; k < N_IMPLS; k++) c->status[k] = ST_NOT_RUN;
    }
    return 0;
}

int kat_check_all(void)
{
    n_failures = 0;
    have_run = 1;

    if (group_vectors() != 0) {
        /* More ciphers than the table holds: whatever did fit may have passed,
         * but the run as a whole is not trustworthy. */
        n_failures++;
        return n_failures;
    }

    for (int i = 0; i < n_ciphers; i++) {
        cipher_rec_t *c = &ciphers[i];
        if (c->block_bytes == 8) {
            run_src(c);
        } else if (c->block_bytes == 16) {
            /* The two 128-bit ciphers are AES and AES with the lin444 layer;
             * the linear layer is named in the cipher's own name, which is
             * where the discriminator comes from rather than a second copy of
             * the cipher list. */
            run_wide(c, strstr(c->name, "lin444") != 0);
        } else {
            fail_all(c);
        }
    }
    return n_failures;
}

/* --- queries -------------------------------------------------------------- */

static const cipher_rec_t *find_cipher(const char *name)
{
    for (int i = 0; i < n_ciphers; i++)
        if (strcmp(ciphers[i].name, name) == 0) return &ciphers[i];
    return 0;
}

/* Every implementation that was checked passed, and at least one was. */
static int cipher_verdict(const cipher_rec_t *c)
{
    int any = 0;
    for (int i = 0; i < N_IMPLS; i++) {
        if (c->status[i] == ST_PASS) any = 1;
        else if (c->status[i] != ST_NA) return 0;
    }
    return any;
}

/* Rows the harness times that this gate has no ciphertext for. There is exactly
 * one: key setup produces a schedule, not a block, so it cannot be compared
 * against a vector. It is answered with the cipher's own verdict -- a cipher
 * whose kernel is broken does not get a key-setup figure published either.
 *
 * The list is closed on purpose. Anything outside it is a name this gate never
 * validated, and an unvalidated row must not be timed: answering "ok" for a name
 * nobody checked would invert the whole point of the gate, and a misspelled impl
 * in the harness is exactly how that would happen. */
static const char *const UNCHECKED_IMPL[] = { "keysetup" };

int kat_ok(const char *cipher, const char *impl)
{
    if (!have_run || !cipher || !impl) return 0;

    const cipher_rec_t *c = find_cipher(cipher);
    if (!c) {
        char buf[128];
        buf[0] = 0;
        sh_append(buf, sizeof buf, "kat: no vectors for cipher=");
        sh_append(buf, sizeof buf, cipher);
        sh_append(buf, sizeof buf, " -- not validated, refusing to clear it\n");
        sh_write0(buf);
        return 0;
    }

    for (int i = 0; i < N_IMPLS; i++)
        if (strcmp(impl, IMPL_NAME[i]) == 0) {
            /* ST_NA included deliberately: a pair with no implementation to run
             * on this target was never validated either, so it is not cleared. */
            return c->status[i] == ST_PASS;
        }

    for (unsigned i = 0; i < sizeof UNCHECKED_IMPL / sizeof UNCHECKED_IMPL[0]; i++)
        if (strcmp(impl, UNCHECKED_IMPL[i]) == 0) return cipher_verdict(c);

    /* Loud, because the alternative is a Task 9 author watching rows vanish with
     * no explanation. Semihosting traps to the host, so this -- like every other
     * kat_* call -- must stay outside any timed region. */
    {
        char buf[128];
        buf[0] = 0;
        sh_append(buf, sizeof buf, "kat: impl=");
        sh_append(buf, sizeof buf, impl);
        sh_append(buf, sizeof buf, " is not one this gate checks (cipher=");
        sh_append(buf, sizeof buf, cipher);
        sh_append(buf, sizeof buf, "); add it to kat.c or fix the name\n");
        sh_write0(buf);
    }
    return 0;
}

int kat_n_ciphers(void) { return n_ciphers; }

const char *kat_cipher_name(int i)
{
    return (i >= 0 && i < n_ciphers) ? ciphers[i].name : 0;
}

int kat_cipher_rounds(int i)
{
    return (i >= 0 && i < n_ciphers) ? ciphers[i].rounds : 0;
}

int kat_cipher_block_bytes(int i)
{
    return (i >= 0 && i < n_ciphers) ? ciphers[i].block_bytes : 0;
}

/* The two large CCM buffers, lent to the harness once the gate is done with
 * them. See the contract in kat.h -- in short, the 64 KiB budget has room for
 * one present_ctx_t and one bitsliced round-key array, not two, and everything
 * this module does after kat_check_all() returns is answered out of
 * ciphers[].status rather than out of either buffer. */
present_ctx_t *kat_lend_ctx(void) { return &ctx; }
uint32_t *kat_lend_bs_km(void) { return bs_km; }

/* --- reporting ------------------------------------------------------------ */

static const char *status_text(int st)
{
    switch (st) {
    case ST_PASS:    return "PASS";
    case ST_FAIL:    return "FAIL";
    case ST_NA:      return "n/a";
    default:         return "NOT-RUN";
    }
}

void kat_print_results(void)
{
    char buf[128];

    for (int i = 0; i < n_ciphers; i++) {
        const cipher_rec_t *c = &ciphers[i];
        for (int k = 0; k < N_IMPLS; k++) {
            buf[0] = 0;
            sh_append(buf, sizeof buf, "kat cipher=");
            sh_append(buf, sizeof buf, c->name);
            sh_append(buf, sizeof buf, " impl=");
            sh_append(buf, sizeof buf, IMPL_NAME[k]);
            sh_append(buf, sizeof buf, " ");
            sh_append(buf, sizeof buf, status_text(c->status[k]));
            sh_append(buf, sizeof buf, "\n");
            sh_write0(buf);
        }
    }

    fmt_u32(buf, sizeof buf, "kat vectors: ", (uint32_t)N_KATS, " over ");
    sh_write0(buf);
    fmt_u32(buf, sizeof buf, "", (uint32_t)n_ciphers, " ciphers\n");
    sh_write0(buf);
}
