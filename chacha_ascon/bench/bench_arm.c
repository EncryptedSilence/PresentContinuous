/* Cycle-estimation harness for the 32-bit ARM builds (no board: see
 * tools/arm_cycles.py). Runs under qemu-arm with an instruction trace; every
 * timed call sits between two calls of ca_mark(), and the model prices exactly
 * the instructions executed between consecutive marks. For each region this
 * prints "REGION <n> <cipher> <impl> <lanes> <msg_bytes> <payload_bytes>", in
 * the order the regions occur. Region 0 is empty: the mark's own overhead.
 *
 * One warm call precedes each timed one (as on hardware, though the model has
 * no caches -- it keeps the data and code paths identical to a real run).
 * Block-cipher CTR implementations (include/blockctr.h) are timed as one xor
 * call on one message with the key setup outside the region (lanes = blocks per
 * inner iteration, payload = msg).
 * Ascon runs with no associated data, the same as the x86 and CUDA benches;
 * multi-stream implementations get `lanes` messages per call, and their payload
 * is lanes x msg_bytes. Inputs are a fixed pattern; outputs are summed into a
 * printed checksum so nothing is dead code. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ascon_aead.h"
#include "blockctr.h"
#include "chacha20.h"

void ca_mark(void); /* bench/ca_mark.c, noinline, never inlined across TUs */

static int region;
static const char *only;
/* --only filter: substring of "<cipher>/<impl>" */
static int wanted(const char *cipher, const char *impl)
{
    char b[96];
    snprintf(b, sizeof b, "%s/%s", cipher, impl);
    return !only || strstr(b, only) != NULL;
}
static void begin(const char *cipher, const char *impl, unsigned lanes, size_t msg, size_t total)
{
    printf("REGION %d %s %s %u %lu %lu\n", ++region, cipher, impl, lanes, (unsigned long)msg, (unsigned long)total);
    ca_mark();
}

#define MAXL 4
static uint8_t buf_in[MAXL][4096 + 16], buf_out[MAXL][4096 + 32];

int main(int argc, char **argv)
{
    only = argc > 1 ? argv[1] : NULL;
    static const size_t sizes[] = {64, 1536, 4096};
    uint8_t key[32], nonce[16];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 16; i++) nonce[i] = (uint8_t)(i * 5 + 3);
    for (int l = 0; l < MAXL; l++)
        for (int i = 0; i < 4096 + 16; i++) buf_in[l][i] = (uint8_t)(i * 31 + l * 101);
    uint32_t sum = 0;

    printf("REGION 0 - - 0 0 0\n");
    ca_mark();
    ca_mark();

    for (const chacha20_impl *im = chacha20_impls; im->name; im++) {
        if (!wanted("chacha20", im->name)) continue;
        for (unsigned s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
            size_t n = sizes[s];
            im->xor_fn(buf_out[0], buf_in[0], n, key, nonce, 1); /* warm */
            begin("chacha20", im->name, im->lanes, n, n);
            im->xor_fn(buf_out[0], buf_in[0], n, key, nonce, 1);
            ca_mark();
            sum += buf_out[0][n - 1];
        }
    }
    for (const ascon_impl *im = ascon_impls; im->name; im++) {
        if (!wanted("ascon128", im->name)) continue;
        for (unsigned s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
            size_t n = sizes[s];
            if (im->enc) {
                unsigned long long clen;
                im->enc(buf_out[0], &clen, buf_in[0], n, NULL, 0, NULL, nonce, key);
                begin("ascon128", im->name, 1, n, n);
                im->enc(buf_out[0], &clen, buf_in[0], n, NULL, 0, NULL, nonce, key);
                ca_mark();
            } else {
                ascon_job jobs[MAXL];
                unsigned L = im->lanes;
                for (unsigned l = 0; l < L; l++)
                    jobs[l] = (ascon_job){buf_out[l], buf_in[l], NULL, nonce, key};
                im->multi(jobs, L, n, 0);
                begin("ascon128", im->name, L, n, (size_t)L * n);
                im->multi(jobs, L, n, 0);
                ca_mark();
            }
            sum += buf_out[0][n + 15];
        }
    }
    static uint8_t bc_ctx[512] __attribute__((aligned(BC_CTX_ALIGN)));
    for (const bc_impl *im = bc_impls; im->name; im++) {
        if (!wanted(im->cipher, im->name) || (im->available && !im->available())) continue;
        if (im->ctx_size > sizeof bc_ctx) { fprintf(stderr, "bc ctx too large\n"); return 2; }
        im->setup(bc_ctx, key);
        for (unsigned s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
            size_t n = sizes[s];
            im->xor_fn(bc_ctx, buf_out[0], buf_in[0], n, nonce, 1); /* warm */
            begin(im->cipher, im->name, im->lanes, n, n);
            im->xor_fn(bc_ctx, buf_out[0], buf_in[0], n, nonce, 1);
            ca_mark();
            sum += buf_out[0][n - 1];
        }
    }
    printf("checksum %08x\n", (unsigned)sum);
    return 0;
}
