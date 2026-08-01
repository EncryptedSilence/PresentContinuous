/* present-cli: encrypt/decrypt single blocks and list variants. */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "present/present.h"

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage:\n"
            "  %s list\n"
            "  %s encrypt --variant NAME --key HEX --block HEX64 [--impl ref|table|bitslice]\n"
            "  %s decrypt --variant NAME --key HEX --block HEX64 [--impl ref|table|bitslice]\n",
            prog, prog, prog);
}

static int cmd_list(void)
{
    printf("%-24s %-7s %-6s %-8s %s\n", "NAME", "ROUNDS", "KEY", "GATES", "DESCRIPTION");
    for (int i = 0; i < present_n_variants; i++) {
        const present_variant_t *v = &present_variants[i];
        printf("%-24s %-7d %-6d %-8d %s\n", v->name, v->rounds, v->key_bits,
               present_circuit_gates(v->circuit_enc), v->description);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 2; }
    if (!strcmp(argv[1], "list")) return cmd_list();

    int encrypting = !strcmp(argv[1], "encrypt");
    if (!encrypting && strcmp(argv[1], "decrypt")) { usage(argv[0]); return 2; }

    const char *variant = "present-80", *key = NULL, *block = NULL, *impl = "table";
    for (int i = 2; i < argc - 1; i += 2) {
        if (!strcmp(argv[i], "--variant")) variant = argv[i + 1];
        else if (!strcmp(argv[i], "--key")) key = argv[i + 1];
        else if (!strcmp(argv[i], "--block")) block = argv[i + 1];
        else if (!strcmp(argv[i], "--impl")) impl = argv[i + 1];
        else { usage(argv[0]); return 2; }
    }
    if (!key || !block) { usage(argv[0]); return 2; }

    const present_variant_t *v = present_variant_by_name(variant);
    if (!v) { fprintf(stderr, "unknown variant %s\n", variant); return 1; }

    present_ctx_t ctx;
    int rc = present_init_hex(&ctx, v, key);
    if (rc) { fprintf(stderr, "bad key for %s (%d)\n", variant, rc); return 1; }

    uint64_t b = strtoull(block, NULL, 16);
    uint64_t out;

    if (!strcmp(impl, "ref")) {
        out = encrypting ? present_encrypt_ref(&ctx, b) : present_decrypt_ref(&ctx, b);
    } else if (!strcmp(impl, "table")) {
        out = encrypting ? present_encrypt_table(&ctx, b) : present_decrypt_table(&ctx, b);
    } else if (!strcmp(impl, "bitslice")) {
        uint64_t in64[64] = {0}, out64[64];
        in64[0] = b;
        if (encrypting) present_encrypt_bitslice(&ctx, in64, out64);
        else present_decrypt_bitslice(&ctx, in64, out64);
        out = out64[0];
    } else {
        fprintf(stderr, "unknown impl %s\n", impl);
        return 1;
    }

    printf("%016" PRIx64 "\n", out);
    return 0;
}
