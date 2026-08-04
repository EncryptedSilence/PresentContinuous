/* Every registered variant must be internally consistent, and the registry must
 * match what the JSON definitions said. The generator computes the inverses, so a
 * silent generator bug would show up here rather than as wrong ciphertext. */

#include <string.h>

#include "present/present.h"
#include "testutil.h"

#include "gen/lin_consts.h"

int main(void)
{
    CHECK(present_n_variants > 0, "no variants registered");

    for (int i = 0; i < present_n_variants; i++) {
        const present_variant_t *v = &present_variants[i];
        CHECK(present_variant_check(v) == 0, "%s: descriptor check failed (%d)",
              v->name, present_variant_check(v));
        CHECK(present_variant_by_name(v->name) == v, "%s: lookup by name failed", v->name);
        CHECK(v->description != NULL && v->description[0] != '\0',
              "%s: missing description", v->name);
        /* Every variant has a synthesised circuit and a bitsliced kernel, at either
         * width. The 8-bit circuits are far larger -- the synthesiser is a BDD
         * heuristic rather than the 4-bit exhaustive search -- but they exist. */
        CHECK(present_circuit_gates(v->circuit_enc) > 0,
              "%s: no synthesised encryption circuit", v->name);
        CHECK(present_circuit_gates(v->circuit_dec) > 0,
              "%s: no synthesised decryption circuit", v->name);
        CHECK(present_variant_has_bitslice(v), "%s: no bitsliced kernel", v->name);
    }

    /* Names are unique. */
    for (int i = 0; i < present_n_variants; i++)
        for (int j = i + 1; j < present_n_variants; j++)
            CHECK(strcmp(present_variants[i].name, present_variants[j].name) != 0,
                  "duplicate variant name %s", present_variants[i].name);

    /* The reference variant must be the textbook one. */
    {
        const present_variant_t *v = present_variant_by_name("present-80");
        static const uint8_t want_sbox[16] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                                              0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};
        CHECK(v != NULL, "present-80 missing");
        if (v) {
            CHECK(memcmp(v->sbox, want_sbox, 16) == 0, "present-80 S-box is not the spec one");
            for (int i = 0; i < 64; i++) {
                int want = (i == 63) ? 63 : (16 * i) % 63;
                CHECK(v->pbox[i] == want, "present-80 pbox[%d] = %d, want %d",
                      i, v->pbox[i], want);
            }
            CHECK(v->rounds == 31, "present-80 rounds = %d", v->rounds);
        }
    }

    /* The generated closed form for the layer's XOR count has to reproduce what the
     * enumeration in analysis/present_sat/slp.py actually counted when it emitted
     * the layer bodies. Two descriptions of the same number, kept honest. */
    {
#define CHECK_COST(C0, C1, C2, ENC, DEC)                                              \
        do {                                                                          \
            const int c[3] = {C0, C1, C2};                                            \
            CHECK(present_lin444_xors(c, 0) == (ENC),                                 \
                  "lin444 (%d,%d,%d): closed form says %d encrypt XORs, slp.py counted %d", \
                  C0, C1, C2, present_lin444_xors(c, 0), ENC);                        \
            CHECK(present_lin444_xors(c, 1) == (DEC),                                 \
                  "lin444 (%d,%d,%d): closed form says %d decrypt XORs, slp.py counted %d", \
                  C0, C1, C2, present_lin444_xors(c, 1), DEC);                        \
        } while (0);
        PRESENT_LIN444_COST_LIST(CHECK_COST)
#undef CHECK_COST
    }

    return test_summary("test_variants");
}
