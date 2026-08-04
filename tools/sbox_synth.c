/* Minimum-gate bitslice circuit synthesis for a 4-bit S-box.
 *
 * Each of the four output coordinate functions is a boolean function of four
 * variables, i.e. a 16-bit truth table. We breadth-first search over all 65536
 * truth tables, in increasing tree cost, until every output function is reachable;
 * then we share common subexpressions across the four outputs and emit C.
 *
 * The cost model counts one operation per gate. The search minimises *tree* size,
 * which is an upper bound on the DAG size; the CSE pass afterwards recovers most of
 * the difference. This is not provably minimal for the 4-output problem, but it
 * lands close to hand-optimised circuits and, unlike a hand-optimised circuit, it
 * works for any S-box you throw at it.
 *
 * Two backends, because the machine's gate set is not the same in both:
 *   u64    scalar uint64_t. The compiler turns ~a|b and ~(a^b) into one or two
 *          instructions as it sees fit, so all six ops cost 1.
 *   avx2   __m256i. AVX2 has vpand / vpor / vpxor / vpandn but *no* single
 *          instruction for ~a|b or ~(a^b) -- those need an extra vpxor against an
 *          all-ones register. (vpternlogd would do any of them in one op, but it
 *          is AVX-512.) So the AVX2 backend searches over the four native ops
 *          only, and pays a few more gates for a circuit that is genuinely one
 *          instruction per gate rather than one that only looks cheap.
 *
 * Usage:  sbox_synth <16 comma-separated S-box entries> [name] [--backend u64|avx2]
 * Output: C fragment on stdout.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NFUNC 65536

enum { OP_INPUT, OP_AND, OP_OR, OP_XOR, OP_ANDN, OP_ORN, OP_XNOR, OP_CONST };

typedef struct {
    int16_t cost; /* -1 = unreachable */
    uint8_t op;
    uint16_t a, b;
} node_t;

static node_t nodes[NFUNC];

/* Truth tables of the four inputs over (x3,x2,x1,x0). Bit i of the table is the
 * function value at input i. */
static const uint16_t INPUT_TT[4] = {0xAAAAu, 0xCCCCu, 0xF0F0u, 0xFF00u};

static uint16_t apply_op(int op, uint16_t a, uint16_t b)
{
    switch (op) {
    case OP_AND:  return (uint16_t)(a & b);
    case OP_OR:   return (uint16_t)(a | b);
    case OP_XOR:  return (uint16_t)(a ^ b);
    case OP_ANDN: return (uint16_t)(~a & b);
    case OP_ORN:  return (uint16_t)(~a | b);
    case OP_XNOR: return (uint16_t)~(a ^ b);
    }
    return 0;
}

/* Ops that are not commutative must be tried in both argument orders. */
static const int OPS_U64[] = {OP_AND, OP_OR, OP_XOR, OP_ANDN, OP_ORN, OP_XNOR};
static const int OPS_AVX2[] = {OP_AND, OP_OR, OP_XOR, OP_ANDN};

static const int *OPS = OPS_U64;
static int N_OPS = (int)(sizeof(OPS_U64) / sizeof(OPS_U64[0]));

/* Everything the emitter needs to know about a target word type. */
typedef struct {
    const char *name;       /* backend name, and the prefix of the emitted function */
    const char *type;       /* C type of a bit-plane */
    const char *zero, *ones;
    const char *e_and, *e_or, *e_xor, *e_andn, *e_orn, *e_xnor;
    const char *prologue;   /* emitted at the top of the function body, or NULL */
} backend_t;

static const backend_t BE_U64 = {
    "u64", "uint64_t", "(uint64_t)0", "~(uint64_t)0",
    "%s & %s", "%s | %s", "%s ^ %s", "~%s & %s", "~%s | %s", "~(%s ^ %s)", NULL,
};

/* ones_ is hoisted so the all-ones register is materialised once, not per gate.
 * It stays unused when the circuit needs no complement, hence the (void) cast. */
static const backend_t BE_AVX2 = {
    "avx2", "__m256i", "_mm256_setzero_si256()", "ones_",
    "_mm256_and_si256(%s, %s)",
    "_mm256_or_si256(%s, %s)",
    "_mm256_xor_si256(%s, %s)",
    "_mm256_andnot_si256(%s, %s)",
    "_mm256_or_si256(_mm256_xor_si256(%s, ones_), %s)",
    "_mm256_xor_si256(_mm256_xor_si256(%s, %s), ones_)",
    "    const __m256i ones_ = _mm256_set1_epi64x(-1); (void)ones_;\n",
};

static uint16_t *by_cost[64];
static int by_cost_n[64];

static void push(int cost, uint16_t f)
{
    by_cost[cost] = realloc(by_cost[cost], (size_t)(by_cost_n[cost] + 1) * sizeof(uint16_t));
    if (!by_cost[cost]) { fprintf(stderr, "oom\n"); exit(1); }
    by_cost[cost][by_cost_n[cost]++] = f;
}

/* Search for a target, treating everything in seed[] as available for free.
 * Seeding with the nodes already in the circuit is what turns four independent
 * minimum-tree searches into something that actively reuses shared subexpressions:
 * the second output is not asked "what is your cheapest tree" but "what is your
 * cheapest tree *given what is already computed*".
 *
 * Two targets are accepted, a function and its complement, and whichever is
 * reached first wins. Complementing an output costs nothing at run time: the
 * S-box is followed by a linear layer L, so a circuit that computes S(x) ^ b
 * leaves the state off by the constant L(b), and XORing that into the next round
 * key -- once, at key setup -- cancels it exactly. Handing the search both
 * options is therefore free accuracy, not a relaxation: for PRESENT's own S-box
 * it removes the two NOT gates that terminate o2 and o3.
 *
 * The mirror trick on the *input* side -- synthesising S(x ^ a) and folding a into
 * the round key, which is equally free -- was measured and buys nothing: all 16
 * choices of a give the identical gate count on all ten S-boxes this project uses,
 * on both backends. So only the output side is searched.
 *
 * Returns the truth table actually reached, or 0xFFFFFFFFu if neither was. */
static unsigned search_seeded(uint16_t target, uint16_t alt,
                              const uint16_t *seed, int seed_n, int max_cost)
{
    for (int i = 0; i < NFUNC; i++) nodes[i].cost = -1;
    for (int i = 0; i < 64; i++) by_cost_n[i] = 0;

    for (int i = 0; i < seed_n; i++) {
        if (nodes[seed[i]].cost < 0) {
            nodes[seed[i]].cost = 0;
            nodes[seed[i]].op = OP_INPUT; /* provenance comes from the circuit, not here */
            push(0, seed[i]);
        }
    }

    if (nodes[target].cost >= 0) return target;
    if (nodes[alt].cost >= 0) return alt;

    for (int cost = 1; cost <= max_cost; cost++) {
        for (int ca = 0; ca <= cost - 1; ca++) {
            int cb = cost - 1 - ca;
            if (cb < ca) continue; /* unordered pair of cost classes */
            for (int ia = 0; ia < by_cost_n[ca]; ia++) {
                uint16_t a = by_cost[ca][ia];
                for (int ib = 0; ib < by_cost_n[cb]; ib++) {
                    uint16_t b = by_cost[cb][ib];
                    if (a == b) continue;
                    for (int oi = 0; oi < N_OPS; oi++) {
                        int op = OPS[oi];
                        uint16_t f = apply_op(op, a, b);
                        if (nodes[f].cost < 0) {
                            nodes[f].cost = (int16_t)cost;
                            nodes[f].op = (uint8_t)op;
                            nodes[f].a = a;
                            nodes[f].b = b;
                            push(cost, f);
                        }
                        /* ANDN and ORN are not commutative. */
                        if (op == OP_ANDN || op == OP_ORN) {
                            uint16_t g = apply_op(op, b, a);
                            if (nodes[g].cost < 0) {
                                nodes[g].cost = (int16_t)cost;
                                nodes[g].op = (uint8_t)op;
                                nodes[g].a = b;
                                nodes[g].b = a;
                                push(cost, g);
                            }
                        }
                    }
                }
            }
        }
        if (nodes[target].cost >= 0) return target;
        if (nodes[alt].cost >= 0) return alt;
    }
    return 0xFFFFFFFFu;
}

/* ---- greedy incremental construction of one shared circuit --------------------
 *
 * Synthesise the four output functions one at a time. After each one, every node
 * it introduced becomes a free seed for the outputs that follow, so later outputs
 * are priced against what is already computed rather than from scratch. The order
 * matters and there are only 24 of them, so we try them all and keep the smallest
 * circuit -- 24 x 4 searches at ~30 ms is a few seconds of one-time code
 * generation, in exchange for a circuit that is executed 16 times a round, 31
 * rounds deep, on every block the cipher will ever process.
 */
static node_t circuit[NFUNC];
static uint8_t in_circuit[NFUNC];
static uint16_t seeds[NFUNC];
static int n_seeds;

static void adopt(uint16_t f)
{
    if (in_circuit[f]) return;                 /* already built: nothing to pay */
    if (nodes[f].op != OP_INPUT) {             /* OP_INPUT here means "was a seed" */
        adopt(nodes[f].a);
        adopt(nodes[f].b);
    }
    in_circuit[f] = 1;
    circuit[f] = nodes[f];
    seeds[n_seeds++] = f;
}

/* Which truth table each output was actually built as: targets[i], or its
 * complement when that turned out cheaper. */
static uint16_t built[4];

/* Build the circuit for one output order; returns the gate count.
 *
 * force_mask pins the output polarities instead of letting the search choose:
 * bit i set means output i must be built complemented. The two backends are
 * synthesised separately but share one round-key correction, so the second one
 * is pinned to the first one's choice. -1 leaves the choice free. */
static int build_order(const uint16_t *targets, const int *order, int max_cost, int force_mask)
{
    memset(in_circuit, 0, sizeof(in_circuit));
    n_seeds = 0;

    for (int i = 0; i < 4; i++) {
        uint16_t f = INPUT_TT[i];
        in_circuit[f] = 1;
        circuit[f].op = OP_INPUT;
        circuit[f].a = (uint16_t)i;
        seeds[n_seeds++] = f;
    }
    /* Constants are free: they never need a gate in the emitted code. */
    for (int c = 0; c <= 1; c++) {
        uint16_t f = c ? 0xFFFFu : 0x0000u;
        if (!in_circuit[f]) {
            in_circuit[f] = 1;
            circuit[f].op = OP_CONST;
            circuit[f].a = (uint16_t)c;
            seeds[n_seeds++] = f;
        }
    }

    int base = n_seeds;
    for (int i = 0; i < 4; i++) {
        const int bit = order[i];
        uint16_t t = targets[bit], tc = (uint16_t)~targets[bit];
        if (force_mask >= 0) {
            if ((force_mask >> bit) & 1) t = tc;
            tc = t;
        }
        if (in_circuit[t])       { built[bit] = t;  continue; }
        if (in_circuit[tc])      { built[bit] = tc; continue; }
        unsigned got = search_seeded(t, tc, seeds, n_seeds, max_cost);
        if (got == 0xFFFFFFFFu) return -1;
        built[bit] = (uint16_t)got;
        adopt((uint16_t)got);
    }

    int gates = 0;
    for (int i = base; i < n_seeds; i++)
        if (circuit[seeds[i]].op != OP_INPUT && circuit[seeds[i]].op != OP_CONST) gates++;
    return gates;
}

/* ---- emission with common-subexpression elimination -------------------------- */

static uint16_t emit_order[4096];
static int emit_n;
static uint8_t emitted[NFUNC];

static void collect(uint16_t f)
{
    if (emitted[f]) return;
    emitted[f] = 1;
    if (circuit[f].op == OP_INPUT || circuit[f].op == OP_CONST) {
        emit_order[emit_n++] = f;
        return;
    }
    collect(circuit[f].a);
    collect(circuit[f].b);
    emit_order[emit_n++] = f;
}

static int slot_of[NFUNC];

int main(int argc, char **argv)
{
    const backend_t *be = &BE_U64;
    const char *positional[2] = {NULL, NULL};
    int n_pos = 0;
    int force_mask = -1;

    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--backend", 9)) {
            const char *val = argv[i][9] == '=' ? argv[i] + 10
                            : (i + 1 < argc ? argv[++i] : NULL);
            if (!val) { fprintf(stderr, "--backend needs a value\n"); return 2; }
            if (!strcmp(val, "u64")) be = &BE_U64;
            else if (!strcmp(val, "avx2")) be = &BE_AVX2;
            else { fprintf(stderr, "unknown backend %s\n", val); return 2; }
        } else if (!strncmp(argv[i], "--outcomp", 9)) {
            const char *val = argv[i][9] == '=' ? argv[i] + 10
                            : (i + 1 < argc ? argv[++i] : NULL);
            if (!val) { fprintf(stderr, "--outcomp needs a value\n"); return 2; }
            force_mask = (int)strtol(val, NULL, 0) & 0xF;
        } else if (n_pos < 2) {
            positional[n_pos++] = argv[i];
        } else {
            fprintf(stderr, "unexpected argument %s\n", argv[i]);
            return 2;
        }
    }
    if (n_pos < 1) {
        fprintf(stderr, "usage: %s <s0,s1,...,s15> [name] [--backend u64|avx2] "
                        "[--outcomp <mask>]\n", argv[0]);
        return 2;
    }
    if (be == &BE_AVX2) { OPS = OPS_AVX2; N_OPS = (int)(sizeof(OPS_AVX2) / sizeof(OPS_AVX2[0])); }

    int sbox[16];
    {
        const char *p = positional[0];
        int n = 0;
        while (*p && n < 16) {
            char *end;
            long val = strtol(p, &end, 0);
            if (end == p) break;
            if (val < 0 || val > 15) { fprintf(stderr, "entry out of range: %ld\n", val); return 2; }
            sbox[n++] = (int)val;
            p = end;
            while (*p == ',' || *p == ' ') p++;
        }
        if (n != 16) { fprintf(stderr, "need 16 entries, got %d\n", n); return 2; }
    }
    const char *name = positional[1] ? positional[1] : "sbox";

    uint16_t targets[4];
    for (int bit = 0; bit < 4; bit++) {
        uint16_t tt = 0;
        for (int x = 0; x < 16; x++)
            if ((sbox[x] >> bit) & 1) tt |= (uint16_t)(1u << x);
        targets[bit] = tt;
    }

    /* All 24 orders in which the outputs can be built; keep the smallest result. */
    static const int PERMS[24][4] = {
        {0,1,2,3},{0,1,3,2},{0,2,1,3},{0,2,3,1},{0,3,1,2},{0,3,2,1},
        {1,0,2,3},{1,0,3,2},{1,2,0,3},{1,2,3,0},{1,3,0,2},{1,3,2,0},
        {2,0,1,3},{2,0,3,1},{2,1,0,3},{2,1,3,0},{2,3,0,1},{2,3,1,0},
        {3,0,1,2},{3,0,2,1},{3,1,0,2},{3,1,2,0},{3,2,0,1},{3,2,1,0},
    };
    int best = -1, best_i = -1;
    for (int i = 0; i < 24; i++) {
        int g = build_order(targets, PERMS[i], 12, force_mask);
        if (g < 0) continue;
        if (best < 0 || g < best) { best = g; best_i = i; }
    }
    if (best_i < 0) {
        fprintf(stderr, "no circuit found within the cost bound\n");
        return 1;
    }
    build_order(targets, PERMS[best_i], 12, force_mask); /* rebuild the winner for emission */

    memset(emitted, 0, sizeof(emitted));
    emit_n = 0;
    for (int i = 0; i < 4; i++) collect(built[i]);

    int gates = 0;
    const char *T = be->type;
    printf("/* S-box %s = {", name);
    for (int i = 0; i < 16; i++) printf("%s0x%x", i ? "," : "", sbox[i]);
    printf("}, %s backend */\n", be->name);
    printf("static inline void present_circuit_%s_%s(%s *o3, %s *o2, %s *o1, %s *o0,\n",
           be->name, name, T, T, T, T);
    printf("        %s x0, %s x1, %s x2, %s x3)\n{\n", T, T, T, T);
    if (be->prologue) printf("%s", be->prologue);

    int tmp = 0;
    for (int i = 0; i < emit_n; i++) {
        uint16_t f = emit_order[i];
        node_t *nd = &circuit[f];
        if (nd->op == OP_INPUT || nd->op == OP_CONST) { slot_of[f] = -1; continue; }
        slot_of[f] = tmp++;
        gates++;
    }
    if (tmp) printf("    %s t[%d];\n", T, tmp);

    for (int i = 0; i < emit_n; i++) {
        uint16_t f = emit_order[i];
        node_t *nd = &circuit[f];
        if (nd->op == OP_INPUT || nd->op == OP_CONST) continue;
        char an[32], bn[32];
#define NAME_OF(fn, out)                                                              \
        do {                                                                          \
            node_t *m = &circuit[fn];                                                   \
            if (m->op == OP_INPUT) snprintf(out, sizeof(out), "x%u", (unsigned)m->a);  \
            else if (m->op == OP_CONST)                                                \
                snprintf(out, sizeof(out), "%s", m->a ? be->ones : be->zero);          \
            else snprintf(out, sizeof(out), "t[%d]", slot_of[fn]);                     \
        } while (0)
        NAME_OF(nd->a, an);
        NAME_OF(nd->b, bn);
#undef NAME_OF
        const char *expr;
        switch (nd->op) {
        case OP_AND:  expr = be->e_and;  break;
        case OP_OR:   expr = be->e_or;   break;
        case OP_XOR:  expr = be->e_xor;  break;
        case OP_ANDN: expr = be->e_andn; break;
        case OP_ORN:  expr = be->e_orn;  break;
        default:      expr = be->e_xnor; break;
        }
        printf("    t[%d] = ", slot_of[f]);
        printf(expr, an, bn);
        printf(";\n");
    }

    static const char *outn[4] = {"o0", "o1", "o2", "o3"};
    int outcomp = 0;
    for (int bit = 0; bit < 4; bit++) {
        uint16_t f = built[bit];
        if (f != targets[bit]) outcomp |= 1 << bit;
        node_t *nd = &circuit[f];
        if (nd->op == OP_INPUT) printf("    *%s = x%u;\n", outn[bit], (unsigned)nd->a);
        else if (nd->op == OP_CONST)
            printf("    *%s = %s;\n", outn[bit], nd->a ? be->ones : be->zero);
        else printf("    *%s = t[%d];\n", outn[bit], slot_of[f]);
    }
    printf("}\n");
    printf("#define PRESENT_CIRCUIT_GATES_%s_%s %d\n", be->name, name, gates);
    printf("#define PRESENT_CIRCUIT_OUTCOMP_%s_%s 0x%x\n", be->name, name, outcomp);
    fprintf(stderr, "%s %s: %d gates, output complements 0x%x\n",
            be->name, name, gates, outcomp);
    return 0;
}
