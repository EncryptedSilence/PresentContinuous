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
 * Usage:  sbox_synth <16 comma-separated S-box entries> [name]
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
static const int OPS[] = {OP_AND, OP_OR, OP_XOR, OP_ANDN, OP_ORN, OP_XNOR};
static const int N_OPS = (int)(sizeof(OPS) / sizeof(OPS[0]));

static uint16_t *by_cost[64];
static int by_cost_n[64];

static void push(int cost, uint16_t f)
{
    by_cost[cost] = realloc(by_cost[cost], (size_t)(by_cost_n[cost] + 1) * sizeof(uint16_t));
    if (!by_cost[cost]) { fprintf(stderr, "oom\n"); exit(1); }
    by_cost[cost][by_cost_n[cost]++] = f;
}

static int all_found(const uint16_t *targets)
{
    for (int i = 0; i < 4; i++)
        if (nodes[targets[i]].cost < 0) return 0;
    return 1;
}

static void search(const uint16_t *targets, int max_cost)
{
    for (int i = 0; i < NFUNC; i++) nodes[i].cost = -1;

    for (int i = 0; i < 4; i++) {
        nodes[INPUT_TT[i]].cost = 0;
        nodes[INPUT_TT[i]].op = OP_INPUT;
        nodes[INPUT_TT[i]].a = (uint16_t)i;
        push(0, INPUT_TT[i]);
    }
    /* Constants are free: they never need a gate in the emitted code. */
    for (int c = 0; c <= 1; c++) {
        uint16_t f = c ? 0xFFFFu : 0x0000u;
        if (nodes[f].cost < 0) {
            nodes[f].cost = 0;
            nodes[f].op = OP_CONST;
            nodes[f].a = (uint16_t)c;
            push(0, f);
        }
    }

    if (all_found(targets)) return;

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
        if (all_found(targets)) return;
    }
}

/* ---- emission with common-subexpression elimination -------------------------- */

static uint16_t emit_order[4096];
static int emit_n;
static uint8_t emitted[NFUNC];

static void collect(uint16_t f)
{
    if (emitted[f]) return;
    emitted[f] = 1;
    if (nodes[f].op == OP_INPUT || nodes[f].op == OP_CONST) {
        emit_order[emit_n++] = f;
        return;
    }
    collect(nodes[f].a);
    collect(nodes[f].b);
    emit_order[emit_n++] = f;
}

static int slot_of[NFUNC];

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <s0,s1,...,s15> [name]\n", argv[0]);
        return 2;
    }
    int sbox[16];
    {
        const char *p = argv[1];
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
    const char *name = argc > 2 ? argv[2] : "sbox";

    uint16_t targets[4];
    for (int bit = 0; bit < 4; bit++) {
        uint16_t tt = 0;
        for (int x = 0; x < 16; x++)
            if ((sbox[x] >> bit) & 1) tt |= (uint16_t)(1u << x);
        targets[bit] = tt;
    }

    search(targets, 12);
    for (int i = 0; i < 4; i++) {
        if (nodes[targets[i]].cost < 0) {
            fprintf(stderr, "no circuit found for output bit %d within cost bound\n", i);
            return 1;
        }
    }

    memset(emitted, 0, sizeof(emitted));
    emit_n = 0;
    for (int i = 0; i < 4; i++) collect(targets[i]);

    int gates = 0;
    printf("/* S-box %s = {", name);
    for (int i = 0; i < 16; i++) printf("%s0x%x", i ? "," : "", sbox[i]);
    printf("} */\n");
    printf("static inline void present_circuit_%s(uint64_t *o3, uint64_t *o2, uint64_t *o1,"
           " uint64_t *o0,\n", name);
    printf("        uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3)\n{\n");

    int tmp = 0;
    for (int i = 0; i < emit_n; i++) {
        uint16_t f = emit_order[i];
        node_t *nd = &nodes[f];
        if (nd->op == OP_INPUT || nd->op == OP_CONST) { slot_of[f] = -1; continue; }
        slot_of[f] = tmp++;
        gates++;
    }
    if (tmp) printf("    uint64_t t[%d];\n", tmp);

    for (int i = 0; i < emit_n; i++) {
        uint16_t f = emit_order[i];
        node_t *nd = &nodes[f];
        if (nd->op == OP_INPUT || nd->op == OP_CONST) continue;
        char an[32], bn[32];
#define NAME_OF(fn, out)                                                              \
        do {                                                                          \
            node_t *m = &nodes[fn];                                                   \
            if (m->op == OP_INPUT) snprintf(out, sizeof(out), "x%u", (unsigned)m->a);  \
            else if (m->op == OP_CONST)                                                \
                snprintf(out, sizeof(out), "%s", m->a ? "~(uint64_t)0" : "(uint64_t)0");\
            else snprintf(out, sizeof(out), "t[%d]", slot_of[fn]);                     \
        } while (0)
        NAME_OF(nd->a, an);
        NAME_OF(nd->b, bn);
#undef NAME_OF
        const char *expr;
        switch (nd->op) {
        case OP_AND:  expr = "%s & %s";     break;
        case OP_OR:   expr = "%s | %s";     break;
        case OP_XOR:  expr = "%s ^ %s";     break;
        case OP_ANDN: expr = "~%s & %s";    break;
        case OP_ORN:  expr = "~%s | %s";    break;
        default:      expr = "~(%s ^ %s)";  break;
        }
        printf("    t[%d] = ", slot_of[f]);
        printf(expr, an, bn);
        printf(";\n");
    }

    static const char *outn[4] = {"o0", "o1", "o2", "o3"};
    for (int bit = 0; bit < 4; bit++) {
        uint16_t f = targets[bit];
        node_t *nd = &nodes[f];
        if (nd->op == OP_INPUT) printf("    *%s = x%u;\n", outn[bit], (unsigned)nd->a);
        else if (nd->op == OP_CONST)
            printf("    *%s = %s;\n", outn[bit], nd->a ? "~(uint64_t)0" : "(uint64_t)0");
        else printf("    *%s = t[%d];\n", outn[bit], slot_of[f]);
    }
    printf("}\n");
    printf("#define PRESENT_CIRCUIT_GATES_%s %d\n", name, gates);
    fprintf(stderr, "%s: %d gates\n", name, gates);
    return 0;
}
