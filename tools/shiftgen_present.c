/* ShiftGen2, re-targeted at a PRESENT block.
 *
 * The original (ShiftGen2/ShiftGen2/main.cpp) scores rotation constants for a
 * 128-bit state of four 32-bit words, counting active *bytes* -- it assumes
 * 8-bit S-boxes. PRESENT is a 64-bit state with 4-bit nibbles, so the search
 * space, the diffusion counts and the branch counts all differ. This port keeps
 * lin444_r1 / lin444_r2 and the scoring function identical and changes only the
 * geometry:
 *
 *     words        4 x 32-bit  ->  4 x 16-bit   (128-bit block -> 64-bit block)
 *     active unit  byte        ->  nibble       (8-bit S-box -> 4-bit S-box)
 *     c0 range     [0,32)      ->  [0,16)       (rotation is within a word)
 *     trials       32 of 128   ->  64 of 64     (every input bit, see below)
 *
 * The original perturbs din[b] = 1 << pos for b in 0..3, pos in 0..7 while din
 * is a uint32_t*, so it only ever tests bits 0..7 of each 32-bit word -- 32 of
 * the 128 positions. Here the word is 16 bits and pos runs the full width, so
 * all 64 input differences are covered. The normalisation divisor stays "number
 * of trials", as in the original (WORDSIZE == 4 words * 8 positions == 32).
 *
 * Metrics, per single-bit input difference, averaged over all trials:
 *   a1, a2  average number of output bits flipped, after 1 and 2 rounds
 *   b1, b2  average number of active nibbles, after 1 and 2 rounds
 *   bmin    minimum active nibbles after 1 round, + 1 for the active input
 *           nibble -- a single-bit upper bound on the differential branch number
 *
 * Usage:  shiftgen_present [a1 a2 b1 b2 bmin]      (default 1 2 1 2 1)
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NWORDS   4
#define WORDBITS 16
#define BLOCKBITS (NWORDS * WORDBITS)   /* 64 */
#define NIBBLES  (BLOCKBITS / 4)        /* 16 */
#define NTRIALS  BLOCKBITS              /* every single-bit input difference */
#define NROT     WORDBITS               /* rotation amounts 0 .. WORDBITS-1 */

/* Masked so ROTL16(a, 0) is well defined, unlike the original's a >> (32 - 0). */
static inline uint16_t ROTL16(uint16_t a, int b)
{
    return (uint16_t)((a << (b & 15)) | (a >> ((16 - b) & 15)));
}

static inline void lin444_r1(const uint16_t *din, uint16_t *dout, const int c0[3])
{
    dout[0] = din[0] ^ ROTL16(din[1], c0[0]) ^ ROTL16(din[2], c0[1]) ^ ROTL16(din[3], c0[2]);
    dout[1] = din[1] ^ ROTL16(din[2], c0[0]) ^ ROTL16(din[3], c0[1]) ^ ROTL16(dout[0], c0[2]);
    dout[2] = din[2] ^ ROTL16(din[3], c0[0]) ^ ROTL16(dout[0], c0[1]) ^ ROTL16(dout[1], c0[2]);
    dout[3] = din[3] ^ ROTL16(dout[0], c0[0]) ^ ROTL16(dout[1], c0[1]) ^ ROTL16(dout[2], c0[2]);
}

static inline void lin444_r2(const uint16_t *din, uint16_t *dout, const int c0[3])
{
    lin444_r1(din, dout, c0);
    uint16_t tmp[NWORDS];
    memcpy(tmp, dout, sizeof(tmp));
    lin444_r1(tmp, dout, c0);
}

typedef struct {
    double a1, a2, b1, b2;
    int bmin;
    double score;
    int c[3];
    int xors;
    int xors_inv;
} res_t;

/* Bitsliced XOR cost per round, which is not the same for every c0.
 *
 * Written out plainly, each of the four output words is a 4-term XOR, so the
 * layer costs 3 XORs per state bit = 192. Two output words can share a
 * subexpression only when the same *pair* of operands appears in both with the
 * same relative rotation. Reading off the term lists,
 *
 *   o0 : d0  R(d1,a)  R(d2,b)  R(d3,c)
 *   o1 : d1  R(d2,a)  R(d3,b)  R(o0,c)
 *   o2 : d2  R(d3,a)  R(o0,b)  R(o1,c)
 *   o3 : d3  R(o0,a)  R(o1,b)  R(o2,c)
 *
 * three independent conditions each buy one sharing, and they coincide only in
 * the geometric family c = (a,2a,3a):
 *
 *   c == a+b   (d1,d3) serves o0,o1; (d2,o0) serves o1,o2; (d3,o1) serves o2,o3
 *   b == 2a    (d1,d2) serves o0,o1; (d3,o0) serves o2,o3
 *   c-b == b-a (d2,d3) serves o0,o1; (o0,o1) serves o2,o3
 *
 * An earlier version of this function recognised only the progression, and so
 * priced 480 of the 4096 triples at 192 when they are 160 or less -- including
 * the whole 144 family, which is the cheapest one that contains usable
 * constants. Selection was being made from a table that never showed it.
 *
 * The authority is now analysis/present_sat/slp.py, which enumerates the
 * sharings rather than pattern-matching them and checks every program it counts
 * against the definition of the layer. This is the same rule stated in closed
 * form; the analysis tests assert the two agree on all 4096 triples. */
static int lin444_cost(const int c[3])
{
    int a = c[0] & (WORDBITS - 1), b = c[1] & (WORDBITS - 1), cc = c[2] & (WORDBITS - 1);
    if (cc == ((a + b) & (WORDBITS - 1))) return 144;
    if (b == ((2 * a) & (WORDBITS - 1))) return 160;
    if (((cc - b) & (WORDBITS - 1)) == ((b - a) & (WORDBITS - 1))) return 160;
    return 192;
}

/* The same question for decryption. The inverse recovers d3 first, from o0..o2,
 * which exchanges the roles of the first and last rotation -- so the conditions
 * are the mirror image. A triple is normally cheap in one direction only. */
static int lin444_inv_cost(const int c[3])
{
    int a = c[0] & (WORDBITS - 1), b = c[1] & (WORDBITS - 1), cc = c[2] & (WORDBITS - 1);
    if (a == ((b + cc) & (WORDBITS - 1))) return 144;
    if (b == ((2 * cc) & (WORDBITS - 1))) return 160;
    if (((cc - b) & (WORDBITS - 1)) == ((b - a) & (WORDBITS - 1))) return 160;
    return 192;
}

/* Identical to the original score(): weighted mean of the five metrics. */
static void score(res_t *r, const double w[5])
{
    double n = 0;
    for (int i = 0; i < 5; i++) n += w[i];
    r->score = (w[0] * r->a1 + w[1] * r->a2 + w[2] * r->b1 + w[3] * r->b2
                + w[4] * (double)r->bmin) / n;
}

static int active_nibbles(const uint16_t *s)
{
    int n = 0;
    for (int i = 0; i < NWORDS; i++)
        for (int k = 0; k < WORDBITS; k += 4)
            if ((s[i] >> k) & 0xF) n++;
    return n;
}

static int popcount_state(const uint16_t *s)
{
    int n = 0;
    for (int i = 0; i < NWORDS; i++) n += __builtin_popcount(s[i]);
    return n;
}

/* One sweep over all single-bit input differences, at the given round depth. */
static void sweep(const int c[3], int rounds, double *avg_bits, double *avg_act, int *min_act)
{
    int diff = 0, act_total = 0, mn = NIBBLES;

    for (int w = 0; w < NWORDS; w++) {
        for (int pos = 0; pos < WORDBITS; pos++) {
            uint16_t din[NWORDS] = { 0 }, dout[NWORDS];
            din[w] = (uint16_t)(1u << pos);

            if (rounds == 1) lin444_r1(din, dout, c);
            else             lin444_r2(din, dout, c);

            diff += popcount_state(dout);
            int act = active_nibbles(dout);
            act_total += act;
            if (act < mn) mn = act;
        }
    }

    *avg_bits = (double)diff / NTRIALS;
    *avg_act  = (double)act_total / NTRIALS;
    *min_act  = mn;
}

static void evaluate(const int c[3], res_t *r)
{
    int mn1, mn2;
    sweep(c, 1, &r->a1, &r->b1, &mn1);
    sweep(c, 2, &r->a2, &r->b2, &mn2);
    r->bmin = mn1 + 1;   /* + the active input nibble */
    r->c[0] = c[0]; r->c[1] = c[1]; r->c[2] = c[2];
    r->xors = lin444_cost(c);
    r->xors_inv = lin444_inv_cost(c);
}

static int by_score_desc(const void *x, const void *y)
{
    const res_t *a = x, *b = y;
    if (a->score < b->score) return 1;
    if (a->score > b->score) return -1;
    if (a->bmin != b->bmin) return b->bmin - a->bmin;
    return 0;
}

int main(int argc, char **argv)
{
    double w[5] = { 1.0, 2.0, 1.0, 2.0, 1.0 };
    int csv = 0;

    /* --csv dumps every candidate so selection can be scripted rather than read
     * off the top of a table: the interesting constants are often not the
     * highest-scoring ones, but the highest-scoring ones in a given cost tier. */
    if (argc >= 2 && strcmp(argv[1], "--csv") == 0) {
        csv = 1;
        argc--; argv++;
    }

    if (argc == 6) {
        double sum = 0;
        for (int i = 0; i < 5; i++) {
            char *end;
            w[i] = strtod(argv[i + 1], &end);
            if (*end || w[i] < 0) {
                fprintf(stderr, "weights must be non-negative numbers\n");
                return 1;
            }
            sum += w[i];
        }
        if (sum == 0) { fprintf(stderr, "weights must not be all zero\n"); return 1; }
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [--csv] [a1 a2 b1 b2 bmin]\n", argv[0]);
        return 1;
    }

    if (!csv)
    printf("PRESENT geometry: %d-bit block, %d x %d-bit words, %d nibbles, "
           "c0 in [0,%d)^3 = %d candidates\n",
           BLOCKBITS, NWORDS, WORDBITS, NIBBLES, NROT, NROT * NROT * NROT);
    if (!csv)
    printf("Weights: a1=%.2f a2=%.2f b1=%.2f b2=%.2f bmin=%.2f\n\n", w[0], w[1], w[2], w[3], w[4]);

    int n = NROT * NROT * NROT;
    res_t *all = malloc((size_t)n * sizeof(*all));
    if (!all) { fprintf(stderr, "out of memory\n"); return 1; }

    int i = 0;
    for (int c0 = 0; c0 < NROT; c0++)
        for (int c1 = 0; c1 < NROT; c1++)
            for (int c2 = 0; c2 < NROT; c2++) {
                int c[3] = { c0, c1, c2 };
                evaluate(c, &all[i]);
                score(&all[i], w);
                i++;
            }

    qsort(all, (size_t)n, sizeof(*all), by_score_desc);

    if (csv) {
        printf("c0,c1,c2,a1,a2,b1,b2,bmin,score,enc_xors,dec_xors\n");
        for (i = 0; i < n; i++)
            printf("%d,%d,%d,%.4f,%.4f,%.4f,%.4f,%d,%.4f,%d,%d\n",
                   all[i].c[0], all[i].c[1], all[i].c[2], all[i].a1, all[i].a2,
                   all[i].b1, all[i].b2, all[i].bmin, all[i].score,
                   all[i].xors, all[i].xors_inv);
        free(all);
        return 0;
    }

    printf("     a1      a2      b1      b2   bmin   score   enc   dec   c0\n");
    double best = all[0].score;
    int shown = 0;
    for (i = 0; i < n && all[i].score >= best - 0.1; i++, shown++)
        printf("%7.2f %7.2f %7.2f %7.2f %6d %7.2f %5d %5d   %2d %2d %2d\n",
               all[i].a1, all[i].a2, all[i].b1, all[i].b2, all[i].bmin,
               all[i].score, all[i].xors, all[i].xors_inv,
               all[i].c[0], all[i].c[1], all[i].c[2]);
    printf("\n%d of %d candidates within 0.1 of the best score %.2f\n", shown, n, best);

    /* Best by branch number alone, which is what actually bounds the trail. */
    int bb = 0;
    for (i = 0; i < n; i++) if (all[i].bmin > bb) bb = all[i].bmin;
    printf("best bmin over all candidates: %d", bb);
    for (i = 0; i < n; i++)
        if (all[i].bmin == bb) { printf("  (e.g. %d %d %d, score %.2f)",
                                        all[i].c[0], all[i].c[1], all[i].c[2], all[i].score); break; }
    printf("\n");

    /* What the cheap implementations cost in diffusion. Candidates whose
     * constants admit common-subexpression elimination run a shorter bitsliced
     * circuit; the question is whether any of them are still good constants. */
    printf("\nBy bitsliced XOR cost for encryption. The families are not nested:\n"
           "c2==c0+c1 gives 144, c1==2*c0 or an arithmetic progression gives 160.\n"
           "Best three of each tier by score, then the best by bmin:\n");
    printf("  xors  count      a1      a2      b1      b2   bmin   score   dec   c0\n");
    for (int tier = 0; tier < 3; tier++) {
        const int want = (int[]){ 192, 160, 144 }[tier];
        int count = 0, ibmin = -1, mb = -1;
        for (i = 0; i < n; i++) {
            if (all[i].xors != want) continue;
            count++;
            if (all[i].bmin > mb) { mb = all[i].bmin; ibmin = i; }
        }
        char nstr[16];
        snprintf(nstr, sizeof(nstr), "%d", count);
        int shown_tier = 0;
        for (i = 0; i < n && shown_tier < 3; i++) {   /* array is sorted by score */
            if (all[i].xors != want) continue;
            printf("  %4d  %5s %7.2f %7.2f %7.2f %7.2f %6d %7.2f %5d   %2d %2d %2d\n",
                   want, shown_tier ? "" : nstr,
                   all[i].a1, all[i].a2, all[i].b1, all[i].b2, all[i].bmin,
                   all[i].score, all[i].xors_inv,
                   all[i].c[0], all[i].c[1], all[i].c[2]);
            shown_tier++;
        }
        if (ibmin >= 0)
            printf("  %4d  %5s %7.2f %7.2f %7.2f %7.2f %6d %7.2f %5d   %2d %2d %2d   <- best bmin\n",
                   want, "", all[ibmin].a1, all[ibmin].a2, all[ibmin].b1, all[ibmin].b2,
                   all[ibmin].bmin, all[ibmin].score, all[ibmin].xors_inv,
                   all[ibmin].c[0], all[ibmin].c[1], all[ibmin].c[2]);
    }

    free(all);
    return 0;
}
