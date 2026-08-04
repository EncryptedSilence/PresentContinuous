/* The lin444 linear layer in bitsliced form, as macro bodies.
 *
 * Both bitsliced backends need the same four assignments; they differ only in the
 * word type and in how an XOR is spelled. Keeping the derivation here means the
 * scalar and AVX2 versions cannot drift apart, and -- the reason this is a header
 * of macros rather than a header of inline functions -- it lets a caller
 * instantiate a body with the rotation constants as *literals*.
 *
 * That last point is what makes the layer fast. Word w bit k is register
 * w * WB + k, so ROTL(x, c) is the index shift BS(w, k - c) and costs nothing --
 * provided c is a constant. Read from the variant descriptor at run time, every
 * index becomes a subtract, an add and a mask, and the layer issues several
 * hundred scalar address instructions per round against 160-192 XORs of real
 * work. tools/gen_c.py emits PRESENT_LIN444_LIST(X) with one entry per triple any
 * variant uses, and each backend instantiates these bodies once per entry.
 *
 * k - c is at worst -(WB-1), hence the + WB before the mask; WB is a power of two
 * so the mask is exact.
 */

#ifndef PRESENT_LIN444_BODY_H
#define PRESENT_LIN444_BODY_H

#define WB PRESENT_LIN444_WORD_BITS
#define BS(w, k) ((w) * WB + (((k) + WB) & (WB - 1)))
#define TS(k) (((k) + WB) & (WB - 1))   /* index into a WB-entry temporary */

/* Common difference of the rotation constants, and whether they are in
 * arithmetic progression. Constant expressions when the arguments are. */
#define LIN444_D(C0, C1, C2) (((((C1) - (C0)) % WB) + WB) % WB)
#define LIN444_IS_AP(C0, C1, C2) \
    (LIN444_D(C0, C1, C2) == ((((C2) - (C1)) % WB + WB) % WB))

/* The general case: four output words, each a four-term XOR. 3 XORs per state
 * bit = 192 per round -- against the ~560 a dense 64x64 matrix would need, because
 * the chained form lets each output word reuse the ones above it. */
#define LIN444_FWD_GEN(XOR, c0, c1, c2, in, out)                                      \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(0, k)] = XOR(XOR(in[BS(0, k)], in[BS(1, k - c0)]),                       \
                            XOR(in[BS(2, k - c1)], in[BS(3, k - c2)]));                 \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(1, k)] = XOR(XOR(in[BS(1, k)], in[BS(2, k - c0)]),                       \
                            XOR(in[BS(3, k - c1)], out[BS(0, k - c2)]));                \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(2, k)] = XOR(XOR(in[BS(2, k)], in[BS(3, k - c0)]),                       \
                            XOR(out[BS(0, k - c1)], out[BS(1, k - c2)]));               \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(3, k)] = XOR(XOR(in[BS(3, k)], out[BS(0, k - c0)]),                      \
                            XOR(out[BS(1, k - c1)], out[BS(2, k - c2)]));

/* Constants in arithmetic progression with common difference D.
 *
 * Two output words can share a subexpression only when the same pair of operands
 * appears in both at the same relative rotation:
 *
 *   o0 : d0  R(d1,c0)  R(d2,c1)  R(d3,c2)     (d2,d3) at offset c2-c1
 *   o1 : d1  R(d2,c0)  R(d3,c1)  R(o0,c2)     (d2,d3) at offset c1-c0
 *   o2 : d2  R(d3,c0)  R(o0,c1)  R(o1,c2)     (o0,o1) at offset c2-c1
 *   o3 : d3  R(o0,c0)  R(o1,c1)  R(o2,c2)     (o0,o1) at offset c1-c0
 *
 * Those offsets agree exactly when c1-c0 == c2-c1, and then two temporaries do it:
 *
 *   V[k] = d2[k] ^ d3[k-D]   so R(d2,c1) ^ R(d3,c2) == V[k-c1], and
 *                               R(d2,c0) ^ R(d3,c1) == V[k-c0]
 *   X[k] = o0[k] ^ o1[k-D]   likewise for the two (o0,o1) pairs
 *
 * Each costs WB XORs and saves 2*WB, so the layer runs at 160 rather than 192.
 * (If the common difference also equals c0 -- c = (a,2a,3a) -- two further
 * temporaries appear and the cost falls to 128, but every triple in that family
 * diffuses badly: run tools/shiftgen_present and compare the a2 column. Not
 * implemented, because no usable constants live there.)
 */
#define LIN444_FWD_AP(T, XOR, c0, c1, c2, D, in, out)                                 \
    T V[WB], X[WB];                                                                   \
    for (int k = 0; k < WB; k++) V[k] = XOR(in[BS(2, k)], in[BS(3, k - D)]);           \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(0, k)] = XOR(XOR(in[BS(0, k)], in[BS(1, k - c0)]), V[TS(k - c1)]);       \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(1, k)] = XOR(XOR(in[BS(1, k)], V[TS(k - c0)]), out[BS(0, k - c2)]);      \
    for (int k = 0; k < WB; k++) X[k] = XOR(out[BS(0, k)], out[BS(1, k - D)]);         \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(2, k)] = XOR(XOR(in[BS(2, k)], in[BS(3, k - c0)]), X[TS(k - c1)]);       \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(3, k)] = XOR(XOR(in[BS(3, k)], X[TS(k - c0)]), out[BS(2, k - c2)]);

/* Undo the four assignments bottom-up. Each line introduces exactly one new
 * unknown, which is why lin444 is invertible for every choice of constants and
 * why the inverse costs the same as the forward direction -- unlike the table
 * path, where the inverse S-box cannot be fused into the inverse permutation. */
#define LIN444_INV_GEN(XOR, c0, c1, c2, in, out)                                      \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(3, k)] = XOR(XOR(in[BS(3, k)], in[BS(0, k - c0)]),                       \
                            XOR(in[BS(1, k - c1)], in[BS(2, k - c2)]));                 \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(2, k)] = XOR(XOR(in[BS(2, k)], out[BS(3, k - c0)]),                      \
                            XOR(in[BS(0, k - c1)], in[BS(1, k - c2)]));                 \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(1, k)] = XOR(XOR(in[BS(1, k)], out[BS(2, k - c0)]),                      \
                            XOR(out[BS(3, k - c1)], in[BS(0, k - c2)]));                \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(0, k)] = XOR(XOR(in[BS(0, k)], out[BS(1, k - c0)]),                      \
                            XOR(out[BS(2, k - c1)], out[BS(3, k - c2)]));

/* The inverse admits the same reduction, with the pairs read off the other way
 * round: (o0,o1) serves d3 and d2, and (d2,d3) serves d1 and d0. */
#define LIN444_INV_AP(T, XOR, c0, c1, c2, D, in, out)                                 \
    T A[WB], B[WB];                                                                   \
    for (int k = 0; k < WB; k++) A[k] = XOR(in[BS(0, k)], in[BS(1, k - D)]);           \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(3, k)] = XOR(XOR(in[BS(3, k)], A[TS(k - c0)]), in[BS(2, k - c2)]);       \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(2, k)] = XOR(XOR(in[BS(2, k)], out[BS(3, k - c0)]), A[TS(k - c1)]);      \
    for (int k = 0; k < WB; k++) B[k] = XOR(out[BS(2, k)], out[BS(3, k - D)]);         \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(1, k)] = XOR(XOR(in[BS(1, k)], B[TS(k - c0)]), in[BS(0, k - c2)]);       \
    for (int k = 0; k < WB; k++)                                                      \
        out[BS(0, k)] = XOR(XOR(in[BS(0, k)], out[BS(1, k - c0)]), B[TS(k - c1)]);

/* The two bodies above are the *runtime-constant* fallbacks, for a triple no
 * variant declared. Every triple that a variant does declare gets a specialised
 * body generated into src/gen/lin444_bodies.h, where the sharing is chosen by the
 * enumeration in analysis/present_sat/slp.py rather than by the two cases spelled
 * out here -- so a specialised layer may run at 144 XORs where this fallback pair
 * only knows 160 and 192.
 *
 * A backend instantiates a generated body by defining a local X-macro over
 * PRESENT_LIN444_LIST. The list callback takes only (tag, c0, c1, c2), so the
 * backend's word type and XOR spelling have to be in scope at the expansion site
 * rather than passed down; that is why the instantiation lives in each .c file
 * instead of in one macro here. */
/* noinline so that every triple is compiled and measured on the same terms. Left
 * to itself the compiler inlines whichever bodies happen to be reached from the
 * dispatcher's fall-through and leaves the rest as calls, which is enough to
 * reorder two layers that differ by 2% -- the inlined one avoids a call and gets
 * scheduled against the round body. The layer is a few hundred instructions
 * operating on 2 KiB of state, so the call itself is noise; what is not noise is
 * comparing one form that was inlined against one that was not. */
#define LIN444_SPEC_ONE(NAME, T, XOR, TAG, BODY)                                      \
    __attribute__((noinline))                                                         \
    static void NAME##_##TAG(const T *in, T *out)                                     \
    {                                                                                 \
        BODY(T, XOR, in, out)                                                         \
    }

#endif /* PRESENT_LIN444_BODY_H */
