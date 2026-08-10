/* Keystream materialisation for the CTR backends: the big-endian serialisation
 * and the in-place XOR, word-wise.
 *
 * Why this is its own header rather than a loop in each backend.
 *
 * The obvious form -- `for (b = 0; b < 8; b++) buf[i + b] ^= ks >> (56 - 8*b);`
 * -- is a read-modify-write of a `uint8_t *` eight times per block. `buf` is a
 * caller-supplied byte pointer, so the compiler must assume it may alias the
 * keystream array and cannot merge the eight accesses into one 64-bit load, one
 * XOR and one store. Measured, that loop costs a flat ~0.7 cycles per byte on
 * every backend that runs it.
 *
 * A flat constant is not a neutral tax. It is a fixed addend on top of a
 * per-backend cost that varies by more than an order of magnitude, so it
 * compresses the fast rows towards each other and leaves the slow ones almost
 * untouched: it penalised ctr-bitslice-avx2 by 41% and ctr-table-x8 by 15%,
 * moving the ratio between them from 2.79x to 4.06x. The table was internally
 * consistent and systematically biased against exactly the backend the result is
 * about, and every Mbit/s figure understated what the machine can do. Since the
 * point of this harness is how many Mbit/s a device actually processes, that is
 * the wrong question answered precisely.
 *
 * `restrict` on `buf` does NOT fix it -- measured 2.2240 -> 2.2313 tsc/B on the
 * byte loop, i.e. nothing, and GCC 13.3 declines to fold the loop either way.
 * What fixes it is doing the byte-order conversion in a register and storing a
 * whole word: `bswap64` plus a 64-bit XOR, which needs no aliasing promise from
 * the caller because the load and the store are single accesses.
 *
 * Every measured backend includes this header and uses these helpers, so there
 * is one implementation of the step rather than one per file and it cannot drift
 * between them. That is weaker than saying the cost is identical everywhere, and
 * the weaker claim is the true one: the 64-bit backends call ctr_xor_be64 once
 * per 8-byte block and pay a byte-order conversion, while the 128-bit backends
 * call ctr_xor_bytes over a keystream their kernels already produced as bytes
 * and pay none, and in both cases how much of the cost is hidden behind
 * surrounding work depends on the backend. Shared code, comparable cost --
 * not equal cost. The one deliberate exception is ctr-ref, which keeps the literal
 * byte-at-a-time loop: it is the correctness oracle, its readability is the
 * point, and its throughput is irrelevant (it is two to three orders of
 * magnitude slower than every other row for reasons that have nothing to do with
 * serialisation). That the two forms must agree byte for byte is then a real
 * cross-check rather than a tautology -- the gate compares every backend against
 * ctr-ref, so a mistake in the word-wise path shows up as a ciphertext mismatch.
 *
 * memcpy, not a cast to `uint64_t *`: `buf` carries no alignment guarantee and a
 * cast would be both an alignment fault waiting to happen and a strict-aliasing
 * violation. GCC and Clang fold an 8-byte memcpy to a single load or store.
 */
#ifndef CTR_XOR_H
#define CTR_XOR_H

#include <stdint.h>
#include <string.h>

/* The host-order word whose bytes, in memory order, are `x` serialised
 * big-endian -- so that storing it reproduces the byte loop exactly. */
static inline uint64_t ctr_be64(uint64_t x)
{
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && defined(__GNUC__)
    return __builtin_bswap64(x);
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return x;
#else
    /* No byte-order macro: build it from the shifts and let the compiler
     * recognise the pattern. Correct on either endianness, because the byte
     * array is written in serialisation order and then reinterpreted. */
    uint8_t t[8];
    uint64_t v;
    for (int b = 0; b < 8; b++) t[b] = (uint8_t)(x >> (56 - 8 * b));
    memcpy(&v, t, sizeof v);
    return v;
#endif
}

/* buf[0..8) ^= the big-endian serialisation of ks. */
static inline void ctr_xor_be64(uint8_t *buf, uint64_t ks)
{
    uint64_t w;
    memcpy(&w, buf, sizeof w);
    w ^= ctr_be64(ks);
    memcpy(buf, &w, sizeof w);
}

/* buf[0..8) = the big-endian serialisation of ks. Used to build counter blocks
 * for the 128-bit ciphers, whose kernels take bytes rather than a uint64_t. */
static inline void ctr_store_be64(uint8_t *buf, uint64_t ks)
{
    const uint64_t w = ctr_be64(ks);
    memcpy(buf, &w, sizeof w);
}

/* buf[0..n) ^= ks[0..n), for a keystream already materialised as bytes. n is a
 * multiple of 8 for every caller here (the 128-bit block is 16); the tail loop
 * is there so the helper is not silently wrong if that ever stops holding. */
static inline void ctr_xor_bytes(uint8_t *buf, const uint8_t *ks, size_t n)
{
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t a, b;
        memcpy(&a, buf + i, sizeof a);
        memcpy(&b, ks + i, sizeof b);
        a ^= b;
        memcpy(buf + i, &a, sizeof a);
    }
    for (; i < n; i++) buf[i] ^= ks[i];
}

#endif /* CTR_XOR_H */
