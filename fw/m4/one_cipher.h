/* Which ciphers this firmware image contains.
 *
 * Two shapes of benchmark image are built from one harness:
 *
 *   the combined image   all seven ciphers, chosen from the KAT table at run time.
 *                        This is what results/m4-speed.csv has always been measured
 *                        with, and it stays: it is the only image that times all
 *                        seven under one layout, in one session, on one board.
 *
 *   a per-cipher image   -DM4_ONE_CIPHER=<slug>. Exactly one cipher's rows, and --
 *                        this is the point -- only that cipher's code. Every other
 *                        cipher's kernels are removed at compile time rather than
 *                        merely left uncalled.
 *
 * Why the second shape exists. The combined image carries every implementation
 * family for every cipher at once: sixteen bitsliced round functions in each of the
 * two word widths, both 128-bit families, and the scalar paths, ~57 KiB of it. That
 * is not a footprint any product would have, so the Flash and RAM figures taken from
 * it need a per-kernel call-graph closure to mean anything, and even then they
 * describe a kernel rather than an image. A per-cipher image *is* the answer to
 * "what does this cipher cost to deploy": its .text is the code, its .bss is the
 * state, and neither needs a tool to attribute.
 *
 * It also removes the sram-noart configuration's binding constraint. That
 * configuration relocates the timed code into SRAM, and the combined image fills
 * 102 KiB of the ~104 KiB available -- so any new kernel has to be paid for by
 * deleting another, which is a poor reason to leave an optimisation out.
 *
 * The slug is the reported cipher name with every character outside [0-9A-Za-z]
 * replaced by '_' (tools/cipher_set.py slug()). gen/cipher_set.h carries one
 * descriptor per cipher under that key; this header selects one and derives from it:
 *
 *   M4_ONE_NAME     the reported name, as a string literal
 *   M4_ONE_ROUNDS   round count
 *   M4_ONE_BB       block bytes, 8 or 16
 *   M4_ONE_FAM      M4_FAM_NARROW | M4_FAM_AES | M4_FAM_LIN
 *   M4_BUILD_NARROW / M4_BUILD_AES / M4_BUILD_LIN
 *                   whether that group of kernels is compiled at all. All three are
 *                   1 in the combined image; exactly one is 1 in a per-cipher image.
 *
 * Selecting the cipher's *bitsliced* kernel is a separate switch, PRESENT_ONE_CIPHER
 * in src/internal.h, because it is the library's business rather than the harness's
 * and because the 128-bit pair does not have one. The Makefile passes both for a
 * 64-bit cipher and only this one for a 128-bit cipher; nothing here depends on
 * that, so an image built with only M4_ONE_CIPHER is correct, just larger.
 */
#ifndef M4_ONE_CIPHER_H
#define M4_ONE_CIPHER_H

#include "gen/cipher_set.h"

#ifdef M4_ONE_CIPHER

/* M4_SEL(M4_CIPHER_ROUNDS_, M4_ONE_CIPHER) -> M4_CIPHER_ROUNDS_cipher_D -> 5.
 * The two levels are what make the paste see M4_ONE_CIPHER's expansion rather than
 * its name; the same trick as PRESENT_ONE_CIPHER_KERNEL in src/internal.h. */
#define M4_SEL_(prefix, slug) prefix##slug
#define M4_SEL(prefix, slug) M4_SEL_(prefix, slug)

#define M4_ONE_NAME   M4_SEL(M4_CIPHER_NAME_, M4_ONE_CIPHER)
#define M4_ONE_ROUNDS M4_SEL(M4_CIPHER_ROUNDS_, M4_ONE_CIPHER)
#define M4_ONE_BB     M4_SEL(M4_CIPHER_BB_, M4_ONE_CIPHER)
#define M4_ONE_FAM    M4_SEL(M4_CIPHER_FAM_, M4_ONE_CIPHER)

#define M4_BUILD_NARROW (M4_ONE_FAM == M4_FAM_NARROW)
#define M4_BUILD_AES    (M4_ONE_FAM == M4_FAM_AES)
#define M4_BUILD_LIN    (M4_ONE_FAM == M4_FAM_LIN)

/* The 128-bit round-count lists, narrowed to this image's one cipher.
 *
 * Redefining what gen/cipher_set.h just defined is deliberate and is the reason
 * this header includes it rather than the other way round: the generated file
 * describes the benchmarked *set*, and only a build knows which member of it this
 * image is. The family guards above already drop the other family entirely, so this
 * matters when one family is benchmarked at more than one round count -- today
 * neither is, and an image would silently carry the unused specialisation.
 *
 * M4_APPLY exists because X(M4_ONE_ROUNDS) would paste the macro's name: the
 * argument of a ## operand is not expanded, and the round-count lists feed macros
 * that paste (aes_table_pass_r##N). Passing it through a parameter that is used
 * without ## expands it first. */
#define M4_APPLY(X, N) X(N)
#undef M4_AES_ROUNDS_LIST
#undef M4_LIN_ROUNDS_LIST
#if M4_BUILD_AES
#define M4_AES_ROUNDS_LIST(X) M4_APPLY(X, M4_ONE_ROUNDS)
#else
#define M4_AES_ROUNDS_LIST(X)
#endif
#if M4_BUILD_LIN
#define M4_LIN_ROUNDS_LIST(X) M4_APPLY(X, M4_ONE_ROUNDS)
#else
#define M4_LIN_ROUNDS_LIST(X)
#endif

#else /* the combined image: every cipher, selected at run time */

#define M4_BUILD_NARROW 1
#define M4_BUILD_AES    1
#define M4_BUILD_LIN    1

#endif /* M4_ONE_CIPHER */

#endif /* M4_ONE_CIPHER_H */
