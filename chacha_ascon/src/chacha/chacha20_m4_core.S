/* ChaCha20 block function for Cortex-M4 (ARMv7E-M Thumb-2), lazy rotation.
 *
 *   void chacha20_m4_blocks(uint8_t *out, const uint8_t *in, size_t nblocks,
 *                           uint32_t state[16]);
 * XORs nblocks (>= 1) full 64-byte keystream blocks into in -> out and advances
 * state[12]. out/in may be unaligned (only single LDR/STR touch them) and may
 * be equal. The C wrapper (chacha20_m4.c) does the RFC 8439 setup and the tail.
 *
 * Method (see chacha20_lazy.c for the derivation): rows b (x4..x7) and d
 * (x12..x15) are held rotated right by 7 and 8, i.e. true = rotl(stored, 7|8),
 * and every rotation is folded into the shifted operand of the next ADD/EOR, so
 * a quarter-round is 8 single-cycle instructions and no ROR is executed in the
 * rounds. Pre-rotating b and d once per block (8 RORs) makes all ten double
 * rounds identical; the feed-forward undoes it for free in its own ADD.
 *
 * Registers: a = r0-r3, b = r4-r7, d = r8-r11, and two of the c row in r12/lr.
 * The c row lives in the stack frame; the two words a half-round needs are in
 * r12/lr. Order column(0,1) column(2,3) diagonal(0,1) diagonal(2,3) needs c8,c9
 * then c10,c11 then c10,c11 then c8,c9 -- two LDRD/STRD swaps per double round.
 * The double-round loop body is two double rounds (5 iterations); its counter
 * is decremented in a swap, when r12 is momentarily free.
 */
    .syntax unified
    .thumb
    .text

    .equ C8,   0
    .equ C10,  8
    .equ X14,  16
    .equ OUTP, 24
    .equ INP,  28
    .equ STP,  32
    .equ NBLK, 36
    .equ CNT,  40
    .equ FRAME, 44

/* QRL a b c d: one lazy quarter-round, b/d pending (7, 8) in and out */
    .macro QRL a, b, c, d
    add.w   \a, \a, \b, ror #25
    eor.w   \d, \a, \d, ror #24
    add.w   \c, \c, \d, ror #16
    eor.w   \b, \c, \b, ror #25
    add.w   \a, \a, \b, ror #20
    eor.w   \d, \a, \d, ror #16
    add.w   \c, \c, \d, ror #24
    eor.w   \b, \c, \b, ror #20
    .endm

/* one double round; c pair enters and leaves as (c8, c9) in (r12, lr) */
    .macro DROUND count=0
    QRL     r0, r4, r12, r8
    QRL     r1, r5, lr,  r9
    strd    r12, lr, [sp, #C8]
    ldrd    r12, lr, [sp, #C10]
    QRL     r2, r6, r12, r10
    QRL     r3, r7, lr,  r11
    QRL     r0, r5, r12, r11
    QRL     r1, r6, lr,  r8
    strd    r12, lr, [sp, #C10]
    .if \count
    ldr     r12, [sp, #CNT]
    subs    r12, r12, #1
    str     r12, [sp, #CNT]
    .endif
    ldrd    r12, lr, [sp, #C8]
    QRL     r2, r7, r12, r9
    QRL     r3, r4, lr,  r10
    .endm

/* out word i (in register \r) = (\r [ror] + state[i]) ^ in[i]; r10 scratch,
 * r11 = out, r12 = state, lr = in */
    .macro OUTW r, i, rot=0
    ldr     r10, [r12, #4*\i]
    .if \rot
    add.w   \r, r10, \r, ror #\rot
    .else
    add.w   \r, \r, r10
    .endif
    ldr     r10, [lr, #4*\i]
    eor.w   \r, \r, r10
    str     \r, [r11, #4*\i]
    .endm

/* two words at once, scratch r0-r3: four back-to-back loads pipeline (2+1+1+1) */
    .macro OUT2 ra, ia, rota, rb, ib, rotb
    ldr     r0, [r12, #4*\ia]
    ldr     r1, [lr, #4*\ia]
    ldr     r2, [r12, #4*\ib]
    ldr     r3, [lr, #4*\ib]
    .if \rota
    add.w   \ra, r0, \ra, ror #\rota
    .else
    add.w   \ra, \ra, r0
    .endif
    eor.w   \ra, \ra, r1
    .if \rotb
    add.w   \rb, r2, \rb, ror #\rotb
    .else
    add.w   \rb, \rb, r2
    .endif
    eor.w   \rb, \rb, r3
    str     \ra, [r11, #4*\ia]
    str     \rb, [r11, #4*\ib]
    .endm

    .global chacha20_m4_blocks
    .type   chacha20_m4_blocks, %function
    .align  4
chacha20_m4_blocks:
    push    {r4-r11, lr}
    sub     sp, sp, #FRAME
    str     r0, [sp, #OUTP]
    str     r1, [sp, #INP]
    str     r3, [sp, #STP]
    str     r2, [sp, #NBLK]
.Lblock:
    ldr     lr, [sp, #STP]
    add     r12, lr, #32
    ldmia   r12, {r0-r3}            /* x8..x11 -> c slots */
    strd    r0, r1, [sp, #C8]
    strd    r2, r3, [sp, #C10]
    add     r12, lr, #48
    ldmia   r12, {r8-r11}           /* x12..x15 */
    ldmia   lr, {r0-r7}             /* x0..x7 */
    ror     r4, r4, #7
    ror     r5, r5, #7
    ror     r6, r6, #7
    ror     r7, r7, #7
    ror     r8, r8, #8
    ror     r9, r9, #8
    ror     r10, r10, #8
    ror     r11, r11, #8
    movs    r12, #5
    str     r12, [sp, #CNT]
    ldrd    r12, lr, [sp, #C8]
.Lrounds:
    DROUND
    DROUND  1
    bne     .Lrounds

    /* feed-forward + XOR. Free r10/r11 by parking x14/x15, c pair to its slots */
    strd    r12, lr, [sp, #C8]
    strd    r10, r11, [sp, #X14]
    ldr     r12, [sp, #STP]
    ldr     lr, [sp, #INP]
    ldr     r11, [sp, #OUTP]
    OUTW    r0, 0
    OUTW    r1, 1
    OUTW    r2, 2
    OUTW    r3, 3               /* r0-r3 free from here: paired, pipelined loads */
    OUT2    r4, 4, 25, r5, 5, 25
    OUT2    r6, 6, 25, r7, 7, 25
    OUT2    r8, 12, 24, r9, 13, 24
    ldrd    r4, r5, [sp, #C8]
    ldrd    r6, r7, [sp, #C10]
    ldrd    r8, r9, [sp, #X14]
    OUT2    r4, 8, 0, r5, 9, 0
    OUT2    r6, 10, 0, r7, 11, 0
    OUT2    r8, 14, 24, r9, 15, 24
    /* advance: counter, pointers, block count */
    ldr     r0, [r12, #48]
    adds    r0, r0, #1
    str     r0, [r12, #48]
    add     r11, r11, #64
    add     lr, lr, #64
    str     r11, [sp, #OUTP]
    str     lr, [sp, #INP]
    ldr     r0, [sp, #NBLK]
    subs    r0, r0, #1
    str     r0, [sp, #NBLK]
    bne     .Lblock

    add     sp, sp, #FRAME
    pop     {r4-r11, pc}
    .size   chacha20_m4_blocks, . - chacha20_m4_blocks
