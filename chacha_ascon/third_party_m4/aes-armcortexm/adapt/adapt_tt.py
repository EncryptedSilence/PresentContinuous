import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
def rep(old, new, count=1):
    global s
    n = s.count(old)
    assert n == count, (old, n)
    s = s.replace(old, new)

HEADER = open(sys.argv[3]).read()
rep(".syntax unified\n.thumb\n\n.align 2\n.type AES_Te0,%object\nAES_Te0:\n",
    HEADER + "TE0_SECTION\n.align 2\n.type AES_Te0,%object\nAES_Te0:\n")
rep("@ void AES_128_keyschedule(const uint8_t *key,\n@       uint8_t *rk) {\n.global AES_128_keyschedule\n.type   AES_128_keyschedule,%function\nAES_128_keyschedule:\n",
    "    .size AES_Te0, .-AES_Te0\n\n.text\n.align 2\n@ void FN_KS(const uint8_t *key /* 4-byte aligned */,\n@       uint8_t *rk /* = rk_words + 4 */) {\n.global FN_KS\n.type   FN_KS,%function\nFN_KS:\n")
rep("    adr r3, AES_Te0\n", "    LOAD_TE0 r3\n")
rep("""@ void AES_128_encrypt_ctr(param const *p,
@       const uint8_t *in, uint8_t *out,
@       uint32_t len) {
.global AES_128_encrypt_ctr
.type   AES_128_encrypt_ctr,%function
AES_128_encrypt_ctr:
""", """@ void FN_CTR(const uint32_t rk[44], const uint8_t *in, uint8_t *out,
@       uint32_t len /* multiple of 16, > 0 */,
@       uint32_t n0, uint32_t n1, uint32_t n2, uint32_t ctr,
@       const uint32_t *rk_end /* rk + 40, used by AES_M4SS_LOOP only */);   [MODIFIED]
.global FN_CTR
.type   FN_CTR,%function
FN_CTR:
""")
rep("    adr r12, AES_Te0\n", "    LOAD_TE0 r12\n")
# precompute: block words from the stack arguments, rk from r14   [MODIFIED]
rep("""partial_precompute: //expect p in r14

    //load from p ctrnonce in r4-r7, key in r8-r11
    ldmia r14!, {r4-r11}
""", """partial_precompute: //expect rk in r14   [MODIFIED]

    //counter block (n0, n1, n2, BE32 ctr) from the stack arguments in r4-r7,
    //key in r8-r11   [MODIFIED: was ldmia r14!, {r4-r11} from p = {ctr, nonce, rk}]
    ldrd r4, r5, [sp, #ARG_N0]
    ldrd r6, r7, [sp, #ARG_N2]
    rev r7, r7
    ldmia r14!, {r8-r11}
""")
rep("""    and r4, r4, #0xffffff00
""", """    bic r7, r7, #0xff000000 //[MODIFIED: the varying byte is block byte 15 (row 3, column 3), was byte 0]
""")
rep("""    eor r1, r8, r3, ror #16
    push.w {r1}
""", """    eor r1, r8, r3, ror #24 //[MODIFIED: cancel the row-3 contribution of the zeroed byte, was ror #16]
    push.w {r1}
""")
rep("""    //load ctr
    ldr r8, [r14, #-64]
    //load key[0]
    ldr r9, [r14, #-48]

    //round 1
    eor r8, r9
    and r8, #0xff
    ldr r8, [r12, r8, lsl #2]
    eor r10, r10, r8, ror #16
""", """    //load ctr   [MODIFIED: from the stack argument; byte 15 of the block = ctr & 0xff]
    ldr r8, [sp, #ARG_CTR_ENC]
    //load rk[3], whose top byte is key byte 15   [MODIFIED: was key[0] at p+16]
    ldr r9, [r14, #-36]

    //round 1
    eor r8, r8, r9, lsr #24
    uxtb r8, r8
    ldr r8, [r12, r8, lsl #2]
    eor r10, r10, r8, ror #24 //[MODIFIED: row 3 rotation, was ror #16]
""")
rep("""    //load input, xor keystream and write to output
    ldmia r1!, {r8-r11}
    str.w r1, [sp, #20]
    eor r4, r8
    eor r5, r9
    eor r6, r10
    eor r7, r11
    stmia r2!, {r4-r7}
    str r2, [sp, #24]
""", """    //load input, xor keystream and write to output
    //[MODIFIED: single LDR/STR instead of LDM/STM, so in/out may be unaligned]
    ldr r9, [r1, #4]
    ldr r10, [r1, #8]
    ldr r11, [r1, #12]
    ldr r8, [r1], #16
    str.w r1, [sp, #20]
    eor r4, r8
    eor r5, r9
    eor r6, r10
    eor r7, r11
    str r5, [r2, #4]
    str r6, [r2, #8]
    str r7, [r2, #12]
    str r4, [r2], #16
    str r2, [sp, #24]
""")
rep("""    //load, inc, store ctrnonce
    sub r14, #128 //reset to p+4*4*4, as required by encrypt_block
    ldr r4, [r14, #-64]
    add r4, #1
    str r4, [r14, #-64]
""", """    //load, inc, store ctr   [MODIFIED: the counter is the stack argument, not p->ctr]
    sub r14, #128 //reset to rk+3*4*4, as required by encrypt_block
    ldr r4, [sp, #ARG_CTR_ENC]
    add r4, #1
    str r4, [sp, #ARG_CTR_ENC]
""")
rep("""    sub r14, #64 //reset to p, as required by partial_precompute
""", """    sub r14, #48 //reset to rk, as required by partial_precompute   [MODIFIED: was #64 to p]
""")
# the keyschedule epilogue is "pop {r4-r11}\n    bx lr"; the ctr one is "pop {r4-r11,r14}\n    bx lr"
rep("    pop {r4-r11,r14}\n    bx lr\n", "    pop {r4-r11,r14}\n    bx lr\n    .size FN_CTR, .-FN_CTR\n")
rep("    pop {r4-r11}\n    bx lr\n", "    pop {r4-r11}\n    bx lr\n    .size FN_KS, .-FN_KS\n")
# optional rolled rounds 3..9 (AES_M4SS_LOOP)   [MODIFIED, our addition]
i0 = s.index("encrypt_first:")
r3 = s.index("    //round 3\n", i0)
r4 = s.index("    //round 4\n", i0)
r5 = s.index("    //round 5\n", i0)
r10 = s.index("    //round 10\n", i0)
A, B, unrolled = s[r3:r4], s[r4:r5], s[r3:r10]
loop = ("    //rounds 3..9 rolled: A = odd rounds (r4-r7 -> r8-r11), B = even rounds\n"
        "    //(r8-r11 -> r4-r7); the loop ends after the A round whose round-key load\n"
        "    //leaves r14 at rk+160 (stack argument rk_end)   [MODIFIED, our addition]\n"
        ".align 2\nrounds_ab:\n" + A +
        "    ldr r0, [sp, #ARG_END_ENC]\n    cmp r14, r0\n    beq rounds_ab_done\n\n" + B +
        "    b rounds_ab\n.align 2\nrounds_ab_done:\n\n")
s = s[:r3] + "#ifndef AES_M4SS_LOOP\n" + unrolled + "#else\n" + loop + "#endif\n" + s[r10:]
s += "\n    .section .note.GNU-stack,\"\",%progbits\n"
open(dst, "w").write(s)
