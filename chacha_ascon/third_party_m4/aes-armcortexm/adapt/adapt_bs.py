import sys
src, dst, hdr = sys.argv[1:4]
s = open(src).read()
def rep(old, new, count=1):
    global s
    n = s.count(old)
    assert n == count, (old, n)
    s = s.replace(old, new)
rep(".syntax unified\n.thumb\n\n", open(hdr).read())
rep("AES_128_keyschedule", "aes128_m4ss_bs_keyschedule", 4)
rep("AES_128_encrypt_ctr", "aes128_m4ss_bs_ctr", 4)
rep("""    //load from p two ctrnonce-blocks in r4-r7 and r8-r11
    ldmia.w r0!, {r4-r7} //increase r0 to point to p.rk for addroundkey
""", """    //load from p two ctrnonce-blocks in r4-r7 and r8-r11
    ldmia.w r0!, {r4-r7} //increase r0 to point to p.rk for addroundkey
    ldr r0, [r0] //[MODIFIED: p = {block[16], const rk *}; the round keys are not in p]
""")
rep("""    //load input, xor keystream and write to output
    ldmia r0!, {r1-r3,r12} //load first block input
    eor r4, r1
    eor r5, r2
    eor r6, r3
    eor r7, r12
    ldr r1, [sp, #60] //load out
    stmia.w r1!, {r4-r7} //write first block output

    ldmia r0!, {r4-r7} //load second block input
    eor r8, r4
    eor r9, r5
    eor r10, r6
    eor r11, r7
    stmia r1!, {r8-r11} //write second block output
""", """    //load input, xor keystream and write to output
    //[MODIFIED: single LDR/STR instead of LDM/STM, so in/out may be unaligned]
    ldr r1, [r0, #0] //load first block input
    ldr r2, [r0, #4]
    ldr r3, [r0, #8]
    ldr r12, [r0, #12]
    eor r4, r1
    eor r5, r2
    eor r6, r3
    eor r7, r12
    ldr r1, [sp, #60] //load out
    str r4, [r1, #0] //write first block output
    str r5, [r1, #4]
    str r6, [r1, #8]
    str r7, [r1, #12]

    ldr r4, [r0, #16] //load second block input
    ldr r5, [r0, #20]
    ldr r6, [r0, #24]
    ldr r7, [r0, #28]
    adds r0, #32
    eor r8, r4
    eor r9, r5
    eor r10, r6
    eor r11, r7
    str r8, [r1, #16] //write second block output
    str r9, [r1, #20]
    str r10, [r1, #24]
    str r11, [r1, #28]
    adds r1, #32
""")
rep("""    //load p, len, ctr
    ldr r0, [sp, #52] //p in r0, as required by encrypt_blocks
""", """    //load p, len, ctr   [p is the caller's mutable 20-byte block struct, not the context]
    ldr r0, [sp, #52] //p in r0, as required by encrypt_blocks
""")
rep("    add sp, #68\n    pop {r4-r11,r14}\n    bx lr\n",
    "    add sp, #68\n    pop {r4-r11,r14}\n    bx lr\n    .ltorg\n    .size aes128_m4ss_bs_ctr, .-aes128_m4ss_bs_ctr\n")
s += "\n    .section .note.GNU-stack,\"\",%progbits\n"
open(dst, "w").write(s)
