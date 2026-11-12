/* Region marker for bench_arm.c: an out-of-line function whose entry address
 * tools/arm_cycles.py looks up in the ELF symbol table. */
__attribute__((noinline)) void ca_mark(void) { __asm__ volatile("" ::: "memory"); }
