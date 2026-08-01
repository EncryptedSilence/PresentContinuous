#ifndef PRESENT_TESTUTIL_H
#define PRESENT_TESTUTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_failed = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        tests_run++;                                                           \
        if (!(cond)) {                                                         \
            tests_failed++;                                                    \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);               \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

#define CHECK_EQ64(got, want, ...)                                             \
    do {                                                                       \
        tests_run++;                                                           \
        if ((got) != (want)) {                                                 \
            tests_failed++;                                                    \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);               \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n  got  %016llx\n  want %016llx\n",              \
                    (unsigned long long)(got), (unsigned long long)(want));    \
        }                                                                      \
    } while (0)

static inline int test_summary(const char *name)
{
    if (tests_failed == 0) {
        printf("ok   %s (%d checks)\n", name, tests_run);
        return 0;
    }
    printf("FAIL %s (%d/%d checks failed)\n", name, tests_failed, tests_run);
    return 1;
}

/* xorshift64*, so tests are reproducible without depending on libc rand(). */
static uint64_t rng_state = 0x243F6A8885A308D3ull;

static inline uint64_t rng_next(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

#endif /* PRESENT_TESTUTIL_H */
