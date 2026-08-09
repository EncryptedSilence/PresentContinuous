#include <string.h>
#include "ctr_backend.h"

extern const ctr_backend_t ctr_backends_narrow[];
extern const size_t ctr_backends_narrow_count;
extern const ctr_backend_t ctr_backends_wide[];
extern const size_t ctr_backends_wide_count;

static const struct { const ctr_backend_t *v; const size_t *n; } groups[] = {
    { ctr_backends_narrow, &ctr_backends_narrow_count },
    { ctr_backends_wide,   &ctr_backends_wide_count   },
    /* Task 4  appends: { ctr_backends_bitslice,  &ctr_backends_bitslice_count  }, */
    /* Task 4  appends: { ctr_backends_avx2,      &ctr_backends_avx2_count      }, */
    /* Task 5  appends: { ctr_backends_neon,      &ctr_backends_neon_count      }, */
    /* Task 6  appends: { ctr_backends_wide_neon, &ctr_backends_wide_neon_count }, */
};

#define NGROUPS (sizeof groups / sizeof groups[0])

size_t ctr_backend_count(void)
{
    size_t n = 0;
    for (size_t g = 0; g < NGROUPS; g++) n += *groups[g].n;
    return n;
}

const ctr_backend_t *ctr_backend_at(size_t i)
{
    for (size_t g = 0; g < NGROUPS; g++) {
        if (i < *groups[g].n) return &groups[g].v[i];
        i -= *groups[g].n;
    }
    return NULL;
}

const ctr_backend_t *ctr_backend_reference_for(const char *cipher)
{
    for (size_t i = 0; i < ctr_backend_count(); i++) {
        const ctr_backend_t *b = ctr_backend_at(i);
        if (!strcmp(b->name, "ctr-ref") && !strcmp(b->cipher, cipher)) return b;
    }
    return NULL;
}
