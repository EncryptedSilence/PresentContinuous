#include "ascon_aead.h"

void ascon_multi_by_single(ascon_enc_fn enc, const ascon_job *jobs, size_t n,
                           size_t mlen, size_t adlen)
{
    for (size_t i = 0; i < n; i++) {
        unsigned long long clen;
        enc(jobs[i].c, &clen, jobs[i].m, mlen, jobs[i].ad, adlen, 0,
            jobs[i].nonce, jobs[i].key);
    }
}
