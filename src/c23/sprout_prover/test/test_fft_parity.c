/* Copyright 2026 The Zclassic developers - MIT License
 *
 * sprout_fft (parallel, used by the prover) must equal the vendored serial
 * fr_fft element for element, forward and inverse, at every power of two
 * from 2^1 to 2^21 (the Sprout domain). Exit status 0 = equal.
 *
 * Also REPORTS (does not gate on) the vendored fr_fft_parallel, which the
 * prover does not use. Before Z23 2bae686c3 it disagreed with fr_fft at every
 * size >= 256; from that revision on the count printed here is 0. */

#include "../sprout_par.h"
#include "sapling/fr.h"
#include "sapling/groth16_prover.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t mismatches(const struct fr *x, const struct fr *y, size_t n)
{
    size_t d = 0;
    for (size_t i = 0; i < n; i++)
        d += !fr_eq(&x[i], &y[i]);
    return d;
}

int main(void)
{
    int bad = 0;
    size_t vendor_parallel_bad = 0;
    unsigned T = sprout_cpu_count();
    for (unsigned lg = 1; lg <= 21; lg++) {
        size_t n = (size_t)1 << lg;
        struct fr *x = malloc(n * sizeof *x);
        struct fr *ref = malloc(n * sizeof *ref);
        struct fr *mine = malloc(n * sizeof *mine);
        if (!x || !ref || !mine) {
            printf("oom\n");
            return 2;
        }
        uint32_t s = 12345u + lg;
        for (size_t i = 0; i < n; i++) {
            uint8_t b[32];
            for (size_t k = 0; k < 32; k++) {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                b[k] = (uint8_t)s;
            }
            b[31] &= 0x3f;
            fr_from_bytes(&x[i], b);
        }
        for (int inv = 0; inv <= 1; inv++) {
            memcpy(ref, x, n * sizeof *x);
            memcpy(mine, x, n * sizeof *x);
            bool a = fr_fft(ref, n, inv);
            bool b = sprout_fft(mine, n, inv, T);
            size_t d = mismatches(ref, mine, n);
            if (d || !a || !b) {
                printf("n=2^%u %s: sprout_fft differs from fr_fft at %zu "
                       "positions (ok %d/%d)\n", lg, inv ? "inverse" : "forward",
                       d, (int)a, (int)b);
                bad++;
            }
            memcpy(mine, x, n * sizeof *x);
            if (fr_fft_parallel(mine, n, inv, (int)T))
                vendor_parallel_bad += mismatches(ref, mine, n) != 0;
        }
        free(x);
        free(ref);
        free(mine);
    }
    printf("sprout_fft vs fr_fft, 2^1..2^21 forward+inverse (%u threads): %s\n",
           T, bad ? "MISMATCH" : "equal");
    printf("finding: vendored fr_fft_parallel disagrees with fr_fft in %zu of "
           "42 cases\n", vendor_parallel_bad);
    return bad ? 1 : 0;
}
