/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Parallel multi-scalar multiplication (Pippenger's algorithm).
 * Splits bucket accumulation across pthreads for ~Nx speedup on N cores.
 *
 * Also: parallel FFT for Groth16 quotient polynomial computation. */

#include "sapling/groth16_prover.h"
#include "sapling/bls12_381.h"
#include "sapling/fr.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

/* ── Parallel FFT ───────────────────────────────────────────────── */

struct fft_butterfly_args {
    struct fr *coeffs;
    size_t n;
    size_t start_k;    /* first group index for this thread */
    size_t end_k;      /* last group index (exclusive) */
    size_t m;           /* group size (2^stage) */
    struct fr *omega_m; /* twiddle factor for this stage */
};

static void *fft_butterfly_thread(void *arg)
{
    struct fft_butterfly_args *a = (struct fft_butterfly_args *)arg;
    size_t half = a->m >> 1;
    struct fr omega_m = *a->omega_m;

    for (size_t k = a->start_k; k < a->end_k; k += a->m) {
        struct fr w;
        /* Compute w = omega_m^(k/m * half) — but actually we start from 1
         * and multiply by omega_m each iteration within the group. */
        fr_one(&w);

        /* Recompute twiddle: w = omega_m^0 at start of each group */
        for (size_t j = 0; j < half; j++) {
            struct fr t, u;
            fr_mul(&t, &w, &a->coeffs[k + j + half]);
            u = a->coeffs[k + j];
            fr_add(&a->coeffs[k + j], &u, &t);
            fr_sub(&a->coeffs[k + j + half], &u, &t);
            fr_mul(&w, &w, &omega_m);
        }
    }
    return NULL;
}

/* Forward declaration from groth16_prover.c */
extern bool fr_fft(struct fr *coeffs, size_t n, bool inverse);

static inline struct fr fft_root_of_unity(unsigned int log_n, bool inverse)
{
    /* Compute omega (root of unity) */
    /* 2^32-th root of unity for BLS12-381 Fr */
    static const uint8_t ROOT_BYTES[32] = {
        0x59, 0xf1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xec, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    struct fr omega;
    fr_from_bytes(&omega, ROOT_BYTES);

    /* Raise to 2^(32-log_n) to get n-th root of unity */
    for (unsigned int i = log_n; i < 32; i++)
        fr_sq(&omega, &omega);

    if (inverse)
        fr_inv(&omega, &omega);
    return omega;
}

static inline struct fr fft_omega_pow_n_over_m(struct fr omega, size_t n,
                                               size_t m)
{
    struct fr omega_m;
    /* omega_m = omega^(n/m) */
    struct fr base = omega;
    uint64_t exp = n / m;
    fr_one(&omega_m);
    while (exp > 0) {
        if (exp & 1) fr_mul(&omega_m, &omega_m, &base);
        fr_sq(&base, &base);
        exp >>= 1;
    }
    return omega_m;
}

static void fft_spawn_group_butterflies(struct fr *coeffs, size_t n, size_t m,
                                        size_t num_groups, struct fr *omega_m,
                                        int num_threads)
{
    /* Parallel: split groups across threads */
    int actual_threads = num_threads;
    if ((size_t)actual_threads > num_groups)
        actual_threads = (int)num_groups;

    struct fft_butterfly_args *args = zcl_calloc((size_t)actual_threads,
        sizeof(struct fft_butterfly_args), "fft_par_args");
    pthread_t *tids = zcl_calloc((size_t)actual_threads, sizeof(pthread_t), "fft_par_threads");

    size_t groups_per_thread = num_groups / (size_t)actual_threads;
    size_t remainder = num_groups % (size_t)actual_threads;

    size_t k_offset = 0;
    for (int t = 0; t < actual_threads; t++) {
        size_t my_groups = groups_per_thread + (t < (int)remainder ? 1 : 0);
        args[t].coeffs = coeffs;
        args[t].n = n;
        args[t].start_k = k_offset;
        args[t].end_k = k_offset + my_groups * m;
        args[t].m = m;
        args[t].omega_m = omega_m;
        k_offset = args[t].end_k;

        /* raw-pthread-ok: short-burst-joined-immediately */
        pthread_create(&tids[t], NULL, fft_butterfly_thread, &args[t]);
    }

    for (int t = 0; t < actual_threads; t++)
        pthread_join(tids[t], NULL);

    free(args);
    free(tids);
}

static inline void fft_scale_by_inverse_n(struct fr *coeffs, size_t n)
{
    /* Multiply all coefficients by n^{-1} */
    struct fr n_fr, n_inv, one_val;
    fr_one(&one_val);
    fr_zero(&n_fr);
    for (size_t i = 0; i < n; i++)
        fr_add(&n_fr, &n_fr, &one_val);
    fr_inv(&n_inv, &n_fr);
    for (size_t i = 0; i < n; i++)
        fr_mul(&coeffs[i], &coeffs[i], &n_inv);
}

bool fr_fft_parallel(struct fr *coeffs, size_t n, bool inverse, int num_threads)
{
    if (n <= 1) return true;
    if (num_threads <= 1 || n < 256)
        return fr_fft(coeffs, n, inverse);

    unsigned int log_n = fr_log2_ceil(n);
    if ((size_t)1 << log_n != n)
        LOG_FAIL("groth16",
                 "fr_fft_parallel: n=%zu is not a power of 2 "
                 "(fr_log2_ceil=%u, 2^log_n=%zu, num_threads=%d); "
                 "refusing to transform — caller would silently "
                 "receive un-FFT'd data",
                 n, log_n, (size_t)1 << log_n, num_threads);

    bit_reverse(coeffs, n, log_n);

    struct fr omega = fft_root_of_unity(log_n, inverse);

    for (unsigned int s = 1; s <= log_n; s++) {
        size_t m = (size_t)1 << s;
        size_t num_groups = n / m;

        struct fr omega_m = fft_omega_pow_n_over_m(omega, n, m);

        if (num_groups < (size_t)num_threads || m <= 4) {
            /* Not enough parallelism, run serial */
            for (size_t k = 0; k < n; k += m) {
                struct fr w;
                fr_one(&w);
                size_t half = m >> 1;
                for (size_t j = 0; j < half; j++) {
                    struct fr t, u;
                    fr_mul(&t, &w, &coeffs[k + j + half]);
                    u = coeffs[k + j];
                    fr_add(&coeffs[k + j], &u, &t);
                    fr_sub(&coeffs[k + j + half], &u, &t);
                    fr_mul(&w, &w, &omega_m);
                }
            }
        } else {
            fft_spawn_group_butterflies(coeffs, n, m, num_groups, &omega_m,
                                        num_threads);
        }
    }

    if (inverse)
        fft_scale_by_inverse_n(coeffs, n);
    return true;
}

#pragma GCC diagnostic pop
