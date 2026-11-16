/* Copyright 2026 The Zclassic developers - MIT License
 *
 * See sprout_par.h. */

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* sched_getaffinity, CPU_COUNT */
#endif

#include "sprout_par.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#ifdef __linux__
#include <sched.h>
#endif

struct sp_pfor_arg {
    sprout_range_fn fn;
    void *ctx;
    size_t lo, hi;
    unsigned tid;
};

static void *sp_pfor_thread(void *p)
{
    struct sp_pfor_arg *a = p;
    a->fn(a->ctx, a->lo, a->hi, a->tid);
    return NULL;
}

void sprout_parallel_for(unsigned T, size_t n, sprout_range_fn fn, void *ctx)
{
    if (T > SPROUT_MAX_THREADS)
        T = SPROUT_MAX_THREADS;
    if (T <= 1 || n < (size_t)T * 2u) {
        fn(ctx, 0, n, 0);
        return;
    }
    pthread_t th[SPROUT_MAX_THREADS];
    bool started[SPROUT_MAX_THREADS];
    struct sp_pfor_arg args[SPROUT_MAX_THREADS];
    for (unsigned t = 0; t < T; t++) {
        args[t].fn = fn;
        args[t].ctx = ctx;
        args[t].lo = n * t / T;
        args[t].hi = n * (t + 1) / T;
        args[t].tid = t;
        started[t] = (t != 0) &&
                     pthread_create(&th[t], NULL, sp_pfor_thread, &args[t]) == 0;
    }
    for (unsigned t = 0; t < T; t++)
        if (!started[t])
            sp_pfor_thread(&args[t]);
    for (unsigned t = 0; t < T; t++)
        if (started[t])
            pthread_join(th[t], NULL);
}

unsigned sprout_cpu_count(void)
{
    long n;
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    n = (long)si.dwNumberOfProcessors;
#else
    n = sysconf(_SC_NPROCESSORS_ONLN);
#ifdef __linux__
    /* Honour taskset / cgroup cpusets: never run more workers than the
     * CPUs this process may use. */
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof set, &set) == 0 && CPU_COUNT(&set) > 0 &&
        CPU_COUNT(&set) < n)
        n = CPU_COUNT(&set);
#endif
#endif
    if (n < 1)
        n = 1;
    if (n > (long)SPROUT_MAX_THREADS)
        n = (long)SPROUT_MAX_THREADS;
    return (unsigned)n;
}

static void sp_pow(struct fr *r, const struct fr *base, uint64_t e)
{
    struct fr acc, b = *base;
    fr_one(&acc);
    while (e) {
        if (e & 1u)
            fr_mul(&acc, &acc, &b);
        fr_sq(&b, &b);
        e >>= 1;
    }
    *r = acc;
}

/* pairing::bls12_381::Fr ROOT_OF_UNITY (2^32-th), canonical little-endian
 * limbs — the value the vendored fr_fft uses (groth16_prover.c). */
static const uint64_t SP_ROOT_OF_UNITY_RAW[4] = {
    0x3829971f439f0d2bULL, 0xb63683508c2280b9ULL,
    0xd09b681922c813b4ULL, 0x16a2a19edfe81f20ULL,
};

static void sp_root(struct fr *omega, unsigned log_n)
{
    uint8_t b[32];
    for (size_t i = 0; i < 32; i++)
        b[i] = (uint8_t)(SP_ROOT_OF_UNITY_RAW[i / 8] >> (8 * (i % 8)));
    fr_from_bytes(omega, b);
    for (unsigned i = log_n; i < 32; i++)
        fr_sq(omega, omega);
}

struct sp_fft_ctx {
    struct fr *v;
    struct fr *tw;
    const struct fr *base;
    unsigned log_n;
    unsigned s; /* current stage */
    size_t n;
};

static size_t sp_rev(size_t i, unsigned bits)
{
    size_t r = 0;
    for (unsigned b = 0; b < bits; b++) {
        r = (r << 1) | (i & 1u);
        i >>= 1;
    }
    return r;
}

static void sp_bitrev_rows(void *p, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    struct sp_fft_ctx *c = p;
    for (size_t i = lo; i < hi; i++) {
        size_t j = sp_rev(i, c->log_n);
        if (j > i) {
            struct fr t = c->v[i];
            c->v[i] = c->v[j];
            c->v[j] = t;
        }
    }
}

/* tw[j] = base^j */
static void sp_powers_rows(void *p, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    struct sp_fft_ctx *c = p;
    struct fr w;
    sp_pow(&w, c->base, (uint64_t)lo);
    for (size_t j = lo; j < hi; j++) {
        c->tw[j] = w;
        fr_mul(&w, &w, c->base);
    }
}

static void sp_stage_rows(void *p, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    struct sp_fft_ctx *c = p;
    unsigned s = c->s;
    size_t half = (size_t)1 << (s - 1);
    size_t stride = c->n >> s;
    for (size_t b = lo; b < hi; b++) {
        size_t j = b & (half - 1);
        size_t k = (b >> (s - 1)) << s;
        struct fr t, u;
        fr_mul(&t, &c->tw[j * stride], &c->v[k + j + half]);
        u = c->v[k + j];
        fr_add(&c->v[k + j], &u, &t);
        fr_sub(&c->v[k + j + half], &u, &t);
    }
}

static void sp_scale_rows(void *p, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    struct sp_fft_ctx *c = p;
    for (size_t i = lo; i < hi; i++)
        fr_mul(&c->v[i], &c->v[i], c->base);
}

bool sprout_fft(struct fr *v, size_t n, bool inverse, unsigned T)
{
    if (n <= 1)
        return true;
    unsigned log_n = 0;
    while (((size_t)1 << log_n) < n)
        log_n++;
    if (((size_t)1 << log_n) != n || log_n > 32)
        return false;
    if (n < 4096)
        T = 1;

    struct fr omega;
    sp_root(&omega, log_n);
    if (inverse)
        fr_inv(&omega, &omega);

    struct fr *tw = malloc((n / 2) * sizeof *tw);
    if (!tw)
        return false;
    struct sp_fft_ctx c = { v, tw, &omega, log_n, 0, n };
    sprout_parallel_for(T, n / 2, sp_powers_rows, &c);
    sprout_parallel_for(T, n, sp_bitrev_rows, &c);
    for (unsigned s = 1; s <= log_n; s++) {
        c.s = s;
        sprout_parallel_for(T, n / 2, sp_stage_rows, &c);
    }
    free(tw);

    if (inverse) {
        uint8_t nb[32];
        memset(nb, 0, sizeof nb);
        for (size_t i = 0; i < 8; i++)
            nb[i] = (uint8_t)((uint64_t)n >> (8 * i));
        struct fr ninv;
        fr_from_bytes(&ninv, nb);
        fr_inv(&ninv, &ninv);
        c.base = &ninv;
        sprout_parallel_for(T, n, sp_scale_rows, &c);
    }
    return true;
}

struct sp_dist_ctx {
    struct fr *v;
    const struct fr *g;
};

static void sp_dist_rows(void *p, size_t lo, size_t hi, unsigned tid)
{
    (void)tid;
    struct sp_dist_ctx *c = p;
    struct fr w;
    sp_pow(&w, c->g, (uint64_t)lo);
    for (size_t i = lo; i < hi; i++) {
        fr_mul(&c->v[i], &c->v[i], &w);
        fr_mul(&w, &w, c->g);
    }
}

void sprout_distribute_powers(struct fr *v, size_t n, const struct fr *g,
                              unsigned T)
{
    struct sp_dist_ctx c = { v, g };
    sprout_parallel_for(T, n, sp_dist_rows, &c);
}
