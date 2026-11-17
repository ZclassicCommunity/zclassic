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
