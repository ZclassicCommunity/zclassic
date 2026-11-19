#define _POSIX_C_SOURCE 200809L
/* Timing harness shared by the C++ (zclassicd) and C23 (Z23) hash drivers.
 * Measurement only: no production code is touched. */
#ifndef HASH_BENCH_COMMON_H
#define HASH_BENCH_COMMON_H
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

static inline double hb_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* Calibrate iterations to ~60 ms, run 7 repetitions, report the minimum
 * ns per op (least perturbed on a shared host) and the median. */
#define HB_RUN(label, bytes_per_op, BODY)                                         \
    do {                                                                          \
        const double target_ns = 60e6;                                            \
        size_t iters = 1;                                                         \
        for (;;) {                                                                \
            double t0 = hb_now();                                                 \
            for (size_t it_ = 0; it_ < iters; it_++) { BODY; }                    \
            double dt = hb_now() - t0;                                            \
            if (dt >= target_ns || iters > (1u << 30)) break;                     \
            iters = dt < 1e5 ? iters * 16 : (size_t)((double)iters * (target_ns * 1.2 / dt) + 1); \
        }                                                                         \
        double best = 1e30, rs[7];                                                \
        for (int r_ = 0; r_ < 7; r_++) {                                          \
            double t0 = hb_now();                                                 \
            for (size_t it_ = 0; it_ < iters; it_++) { BODY; }                    \
            double ns = (hb_now() - t0) / (double)iters;                          \
            rs[r_] = ns; if (ns < best) best = ns;                                \
        }                                                                         \
        for (int a_ = 0; a_ < 7; a_++) for (int b_ = a_ + 1; b_ < 7; b_++)        \
            if (rs[b_] < rs[a_]) { double t_ = rs[a_]; rs[a_] = rs[b_]; rs[b_] = t_; } \
        double bpo = (double)(bytes_per_op);                                      \
        printf("%-52s min %10.1f ns/op  med %10.1f ns/op  %9.1f MB/s(min)\n",     \
               label, best, rs[3], bpo > 0 ? bpo / best * 1000.0 : 0.0);          \
        fflush(stdout);                                                           \
    } while (0)

#endif
