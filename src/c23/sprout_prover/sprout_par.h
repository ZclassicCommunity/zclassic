/* Copyright 2026 The Zclassic developers - MIT License
 *
 * Thread helpers for the Sprout prover. The FFTs and the dense H sum run in
 * the vendored fr_fft_many and groth16_g1_msm (sapling/groth16_prover.h). */

#ifndef ZC23_SPROUT_PAR_H
#define ZC23_SPROUT_PAR_H

#include "sapling/fr.h"

#include <stdbool.h>
#include <stddef.h>

#define SPROUT_MAX_THREADS 64u

typedef void (*sprout_range_fn)(void *ctx, size_t lo, size_t hi, unsigned tid);

/* Run fn over [0, n) split into T contiguous ranges, range t on thread t
 * (tid = t). A thread that cannot be started runs its range inline, so the
 * result never depends on thread creation succeeding. */
void sprout_parallel_for(unsigned T, size_t n, sprout_range_fn fn, void *ctx);

/* Online CPU count clamped to [1, SPROUT_MAX_THREADS]. */
unsigned sprout_cpu_count(void);

/* v[i] *= g^i for i in [0, n). */
void sprout_distribute_powers(struct fr *v, size_t n, const struct fr *g,
                              unsigned T);

#endif
