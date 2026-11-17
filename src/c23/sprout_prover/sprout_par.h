/* Copyright 2026 The Zclassic developers - MIT License
 *
 * Thread helpers and a parallel radix-2 FFT over BLS12-381 Fr for the
 * Sprout prover. sprout_fft() returns exactly what the vendored serial
 * fr_fft() returns (same domain, same root of unity, same bit-reversed
 * iterative order) — test/test_fft_parity.c checks equality element by
 * element. The vendored fr_fft_parallel is not used. Before Z23 2bae686c3 it
 * disagreed with fr_fft at every size >= 256; it is now the same transform. */

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

/* In-place FFT of n = 2^k elements (inverse includes the 1/n scaling).
 * Returns false if n is not a power of two or a scratch allocation fails;
 * v is then unspecified. */
bool sprout_fft(struct fr *v, size_t n, bool inverse, unsigned T);

/* v[i] *= g^i for i in [0, n). */
void sprout_distribute_powers(struct fr *v, size_t n, const struct fr *g,
                              unsigned T);

#endif
