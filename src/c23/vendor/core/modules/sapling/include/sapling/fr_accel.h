/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BLS12-381 Fr/Fp Montgomery-multiply acceleration — runtime-dispatched
 * BMI2 MULX with a portable __int128 fallback. Every path returns the identical
 * canonical Montgomery product (SPEED path only; consensus result unchanged).
 * See core/modules/sapling/src/fr_avx512.c.
 *
 * Before this header the two dispatchers were declared by hand-copied `extern`
 * lines in fr.c and bls12_381.c with no shared prototype, so a signature drift
 * on the hottest consensus multiply produced no diagnostic. */

#ifndef ZCL_SAPLING_FR_ACCEL_H
#define ZCL_SAPLING_FR_ACCEL_H

#include <stdbool.h>
#include <stdint.h>

/* Dispatched Montgomery multiplies: r = a * b * R^{-1} mod p, canonical.
 * Fr is the 255-bit scalar field (4 limbs); Fp the 381-bit base field (6). */
void fr_mont_mul_accel(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
void fp_mont_mul_accel(uint64_t r[6], const uint64_t a[6], const uint64_t b[6]);

/* Human-readable name of the selected implementation (for logs/benchmarks).
 * Reports the tier that ACTUALLY runs, never one merely present in CPUID. */
const char *fr_accel_implementation(void);

/* Differential-oracle / benchmark hooks (test-only): force a specific
 * implementation so a caller can drive the SAME input through every path and
 * assert byte-identical output. The accelerated variants return false (leaving
 * r untouched) on a host without the instructions, so the caller can skip
 * rather than mis-assert.
 *
 * There is deliberately no _bmi2 pair here. A MULX-only tier used to exist and
 * measured SLOWER than the portable code it displaced, so it was deleted rather
 * than left switched off; _adx is the dual-carry-chain path that replaced it and
 * is genuinely faster. Two declarations for the deleted pair outlived it here
 * with no definition anywhere in the tree, which turned a rename into a
 * link-time failure for the one test that still called them. */
void fr_accel_mont_mul_portable(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
void fp_accel_mont_mul_portable(uint64_t r[6], const uint64_t a[6], const uint64_t b[6]);
bool fr_accel_mont_mul_adx(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
bool fp_accel_mont_mul_adx(uint64_t r[6], const uint64_t a[6], const uint64_t b[6]);

#endif /* ZCL_SAPLING_FR_ACCEL_H */
