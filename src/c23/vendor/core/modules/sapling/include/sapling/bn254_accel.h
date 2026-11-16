/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BN254 (alt-bn128) Fq Montgomery-multiply acceleration — runtime-dispatched
 * BMI2+ADX with a portable scalar fallback. Every path returns the identical
 * canonical Montgomery product (SPEED path only; consensus result unchanged).
 * See core/modules/sapling/src/bn254_accel.c. */

#ifndef ZCL_SAPLING_BN254_ACCEL_H
#define ZCL_SAPLING_BN254_ACCEL_H

#include <stdbool.h>
#include <stdint.h>

/* Dispatched Fq Montgomery multiply: r = a * b * R^{-1} mod q, canonical
 * (reduced into [0, q)). Selects the fastest available path at first use. This
 * is the single primitive bn254.c's bn_fq_mont_mul calls. */
void bn_fq_mont_mul_accel(uint64_t r[4], const uint64_t a[4],
                          const uint64_t b[4]);

/* Human-readable name of the selected implementation (for logs/benchmarks). */
const char *bn254_accel_implementation(void);

/* Differential-oracle hooks (test-only): force a specific implementation so the
 * test can assert byte-identical output across every path. */
void bn254_accel_mont_mul_portable(uint64_t r[4], const uint64_t a[4],
                                   const uint64_t b[4]);
/* Runs the BMI2+ADX path when the host supports it; returns false (leaving r
 * untouched) when it does not, so the test can skip rather than mis-assert. */
bool bn254_accel_mont_mul_adx(uint64_t r[4], const uint64_t a[4],
                              const uint64_t b[4]);

/* Entry address of the compiled BMI2+ADX multiply, or NULL when that path is
 * not installed on this host. Test-only, and specifically so a test can read
 * the machine code the linker actually produced instead of believing
 * bn254_accel_implementation(). The string used to say "MULX+ADCX+ADOX" while
 * the object held mulx=64, adcx=0, adox=0; test_mont_adx_honest is the guard
 * that makes that combination impossible to ship again. */
const void *bn254_accel_adx_code(void);

#endif /* ZCL_SAPLING_BN254_ACCEL_H */
