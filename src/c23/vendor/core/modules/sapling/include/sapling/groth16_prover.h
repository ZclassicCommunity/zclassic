/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Groth16 zero-knowledge proof prover — pure C23 implementation.
 * Generates proofs for Sapling spend and output circuits. */

#ifndef ZCL_SAPLING_GROTH16_PROVER_H
#define ZCL_SAPLING_GROTH16_PROVER_H

#include "sapling/bls12_381.h"
#include "sapling/fr.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ── R1CS Constraint System ─────────────────────────────────────── */

/* A linear combination: sum of (variable_index, coefficient) pairs */
struct lc_term {
    size_t var;
    struct fr coeff;
};

struct linear_combination {
    struct lc_term *terms;
    size_t num_terms;
    size_t cap;
    /* sticky flag set by lc_add_term when zcl_realloc fails.
     * cs_enforce propagates into cs->oom_error. */
    bool oom_error;
};

/* R1CS constraint: A * B = C (each is a linear combination) */
struct r1cs_constraint {
    struct linear_combination a, b, c;
};

/* Constraint system with witness assignment */
struct constraint_system {
    struct r1cs_constraint *constraints;
    size_t num_constraints;
    size_t cap_constraints;

    struct fr *witness;       /* full variable assignment */
    size_t num_vars;          /* total variables (including ONE at index 0) */
    size_t cap_vars;
    size_t num_inputs;        /* public inputs (indices 1..num_inputs) */

    /* sticky flag set by cs_alloc_var cs_enforce when a realloc
     * fails (or when an input LC arrives with oom_error already set).
     * groth16_prove checks this at entry and refuses — otherwise the
     * prover would emit a valid-looking proof for a silently-wrong
     * circuit. */
    bool oom_error;
};

void cs_init(struct constraint_system *cs);
void cs_free(struct constraint_system *cs);

/* Allocate a new variable, return its index */
size_t cs_alloc_input(struct constraint_system *cs, const struct fr *value);
size_t cs_alloc_aux(struct constraint_system *cs, const struct fr *value);

/* Add linear combination term.
 * Returns true on success. On zcl_realloc failure, sets lc->oom_error,
 * emits LOG_FAIL, returns false. Callers that discard the return still
 * propagate via cs_enforce picking up lc->oom_error. */
void lc_init(struct linear_combination *lc);
void lc_free(struct linear_combination *lc);
bool lc_add_term(struct linear_combination *lc, size_t var,
                   const struct fr *coeff);

/* Add constraint: A * B = C.
 * Returns true on success. On zcl_realloc failure, on internal
 * lc_add_term failure, or when any of a/b/c has oom_error set,
 * sets cs->oom_error, emits LOG_FAIL, returns false. */
bool cs_enforce(struct constraint_system *cs,
                const struct linear_combination *a,
                const struct linear_combination *b,
                const struct linear_combination *c);

/* test hook: when non-NULL, the three CS-building helpers
 * (lc_add_term, cs_alloc_var, cs_enforce) call this instead of
 * zcl_realloc. Returning NULL simulates OOM. File-scope so the
 * hook influences only this translation unit. */
void groth16_prover_test_set_realloc_hook(void *(*hook)(void *ptr, size_t size));

/* test hook: when non-zero, overrides the computed FFT domain
 * size in groth16_prove so tests can exercise the fr_fft /
 * fr_fft_parallel non-pow-2 branch through the real prover call
 * path. Pass 0 to disarm. */
void groth16_prover_test_set_force_domain(size_t forced);

/* Evaluate a linear combination with the current witness */
void lc_evaluate(struct fr *result, const struct linear_combination *lc,
                   const struct fr *witness);

/* R1CS satisfaction: does the recorded witness actually satisfy A*B=C for
 * every emitted constraint? This is the ONLY check that reads constraint
 * COEFFICIENTS — constraint counts and a handful of probed wire values cannot
 * see a wrong coefficient, and a circuit whose honest witness does not satisfy
 * its own constraints produces proofs the network rejects. Mirrors bellman's
 * TestConstraintSystem::which_is_unsatisfied (sapling-crypto circuit/test).
 * Returns true when every constraint holds; on failure returns false and, when
 * bad_index_out is non-NULL, stores the index of the first unsatisfied
 * constraint (SIZE_MAX when the system itself is unusable). O(total LC terms). */
bool cs_is_satisfied(const struct constraint_system *cs, size_t *bad_index_out);

/* ── Proving Key ────────────────────────────────────────────────── */

/* Proving key for Groth16.
 * Parsed from bellman Parameters format. */
struct groth16_pk {
    size_t num_inputs;    /* l: public inputs */
    size_t h_len;         /* H query length */
    size_t l_len;         /* L query length */
    size_t a_len;         /* A query length */
    size_t b_len;         /* B query length (same for G1 and G2) */

    /* Points from CRS */
    struct g1_point alpha_g1;
    struct g1_point beta_g1;
    struct g1_point delta_g1;
    struct g2_point beta_g2;
    struct g2_point gamma_g2;
    struct g2_point delta_g2;

    /* CRS query arrays */
    struct g1_point *h_g1;    /* H polynomial evaluation points */
    struct g1_point *l_g1;    /* Private variable commitments */
    struct g1_point *a_g1;    /* A query */
    struct g1_point *b_g1;    /* B query (G1) */
    struct g2_point *b_g2;    /* B query (G2) */

    /* Verification key */
    struct groth16_vk vk;
};

/* Read a proving key from bellman Parameters file.
 * Format: VK | h[] | l[] | a[] | b_g1[] | b_g2[] | hash
 * All lengths are u32 big-endian. Points are uncompressed.
 * Caller must call groth16_pk_free() when done. */
bool groth16_pk_read(struct groth16_pk *pk, const uint8_t *data, size_t len);
void groth16_pk_free(struct groth16_pk *pk);

/* ── FFT ────────────────────────────────────────────────────────── */

/* Iterative radix-2 FFT over Fr. Requires n to be a power of 2 (or
 * n <= 1 for the trivial case). Returns true on success; returns
 * false if n is not a power of 2 (data left unmodified). Callers
 * MUST check the return — silent-dropping yields un-transformed
 * evaluations and, in the Groth16 prover, mathematically invalid
 * proofs. */
bool fr_fft(struct fr *coeffs, size_t n, bool inverse);

/* Smallest k such that 2^k >= n (ceil(log2(n))). Underflow-safe at
 * n=0 (returns 0). Shared by fr_fft and fr_fft_parallel. */
static inline unsigned int fr_log2_ceil(size_t n)
{
    unsigned int k = 0;
    size_t v = 1;
    while (v < n) { v <<= 1; k++; }
    return k;
}

/* In-place bit-reversal permutation of arr (length n, log_n = log2(n)).
 * Shared by fr_fft and fr_fft_parallel. */
static inline void bit_reverse(struct fr *arr, size_t n, unsigned int log_n)
{
    for (size_t i = 0; i < n; i++) {
        size_t j = 0;
        for (unsigned int b = 0; b < log_n; b++)
            j |= ((i >> b) & 1) << (log_n - 1 - b);
        if (j > i) {
            struct fr tmp = arr[i];
            arr[i] = arr[j];
            arr[j] = tmp;
        }
    }
}

/* ── Multi-scalar multiplication ────────────────────────────────── */

void g1_msm(struct g1_point *result,
            const struct g1_point *points, const struct fr *scalars,
            size_t n);

void g2_msm(struct g2_point *result,
            const struct g2_point *points, const struct fr *scalars,
            size_t n);

/* ── Parallel FFT ───────────────────────────────────────────────── */

/* Parallel radix-2 FFT over Fr. Dispatches to serial fr_fft when
 * n < 256 or num_threads <= 1. Returns true on success; returns
 * false if n is not a power of 2 (same contract as fr_fft). */
bool fr_fft_parallel(struct fr *coeffs, size_t n, bool inverse, int num_threads);

/* ── Groth16 Prover ─────────────────────────────────────────────── */

/* Generate a Groth16 proof from a satisfied constraint system and proving key.
 *
 * The constraint system must already have its witness fully assigned.
 * The prover:
 *   1. Evaluates constraint polynomials via the witness
 *   2. Computes h(x) quotient polynomial via FFT
 *   3. Computes proof elements (A, B, C) via MSM with CRS
 *   4. Adds random blinding (r, s) for zero-knowledge */
bool groth16_prove(const struct groth16_pk *pk,
                   const struct constraint_system *cs,
                   struct groth16_proof *proof_out);

#ifdef ZCL_TESTING
/* ── Test-ONLY deterministic RNG injection for the Groth16 blinding
 *    factors r, s (Sapling Lane C) ──────────────────────────────────
 *
 * groth16_prove draws two 32-byte blinding scalars r, s from
 * `zcl_random_secret_bytes` (kernel CSPRNG). Those bytes flow into the
 * 192-byte zk-proof, so with real entropy the proof (and therefore the
 * enclosing shielded transaction's txid) is NON-reproducible run-to-run —
 * exactly the gap Lane B (`sapling_set_test_rng_hook`) left open for the
 * proof itself (its scope note: "the 192-byte zk-proof stays
 * non-deterministic under THIS hook alone").
 *
 * This seam is compiled ONLY under `-DZCL_TESTING`. It does not exist in
 * the production node binary — there `groth16_prove` ALWAYS draws r, s from
 * `zcl_random_secret_bytes`, with no runtime flag or symbol to divert it.
 *
 * When `fn` is NULL (the default, even in a ZCL_TESTING build) the prover is
 * byte-identical to today. When `fn` is set, each r/s draw is filled via
 * `fn(user, buf, 32)` instead. `fn` returns true on success (buffer filled)
 * or false to signal RNG failure (handled exactly like a
 * `zcl_random_secret_bytes` failure — the prove aborts, returns false). Pass
 * NULL to restore the default. Set it around a single-threaded deterministic
 * build, then clear it. Mirrors `sapling_set_test_rng_hook`. */
typedef bool (*groth16_test_rng_fn)(void *user, uint8_t *out, size_t n);
void groth16_set_test_rng_hook(groth16_test_rng_fn fn, void *user);
#endif /* ZCL_TESTING */

#endif
