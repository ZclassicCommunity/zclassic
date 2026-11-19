/* Copyright 2026 The Zclassic developers - MIT License
 *
 * C23 Sprout JoinSplit Groth16 prover — replaces librustzcash_sprout_prove.
 *
 * zc23_sprout_prove() takes exactly the argument layout of
 * librustzcash_sprout_prove (librustzcash.h at 06da3b9a) and writes a
 * 192-byte compressed Groth16 proof (A 48 | B 96 | C 48) for the Sprout
 * JoinSplit circuit over BLS12-381, using sprout-groth16.params.
 *
 * Failure behaviour, mapped from rustzcash.rs:943-1089:
 *   - auth blob layout violations (depth byte != 29, inner length != 32),
 *     params path never set, params file missing / unreadable / malformed,
 *     OS RNG failure, out of memory: abort(), as Rust's assert/expect panic
 *     does across the FFI boundary.
 *   - a witness that does not satisfy the circuit (unbalanced values, wrong
 *     path or key on a non-zero note, value overflow): Rust's bellman does
 *     not check and emits a proof that cannot verify. This prover checks every
 *     A*B=C row first and, on failure, writes 192 zero bytes (not a valid
 *     point encoding, so JSDescription::Verify — which the wallet runs right
 *     after proving, asyncrpcoperation_sendmany.cpp:1184 — rejects it).
 *   - every emitted proof is verified against the compiled-in Sprout Groth16
 *     verifying key before it is returned; a proof that does not verify is
 *     replaced by 192 zero bytes. The params file's verifying-key prefix must
 *     equal the compiled-in key byte for byte, or the call aborts.
 *
 * Thread-safe: no mutable global state except the params path, which is set
 * once at startup. Each call streams the 725 MB parameter file instead of
 * holding it; nothing stays resident between calls. */

#ifndef ZC23_SPROUT_PROVER_H
#define ZC23_SPROUT_PROVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZC23_SPROUT_PROOF_SIZE 192u
#define ZC23_SPROUT_AUTH_SIZE 966u /* 1 + 33 * 29 + 8 */

/* Record the sprout-groth16.params path (UTF-8; converted to UTF-16 for
 * _wfopen on Windows). The string is copied. Returns false on NULL/empty
 * path or out of memory. Mirrors the SPROUT_GROTH16_PARAMS_PATH that
 * librustzcash_init_zksnark_params stores. */
bool zc23_sprout_prover_set_params_path(const char *utf8_path);

enum zc23_sprout_status {
    ZC23_SPROUT_OK = 0,
    ZC23_SPROUT_BAD_AUTH,      /* auth blob layout (Rust: assert_eq! panic) */
    ZC23_SPROUT_NO_PARAMS,     /* path not set (Rust: expect panic) */
    ZC23_SPROUT_PARAMS_IO,     /* open/read failure (Rust: expect panic) */
    ZC23_SPROUT_PARAMS_FORMAT, /* shape, VK prefix or point decode mismatch */
    ZC23_SPROUT_UNSATISFIED,   /* witness does not satisfy the circuit */
    ZC23_SPROUT_OOM,
    ZC23_SPROUT_RNG,
    ZC23_SPROUT_INTERNAL,      /* synthesis/FFT failure */
    ZC23_SPROUT_SELFVERIFY,    /* produced proof failed verification */
};

const char *zc23_sprout_status_str(enum zc23_sprout_status s);

/* Optional per-call measurements (seconds, wall clock). */
struct zc23_sprout_prove_stats {
    double synth_s;    /* circuit synthesis + satisfaction check */
    double qap_s;      /* a/b/c evaluation, FFTs, h(x) */
    double msm_s;      /* streaming the params file + all MSMs */
    double h_s;        /*   of which: the H query (read + dense MSM) */
    double verify_s;   /* self-verification */
    double total_s;
    size_t num_constraints, num_inputs, num_aux;
    size_t h_len, l_len, a_len, b_len;
    unsigned threads;
};

/* Status-returning core. `params_path` NULL means the path set with
 * zc23_sprout_prover_set_params_path. On any status other than OK the 192
 * output bytes are zero. `stats` may be NULL. Never aborts. */
enum zc23_sprout_status zc23_sprout_prove_status(
    unsigned char *proof_out,
    const unsigned char *phi, const unsigned char *rt,
    const unsigned char *h_sig,
    const unsigned char *in_sk1, uint64_t in_value1,
    const unsigned char *in_rho1, const unsigned char *in_r1,
    const unsigned char *in_auth1,
    const unsigned char *in_sk2, uint64_t in_value2,
    const unsigned char *in_rho2, const unsigned char *in_r2,
    const unsigned char *in_auth2,
    const unsigned char *out_pk1, uint64_t out_value1,
    const unsigned char *out_r1,
    const unsigned char *out_pk2, uint64_t out_value2,
    const unsigned char *out_r2,
    uint64_t vpub_old, uint64_t vpub_new,
    const char *params_path, struct zc23_sprout_prove_stats *stats);

/* Drop-in for librustzcash_sprout_prove (same argument order and sizes). */
void zc23_sprout_prove(
    unsigned char *proof_out,
    const unsigned char *phi, const unsigned char *rt,
    const unsigned char *h_sig,
    const unsigned char *in_sk1, uint64_t in_value1,
    const unsigned char *in_rho1, const unsigned char *in_r1,
    const unsigned char *in_auth1,
    const unsigned char *in_sk2, uint64_t in_value2,
    const unsigned char *in_rho2, const unsigned char *in_r2,
    const unsigned char *in_auth2,
    const unsigned char *out_pk1, uint64_t out_value1,
    const unsigned char *out_r1,
    const unsigned char *out_pk2, uint64_t out_value2,
    const unsigned char *out_r2,
    uint64_t vpub_old, uint64_t vpub_new);

#ifdef SPROUT_PROVER_TESTING
/* Test-only: replace the OS RNG used for the Groth16 blinding factors r, s.
 * NULL restores the OS RNG. Not compiled into the daemon. */
typedef bool (*zc23_sprout_test_rng_fn)(void *user, uint8_t *out, size_t n);
void zc23_sprout_set_test_rng(zc23_sprout_test_rng_fn fn, void *user);
/* Test-only: force the worker-thread count (0 = auto). */
void zc23_sprout_set_test_threads(unsigned n);
#endif

#ifdef __cplusplus
}
#endif

#endif
