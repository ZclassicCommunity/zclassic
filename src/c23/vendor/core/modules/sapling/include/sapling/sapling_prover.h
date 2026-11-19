/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Stable C23 API for Sapling proving and verification.
 * Consensus verification is native C23. Proving remains disabled until the
 * in-tree C23 prover passes a positive prover-to-consensus-verifier self-test. */

#ifndef ZCL_SAPLING_PROVER_H
#define ZCL_SAPLING_PROVER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Parameter loading. The caller supplies the canonical BLAKE2b hashes used
 * by the parameter publisher; sapling_init_params independently checks
 * SHA-512 first. */
void zclassic_init_zksnark_params(
    const uint8_t *spend_path, size_t spend_path_len,
    const char *spend_hash,
    const uint8_t *output_path, size_t output_path_len,
    const char *output_hash,
    const uint8_t *sprout_path, size_t sprout_path_len,
    const char *sprout_hash);

/* Runtime proving capability. `run_self_test` must be called after the C23
 * verifying keys and native proving parameters have initialized. No proving
 * context can be created until it returns true. */
bool zclassic_sapling_prover_run_self_test(void);
bool zclassic_sapling_prover_is_ready(void);
/* Return the backend to "no parameters, not ready" and allow a fresh
 * zclassic_init_zksnark_params. Used when an on-demand pair load ends or
 * fails; the full-set path never calls it. */
void zclassic_sapling_prover_unarm(void);
const char *zclassic_sapling_prover_status(void);
const char *zclassic_sapling_prover_backend(void);

#ifdef ZCL_TESTING
/* Return the proving backend to its process-start state (no parameters, not
 * ready). Test-only: production has no un-ready transition, because a node
 * that has proved once has the keys resident for the life of the process.
 * A test that asserts "verifying keys alone do NOT arm proving" needs a
 * deterministic starting point even when an earlier group in the same
 * process already loaded a full parameter directory. */
void zclassic_test_prover_reset(void);
/* Number of times the Groth16 self-test body has run in this process. */
int zclassic_test_prover_self_test_runs(void);
#endif

/* Verification context */
void *zclassic_sapling_verification_ctx_init(void);
void zclassic_sapling_verification_ctx_free(void *ctx);

bool zclassic_sapling_check_spend(
    void *ctx, const uint8_t *cv, const uint8_t *anchor,
    const uint8_t *nullifier, const uint8_t *rk,
    const uint8_t *zkproof, const uint8_t *spend_auth_sig,
    const uint8_t *sighash_value);

bool zclassic_sapling_check_output(
    void *ctx, const uint8_t *cv, const uint8_t *cm,
    const uint8_t *epk, const uint8_t *zkproof);

bool zclassic_sapling_final_check(
    void *ctx, int64_t value_balance,
    const uint8_t *binding_sig, const uint8_t *sighash_value);

/* Batched Groth16 verification for the BACKGROUND re-validation pass only.
 * `*_prepare` runs every non-Groth16 gate + folds cv into the ctx balance +
 * decodes the proof + builds the public inputs (verdict-identical to the
 * matching check_* up to the Groth16 step). `*_batch` verifies many prepared
 * proofs in ~N+2 Miller loops + ONE final-exp; `*_one` is the per-proof
 * fallback the caller MUST use on a batch reject to attribute the failure.
 * pub_out points at a caller-owned [7][4] (spend) / [5][4] (output) block;
 * for batch/one `pub` is flat with proof j at rows [j*7) / [j*5). See
 * sapling.h for the full verdict-safety contract. */
struct groth16_proof;
bool zclassic_sapling_spend_prepare(
    void *ctx, const uint8_t *cv, const uint8_t *anchor,
    const uint8_t *nullifier, const uint8_t *rk, const uint8_t *zkproof,
    const uint8_t *spend_auth_sig, const uint8_t *sighash_value,
    struct groth16_proof *proof_out, uint64_t (*pub_out)[4]);
bool zclassic_sapling_output_prepare(
    void *ctx, const uint8_t *cv, const uint8_t *cm,
    const uint8_t *epk, const uint8_t *zkproof,
    struct groth16_proof *proof_out, uint64_t (*pub_out)[4]);
bool zclassic_sapling_spend_groth16_batch(
    const struct groth16_proof *proofs, const uint64_t (*pub)[4], size_t n);
bool zclassic_sapling_output_groth16_batch(
    const struct groth16_proof *proofs, const uint64_t (*pub)[4], size_t n);
bool zclassic_sapling_spend_groth16_one(
    const struct groth16_proof *proof, const uint64_t (*pub)[4]);
bool zclassic_sapling_output_groth16_one(
    const struct groth16_proof *proof, const uint64_t (*pub)[4]);

/* Proving context */
void *zclassic_sapling_proving_ctx_init(void);
void zclassic_sapling_proving_ctx_free(void *ctx);

bool zclassic_sapling_output_proof(
    void *ctx,
    const unsigned char *esk,
    const unsigned char *diversifier,
    const unsigned char *pk_d,
    const unsigned char *rcm,
    const uint64_t value,
    unsigned char *cv,
    unsigned char *zkproof);

/* `witness` points to a caller-supplied merkle authentication
 * path with the fixed wire layout
 *     depth (1) || 32 × (sibling (32) || bit (1))  = 1057 bytes
 * `witness_len` is the buffer length and must be >= 1057; shorter
 * buffers are rejected without any read past the first byte. */
bool zclassic_sapling_spend_proof(
    void *ctx,
    const unsigned char *ak,
    const unsigned char *nsk,
    const unsigned char *diversifier,
    const unsigned char *rcm,
    const unsigned char *ar,
    const uint64_t value,
    const unsigned char *anchor,
    const unsigned char *witness,
    size_t witness_len,
    unsigned char *cv,
    unsigned char *rk,
    unsigned char *zkproof);

bool zclassic_sapling_binding_sig(
    const void *ctx,
    int64_t valueBalance,
    const unsigned char *sighash,
    unsigned char *result);

#endif
