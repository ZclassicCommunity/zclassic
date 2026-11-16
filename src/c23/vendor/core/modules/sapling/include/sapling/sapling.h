/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling key operations — pure C23 implementation.
 * group_hash, key derivation, commitment, nullifier. */

#ifndef ZCL_SAPLING_SAPLING_H
#define ZCL_SAPLING_SAPLING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sapling/fr.h"

/* Derive a Jubjub point via group_hash:
 * BLAKE2s-256(personalization, GH_FIRST_BLOCK || tag) → decompress → mul_by_cofactor.
 * Returns false if the result is the identity point (invalid). */
bool group_hash(struct jub_point *result,
                const uint8_t *tag, size_t tag_len,
                const uint8_t personalization[8]);

/* Check if a diversifier is valid (i.e., group_hash("Zcash_gd", d) is not identity) */
bool sapling_check_diversifier(const uint8_t diversifier[11]);

/* Compute g_d = GH("Zcash_gd", diversifier) */
bool sapling_diversifier_to_gd(struct jub_point *g_d, const uint8_t diversifier[11]);

/* ask → ak: ak = ask * SpendingKeyGenerator */
void sapling_ask_to_ak(const uint8_t ask[32], uint8_t ak[32]);

/* nsk → nk: nk = nsk * ProofGenerationKey */
void sapling_nsk_to_nk(const uint8_t nsk[32], uint8_t nk[32]);

/* rk = ak + ar * SpendAuthSig.G (re-randomized verification key) */
bool sapling_compute_rk(const uint8_t ak[32], const uint8_t ar[32],
                          uint8_t rk[32]);

/* Expose the two fixed Jubjub generators the spend circuit multiplies by,
 * as (x, y) field coordinates, so an in-circuit fixed-base multiplication
 * uses the IDENTICAL generator as the out-of-circuit key derivation
 * (sapling_ask_to_ak / sapling_nsk_to_nk / sapling_compute_rk). These are the
 * canonical find_group_hash-derived generators (URS-counter iterated), NOT the
 * single-shot group_hash() the output-circuit value-commitment path uses.
 *   sapling_spend_auth_generator      -> GEN_SPENDING_KEY (SpendAuthSig.G)
 *   sapling_proof_gen_key_generator   -> GEN_PROOF_GENERATION_KEY */
void sapling_spend_auth_generator(struct fr *x, struct fr *y);
void sapling_proof_gen_key_generator(struct fr *x, struct fr *y);

/* The two generators the value commitment cv = [value] G_v + [rcv] G_rcv is
 * built from, as (x, y) field coordinates, so the in-circuit fixed-base
 * multiplications of spend section 14 use the IDENTICAL points
 * sapling_value_commit() uses out of circuit. Also find_group_hash-derived:
 *   sapling_value_commit_value_generator      -> GEN_VALUE_COMMITMENT_VALUE
 *   sapling_value_commit_randomness_generator -> GEN_VALUE_COMMITMENT_RANDOMNESS
 * Taking these from the single-shot group_hash() instead (as the output circuit
 * does) yields a DIFFERENT point, and the circuit's cv then disagrees with the
 * public input it is bound to. */
void sapling_value_commit_value_generator(struct fr *x, struct fr *y);
void sapling_value_commit_randomness_generator(struct fr *x, struct fr *y);

/* The generator the note commitment is randomized over:
 *   cm = PedersenHash(NoteCommitment, note) + [rcm] G_rcm
 * as (x, y) field coordinates, so spend section 19's in-circuit fixed-base
 * multiplication uses the IDENTICAL point sapling_compute_cm() uses out of
 * circuit. find_group_hash(b"r", "Zcash_PH") — the URS-counter-iterated
 * derivation, NOT the single-shot group_hash() the legacy output circuit
 * reached for; those are different points and the note commitments would
 * disagree. */
void sapling_note_commit_randomness_generator(struct fr *x, struct fr *y);

/* The generator the note's tree POSITION is multiplied by when building rho:
 *   rho = cm + [position] G_pos
 * as (x, y) field coordinates, so spend section 24's in-circuit g^position uses
 * the IDENTICAL point sapling_compute_nf() uses out of circuit
 * (GEN_NULLIFIER_POSITION). Getting a different point here yields a different
 * rho, hence a different nullifier, and the circuit's nf then disagrees with the
 * public input section 28 binds it to. */
void sapling_nullifier_position_generator(struct fr *x, struct fr *y);

/* CRH^ivk(ak, nk) = BLAKE2s("Zcashivk", ak || nk) with top 5 bits dropped */
void sapling_crh_ivk(const uint8_t ak[32], const uint8_t nk[32], uint8_t ivk[32]);

/* ivk → pk_d: pk_d = ivk * g_d(diversifier) */
bool sapling_ivk_to_pkd(const uint8_t ivk[32], const uint8_t diversifier[11],
                         uint8_t pk_d[32]);

/* Sapling key agreement: result = [sk] [8] p */
bool sapling_ka_agree(const uint8_t p[32], const uint8_t sk[32], uint8_t result[32]);

/* Derive ephemeral public key: result = [esk] g_d(diversifier) */
bool sapling_ka_derivepublic(const uint8_t diversifier[11], const uint8_t esk[32],
                              uint8_t result[32]);

/* Compute Sapling note commitment cm = x-coord of the Jubjub point
 *   WindowedPedersenHash(NoteCommitment, value(8 LE) || g_d || pk_d)
 *     + rcm · NoteCommitmentRandomness
 * where g_d = GH("Zcash_gd", diversifier). The output `cm[32]` is the
 * affine x-coordinate (an Fr element) — this is exactly the leaf that
 * gets appended to the note-commitment merkle tree. Returns false only
 * if `diversifier` is invalid (g_d would be the identity). `value` is in
 * zatoshi; `rcm` must be a valid Fs scalar. Same note contents bound here
 * are re-derived inside the output proof, so a mismatched cm fails the
 * Groth16 check in sapling_check_output. */
bool sapling_compute_cm(const uint8_t diversifier[11], const uint8_t pk_d[32],
                         uint64_t value, const uint8_t rcm[32],
                         uint8_t cm[32]);

/* The full note-commitment POINT rather than only its x-coordinate:
 *   cm_full = PedersenHash(NoteCommitment, value || g_d || pk_d) + [rcm] G_rcm
 * This is the ONE body behind both sapling_compute_cm() (which publishes the
 * x-coordinate — the protocol's `cmu`, the note-commitment tree leaf) and
 * sapling_compute_nf() (which needs the whole point to build rho), so a
 * nullifier can never be computed over a different note than the commitment.
 * It is also what an in-circuit section-20 wire pair is diffed against, since a
 * matching x with a mismatched y is a point that is not the commitment.
 * Returns false only if `diversifier` is invalid (g_d would be the identity). */
bool sapling_note_commitment_point(const uint8_t diversifier[11],
                                    const uint8_t pk_d[32],
                                    uint64_t value, const uint8_t rcm[32],
                                    struct jub_point *cm_out);

/* Compute the Sapling nullifier that double-spend protection keys on:
 *   nf = BLAKE2s-256("Zcash_nf", nk || rho)
 * where rho = cm_full_point + position · NullifierPosition, and
 * cm_full_point is the *uncompressed* note-commitment point (the same
 * point whose x-coord is cm). `position` is the leaf's 0-based index in
 * the note-commitment tree — it is what binds the nullifier to where the
 * note sits in the tree, so an honest spend must pass the real merkle
 * position. `ak` is unused for nf (it gates only the viewing key); only
 * `nk` enters the hash. Returns false only if `diversifier` is invalid. */
bool sapling_compute_nf(const uint8_t diversifier[11], const uint8_t pk_d[32],
                         uint64_t value, const uint8_t rcm[32],
                         const uint8_t ak[32], const uint8_t nk[32],
                         uint64_t position, uint8_t nf[32]);

/* Generate a random Fs scalar (for commitment/note randomness).
 * Returns false on RNG failure (see crypto/random_secret.h); on success
 * `result` holds 32 bytes of a uniformly-sampled Fs element. Test paths
 * may discard the return value; production callers must propagate. */
bool sapling_generate_r(uint8_t result[32]);

#ifdef ZCL_TESTING
/* ── Test-ONLY deterministic RNG injection for sapling_generate_r ──
 *
 * The deterministic simulator needs the Sapling prover's note
 * randomness (rcv/esk/rcm/ar) to be reproducible run-to-run so tx
 * bytes / txids are stable for a given 64-bit seed. In a normal
 * build these come from `zcl_random_secret_bytes` → `GetRandBytes`
 * (real kernel CSPRNG) and are NON-reproducible by design.
 *
 * This seam is compiled ONLY under `-DZCL_TESTING` (test_zcl /
 * test_parallel and the sim harness). It does not exist in the
 * production node binary, so `sapling_generate_r()` there ALWAYS
 * draws from `GetRandBytes` — there is no runtime flag, env var, or
 * symbol a production path could flip to divert the prover RNG.
 *
 * When `fn` is NULL (the default, even in a ZCL_TESTING build),
 * `sapling_generate_r()` is byte-identical to today. When `fn` is
 * set, each `sapling_generate_r()` call fills its 64-byte reduction
 * buffer via `fn(user, buf, 64)` instead. `fn` must return true on
 * success (buffer filled) or false to signal RNG failure (handled
 * exactly like a `zcl_random_secret_bytes` failure). Pass NULL to
 * restore the default. Not thread-partitioned: set it around a
 * single-threaded deterministic build, then clear it. */
typedef bool (*sapling_test_rng_fn)(void *user, uint8_t *out, size_t n);
void sapling_set_test_rng_hook(sapling_test_rng_fn fn, void *user);

/* ── Test-ONLY deterministic RNG injection for the RedJubjub signing nonce ──
 *
 * redjubjub_sign draws an 80-byte nonce seed T from `zcl_random_secret_bytes`
 * (kernel CSPRNG) — the spend_auth_sig and binding_sig of a Sapling tx. Those
 * nonces feed the signature bytes, so with real entropy the enclosing tx's
 * txid is NON-reproducible run-to-run. This is the last randomness seam a
 * deterministic shielded transaction needs seeded (after Lane B's
 * sapling_generate_r and Lane C's Groth16 r,s), so a seeded build is
 * txid-stable.
 *
 * Compiled ONLY under `-DZCL_TESTING`; absent from the production node binary
 * (no symbol, no branch), so `redjubjub_sign` there ALWAYS draws T from
 * `zcl_random_secret_bytes`. NULL (the default even under ZCL_TESTING) is
 * byte-identical to today. When set, each T draw is filled via `fn(user, buf,
 * 80)`. Set around a single-threaded deterministic build, then clear it.
 * Mirrors sapling_set_test_rng_hook / groth16_set_test_rng_hook.
 *
 * SECURITY NOTE: a repeated signing nonce leaks the signing key. This seam is
 * why the deterministic simulator is TEST-ONLY: it deliberately makes nonces
 * reproducible, which is catastrophic on a real key. It cannot exist in the
 * production binary (compiled out), and no production path can install it. */
void redjubjub_set_test_rng_hook(sapling_test_rng_fn fn, void *user);
#endif /* ZCL_TESTING */

/* RedJubjub signature verification (Zcash spec §5.4.7).
 * Returns true iff (vk, msg, sig) is a valid signature, asserting:
 *   - vk and R = sig_rbar deserialize to valid Jubjub points;
 *   - S = sig_sbar is canonical, i.e. S < Fs subgroup order (a
 *     non-canonical S is rejected to match zcashd and prevent
 *     signature malleability that could split consensus);
 *   - the cofactored equation [8]·(R + c·vk - S·G) == identity holds,
 *     where c = H*(Rbar || vk_bytes || msg) and G is the fixed generator.
 * msg/msg_len: message bytes (32 for sighash in spend_auth/binding).
 * generator_idx: 5 for SpendingKey (spend_auth_sig),
 *                4 for ValueCommitmentRandomness (binding_sig).
 * Returns false (and logs) on any malformed input or rejected signature. */
bool redjubjub_verify(const uint8_t vk_bytes[32],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t sig_rbar[32],
                       const uint8_t sig_sbar[32],
                       int generator_idx);

/* RedJubjub signing.
 * sk: secret key scalar (32 bytes)
 * msg/msg_len: message to sign
 * sig_out: output signature (64 bytes: rbar || sbar)
 * generator_idx: 5 for SpendAuth, 4 for ValueCommitment */
bool redjubjub_sign(const uint8_t sk[32],
                     const uint8_t *msg, size_t msg_len,
                     uint8_t sig_out[64],
                     int generator_idx);

/* Compute value commitment: cv = value * G_v + rcv * G_rcv
 * rcv: randomness scalar (32 bytes, must be a valid Fs)
 * cv_out: compressed Jubjub point (32 bytes) */
bool sapling_value_commit(uint64_t value, const uint8_t rcv[32],
                           uint8_t cv_out[32]);

/* Build a complete Sapling OutputDescription.
 * ovk: outgoing viewing key for sender recovery (32 bytes)
 * to_d, to_pk_d: recipient diversifier and pk_d
 * value: amount in zatoshi
 * memo: optional memo (512 bytes), NULL for default (0xF6 padding)
 * od_cv, od_cm, od_epk, od_enc, od_out, od_proof: output fields
 * rcv_out: if non-NULL, receives the rcv scalar (for binding sig)
 * Returns false on failure. */
bool sapling_build_output_description(
    const uint8_t ovk[32],
    const uint8_t to_d[11], const uint8_t to_pk_d[32],
    uint64_t value, const uint8_t memo[512],
    uint8_t od_cv[32], uint8_t od_cm[32], uint8_t od_epk[32],
    uint8_t od_enc[580], uint8_t od_out[80], uint8_t od_proof[192],
    uint8_t rcv_out[32]);

/* Build output description using Sapling proving context.
 * proving_ctx: opaque proving context from zclassic_sapling_proving_ctx_init
 * The pinned canonical backend produces cv and zkproof; consensus
 * verification, cm, epk, and encryption remain in independent C23 code. */
bool sapling_build_output_with_ctx(
    void *proving_ctx,
    const uint8_t ovk[32],
    const uint8_t to_d[11], const uint8_t to_pk_d[32],
    uint64_t value, const uint8_t memo[512],
    uint8_t od_cv[32], uint8_t od_cm[32], uint8_t od_epk[32],
    uint8_t od_enc[580], uint8_t od_out[80], uint8_t od_proof[192]);

/* Create binding signature for Sapling transaction.
 * bsk: total binding secret key (sum of rcv for spends, negated for outputs)
 * sighash: transaction sighash (32 bytes)
 * binding_sig_out: output signature (64 bytes) */
bool sapling_create_binding_sig(const uint8_t bsk[32],
                                 const uint8_t sighash[32],
                                 uint8_t binding_sig_out[64]);

/* Build a Sapling spend description using Sapling proving context.
 * Generates spend proof, cv, rk, nullifier.
 * Returns ar (randomness for spend_auth_sig) in ar_out for later signing. */
bool sapling_build_spend_with_ctx(
    void *proving_ctx,
    const uint8_t ask[32], const uint8_t nsk[32],
    const uint8_t diversifier[11], const uint8_t pk_d[32],
    const uint8_t rcm[32], uint64_t value, uint64_t position,
    const uint8_t anchor[32],
    const uint8_t *witness_path, size_t witness_len,
    uint8_t sd_cv[32], uint8_t sd_nullifier[32],
    uint8_t sd_rk[32], uint8_t sd_zkproof[192],
    uint8_t ar_out[32]);

/* Sapling verification context — accumulates the value-commitment balance
 * point `bvk` across every spend/output in ONE transaction. The full
 * bundle verification is a 3-phase sequence and the phases are stateful and
 * ORDER-DEPENDENT:
 *   1. init       — bvk := identity
 *   2. check_spend per spend  (adds  cv to bvk)
 *   3. check_output per output (subtracts cv from bvk)
 *   4. final_check — asserts bvk - value_balance·G_v opens the binding sig
 * The per-description checks below verify the proof/sig for that one
 * description but DO NOT establish transaction balance on their own —
 * only sapling_final_check closes that. Use one ctx per transaction;
 * sharing a ctx across transactions corrupts the balance accumulator. */
struct sapling_verification_ctx {
    struct jub_point bvk; /* accumulated value commitment balance */
};

void sapling_verification_ctx_init(struct sapling_verification_ctx *ctx);

/* Set the global Groth16 verifying keys. MUST be called once at startup
 * (sapling_init_params) before any check_spend/check_output. The check
 * functions fail closed — a NULL VK makes them reject every proof rather
 * than silently accept it — so forgetting this is loud, not silent. */
struct groth16_vk;
void sapling_set_spend_vk(struct groth16_vk *vk);
void sapling_set_output_vk(struct groth16_vk *vk);

#ifdef ZCL_TESTING
/* Read back what is currently PUBLISHED to the consensus verifiers.
 *
 * Exists so a test can assert the publish/free invariant in params_init.c
 * directly — "every failure path leaves the verifier VKs NULL" — rather than
 * inferring it from a verdict. Inference does not work here: the fail-closed
 * guards above only ask whether the pointer is NULL, so a pointer left aimed
 * at freed storage passes them, and the verdict that follows is whatever the
 * freed heap happens to say. The pointer itself is the observable. */
const struct groth16_vk *sapling_test_published_spend_vk(void);
const struct groth16_vk *sapling_test_published_output_vk(void);
#endif

/* Verify one Sapling SpendDescription and fold it into the bundle balance.
 * On success (`true`) this asserts ALL of:
 *   - cv and rk deserialize to valid Jubjub points and are NOT small-order
 *     (rejects the cofactor-subgroup malleability attack);
 *   - spend_auth_sig is a valid RedJubjub signature over `sighash` under
 *     the re-randomized key rk (proves authority to spend without
 *     revealing ak);
 *   - the Groth16 spend proof verifies against the 7 public inputs
 *     {rk.x, rk.y, cv.x, cv.y, anchor, nullifier_packed[0..1]} — i.e. the
 *     note is committed under `anchor` (a past note-commitment tree root),
 *     its value matches cv, and `nullifier` is the correct nf for it.
 * SIDE EFFECT: on success cv is ADDED to ctx->bvk. NOTE: this does NOT
 * check that `anchor` is a recognized historical root, nor that
 * `nullifier` is unspent — those are the caller's (chainstate) job.
 * Returns false (and logs) on the first failed check. */
bool sapling_check_spend(struct sapling_verification_ctx *ctx,
                          const uint8_t cv[32],
                          const uint8_t anchor[32],
                          const uint8_t nullifier[32],
                          const uint8_t rk[32],
                          const uint8_t zkproof[192],
                          const uint8_t spend_auth_sig[64],
                          const uint8_t sighash[32]);

/* Verify one Sapling OutputDescription and fold it into the bundle balance.
 * On success (`true`) this asserts ALL of:
 *   - cv and epk deserialize to valid Jubjub points and are NOT small-order;
 *   - the Groth16 output proof verifies against the 5 public inputs
 *     {cv.x, cv.y, epk.x, epk.y, cm} — i.e. cv commits to the same value
 *     the note plaintext encodes and `cm` is the correct note commitment
 *     for epk's diversifier. (The new note's `cm` is what the caller
 *     appends to the commitment tree.)
 * SIDE EFFECT: on success cv is SUBTRACTED from ctx->bvk. Returns false
 * (and logs) on the first failed check. */
bool sapling_check_output(struct sapling_verification_ctx *ctx,
                           const uint8_t cv[32],
                           const uint8_t cm[32],
                           const uint8_t epk[32],
                           const uint8_t zkproof[192]);

/* Close the bundle: assert that the accumulated value commitments balance
 * to the declared `value_balance` (net zatoshi moving in/out of the shielded
 * pool). Computes final_bvk = ctx->bvk - value_balance·ValueCommitmentValue
 * and verifies `binding_sig` is a valid RedJubjub signature over `sighash`
 * under final_bvk as the verification key. This succeeds iff the prover knew
 * bsk = sum(rcv_spends) - sum(rcv_outputs), which is only possible when the
 * value commitments actually sum to value_balance — i.e. no value was minted
 * or burned. value_balance == INT64_MIN is rejected (matches Rust
 * checked_abs). MUST be called only after every check_spend/check_output for
 * the transaction has run; returns false (and logs) on rejection. */
bool sapling_final_check(struct sapling_verification_ctx *ctx,
                          int64_t value_balance,
                          const uint8_t binding_sig[64],
                          const uint8_t sighash[32]);

/* ── Batched Groth16 verification (BACKGROUND re-validation ONLY) ──────────
 *
 * These split each per-description check into (1) a "prepare" that runs every
 * NON-Groth16 gate (point decode, small-order, RedJubjub sig, bvk fold, proof
 * decode, public-input construction) with the EXACT order and early-returns of
 * sapling_check_spend / sapling_check_output — the consensus functions are
 * literally implemented as prepare()+the single verify below — and (2) a
 * Groth16 stage that can be run either batched (many proofs, one final-exp) or
 * per-proof. This lets the background full-validation pass verify a whole
 * transaction's shielded proofs with ~N+2 Miller loops + ONE final
 * exponentiation instead of 4N loops + N final-exps.
 *
 * VERDICT SAFETY: the accept set is identical to a per-proof sweep (a valid
 * set yields the exact GT identity — batch never false-rejects it). A caller
 * MUST, on a batch reject, fall back to the per-proof `*_groth16_one` calls to
 * attribute the failure — never accept a set the per-proof sweep would reject.
 * The consensus tip path (contextual_check_tx) still calls sapling_check_spend
 * / sapling_check_output unchanged; only offline re-validation uses batching.
 *
 * `pub_out` points at a caller-owned [7][4] (spend) or [5][4] (output) block.
 * The prepare folds cv into ctx->bvk on success exactly like the check fn. */
struct groth16_proof;

bool sapling_spend_prepare(struct sapling_verification_ctx *ctx,
                           const uint8_t cv[32], const uint8_t anchor[32],
                           const uint8_t nullifier[32], const uint8_t rk[32],
                           const uint8_t zkproof[192],
                           const uint8_t spend_auth_sig[64],
                           const uint8_t sighash[32],
                           struct groth16_proof *proof_out,
                           uint64_t (*pub_out)[4]);

bool sapling_output_prepare(struct sapling_verification_ctx *ctx,
                            const uint8_t cv[32], const uint8_t cm[32],
                            const uint8_t epk[32], const uint8_t zkproof[192],
                            struct groth16_proof *proof_out,
                            uint64_t (*pub_out)[4]);

/* Batch-verify n_proofs prepared spend/output proofs against the loaded VK.
 * `pub` is a flat array: proof j uses rows [j*7 .. ) (spend) / [j*5 .. )
 * (output). Returns true iff every proof verifies (deterministic on a valid
 * set). On false the caller falls back to *_groth16_one per proof. */
bool sapling_spend_groth16_batch(const struct groth16_proof *proofs,
                                 const uint64_t (*pub)[4], size_t n_proofs);
bool sapling_output_groth16_batch(const struct groth16_proof *proofs,
                                  const uint64_t (*pub)[4], size_t n_proofs);

/* Per-proof Groth16 verify against the loaded VK (fallback / attribution).
 * `pub` points at this proof's [7][4] (spend) or [5][4] (output) block. */
bool sapling_spend_groth16_one(const struct groth16_proof *proof,
                               const uint64_t (*pub)[4]);
bool sapling_output_groth16_one(const struct groth16_proof *proof,
                                const uint64_t (*pub)[4]);

#endif
