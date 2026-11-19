/* zclassicd-owned. Drop-in replacement for librustzcash's include/librustzcash.h
 * at librustzcash 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5 (the pin in
 * depends/packages/librustzcash.mk), implemented in C23 by
 * c23/compat/librustzcash_compat.c on top of the vendored Z23 core.
 *
 * Every declaration below has the same name, parameter list and return type
 * as the Rust header, so the existing C++ call sites compile unchanged. The
 * one declaration of the Rust header that zclassicd never calls,
 * librustzcash_eh_isvalid, is intentionally NOT declared (zclassicd verifies
 * Equihash in C++, src/crypto/equihash.h).
 *
 * Differences from the Rust header that do not change any call site:
 *   - usable from C as well as C++ (extern "C" only under __cplusplus, and
 *     <stdbool.h>/<stddef.h> are included for C);
 *   - `codeunit` is uint16_t when WIN32 or _WIN32 is defined (the Rust header
 *     tests WIN32 only; every zclassicd Windows build defines both);
 *   - additional zcl_c23_* entry points (batch-capable verification,
 *     diagnostics). They replace nothing.
 *
 * Behaviour contract (see librustzcash_compat.c for the per-check rustzcash.rs
 * line references): every function returns the boolean Rust returns for the
 * same input, and calls abort() where Rust panics (Cargo profile.release
 * panic = 'abort'), with the documented exception that verification and
 * proving functions abort on ANY call made before
 * librustzcash_init_zksnark_params, where Rust aborts on well-formed input
 * and returns false on some malformed input. */
#ifndef LIBRUSTZCASH_INCLUDE_H_
#define LIBRUSTZCASH_INCLUDE_H_

#include <stdint.h>
#include <stddef.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(WIN32) || defined(_WIN32)
    typedef uint16_t codeunit;
#else
    typedef uint8_t codeunit;
#endif

    void librustzcash_to_scalar(const unsigned char *input, unsigned char *result);

    void librustzcash_ask_to_ak(const unsigned char *ask, unsigned char *result);

    void librustzcash_nsk_to_nk(const unsigned char *nsk, unsigned char *result);

    void librustzcash_crh_ivk(const unsigned char *ak, const unsigned char *nk, unsigned char *result);

    bool librustzcash_check_diversifier(const unsigned char *diversifier);

    bool librustzcash_ivk_to_pkd(const unsigned char *ivk, const unsigned char *diversifier, unsigned char *result);

    /// Loads the zk-SNARK parameters into memory and saves
    /// paths as necessary. Only called once.
    void librustzcash_init_zksnark_params(
        const codeunit* spend_path,
        size_t spend_path_len,
        const char* spend_hash,
        const codeunit* output_path,
        size_t output_path_len,
        const char* output_hash,
        const codeunit* sprout_path,
        size_t sprout_path_len,
        const char* sprout_hash
    );

    /// Writes the "uncommitted" note value for empty leaves
    /// of the merkle tree. `result` must be a valid pointer
    /// to 32 bytes which will be written.
    void librustzcash_tree_uncommitted(
        unsigned char *result
    );

    /// Computes a merkle tree hash for a given depth.
    /// The `depth` parameter should not be larger than
    /// 62.
    ///
    /// `a` and `b` each must be of length 32, and must each
    /// be scalars of BLS12-381.
    ///
    /// The result of the merkle tree hash is placed in
    /// `result`, which must also be of length 32.
    void librustzcash_merkle_hash(
        size_t depth,
        const unsigned char *a,
        const unsigned char *b,
        unsigned char *result
    );

    /// Computes the signature for each Spend description, given the key
    /// `ask`, the re-randomization `ar`, the 32-byte sighash `sighash`,
    /// and an output `result` buffer of 64-bytes for the signature.
    ///
    /// This function will fail if the provided `ask` or `ar` are invalid.
    bool librustzcash_sapling_spend_sig(
        const unsigned char *ask,
        const unsigned char *ar,
        const unsigned char *sighash,
        unsigned char *result
    );

    /// Creates a Sapling proving context. Please free this when you're done.
    void * librustzcash_sapling_proving_ctx_init(void);

    /// This function (using the proving context) constructs a Spend proof
    /// given the necessary witness information. It outputs `cv` (the value
    /// commitment) and `rk` (so that you don't have to compute it) along
    /// with the proof.
    bool librustzcash_sapling_spend_proof(
        void *ctx,
        const unsigned char *ak,
        const unsigned char *nsk,
        const unsigned char *diversifier,
        const unsigned char *rcm,
        const unsigned char *ar,
        const uint64_t value,
        const unsigned char *anchor,
        const unsigned char *witness,
        unsigned char *cv,
        unsigned char *rk,
        unsigned char *zkproof
    );

    /// This function (using the proving context) constructs an Output
    /// proof given the necessary witness information. It outputs `cv`
    /// and the `zkproof`.
    bool librustzcash_sapling_output_proof(
        void *ctx,
        const unsigned char *esk,
        const unsigned char *diversifier,
        const unsigned char *pk_d,
        const unsigned char *rcm,
        const uint64_t value,
        unsigned char *cv,
        unsigned char *zkproof
    );

    /// This function (using the proving context) constructs a binding
    /// signature. You must provide the intended valueBalance so that
    /// we can internally check consistency.
    bool librustzcash_sapling_binding_sig(
        const void *ctx,
        int64_t valueBalance,
        const unsigned char *sighash,
        unsigned char *result
    );

    /// Frees a Sapling proving context returned from
    /// `librustzcash_sapling_proving_ctx_init`.
    void librustzcash_sapling_proving_ctx_free(void *);

    /// Creates a Sapling verification context. Please free this
    /// when you're done.
    void * librustzcash_sapling_verification_ctx_init(void);

    /// Check the validity of a Sapling Spend description,
    /// accumulating the value commitment into the context.
    bool librustzcash_sapling_check_spend(
        void *ctx,
        const unsigned char *cv,
        const unsigned char *anchor,
        const unsigned char *nullifier,
        const unsigned char *rk,
        const unsigned char *zkproof,
        const unsigned char *spendAuthSig,
        const unsigned char *sighashValue
    );

    /// Check the validity of a Sapling Output description,
    /// accumulating the value commitment into the context.
    bool librustzcash_sapling_check_output(
        void *ctx,
        const unsigned char *cv,
        const unsigned char *cm,
        const unsigned char *ephemeralKey,
        const unsigned char *zkproof
    );

    /// Finally checks the validity of the entire Sapling
    /// transaction given valueBalance and the binding signature.
    bool librustzcash_sapling_final_check(
        void *ctx,
        int64_t valueBalance,
        const unsigned char *bindingSig,
        const unsigned char *sighashValue
    );

    /// Frees a Sapling verification context returned from
    /// `librustzcash_sapling_verification_ctx_init`.
    void librustzcash_sapling_verification_ctx_free(void *);

    /// Compute a Sapling nullifier.
    ///
    /// The `diversifier` parameter must be 11 bytes in length.
    /// The `pk_d`, `r`, `ak` and `nk` parameters must be of length 32.
    /// The result is also of length 32 and placed in `result`.
    /// Returns false if the diversifier or pk_d is not valid
    bool librustzcash_sapling_compute_nf(
        const unsigned char *diversifier,
        const unsigned char *pk_d,
        const uint64_t value,
        const unsigned char *r,
        const unsigned char *ak,
        const unsigned char *nk,
        const uint64_t position,
        unsigned char *result
    );

    /// Compute a Sapling commitment.
    ///
    /// The `diversifier` parameter must be 11 bytes in length.
    /// The `pk_d` and `r` parameters must be of length 32.
    /// The result is also of length 32 and placed in `result`.
    /// Returns false if the diversifier or pk_d is not valid
    bool librustzcash_sapling_compute_cm(
        const unsigned char *diversifier,
        const unsigned char *pk_d,
        const uint64_t value,
        const unsigned char *r,
        unsigned char *result
    );

    /// Compute [sk] [8] P for some 32-byte
    /// point P, and 32-byte Fs. If P or sk
    /// are invalid, returns false. Otherwise,
    /// the result is written to the 32-byte
    /// `result` buffer.
    bool librustzcash_sapling_ka_agree(
        const unsigned char *p,
        const unsigned char *sk,
        unsigned char *result
    );

    /// Compute g_d = GH(diversifier) and returns
    /// false if the diversifier is invalid.
    /// Computes [esk] g_d and writes the result
    /// to the 32-byte `result` buffer. Returns
    /// false if `esk` is not a valid scalar.
    bool librustzcash_sapling_ka_derivepublic(
        const unsigned char *diversifier,
        const unsigned char *esk,
        unsigned char *result
    );

    /// Generate uniformly random scalar in Jubjub.
    /// The result is of length 32.
    void librustzcash_sapling_generate_r(
        unsigned char *result
    );

    /// Sprout JoinSplit proof generation.
    void librustzcash_sprout_prove(
        unsigned char *proof_out,

        const unsigned char *phi,
        const unsigned char *rt,
        const unsigned char *h_sig,

        const unsigned char *in_sk1,
        uint64_t in_value1,
        const unsigned char *in_rho1,
        const unsigned char *in_r1,
        const unsigned char *in_auth1,

        const unsigned char *in_sk2,
        uint64_t in_value2,
        const unsigned char *in_rho2,
        const unsigned char *in_r2,
        const unsigned char *in_auth2,

        const unsigned char *out_pk1,
        uint64_t out_value1,
        const unsigned char *out_r1,

        const unsigned char *out_pk2,
        uint64_t out_value2,
        const unsigned char *out_r2,

        uint64_t vpub_old,
        uint64_t vpub_new
    );

    /// Sprout JoinSplit proof verification.
    bool librustzcash_sprout_verify(
        const unsigned char *proof,
        const unsigned char *rt,
        const unsigned char *h_sig,
        const unsigned char *mac1,
        const unsigned char *mac2,
        const unsigned char *nf1,
        const unsigned char *nf2,
        const unsigned char *cm1,
        const unsigned char *cm2,
        uint64_t vpub_old,
        uint64_t vpub_new
    );

    /// Derive the master ExtendedSpendingKey from a seed.
    void librustzcash_zip32_xsk_master(
        const unsigned char *seed,
        size_t seedlen,
        unsigned char *xsk_master
    );

    /// Derive a child ExtendedSpendingKey from a parent.
    void librustzcash_zip32_xsk_derive(
        const unsigned char *xsk_parent,
        uint32_t i,
        unsigned char *xsk_i
    );

    /// Derive a child ExtendedFullViewingKey from a parent.
    bool librustzcash_zip32_xfvk_derive(
        const unsigned char *xfvk_parent,
        uint32_t i,
        unsigned char *xfvk_i
    );

    /// Derive a PaymentAddress from an ExtendedFullViewingKey.
    bool librustzcash_zip32_xfvk_address(
        const unsigned char *xfvk,
        const unsigned char *j,
        unsigned char *j_ret,
        unsigned char *addr_ret
    );

    /* ------------------------------------------------------------------
     * Additional C23 entry points. Not part of the Rust ABI; nothing above
     * calls them. All names carry the zcl_c23_ prefix.
     * ------------------------------------------------------------------ */

    /// Batch-capable Sapling verification for a later unit. A batch holds
    /// the decoded proofs and public inputs of many Spend/Output
    /// descriptions (any number of transactions). Each add_* call performs,
    /// in Rust's order, EVERY check of librustzcash_sapling_check_spend /
    /// _check_output except the final pairing equation, including the bvk
    /// update of `ctx` and the proof infinity-flag rejection, so its
    /// ZCL_C23_ITEM_REJECT verdict is exactly the Rust false for that
    /// description. The pairing equations are then checked together.
    ///
    /// zcl_c23_batch_verify_each checks every queued proof on its own and
    /// is verdict-exact. zcl_c23_batch_verify combines all pairing checks
    /// with Z23's deterministic Fiat-Shamir weights (accepts a set the
    /// per-proof sweep would reject only with probability ~2^-128) and falls
    /// back to the per-proof sweep on failure to name the first failing
    /// item. Using the combined form on the consensus tip path is an
    /// acceptance-set decision that needs the owner's sign-off (plan hard
    /// stop H3); the 31 ABI functions above keep per-proof semantics.
    typedef struct zcl_c23_batch zcl_c23_batch;

    enum zcl_c23_item_status {
        ZCL_C23_ITEM_QUEUED = 1, /* all non-pairing checks passed; queued */
        ZCL_C23_ITEM_REJECT = 0, /* Rust's check_* would return false */
        ZCL_C23_ITEM_FULL = -1   /* batch capacity exhausted; nothing done */
    };

    /// NULL on allocation failure. Capacities are fixed for the batch's life.
    zcl_c23_batch *zcl_c23_batch_new(size_t max_spends, size_t max_outputs);
    void zcl_c23_batch_free(zcl_c23_batch *batch);
    void zcl_c23_batch_clear(zcl_c23_batch *batch);
    size_t zcl_c23_batch_spends(const zcl_c23_batch *batch);
    size_t zcl_c23_batch_outputs(const zcl_c23_batch *batch);

    /// `ctx` is a librustzcash_sapling_verification_ctx_init context.
    enum zcl_c23_item_status zcl_c23_batch_add_spend(
        zcl_c23_batch *batch, void *ctx,
        const unsigned char *cv, const unsigned char *anchor,
        const unsigned char *nullifier, const unsigned char *rk,
        const unsigned char *zkproof, const unsigned char *spendAuthSig,
        const unsigned char *sighashValue);
    enum zcl_c23_item_status zcl_c23_batch_add_output(
        zcl_c23_batch *batch, void *ctx,
        const unsigned char *cv, const unsigned char *cm,
        const unsigned char *ephemeralKey, const unsigned char *zkproof);

    /// True iff every queued proof verifies. On false, *bad_is_output and
    /// *bad_index (either may be NULL) name the first failing item, spends
    /// before outputs, in insertion order.
    bool zcl_c23_batch_verify_each(const zcl_c23_batch *batch,
                                   bool *bad_is_output, size_t *bad_index);
    bool zcl_c23_batch_verify(const zcl_c23_batch *batch,
                              bool *bad_is_output, size_t *bad_index);

    /// Diagnostics: "none" before init, "resident" once init holds the
    /// verified Sapling proving keys (as librustzcash does). The last
    /// refusal is always NULL: proving no longer loads anything, so nothing
    /// is refused at proof time. Kept for ABI stability.
    const char *zcl_c23_proving_status(void);
    const char *zcl_c23_proving_last_refusal(void);

    /// True once librustzcash_init_zksnark_params has completed.
    bool zcl_c23_params_initialized(void);

    /// Thread budget of the Groth16 prover (Sapling spend/output). 0 = the
    /// vendored default (online processors, at most 8; 1 on mingw). Takes
    /// effect on the next proof; threads never outlive a proof.
#define ZCL_C23_HAVE_PROVER_THREADS 1
    void zcl_c23_set_prover_threads(unsigned n);

    /// Splits the thread budget among `concurrent_proofs` proofs that a caller
    /// is about to run at the same time, for the duration of that batch, so the
    /// total stays at the budget; returns the per-proof budget (>= 1). Every
    /// enter must be paired with a leave. Batches may nest or overlap: the
    /// largest split in force applies until the last one leaves.
    unsigned zcl_c23_prover_budget_enter(unsigned concurrent_proofs);
    void zcl_c23_prover_budget_leave(void);
    /// The configured total budget, with the automatic default resolved.
    unsigned zcl_c23_prover_budget(void);

    /// Adds the value-commitment accumulators of proving context `src` to
    /// `dst` (as if src's spend and output proofs had been made on dst). Used
    /// to prove one transaction's descriptions on private contexts in parallel
    /// and still sign with a single binding key. `src` is not freed.
    void zcl_c23_sapling_proving_ctx_merge(void *dst, const void *src);

    /// True while the shared parsed Sapling proving keys are resident: from the
    /// first proof of a send until its last proving context is freed.
    bool zcl_c23_proving_keys_parsed(void);

#ifdef __cplusplus
}
#endif

#endif // LIBRUSTZCASH_INCLUDE_H_
