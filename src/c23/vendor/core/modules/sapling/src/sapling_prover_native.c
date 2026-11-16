/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet-side Sapling proving, entirely in C23. The backend is promoted to
 * READY only after a native Spend + Output + binding-signature bundle is
 * accepted by the independent consensus verifier in sapling.c. */

#include "sapling/sapling_prover.h"

#include "sapling_prover_internal.h"

#include "sapling/fr.h"
#include "sapling/incremental_merkle_tree.h"
#include "sapling/params_init.h"
#include "sapling/sapling.h"
#include "sapling/sapling_circuit.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum native_prover_state {
    NATIVE_PROVER_UNINITIALIZED = 0,
    NATIVE_PROVER_INITIALIZED,
    NATIVE_PROVER_SELF_TESTING,
    NATIVE_PROVER_READY,
    NATIVE_PROVER_FAILED,
};

static _Atomic int g_native_state = NATIVE_PROVER_UNINITIALIZED;
static _Atomic bool g_native_params_initialized = false;

struct native_proving_ctx {
    struct fs bsk;
    bool has_bsk;
};

static const char *native_state_name(int state)
{
    switch (state) {
    case NATIVE_PROVER_UNINITIALIZED: return "params_not_initialized";
    case NATIVE_PROVER_INITIALIZED: return "self_test_pending";
    case NATIVE_PROVER_SELF_TESTING: return "self_test_running";
    case NATIVE_PROVER_READY: return "ready";
    case NATIVE_PROVER_FAILED: return "self_test_failed";
    default: return "invalid_state";
    }
}

bool zclassic_sapling_prover_is_ready(void)
{
    return atomic_load(&g_native_state) == NATIVE_PROVER_READY;
}

const char *zclassic_sapling_prover_status(void)
{
    int state = atomic_load(&g_native_state);
    const char *why = sapling_proving_last_refusal();
    if (why && state == NATIVE_PROVER_UNINITIALIZED)
        return why;
    return native_state_name(state);
}

const char *zclassic_sapling_prover_backend(void)
{
    return "native-c23-groth16";
}

static struct native_proving_ctx *native_ctx_new(void)
{
    return zcl_calloc(1, sizeof(struct native_proving_ctx),
                      "native_sapling_proving_ctx");
}

void *zclassic_sapling_proving_ctx_init(void)
{
    if (!sapling_proving_session_acquire())
        LOG_NULL("sapling_prover",
                 "native proving context refused: status=%s",
                 zclassic_sapling_prover_status());
    void *ctx = native_ctx_new();
    if (!ctx)
        sapling_proving_session_release();
    return ctx;
}

static void native_ctx_free(void *ctx)
{
    if (!ctx)
        return;
    memory_cleanse(ctx, sizeof(struct native_proving_ctx));
    free(ctx);
}

void zclassic_sapling_proving_ctx_free(void *ctx)
{
    if (!ctx)
        return;
    native_ctx_free(ctx);
    sapling_proving_session_release();
}

static bool native_accumulate_rcv(struct native_proving_ctx *ctx,
                                  const uint8_t rcv[32], bool subtract)
{
    if (!ctx)
        LOG_FAIL("sapling_prover", "accumulate_rcv: NULL context");
    struct fs term;
    if (!fs_from_bytes(&term, rcv))
        LOG_FAIL("sapling_prover", "accumulate_rcv: non-canonical scalar");
    if (subtract) {
        struct fs neg;
        fs_neg(&neg, &term);
        term = neg;
        memory_cleanse(&neg, sizeof(neg));
    }
    struct fs sum;
    fs_add(&sum, &ctx->bsk, &term);
    ctx->bsk = sum;
    ctx->has_bsk = true;
    memory_cleanse(&term, sizeof(term));
    memory_cleanse(&sum, sizeof(sum));
    return true;
}

/* True when an output-proof argument or the output proving key is absent. */
static bool native_output_proof_inputs_missing(
    const struct native_proving_ctx *ctx, const uint8_t esk[32],
    const uint8_t diversifier[11], const uint8_t pk_d[32],
    const uint8_t rcm[32], const uint8_t cv[32],
    const uint8_t zkproof[192], const uint8_t *pk, size_t pk_len)
{
    return !ctx || !esk || !diversifier || !pk_d || !rcm || !cv || !zkproof ||
        !pk || pk_len == 0;
}

static bool native_output_proof_raw(
    struct native_proving_ctx *ctx, const uint8_t esk[32],
    const uint8_t diversifier[11], const uint8_t pk_d[32],
    const uint8_t rcm[32], uint64_t value, uint8_t cv[32],
    uint8_t zkproof[192])
{
    bool ok = false;
    uint8_t rcv[32] = {0};
    struct sapling_output_witness wit;
    struct sapling_output_inputs pub;
    memset(&wit, 0, sizeof(wit));
    memset(&pub, 0, sizeof(pub));

    size_t pk_len = 0;
    const uint8_t *pk = sapling_get_output_pk(&pk_len);
    if (native_output_proof_inputs_missing(ctx, esk, diversifier, pk_d, rcm,
                                           cv, zkproof, pk, pk_len))
        goto cleanup;
    if (!sapling_generate_r(rcv))
        goto cleanup;

    wit.value = value;
    memcpy(wit.diversifier, diversifier, sizeof(wit.diversifier));
    memcpy(wit.pk_d, pk_d, sizeof(wit.pk_d));
    memcpy(wit.rcm, rcm, sizeof(wit.rcm));
    memcpy(wit.esk, esk, sizeof(wit.esk));
    memcpy(wit.rcv, rcv, sizeof(wit.rcv));

    if (!sapling_value_commit(value, rcv, pub.cv) ||
        !sapling_ka_derivepublic(diversifier, esk, pub.epk) ||
        !sapling_compute_cm(diversifier, pk_d, value, rcm, pub.cm) ||
        !sapling_create_output_proof(pk, pk_len, &wit, &pub, zkproof) ||
        !native_accumulate_rcv(ctx, rcv, true))
        goto cleanup;
    memcpy(cv, pub.cv, 32);
    ok = true;

cleanup:
    memory_cleanse(rcv, sizeof(rcv));
    memory_cleanse(&wit, sizeof(wit));
    memory_cleanse(&pub, sizeof(pub));
    return ok;
}

/* True when ctx, ak, nsk, diversifier, rcm, ar, anchor, witness, cv or rk is null. */
static bool native_spend_proof_inputs_missing(
    const struct native_proving_ctx *ctx, const uint8_t ak[32],
    const uint8_t nsk[32], const uint8_t diversifier[11],
    const uint8_t rcm[32], const uint8_t ar[32], const uint8_t anchor[32],
    const uint8_t *witness, const uint8_t cv[32], const uint8_t rk[32])
{
    return !ctx || !ak || !nsk || !diversifier || !rcm || !ar || !anchor ||
        !witness || !cv || !rk;
}

static bool native_spend_proof_raw(
    struct native_proving_ctx *ctx, const uint8_t ak[32],
    const uint8_t nsk[32], const uint8_t diversifier[11],
    const uint8_t rcm[32], const uint8_t ar[32], uint64_t value,
    const uint8_t anchor[32], const uint8_t *witness, size_t witness_len,
    uint8_t cv[32], uint8_t rk[32], uint8_t zkproof[192])
{
    bool ok = false;
    uint8_t rcv[32] = {0};
    struct sapling_spend_witness wit;
    struct sapling_spend_inputs pub;
    memset(&wit, 0, sizeof(wit));
    memset(&pub, 0, sizeof(pub));

    size_t pk_len = 0;
    const uint8_t *pk = sapling_get_spend_pk(&pk_len);
    if (native_spend_proof_inputs_missing(ctx, ak, nsk, diversifier, rcm, ar,
                                          anchor, witness, cv, rk) ||
        !zkproof || !pk || pk_len == 0)
        goto cleanup;
    if (!sapling_generate_r(rcv))
        goto cleanup;

    memcpy(wit.ak, ak, sizeof(wit.ak));
    memcpy(wit.nsk, nsk, sizeof(wit.nsk));
    memcpy(wit.ar, ar, sizeof(wit.ar));
    wit.value = value;
    memcpy(wit.diversifier, diversifier, sizeof(wit.diversifier));
    memcpy(wit.rcm, rcm, sizeof(wit.rcm));
    memcpy(wit.rcv, rcv, sizeof(wit.rcv));
    if (!sapling_spend_parse_witness(witness, witness_len, &wit) ||
        !sapling_spend_derive_public(&wit, &pub) ||
        memcmp(pub.anchor, anchor, 32) != 0 ||
        !sapling_create_spend_proof(pk, pk_len, &wit, &pub, zkproof) ||
        !native_accumulate_rcv(ctx, rcv, false))
        goto cleanup;
    memcpy(cv, pub.cv, 32);
    memcpy(rk, pub.rk, 32);
    ok = true;

cleanup:
    memory_cleanse(rcv, sizeof(rcv));
    memory_cleanse(&wit, sizeof(wit));
    memory_cleanse(&pub, sizeof(pub));
    return ok;
}

static bool native_binding_sig_raw(const struct native_proving_ctx *ctx,
                                   const uint8_t sighash[32],
                                   uint8_t result[64])
{
    if (!ctx || !ctx->has_bsk || !sighash || !result)
        return false;
    uint8_t bsk[32];
    fs_to_bytes(bsk, &ctx->bsk);
    bool ok = redjubjub_sign(bsk, sighash, 32, result, 4);
    memory_cleanse(bsk, sizeof(bsk));
    return ok;
}

bool zclassic_sapling_output_proof(
    void *ctx, const unsigned char *esk, const unsigned char *diversifier,
    const unsigned char *pk_d, const unsigned char *rcm, uint64_t value,
    unsigned char *cv, unsigned char *zkproof)
{
    if (!zclassic_sapling_prover_is_ready())
        LOG_FAIL("sapling_prover", "output proof disabled: status=%s",
                 zclassic_sapling_prover_status());
    if (!native_output_proof_raw(ctx, esk, diversifier, pk_d, rcm, value,
                                 cv, zkproof))
        LOG_FAIL("sapling_prover", "native output proof construction failed");
    return true;
}

bool zclassic_sapling_spend_proof(
    void *ctx, const unsigned char *ak, const unsigned char *nsk,
    const unsigned char *diversifier, const unsigned char *rcm,
    const unsigned char *ar, uint64_t value, const unsigned char *anchor,
    const unsigned char *witness, size_t witness_len, unsigned char *cv,
    unsigned char *rk, unsigned char *zkproof)
{
    if (!zclassic_sapling_prover_is_ready())
        LOG_FAIL("sapling_prover", "spend proof disabled: status=%s",
                 zclassic_sapling_prover_status());
    if (!native_spend_proof_raw(ctx, ak, nsk, diversifier, rcm, ar, value,
                                anchor, witness, witness_len, cv, rk, zkproof))
        LOG_FAIL("sapling_prover", "native spend proof construction failed");
    return true;
}

bool zclassic_sapling_binding_sig(
    const void *ctx, int64_t value_balance, const unsigned char *sighash,
    unsigned char *result)
{
    (void)value_balance;
    if (!zclassic_sapling_prover_is_ready())
        LOG_FAIL("sapling_prover", "binding signature disabled: status=%s",
                 zclassic_sapling_prover_status());
    if (!native_binding_sig_raw(ctx, sighash, result))
        LOG_FAIL("sapling_prover", "native binding signature failed");
    return true;
}

static bool native_find_diversifier(uint8_t diversifier[11])
{
    memset(diversifier, 0, 11);
    for (unsigned int i = 0; i < 256; i++) {
        diversifier[0] = (uint8_t)i;
        if (sapling_check_diversifier(diversifier))
            return true;
    }
    return false;
}

/* True when any self-test scalar draw fails. */
static bool native_self_test_random_scalars_missing(
    uint8_t ask[32], uint8_t nsk[32], uint8_t spend_rcm[32],
    uint8_t ar[32], uint8_t output_rcm[32], uint8_t esk[32])
{
    memset(ask, 0, 32);
    memset(nsk, 0, 32);
    memset(spend_rcm, 0, 32);
    memset(ar, 0, 32);
    memset(output_rcm, 0, 32);
    memset(esk, 0, 32);
    return !sapling_generate_r(ask) || !sapling_generate_r(nsk) ||
        !sapling_generate_r(spend_rcm) || !sapling_generate_r(ar) ||
        !sapling_generate_r(output_rcm) || !sapling_generate_r(esk);
}

/* True when no diversifier is found, or pk_d or the note commitment fails. */
static bool native_self_test_recipient_rejected(
    const uint8_t ask[32], const uint8_t nsk[32],
    const uint8_t spend_rcm[32], uint64_t value, uint8_t d[11],
    uint8_t ak[32], uint8_t nk[32], uint8_t ivk[32], uint8_t pk_d[32],
    uint8_t spend_cm[32])
{
    memset(d, 0, 11);
    memset(ak, 0, 32);
    memset(nk, 0, 32);
    memset(ivk, 0, 32);
    memset(pk_d, 0, 32);
    memset(spend_cm, 0, 32);
    bool rejected = !native_find_diversifier(d);
    if (!rejected) {
        sapling_ask_to_ak(ask, ak);
        sapling_nsk_to_nk(nsk, nk);
        sapling_crh_ivk(ak, nk, ivk);
        rejected = !sapling_ivk_to_pkd(ivk, d, pk_d) ||
            !sapling_compute_cm(d, pk_d, value, spend_rcm, spend_cm);
    }
    return rejected;
}

/* True when the proving context is null or the spend proof or nullifier fails. */
static bool native_self_test_spend_rejected(
    struct native_proving_ctx *pctx, const uint8_t ak[32],
    const uint8_t nsk[32], const uint8_t d[11],
    const uint8_t spend_rcm[32], const uint8_t ar[32], uint64_t value,
    const uint8_t anchor[32], const uint8_t *compact_witness,
    size_t compact_len, uint8_t spend_cv[32], uint8_t rk[32],
    uint8_t spend_proof[192], uint8_t nf[32], const uint8_t nk[32],
    const uint8_t pk_d[32])
{
    memset(spend_cv, 0, 32);
    memset(rk, 0, 32);
    memset(spend_proof, 0, 192);
    memset(nf, 0, 32);
    return !pctx || !native_spend_proof_raw(
            pctx, ak, nsk, d, spend_rcm, ar, value, anchor,
            compact_witness, compact_len, spend_cv, rk, spend_proof) ||
        !sapling_compute_nf(d, pk_d, value, spend_rcm, ak, nk, 0, nf);
}

/* True when the output proof, note commitment, epk or binding signature fails. */
static bool native_self_test_output_rejected(
    struct native_proving_ctx *pctx, const uint8_t esk[32],
    const uint8_t d[11], const uint8_t pk_d[32],
    const uint8_t output_rcm[32], uint64_t value, uint8_t output_cv[32],
    uint8_t output_proof[192], uint8_t output_cm[32], uint8_t epk[32],
    const uint8_t sighash[32], uint8_t binding_sig[64])
{
    memset(output_cv, 0, 32);
    memset(output_proof, 0, 192);
    memset(output_cm, 0, 32);
    memset(epk, 0, 32);
    memset(binding_sig, 0, 64);
    return !native_output_proof_raw(pctx, esk, d, pk_d, output_rcm, value,
                                    output_cv, output_proof) ||
        !sapling_compute_cm(d, pk_d, value, output_rcm, output_cm) ||
        !sapling_ka_derivepublic(d, esk, epk) ||
        !native_binding_sig_raw(pctx, sighash, binding_sig);
}

/* Consensus stage that rejected the bundle, or NULL when every check passed. */
static const char *native_self_test_consensus_failure(
    const uint8_t spend_cv[32], const uint8_t anchor[32],
    const uint8_t nf[32], const uint8_t rk[32],
    const uint8_t spend_proof[192], const uint8_t spend_sig[64],
    const uint8_t sighash[32], const uint8_t output_cv[32],
    const uint8_t output_cm[32], const uint8_t epk[32],
    const uint8_t output_proof[192], const uint8_t binding_sig[64])
{
    struct sapling_verification_ctx vctx;
    sapling_verification_ctx_init(&vctx);
    const char *stage = NULL;
    if (!sapling_check_spend(&vctx, spend_cv, anchor, nf, rk,
                             spend_proof, spend_sig, sighash))
        stage = "spend_consensus_verifier";
    else if (!sapling_check_output(&vctx, output_cv, output_cm, epk,
                                   output_proof))
        stage = "output_consensus_verifier";
    else if (!sapling_final_check(&vctx, 0, binding_sig, sighash))
        stage = "binding_consensus_verifier";
    return stage;
}

static bool native_self_test_bundle(void)
{
    const uint64_t value = UINT64_C(12345);
    bool ok = false;
    const char *failed_at = "rng";
    struct native_proving_ctx *pctx = NULL;
    uint8_t ask[32] = {0}, nsk[32] = {0}, ak[32] = {0}, nk[32] = {0};
    uint8_t ivk[32] = {0}, d[11] = {0}, pk_d[32] = {0};
    uint8_t spend_rcm[32] = {0}, ar[32] = {0}, spend_cm[32] = {0};
    uint8_t spend_cv[32] = {0}, rk[32] = {0}, nf[32] = {0};
    uint8_t spend_proof[192] = {0}, spend_sig[64] = {0};
    uint8_t output_rcm[32] = {0}, esk[32] = {0}, output_cv[32] = {0};
    uint8_t output_cm[32] = {0}, epk[32] = {0}, output_proof[192] = {0};
    uint8_t binding_sig[64] = {0}, sighash[32] = {0};
    uint8_t compact_witness[SAPLING_COMPACT_WITNESS_LEN] = {0};

    if (native_self_test_random_scalars_missing(ask, nsk, spend_rcm, ar,
                                                output_rcm, esk))
        goto cleanup;
    failed_at = "recipient";
    if (native_self_test_recipient_rejected(ask, nsk, spend_rcm, value, d,
                                            ak, nk, ivk, pk_d, spend_cm))
        goto cleanup;

    struct incremental_merkle_tree tree;
    struct incremental_witness inc_witness;
    struct uint256 leaf, anchor;
    memcpy(leaf.data, spend_cm, 32);
    sapling_tree_init(&tree);
    incremental_tree_append(&tree, &leaf);
    incremental_witness_init(&inc_witness, &tree);
    incremental_witness_root(&inc_witness, &anchor);
    size_t compact_len = 0;
    failed_at = "merkle_witness";
    if (!incremental_witness_merkle_path(&inc_witness, compact_witness,
                                         &compact_len) ||
        compact_len != sizeof(compact_witness))
        goto cleanup;

    pctx = native_ctx_new();
    failed_at = "spend_proof";
    if (native_self_test_spend_rejected(
            pctx, ak, nsk, d, spend_rcm, ar, value, anchor.data,
            compact_witness, compact_len, spend_cv, rk, spend_proof, nf,
            nk, pk_d))
        goto cleanup;

    struct fs ask_fs, ar_fs, rsk_fs;
    uint8_t rsk[32] = {0};
    if (!fs_from_bytes(&ask_fs, ask) || !fs_from_bytes(&ar_fs, ar))
        goto cleanup;
    fs_add(&rsk_fs, &ask_fs, &ar_fs);
    fs_to_bytes(rsk, &rsk_fs);
    memset(sighash, 0x5a, sizeof(sighash));
    failed_at = "spend_signature";
    if (!redjubjub_sign(rsk, sighash, sizeof(sighash), spend_sig, 5))
        goto cleanup;
    memory_cleanse(rsk, sizeof(rsk));
    memory_cleanse(&ask_fs, sizeof(ask_fs));
    memory_cleanse(&ar_fs, sizeof(ar_fs));
    memory_cleanse(&rsk_fs, sizeof(rsk_fs));

    failed_at = "output_proof";
    if (native_self_test_output_rejected(
            pctx, esk, d, pk_d, output_rcm, value, output_cv, output_proof,
            output_cm, epk, sighash, binding_sig))
        goto cleanup;

    const char *consensus_failure = native_self_test_consensus_failure(
        spend_cv, anchor.data, nf, rk, spend_proof, spend_sig, sighash,
        output_cv, output_cm, epk, output_proof, binding_sig);
    if (consensus_failure) {
        failed_at = consensus_failure;
        goto cleanup;
    }
    ok = true;

cleanup:
    if (!ok)
        LOG_WARN("sapling_prover", "native self-test failed at stage=%s",
                 failed_at);
    native_ctx_free(pctx);
    memory_cleanse(ask, sizeof(ask));
    memory_cleanse(nsk, sizeof(nsk));
    memory_cleanse(ak, sizeof(ak));
    memory_cleanse(nk, sizeof(nk));
    memory_cleanse(ivk, sizeof(ivk));
    memory_cleanse(pk_d, sizeof(pk_d));
    memory_cleanse(spend_rcm, sizeof(spend_rcm));
    memory_cleanse(ar, sizeof(ar));
    memory_cleanse(output_rcm, sizeof(output_rcm));
    memory_cleanse(esk, sizeof(esk));
    memory_cleanse(compact_witness, sizeof(compact_witness));
    return ok;
}

#ifdef ZCL_TESTING
static _Atomic int g_self_test_runs;
int zclassic_test_prover_self_test_runs(void)
{
    return atomic_load(&g_self_test_runs);
}
#endif

bool zclassic_sapling_prover_run_self_test(void)
{
    int expected = NATIVE_PROVER_INITIALIZED;
    if (!atomic_compare_exchange_strong(&g_native_state, &expected,
                                        NATIVE_PROVER_SELF_TESTING)) {
        if (expected == NATIVE_PROVER_READY)
            return true;
        LOG_FAIL("sapling_prover", "cannot run native self-test from state=%s",
                 native_state_name(expected));
    }
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_self_test_runs, 1);
#endif
    if (!native_self_test_bundle()) {
        atomic_store(&g_native_state, NATIVE_PROVER_FAILED);
        LOG_FAIL("sapling_prover",
                 "native Spend/Output/binding gate failed; proving disabled");
    }
    atomic_store(&g_native_state, NATIVE_PROVER_READY);
    LOG_INFO("sapling_prover",
             "native Spend/Output/binding prover->C23-verifier gate passed");
    return true;
}

void zclassic_init_zksnark_params(
    const uint8_t *spend_path, size_t spend_path_len, const char *spend_hash,
    const uint8_t *output_path, size_t output_path_len, const char *output_hash,
    const uint8_t *sprout_path, size_t sprout_path_len, const char *sprout_hash)
{
    if (atomic_load(&g_native_params_initialized))
        return;
    if (!spend_path || spend_path_len == 0 || !spend_hash || !output_path ||
        output_path_len == 0 || !output_hash || !sprout_path ||
        sprout_path_len == 0 || !sprout_hash ||
        !sapling_get_spend_pk(NULL) || !sapling_get_output_pk(NULL)) {
        atomic_store(&g_native_state, NATIVE_PROVER_FAILED);
        LOG_WARN("sapling_prover",
                 "native parameter initialization rejected incomplete input");
        return;
    }
    atomic_store(&g_native_params_initialized, true);
    atomic_store(&g_native_state, NATIVE_PROVER_INITIALIZED);
}

bool zclassic_sapling_prover_adopt_verified(void)
{
    int expected = NATIVE_PROVER_INITIALIZED;
    return atomic_compare_exchange_strong(&g_native_state, &expected,
                                          NATIVE_PROVER_READY);
}

void zclassic_sapling_prover_unarm(void)
{
    atomic_store(&g_native_state, NATIVE_PROVER_UNINITIALIZED);
    atomic_store(&g_native_params_initialized, false);
}

#ifdef ZCL_TESTING
void zclassic_test_prover_reset(void)
{
    /* Order matters even here: clear readiness first, so no window exists in
     * which the state says READY while the parameter latch says "not
     * initialized". */
    atomic_store(&g_native_state, NATIVE_PROVER_UNINITIALIZED);
    atomic_store(&g_native_params_initialized, false);
}
#endif
