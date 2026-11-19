/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * Stable C facade for Sapling VERIFICATION, plus the witness ABI parser both
 * proving backends share.
 *
 * Consensus verification is the independent C23 implementation in sapling.c
 * and is present in every build — it never depends on a proving backend.
 * Wallet-side PROVING is implemented by sapling_prover_native.c and remains
 * fail-closed until its in-process Spend/Output/binding proof bundle passes the
 * verifier here. Nothing in this file branches on proving readiness, so the
 * consensus surface is never inside that policy boundary.
 */

#include "sapling/sapling_prover.h"

#include "sapling_prover_internal.h"

#include "sapling/incremental_merkle_tree.h"
#include "sapling/sapling.h"
#include "sapling/sapling_circuit.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* --- Verification: the consensus C23 implementation -------------------- */

void *zclassic_sapling_verification_ctx_init(void)
{
    struct sapling_verification_ctx *ctx =
        zcl_calloc(1, sizeof(*ctx), "sapling_verify_ctx");
    if (ctx)
        sapling_verification_ctx_init(ctx);
    return ctx;
}

void zclassic_sapling_verification_ctx_free(void *ctx)
{
    free(ctx);
}

bool zclassic_sapling_check_spend(
    void *ctx, const uint8_t *cv, const uint8_t *anchor,
    const uint8_t *nullifier, const uint8_t *rk,
    const uint8_t *zkproof, const uint8_t *spend_auth_sig,
    const uint8_t *sighash_value)
{
    return sapling_check_spend(ctx, cv, anchor, nullifier, rk,
                               zkproof, spend_auth_sig, sighash_value);
}

bool zclassic_sapling_check_output(
    void *ctx, const uint8_t *cv, const uint8_t *cm,
    const uint8_t *epk, const uint8_t *zkproof)
{
    return sapling_check_output(ctx, cv, cm, epk, zkproof);
}

bool zclassic_sapling_final_check(
    void *ctx, int64_t value_balance,
    const uint8_t *binding_sig, const uint8_t *sighash_value)
{
    return sapling_final_check(ctx, value_balance, binding_sig,
                               sighash_value);
}

/* --- Batched Groth16 verification (background re-validation) ------------- */

bool zclassic_sapling_spend_prepare(
    void *ctx, const uint8_t *cv, const uint8_t *anchor,
    const uint8_t *nullifier, const uint8_t *rk, const uint8_t *zkproof,
    const uint8_t *spend_auth_sig, const uint8_t *sighash_value,
    struct groth16_proof *proof_out, uint64_t (*pub_out)[4])
{
    return sapling_spend_prepare(ctx, cv, anchor, nullifier, rk, zkproof,
                                 spend_auth_sig, sighash_value,
                                 proof_out, pub_out);
}

bool zclassic_sapling_output_prepare(
    void *ctx, const uint8_t *cv, const uint8_t *cm,
    const uint8_t *epk, const uint8_t *zkproof,
    struct groth16_proof *proof_out, uint64_t (*pub_out)[4])
{
    return sapling_output_prepare(ctx, cv, cm, epk, zkproof,
                                  proof_out, pub_out);
}

bool zclassic_sapling_spend_groth16_batch(
    const struct groth16_proof *proofs, const uint64_t (*pub)[4], size_t n)
{
    return sapling_spend_groth16_batch(proofs, pub, n);
}

bool zclassic_sapling_output_groth16_batch(
    const struct groth16_proof *proofs, const uint64_t (*pub)[4], size_t n)
{
    return sapling_output_groth16_batch(proofs, pub, n);
}

bool zclassic_sapling_spend_groth16_one(
    const struct groth16_proof *proof, const uint64_t (*pub)[4])
{
    return sapling_spend_groth16_one(proof, pub);
}

bool zclassic_sapling_output_groth16_one(
    const struct groth16_proof *proof, const uint64_t (*pub)[4])
{
    return sapling_output_groth16_one(proof, pub);
}

/* --- Witness ABI parsing (backend-independent) --------------------------- */

bool sapling_spend_parse_witness(const uint8_t *witness,
                                 size_t witness_len,
                                 struct sapling_spend_witness *wit)
{
    if (!witness || !wit)
        LOG_FAIL("sapling_prover", "parse_witness: NULL input");
    if (witness_len < SAPLING_COMPACT_WITNESS_LEN)
        LOG_FAIL("sapling_prover",
                 "parse_witness: short input: got=%zu need=%zu",
                 witness_len, SAPLING_COMPACT_WITNESS_LEN);
    if (witness[0] != SAPLING_MERKLE_DEPTH)
        LOG_FAIL("sapling_prover",
                 "parse_witness: depth=%u expected=%u",
                 witness[0], SAPLING_MERKLE_DEPTH);

    for (size_t i = 0; i < SAPLING_MERKLE_DEPTH; i++) {
        const size_t off = 1 + i * 33;
        memcpy(wit->auth_path[i], witness + off, 32);
        if (witness[off + 32] > 1)
            LOG_FAIL("sapling_prover",
                     "parse_witness: invalid direction byte at level=%zu",
                     i);
        wit->auth_path_bits[i] = witness[off + 32] != 0;
    }
    return true;
}
