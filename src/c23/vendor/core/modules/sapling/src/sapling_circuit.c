/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling OUTPUT circuit synthesis (5 public inputs, ~16K constraints):
 *   proves correct note commitment and ephemeral key derivation — plus the
 *   Groth16 proof serialization and the two public prove entry points shared
 *   with the spend circuit.
 *
 * The SPEND circuit lives in circuit_spend.c: it is a section-by-section port
 * of bellman's Spend::synthesize whose per-section constraint boundaries are
 * pinned against the reference trace, and keeping it in its own translation
 * unit is what lets that port grow without this file becoming a mega-module. */

#include "sapling/sapling_circuit.h"
#include "sapling/circuit_gadgets.h"
#include "sapling/pedersen_hash.h"
#include "sapling/sapling.h"
#include "base/serialize_le.h"
#include "support/cleanse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

/* ── Helper: convert bytes to Fr ────────────────────────────────── */

static void bytes_to_fr(struct fr *out, const uint8_t bytes[32])
{
    fr_from_bytes(out, bytes);
}

/* Bellman's field_into_boolean_vec_le allocates Fs::NUM_BITS booleans and
 * deliberately does not pack them back into a field wire. These scalars are
 * consumed only as bits, so adding a packing wire changes the trusted-setup
 * QAP even though the honest witness still satisfies it. */
static void output_boolean_vec_le(struct constraint_system *cs,
                                  size_t *bits_out, size_t n_bits,
                                  const struct fr *value)
{
    uint8_t bytes[32];
    fr_to_bytes(bytes, value);
    for (size_t i = 0; i < n_bits; i++) {
        bool bit = ((bytes[i / 8] >> (i % 8)) & 1u) != 0;
        bits_out[i] = gadget_alloc_boolean(cs, bit);
    }
    memory_cleanse(bytes, sizeof(bytes));
}

/* AllocatedNum::inputize orientation: input * ONE = computed. Mirroring the
 * equality is arithmetically equivalent but produces a different QAP. */
static void output_enforce_equal(struct constraint_system *cs,
                                 size_t computed, size_t input_slot)
{
    struct linear_combination la, lb, lc;
    struct fr one_val;
    fr_one(&one_val);
    lc_init(&la); lc_add_term(&la, input_slot, &one_val);
    lc_init(&lb); lc_add_term(&lb, 0, &one_val);
    lc_init(&lc); lc_add_term(&lc, computed, &one_val);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
}

static bool output_point_to_xy(struct fr *x, struct fr *y,
                               const uint8_t compressed[32])
{
    struct jub_point point;
    if (!jub_from_bytes(&point, compressed))
        LOG_FAIL("sapling_circuit",
                 "output_point_to_xy: invalid compressed Jubjub point");
    jub_get_x(x, &point);
    jub_get_y(y, &point);
    return true;
}

/* True when cv, epk, or cm fails to decode, in that order. */
static bool output_public_fields_malformed(struct fr *cv_pub_x,
                                           struct fr *cv_pub_y,
                                           struct fr *epk_pub_x,
                                           struct fr *epk_pub_y,
                                           struct fr *cm_fr,
                                           const struct sapling_output_inputs *pub)
{
    memset(cv_pub_x, 0, sizeof(*cv_pub_x));
    memset(cv_pub_y, 0, sizeof(*cv_pub_y));
    memset(epk_pub_x, 0, sizeof(*epk_pub_x));
    memset(epk_pub_y, 0, sizeof(*epk_pub_y));
    memset(cm_fr, 0, sizeof(*cm_fr));
    return !output_point_to_xy(cv_pub_x, cv_pub_y, pub->cv) ||
           !output_point_to_xy(epk_pub_x, epk_pub_y, pub->epk) ||
           !fr_from_bytes(cm_fr, pub->cm);
}

/* Booleanize value and rcv, enforce cv, and append the value bits. */
static size_t output_synthesize_value_commitment(struct constraint_system *cs,
                                                 size_t *note_contents,
                                                 size_t nc_idx,
                                                 const struct sapling_output_witness *wit,
                                                 size_t in_cv_x, size_t in_cv_y)
{
    /* 1a. Booleanize value (64 bits) */
    struct fr value_fr;
    {
        uint8_t vbytes[32] = {0};
        for (int i = 0; i < 8; i++)
            vbytes[i] = (uint8_t)(wit->value >> (i * 8));
        bytes_to_fr(&value_fr, vbytes);
    }
    size_t value_bits[64];
    output_boolean_vec_le(cs, value_bits, 64, &value_fr);

    /* Store value bits into note_contents */
    for (size_t i = 0; i < 64; i++)
        note_contents[nc_idx++] = value_bits[i];

    /* 1b. fixed_base_mul(G_v, value_bits) → value_point */
    struct fr gv_x, gv_y;
    {
        sapling_value_commit_value_generator(&gv_x, &gv_y);
    }
    size_t val_pt_x, val_pt_y;
    gadget_fixed_base_mul(cs, value_bits, 64, &gv_x, &gv_y,
                           &val_pt_x, &val_pt_y);

    /* 1c. Booleanize rcv (252 bits — Fs::CAPACITY) */
    struct fr rcv_fr;
    bytes_to_fr(&rcv_fr, wit->rcv);
    size_t rcv_bits[252];
    output_boolean_vec_le(cs, rcv_bits, 252, &rcv_fr);

    /* 1d. fixed_base_mul(G_rcv, rcv_bits) → rcv_point */
    struct fr grcv_x, grcv_y;
    {
        sapling_value_commit_randomness_generator(&grcv_x, &grcv_y);
    }
    size_t rcv_pt_x, rcv_pt_y;
    gadget_fixed_base_mul(cs, rcv_bits, 252, &grcv_x, &grcv_y,
                           &rcv_pt_x, &rcv_pt_y);

    /* 1e. cv = value_point + rcv_point */
    size_t cv_x, cv_y;
    gadget_edwards_add(cs, val_pt_x, val_pt_y, rcv_pt_x, rcv_pt_y,
                        &cv_x, &cv_y);

    /* 1f. Inputize cv (public inputs 1,2: cv.x, cv.y) */
    output_enforce_equal(cs, cv_x, in_cv_x);
    output_enforce_equal(cs, cv_y, in_cv_y);
    return nc_idx;
}

/* Append pk_d as 255 y-coordinate bits plus the x sign bit. */
static size_t output_synthesize_pkd_repr(struct constraint_system *cs,
                                         size_t *note_contents,
                                         size_t nc_idx,
                                         const struct sapling_output_witness *wit)
{
    /* pk_d is witnessable as any 256 bits (no constraints).
     * Representation: y_bits(255) + x_sign_bit(1) */
    struct jub_point pkd_point;
    jub_from_bytes(&pkd_point, wit->pk_d);
    struct fr pkd_x_val, pkd_y_val;
    jub_get_x(&pkd_x_val, &pkd_point);
    jub_get_y(&pkd_y_val, &pkd_point);

    /* field_into_boolean_vec_le emits Fr::NUM_BITS == 255 bits and no
     * packing constraint. pk_d is intentionally not checked on-curve. */
    size_t pkd_y_bits[255];
    output_boolean_vec_le(cs, pkd_y_bits, 255, &pkd_y_val);

    /* Get x sign bit */
    uint8_t pkd_x_bytes[32];
    fr_to_bytes(pkd_x_bytes, &pkd_x_val);
    bool x_is_odd = pkd_x_bytes[0] & 1;
    size_t pkd_x_sign = gadget_alloc_boolean(cs, x_is_odd);

    /* repr = y_bits(first 255) + x_sign_bit */
    for (size_t i = 0; i < 255; i++)
        note_contents[nc_idx++] = pkd_y_bits[i];
    note_contents[nc_idx++] = pkd_x_sign;
    return nc_idx;
}

/* True when inputs, aux, or constraints differ from 5, 7821, and 7827. */
static bool output_production_shape_mismatch(const struct constraint_system *cs)
{
    return cs->num_inputs != 5 || cs->num_constraints != 7827 ||
           cs->num_vars - cs->num_inputs - 1 != 7821;
}

/* ── Output Circuit Synthesis ───────────────────────────────────── */

/* C23 port of sapling-crypto Output::synthesize at the pinned parameter commit.
 * Allocation order and A/B/C orientation are trusted-setup inputs, not merely
 * implementation details. The production shape is 5 public inputs, 7821 aux
 * variables, and 7827 constraints.
 *
 * Steps:
 *   1. expose_value_commitment: value_bits→fixed_base_mul(G_v) +
 *      rcv_bits→fixed_base_mul(G_rcv) + add → inputize cv
 *   2. witness g_d + on_curve + not_small_order + repr (256 bits)
 *   3. esk_bits → g_d.mul(esk) → inputize epk
 *   4. pk_d witness: y_bits(255) + x_sign_bit(1) = 256 bits
 *   5. pedersen_hash(NoteCommitment, value_bits||g_d_repr||pk_d_repr)
 *   6. rcm_bits→fixed_base_mul(G_rcm) + add → cm.x inputize */

bool sapling_output_synthesize(struct constraint_system *cs,
                                const struct sapling_output_witness *wit,
                                const struct sapling_output_inputs *pub)
{
    if (!cs || !wit || !pub)
        LOG_FAIL("sapling_circuit", "output_synthesize: NULL argument");

    /* Bellman has a separate input namespace. Allocate all five inputs first
     * so our unified variable vector has ONE, inputs, then auxiliaries. */
    struct fr cv_pub_x, cv_pub_y, epk_pub_x, epk_pub_y, cm_fr;
    if (output_public_fields_malformed(&cv_pub_x, &cv_pub_y,
                                      &epk_pub_x, &epk_pub_y, &cm_fr, pub))
        LOG_FAIL("sapling_circuit",
                 "output_synthesize: malformed public input encoding");
    size_t in_cv_x = cs_alloc_input(cs, &cv_pub_x);
    size_t in_cv_y = cs_alloc_input(cs, &cv_pub_y);
    size_t in_epk_x = cs_alloc_input(cs, &epk_pub_x);
    size_t in_epk_y = cs_alloc_input(cs, &epk_pub_y);
    size_t in_cm = cs_alloc_input(cs, &cm_fr);

    /* note_contents accumulates boolean variable indices:
     * value(64) + g_d_repr(256) + pk_d_repr(256) = 576 bits */
    size_t *note_contents = zcl_malloc(576 * sizeof(size_t), "note_contents");
    if (!note_contents)
        LOG_FAIL("sapling_circuit",
                 "note_contents: zcl_malloc(%zu) failed", 576 * sizeof(size_t));
    size_t nc_idx = 0;

    /* ════════════════════════════════════════════════════════
     * Step 1: Value Commitment — expose_value_commitment()
     * ════════════════════════════════════════════════════════ */

    nc_idx = output_synthesize_value_commitment(cs, note_contents, nc_idx,
                                               wit, in_cv_x, in_cv_y);

    /* ════════════════════════════════════════════════════════
     * Step 2: Witness g_d, verify not small order, compute repr
     * ════════════════════════════════════════════════════════ */

    /* Compute g_d from diversifier outside circuit */
    struct jub_point gd_point;
    if (!sapling_diversifier_to_gd(&gd_point, wit->diversifier)) {
        memory_cleanse(note_contents, 576 * sizeof(size_t));
        free(note_contents);
        LOG_FAIL("sapling_circuit",
                 "output_synthesize: diversifier has no g_d point");
    }
    struct fr gd_x_val, gd_y_val;
    jub_get_x(&gd_x_val, &gd_point);
    jub_get_y(&gd_y_val, &gd_point);

    /* Witness g_d as (x, y) with on-curve check */
    size_t gd_x = cs_alloc_aux(cs, &gd_x_val);
    size_t gd_y = cs_alloc_aux(cs, &gd_y_val);
    gadget_point_interpret(cs, gd_x, gd_y);

    /* Assert g_d is not small order */
    gadget_assert_not_small_order(cs, gd_x, gd_y);

    /* repr() uses strict field decompositions for both coordinates. */
    size_t gd_repr[256];
    gadget_point_repr(cs, gd_x, gd_y, gd_repr);
    memcpy(&note_contents[nc_idx], gd_repr, sizeof(gd_repr));
    nc_idx += 256;

    /* ════════════════════════════════════════════════════════
     * Step 3: epk = esk * g_d → inputize
     * ════════════════════════════════════════════════════════ */

    /* Booleanize esk (252 bits) */
    struct fr esk_fr;
    bytes_to_fr(&esk_fr, wit->esk);
    size_t esk_bits[252];
    output_boolean_vec_le(cs, esk_bits, 252, &esk_fr);

    /* Variable-base scalar mul: epk = g_d * esk */
    size_t epk_x, epk_y;
    gadget_variable_base_mul(cs, gd_x, gd_y, esk_bits, 252,
                              &epk_x, &epk_y);

    /* Inputize epk (public inputs 3,4: epk.x, epk.y) */
    output_enforce_equal(cs, epk_x, in_epk_x);
    output_enforce_equal(cs, epk_y, in_epk_y);

    /* ════════════════════════════════════════════════════════
     * Step 4: pk_d witness — 256 bits for note contents
     * ════════════════════════════════════════════════════════ */

    nc_idx = output_synthesize_pkd_repr(cs, note_contents, nc_idx, wit);

    /* ════════════════════════════════════════════════════════
     * Step 5: Note commitment via Pedersen hash
     * ════════════════════════════════════════════════════════ */

    /* note_contents should now have 64+256+256 = 576 bits */
    size_t cm_hash_x, cm_hash_y;
    bool note_pers[PEDERSEN_PERSONALIZATION_BITS];
    gadget_pedersen_personalization_note_commitment(note_pers);
    gadget_pedersen_hash_pers(cs, note_pers, note_contents, 576,
                              &cm_hash_x, &cm_hash_y);
    if (cm_hash_x >= cs->num_vars || cm_hash_y >= cs->num_vars) {
        memory_cleanse(note_contents, 576 * sizeof(size_t));
        free(note_contents);
        LOG_FAIL("sapling_circuit",
                 "output_synthesize: note Pedersen hash failed");
    }

    /* ════════════════════════════════════════════════════════
     * Step 6: Randomize note commitment: cm = hash + rcm*G_rcm
     * ════════════════════════════════════════════════════════ */

    /* Booleanize rcm (252 bits) */
    struct fr rcm_fr;
    bytes_to_fr(&rcm_fr, wit->rcm);
    size_t rcm_bits[252];
    output_boolean_vec_le(cs, rcm_bits, 252, &rcm_fr);

    /* fixed_base_mul(G_rcm, rcm_bits) */
    struct fr grcm_x, grcm_y;
    {
        sapling_note_commit_randomness_generator(&grcm_x, &grcm_y);
    }
    size_t rcm_pt_x, rcm_pt_y;
    gadget_fixed_base_mul(cs, rcm_bits, 252, &grcm_x, &grcm_y,
                           &rcm_pt_x, &rcm_pt_y);

    /* cm = hash_point + rcm_point */
    size_t cm_x, cm_y;
    gadget_edwards_add(cs, cm_hash_x, cm_hash_y, rcm_pt_x, rcm_pt_y,
                        &cm_x, &cm_y);

    /* Inputize cm.x only (public input 5) */
    output_enforce_equal(cs, cm_x, in_cm);

    /* note_contents holds the boolean-variable layout of the secret note
     * (value/g_d/pk_d bit witnesses) — wipe before free; it is fully
     * consumed by gadget_pedersen_hash above (output-neutral). */
    memory_cleanse(note_contents, 576 * sizeof(size_t));
    free(note_contents);

    if (output_production_shape_mismatch(cs))
        LOG_FAIL("sapling_circuit",
                 "output_synthesize: production shape mismatch "
                 "(inputs=%zu aux=%zu constraints=%zu)",
                 cs->num_inputs, cs->num_vars - cs->num_inputs - 1,
                 cs->num_constraints);

    size_t bad = SIZE_MAX;
    if (!cs_is_satisfied(cs, &bad))
        LOG_FAIL("sapling_circuit",
                 "output_synthesize: honest witness is unsatisfied at %zu", bad);
    return true;
}

/* ── Full Proof Generation ──────────────────────────────────────── */

/* Serialize a Groth16 proof to 192 bytes (compressed):
 * A (G1 compressed, 48 bytes) + B (G2 compressed, 96 bytes) + C (G1 compressed, 48 bytes)
 *
 * Note: Zcash uses a specific serialization where:
 * A = 32 bytes (BLS12-381 G1 compressed)
 * B = 64 bytes (BLS12-381 G2 compressed)
 * C = 32 bytes (BLS12-381 G1 compressed)
 * But the standard format uses 48+96+48 = 192 bytes. */

static bool serialize_proof(uint8_t out[192], const struct groth16_proof *proof)
{
    /* BLS12-381 compressed point format:
     * bit 7 (0x80) = compressed flag (always set)
     * bit 6 (0x40) = infinity flag
     * bit 5 (0x20) = y-coordinate sign (set if y is lexicographically largest) */

    /* G1 point A (48 bytes compressed) */
    struct fp ax, ay;
    g1_to_affine(&ax, &ay, &proof->a);
    fp_to_bytes(out, &ax);
    out[0] &= 0x1F;
    out[0] |= 0x80;
    if (fp_lexicographically_largest(&ay))
        out[0] |= 0x20;

    /* G2 point B (96 bytes compressed: c1 || c0) */
    struct fp2 bx, by;
    g2_to_affine(&bx, &by, &proof->b);
    fp_to_bytes(out + 48, &bx.c1);
    fp_to_bytes(out + 48 + 48, &bx.c0);
    out[48] &= 0x1F;
    out[48] |= 0x80;
    if (fp2_lexicographically_largest(&by))
        out[48] |= 0x20;

    /* G1 point C (48 bytes compressed) */
    struct fp cx, cy;
    g1_to_affine(&cx, &cy, &proof->c);
    fp_to_bytes(out + 144, &cx);
    out[144] &= 0x1F;
    out[144] |= 0x80;
    if (fp_lexicographically_largest(&cy))
        out[144] |= 0x20;

    return true;
}

bool sapling_create_spend_proof(const uint8_t *pk_data, size_t pk_len,
                                 const struct sapling_spend_witness *wit,
                                 const struct sapling_spend_inputs *pub,
                                 uint8_t proof_out[192])
{
    /* Load proving key */
    struct groth16_pk pk;
    if (!groth16_pk_read(&pk, pk_data, pk_len))
        LOG_FAIL("sapling_circuit",
                 "create_spend_proof: groth16_pk_read failed (pk_len=%zu)", pk_len);

    /* Synthesize circuit */
    struct constraint_system cs;
    cs_init(&cs);

    if (!sapling_spend_synthesize(&cs, wit, pub)) {
        if (cs.witness)
            memory_cleanse(cs.witness, cs.cap_vars * sizeof(struct fr));
        cs_free(&cs);
        groth16_pk_free(&pk);
        LOG_FAIL("sapling_circuit",
                 "create_spend_proof: sapling_spend_synthesize failed");
    }

    /* Generate proof */
    struct groth16_proof proof;
    if (!groth16_prove(&pk, &cs, &proof)) {
        if (cs.witness)
            memory_cleanse(cs.witness, cs.cap_vars * sizeof(struct fr));
        cs_free(&cs);
        groth16_pk_free(&pk);
        LOG_FAIL("sapling_circuit",
                 "create_spend_proof: groth16_prove failed");
    }

    /* Serialize */
    serialize_proof(proof_out, &proof);

    /* The constraint witness vector holds the secret spend assignments
     * (ar, nsk, value, rcm, rcv, auth path). The proof is now produced;
     * wipe the witness scalars before freeing (output-neutral). */
    if (cs.witness)
        memory_cleanse(cs.witness, cs.cap_vars * sizeof(struct fr));
    cs_free(&cs);
    groth16_pk_free(&pk);
    return true;
}

bool sapling_create_output_proof(const uint8_t *pk_data, size_t pk_len,
                                  const struct sapling_output_witness *wit,
                                  const struct sapling_output_inputs *pub,
                                  uint8_t proof_out[192])
{
    struct groth16_pk pk;
    if (!groth16_pk_read(&pk, pk_data, pk_len))
        LOG_FAIL("sapling_circuit",
                 "create_output_proof: groth16_pk_read failed (pk_len=%zu)", pk_len);

    struct constraint_system cs;
    cs_init(&cs);

    if (!sapling_output_synthesize(&cs, wit, pub)) {
        if (cs.witness)
            memory_cleanse(cs.witness, cs.cap_vars * sizeof(struct fr));
        cs_free(&cs);
        groth16_pk_free(&pk);
        LOG_FAIL("sapling_circuit",
                 "create_output_proof: sapling_output_synthesize failed");
    }

    struct groth16_proof proof;
    if (!groth16_prove(&pk, &cs, &proof)) {
        if (cs.witness)
            memory_cleanse(cs.witness, cs.cap_vars * sizeof(struct fr));
        cs_free(&cs);
        groth16_pk_free(&pk);
        LOG_FAIL("sapling_circuit",
                 "create_output_proof: groth16_prove failed");
    }

    serialize_proof(proof_out, &proof);

    /* The constraint witness vector holds the secret output assignments
     * (value, rcv, esk, rcm). The proof is now produced; wipe the witness
     * scalars before freeing (output-neutral). */
    if (cs.witness)
        memory_cleanse(cs.witness, cs.cap_vars * sizeof(struct fr));
    cs_free(&cs);
    groth16_pk_free(&pk);
    return true;
}
