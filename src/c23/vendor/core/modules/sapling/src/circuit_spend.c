/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ported from librustzcash / bellman / sapling-crypto
 * (The Zcash developers / Electric Coin Company), pinned commit
 * 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5, MIT / Apache-2.0. Reimplemented in
 * C23; no reference code is linked into the production binary.
 *
 * Sapling SPEND circuit synthesis — the C23 port of bellman's
 * Spend::synthesize (librustzcash 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5),
 * 7 public inputs / 98777 constraints when complete.
 *
 * PORT STATUS. All 28 sections are ported in the exact synthesis order
 * (variable-allocation order is load-bearing for QAP alignment against the
 * trusted-setup proving key): 98777 constraints, 7 public inputs, 98638 aux —
 * and that aux count is the official sapling-spend.params `l_len`, which is an
 * external check the circuit cannot fake. Every emitted constraint is satisfied
 * by the honest witness (A*B==C), sections 8/9/15/16 reproduce librustzcash's
 * compressed point encodings bit for bit, section 10's 256 digest bits
 * reproduce CRH^ivk, section 13's pk_d wire equals the out-of-circuit [ivk]
 * g_d, section 20's cm wire equals sapling_compute_cm(), and section 21's
 * anchor wire equals an out-of-circuit fold of the same witnessed path.
 * Sections 1..21 additionally match the reference R1CS transcript's per-section
 * A/B/C matrix hashes byte for byte (test_groth16_r1cs_oracle); 22..28 carry
 * native regression pins there, not reference-derived goldens.
 *
 * NOT YET PROVEN: a native proof accepted by the official verifying key. The
 * prover, not the circuit, is the open work — see test_native_spend_proof.
 *
 * Section 21 — the 32-level Merkle authentication path, 44224 constraints and
 * the largest section in the circuit — lives in sapling/circuit_merkle.h. Its
 * cost, its anchor value against an out-of-circuit fold, its swap sensitivity
 * and its wire boundness are gated by tests/harness/src/groth16_merkle_path.c. It
 * consumes section 20's cm.x directly, so the note commitment now flows into
 * the tree fold in ONE synthesis pass rather than the two isolated proofs the
 * sections had while 17..20 were unported.
 *
 * Section 10 was the architectural fork, and it is resolved rather than worked
 * around: blake2s is built on bellman's Boolean/UInt32/multieq stack, where a
 * circuit bit is `Constant(bool) | Is(AllocatedBit) | Not(AllocatedBit)` so
 * that constant folding and negation cost ZERO constraints. `circuit_gadgets.h`
 * represents every wire as a bare variable index and can express neither, so
 * that stack lives in its own module — `sapling/circuit_bits.h` — and section 10
 * lands on 21006 exactly. Section 27 (nf) is the same gadget over the 256-bit
 * nf preimage and reuses it unchanged; section 13 consumes the Boolean digest
 * directly through gadget_variable_base_mul_cbits, which is why the scalar
 * multiplication had to become Boolean-driven rather than wire-driven.
 *
 * The seven public inputs are allocated up front (indices 1..7) in bellman's
 * input order (rk.x, rk.y, cv.x, cv.y, anchor, nf[0], nf[1]). Under this
 * constraint system's shared variable counter, allocating all inputs first is
 * what places them at the low indices bellman reserves for its separate input
 * namespace, so this is the QAP-faithful placement — inline inputize() would
 * scatter inputs among aux and permanently misalign the QAP. Wires computed
 * later are bound to their input slot by a copy constraint (see rk and cv);
 * the anchor is bound in section 23 and the packed nullifier in section 28. */

#include "sapling/sapling_circuit.h"
#include "sapling/sapling_prover.h"
#include "sapling/circuit_bits.h"
#include "sapling/circuit_gadgets.h"
#include "sapling/circuit_merkle.h"
#include "sapling/pedersen_hash.h"
#include "sapling/sapling.h"
#include "base/serialize_le.h"
#include "support/cleanse.h"
#include <string.h>
#include "util/log_macros.h"

/* Index of the constant-ONE variable in every constraint system. */
#define CS_ONE 0

/* Note contents fed to the section-17 Pedersen hash: value(64) || repr(g_d)(256)
 * || repr(pk_d)(256), in bellman's order. */
#define SPEND_NOTE_VALUE_BITS   64u
#define SPEND_NOTE_CONTENT_BITS 576u

/* ── Shared section primitives ──────────────────────────────────── */

/* Jubjub point from a compressed encoding, as (x, y) Fr coordinates. */
static bool point_to_xy(struct fr *x, struct fr *y, const uint8_t compressed[32])
{
    struct jub_point p;
    if (!jub_from_bytes(&p, compressed))
        LOG_FAIL("circuit_spend",
                 "point_to_xy: jub_from_bytes failed on compressed input");
    jub_get_x(x, &p);
    jub_get_y(y, &p);
    return true;
}

/* bellman boolean::field_into_boolean_vec_le / u64_into_boolean_vec_le — the
 * boolean-only little-endian decomposition. n_bits boolean aux + n_bits
 * booleanity constraints, and NO packing constraint back to a field element:
 * every caller here (ar, nsk, value, rcv) consumes the scalar only as bits, fed
 * to a fixed-base multiplication. Sections 2, 6 and 14 all use this one body. */
static void boolean_vec_le(struct constraint_system *cs,
                           size_t *bits_out, size_t n_bits,
                           const struct fr *value)
{
    uint8_t bytes[32];
    fr_to_bytes(bytes, value);
    for (size_t i = 0; i < n_bits; i++) {
        size_t byte_idx = i / 8, bit_idx = i % 8;
        bool bit = byte_idx < 32 && ((bytes[byte_idx] >> bit_idx) & 1);
        bits_out[i] = gadget_alloc_boolean(cs, bit);
    }
    memory_cleanse(bytes, sizeof(bytes));
}

/* Copy constraint binding a computed wire to a pre-allocated public-input slot
 * — bellman AllocatedNum::inputize's equality enforcement. One constraint.
 *
 * WHICH SIDE IS WHICH MATTERS. bellman emits
 *
 *     cs.enforce(|lc| lc + input, |lc| lc + CS::one(), |lc| lc + self.variable)
 *
 * i.e. A = the INPUT variable, B = ONE, C = the COMPUTED wire. Emitting the
 * mirror image (`computed * 1 = input`) satisfies exactly the same A*B==C check
 * on exactly the same witness, but it moves a coefficient between the A and C
 * matrices. Groth16's proving key is built per variable from which matrix its
 * coefficients sit in, so the mirrored form is a DIFFERENT QAP and cannot
 * verify against the Sapling trusted setup. Pinned by
 * test_groth16_r1cs_oracle, which diffs the A/B/C matrices row by row against
 * the reference transcript; cs_is_satisfied() is blind to it by construction. */
static void enforce_equal(struct constraint_system *cs,
                          size_t computed, size_t input_slot)
{
    struct linear_combination la, lb, lc;
    struct fr one_val;
    fr_one(&one_val);
    lc_init(&la); lc_add_term(&la, input_slot, &one_val);
    lc_init(&lb); lc_add_term(&lb, CS_ONE, &one_val);
    lc_init(&lc); lc_add_term(&lc, computed, &one_val);
    cs_enforce(cs, &la, &lb, &lc);
    lc_free(&la); lc_free(&lb); lc_free(&lc);
}

/* Record a per-section shape checkpoint (no-op when sections==NULL). */
static void section_record(struct constraint_system *cs,
                           struct spend_section_shape *sections,
                           size_t max_sections, size_t *n, const char *name)
{
    if (!sections || *n >= max_sections)
        return;
    sections[*n].name = name;
    sections[*n].num_constraints = cs->num_constraints;
    sections[*n].num_vars = cs->num_vars;
    sections[*n].num_inputs = cs->num_inputs;
    (*n)++;
}

/* bellman ecc::EdwardsPoint::witness — allocate (x, y) then check the point is
 * on the curve. 4 constraints. Shared by sections 1 (ak) and 11 (g_d). */
static void witness_point(struct constraint_system *cs,
                          const struct fr *x, const struct fr *y,
                          size_t *x_var, size_t *y_var)
{
    *x_var = cs_alloc_aux(cs, x);
    *y_var = cs_alloc_aux(cs, y);
    gadget_point_interpret(cs, *x_var, *y_var);
}

/* bellman ecc::EdwardsPoint::repr — 256 little-endian bits (y's 255 bits then
 * x's sign bit), which for Jubjub ARE the bits of the point's 32-byte
 * compressed encoding. 776 constraints.
 *
 * This is the ONE body behind all four "representation of <point>" sections —
 * 8 (ak), 9 (nk), 15 (g_d), 16 (pk_d). They differ only in where the bits land
 * and which probe slot publishes the wire indices, so they share this, not four
 * copies of it. `probe_dst` may be NULL. */
static void section_point_repr(struct constraint_system *cs,
                               size_t x_var, size_t y_var,
                               size_t dst[256], size_t *probe_dst)
{
    gadget_point_repr(cs, x_var, y_var, dst);
    if (probe_dst)
        memcpy(probe_dst, dst, 256 * sizeof(*dst));
}

/* ── Section 14: expose_value_commitment ────────────────────────── */

/* bellman's `expose_value_commitment`: booleanize value and rcv, multiply the
 * two value-commitment generators, add, and bind the result to the circuit's
 * cv public-input slots. Returns the 64 value bits (they open the note in
 * section 17 and gate the dummy-input check in section 22).
 *
 * 1265 constraints: 64 value bits + 191 [value]G_v + 252 rcv bits
 * + 750 [rcv]G_rcv + 6 add + 2 inputize. The 191 is not a typo for the 192 a
 * naive 22-window count suggests: 64 is not a multiple of 3, so the last window
 * carries two CONSTANT false bits and bellman's `Boolean::and` folds them away
 * for free, leaving that window at 2 constraints instead of 3.
 *
 * The generators MUST be the find_group_hash-derived ones (see
 * sapling_value_commit_value_generator) — the same points sapling_value_commit
 * uses out of circuit. With any other pair the circuit's cv is a different
 * point and the copy constraint against the public input is unsatisfiable. */
static bool expose_value_commitment(struct constraint_system *cs,
                                    uint64_t value, const uint8_t rcv[32],
                                    size_t in_cv_x, size_t in_cv_y,
                                    size_t value_bits_out[64],
                                    size_t *cv_x_out, size_t *cv_y_out)
{
    struct fr value_fr;
    {
        uint8_t vbytes[32] = {0};
        zcl_write_u64_le(vbytes, value);
        fr_from_bytes(&value_fr, vbytes);
    }
    boolean_vec_le(cs, value_bits_out, SPEND_NOTE_VALUE_BITS, &value_fr);

    struct fr gv_x, gv_y;
    sapling_value_commit_value_generator(&gv_x, &gv_y);
    size_t val_pt_x, val_pt_y;
    gadget_fixed_base_mul(cs, value_bits_out, SPEND_NOTE_VALUE_BITS,
                          &gv_x, &gv_y, &val_pt_x, &val_pt_y);

    struct fr rcv_fr;
    fr_from_bytes(&rcv_fr, rcv);
    size_t rcv_bits[252];
    boolean_vec_le(cs, rcv_bits, 252, &rcv_fr);
    memory_cleanse(&rcv_fr, sizeof(rcv_fr));

    struct fr grcv_x, grcv_y;
    sapling_value_commit_randomness_generator(&grcv_x, &grcv_y);
    size_t rcv_pt_x, rcv_pt_y;
    gadget_fixed_base_mul(cs, rcv_bits, 252, &grcv_x, &grcv_y,
                          &rcv_pt_x, &rcv_pt_y);

    size_t cv_x, cv_y;
    gadget_edwards_add(cs, val_pt_x, val_pt_y, rcv_pt_x, rcv_pt_y,
                       &cv_x, &cv_y);
    if (cv_x >= cs->num_vars || cv_y >= cs->num_vars)
        LOG_FAIL("circuit_spend",
                 "expose_value_commitment: cv wires out of range "
                 "(x=%zu y=%zu num_vars=%zu)", cv_x, cv_y, cs->num_vars);

    /* cv.inputize() — bind to the pre-allocated public-input slots. */
    enforce_equal(cs, cv_x, in_cv_x);
    enforce_equal(cs, cv_y, in_cv_y);

    *cv_x_out = cv_x;
    *cv_y_out = cv_y;
    return true;
}

/* ── Spend Circuit Synthesis ────────────────────────────────────── */

static void probe_reset(struct spend_wire_probe *probe)
{
    if (!probe)
        return;
    probe->ak_x = probe->ak_y = SIZE_MAX;
    probe->rk_x = probe->rk_y = SIZE_MAX;
    probe->nk_x = probe->nk_y = SIZE_MAX;
    probe->gd_x = probe->gd_y = SIZE_MAX;
    probe->pkd_x = probe->pkd_y = SIZE_MAX;
    probe->cv_x = probe->cv_y = SIZE_MAX;
    probe->note_hash_x = probe->note_hash_y = SIZE_MAX;
    probe->cm_x = probe->cm_y = SIZE_MAX;
    probe->anchor = SIZE_MAX;
    for (size_t i = 0; i < 256; i++) {
        probe->ak_repr[i] = probe->nk_repr[i] = SIZE_MAX;
        probe->gd_repr[i] = probe->pkd_repr[i] = SIZE_MAX;
        probe->ivk_bit[i] = SIZE_MAX;
        probe->ivk_bit_negated[i] = false;
    }
    for (size_t i = 0; i < SPEND_NOTE_VALUE_BITS; i++)
        probe->value_bit[i] = SIZE_MAX;
}

/* State threaded through the spend-circuit synthesis steps. The steps run in
 * the fixed order of spend_steps[]; each reads and writes only the fields the
 * section comments name, so the allocation order of variables and constraints
 * is exactly the section order of the circuit. */
struct spend_synth {
    struct constraint_system *cs;
    const struct sapling_spend_witness *wit;
    const struct sapling_spend_inputs *pub;
    struct spend_section_shape *sections;
    size_t max_sections;
    size_t nsec;
    struct spend_wire_probe *probe;

    struct fr anchor_fr;
    struct fr nf0, nf1;
    size_t in_rk_x, in_rk_y, in_cv_x, in_cv_y, in_anchor, in_nf0, in_nf1;

    size_t ak_x_var, ak_y_var;
    size_t nk_var_x, nk_var_y;
    size_t ivk_preimage[512];
    size_t nf_preimage[256];
    size_t nf_pre_bits[512];
    struct cbit ivk_bits[256];
    size_t gd_x_var, gd_y_var;
    size_t pkd_x_var, pkd_y_var;
    size_t note_contents[SPEND_NOTE_CONTENT_BITS];
    size_t note_hash_x, note_hash_y;
    size_t cm_x_var, cm_y_var;
    size_t anchor_var;
    size_t position_bits[SAPLING_MERKLE_DEPTH];
    size_t rt_var;
    size_t pos_pt_x, pos_pt_y;
    size_t rho_x, rho_y;
    struct cbit nf_bits[256];
};

static void spend_record(struct spend_synth *s, const char *name)
{
    section_record(s->cs, s->sections, s->max_sections, &s->nsec, name);
}

static bool spend_pack_nullifier(struct spend_synth *s)
{
    /* The nullifier's two packed scalars. multipack_bytes_to_fr writes PLAIN
     * integer limbs — the representation the VERIFIER wants (sapling.c pairs it
     * with jub_to_affine_raw/bytes_le_to_fr_raw for exactly that reason) —
     * whereas `struct fr` is Montgomery form. So the limbs are serialized back
     * to little-endian bytes and converted, the same way anchor above goes
     * through fr_from_bytes. A straight memcpy into fr.d stores value * R^-1:
     * for a packed scalar of 1 the witness would hold R^-1 mod r instead of 1.
     * Nothing reads these slots until section 28 binds nf to them, and
     * cs_is_satisfied() cannot see it either, so the mistake would have
     * surfaced later as an apparent nullifier-PACKING bug — far from its cause.
     * Each packed scalar is at most CBIT_FR_CAPACITY = 254 bits, so it is
     * always canonical and fr_from_bytes cannot reject it. */
    uint64_t nf_packed[2][4];
    size_t nf_count = 0;
    multipack_bytes_to_fr(nf_packed, &nf_count, s->pub->nullifier, 32);
    fr_zero(&s->nf0);
    fr_zero(&s->nf1);
    for (size_t k = 0; k < 2 && k < nf_count; k++) {
        uint8_t le[32];
        for (size_t limb = 0; limb < 4; limb++)
            zcl_write_u64_le(le + limb * 8, nf_packed[k][limb]);
        if (!fr_from_bytes(k == 0 ? &s->nf0 : &s->nf1, le)) {
            LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                         "spend: packed nullifier scalar %zu is not a canonical Fr "
                         "encoding (multipack emits <= 253 bits, so this cannot "
                         "happen without a multipack change)", k);
            return false;
        }
    }
    return true;
}

/* ── Public inputs 1..7 (allocated up front — see header note) ── */
static bool spend_step_inputs(struct spend_synth *s)
{
    struct constraint_system *cs = s->cs;
    struct fr rk_x, rk_y;
    if (!point_to_xy(&rk_x, &rk_y, s->pub->rk)) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: point_to_xy(rk) failed");
        return false;
    }
    struct fr cv_x, cv_y;
    if (!point_to_xy(&cv_x, &cv_y, s->pub->cv)) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: point_to_xy(cv) failed");
        return false;
    }
    fr_from_bytes(&s->anchor_fr, s->pub->anchor);

    if (!spend_pack_nullifier(s))
        return false;

    s->in_rk_x = cs_alloc_input(cs, &rk_x);  /* input 1: rk.x */
    s->in_rk_y = cs_alloc_input(cs, &rk_y);  /* input 2: rk.y */
    s->in_cv_x = cs_alloc_input(cs, &cv_x);  /* input 3: cv.x */
    s->in_cv_y = cs_alloc_input(cs, &cv_y);  /* input 4: cv.y */
    /* input 5: anchor (bound in section 23) */
    s->in_anchor = cs_alloc_input(cs, &s->anchor_fr);
    /* inputs 6, 7: the packed nullifier (bound in section 28) */
    s->in_nf0 = cs_alloc_input(cs, &s->nf0);
    s->in_nf1 = cs_alloc_input(cs, &s->nf1);
    return true;
}

/* Sections 1..5: ak, ar, rk. */
static bool spend_step_rk(struct spend_synth *s)
{
    struct constraint_system *cs = s->cs;
    struct spend_wire_probe *probe = s->probe;

    /* ════ Section 1: witness ak, on-curve + not-small-order (20) ════ */
    struct fr ak_x, ak_y;
    if (!point_to_xy(&ak_x, &ak_y, s->wit->ak)) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: point_to_xy(ak) failed");
        return false;
    }
    size_t ak_x_var, ak_y_var;
    witness_point(cs, &ak_x, &ak_y, &ak_x_var, &ak_y_var);  /* (4) */
    gadget_assert_not_small_order(cs, ak_x_var, ak_y_var);   /* (16) */
    if (probe) { probe->ak_x = ak_x_var; probe->ak_y = ak_y_var; }
    s->ak_x_var = ak_x_var;
    s->ak_y_var = ak_y_var;
    spend_record(s, "1:ak witness+on-curve+not-small-order");

    /* ════ Section 2: ar into 252 boolean bits (252) ════ */
    struct fr ar_fr;
    fr_from_bytes(&ar_fr, s->wit->ar);
    size_t ar_bits[252];
    boolean_vec_le(cs, ar_bits, 252, &ar_fr);
    memory_cleanse(&ar_fr, sizeof(ar_fr));
    spend_record(s, "2:ar bits");

    /* ════ Section 3: ar_g = [ar] SpendAuthGenerator (750) ════ */
    struct fr sag_x, sag_y;
    sapling_spend_auth_generator(&sag_x, &sag_y);
    size_t arg_x, arg_y;
    gadget_fixed_base_mul(cs, ar_bits, 252, &sag_x, &sag_y, &arg_x, &arg_y);
    spend_record(s, "3:randomization of signing key");

    /* ════ Section 4: rk = ak + ar_g (6) ════ */
    size_t rk_var_x, rk_var_y;
    gadget_edwards_add(cs, ak_x_var, ak_y_var, arg_x, arg_y,
                       &rk_var_x, &rk_var_y);
    if (probe) { probe->rk_x = rk_var_x; probe->rk_y = rk_var_y; }
    spend_record(s, "4:computation of rk");

    /* ════ Section 5: rk inputize — bind to input slots 1,2 (2) ════ */
    enforce_equal(cs, rk_var_x, s->in_rk_x);
    enforce_equal(cs, rk_var_y, s->in_rk_y);
    spend_record(s, "5:rk inputize");
    return true;
}

/* Sections 6..9: nsk, nk, and the representations of ak and nk. */
static bool spend_step_nk(struct spend_synth *s)
{
    struct constraint_system *cs = s->cs;
    struct spend_wire_probe *probe = s->probe;

    /* ════ Section 6: nsk into 252 boolean bits (252) ════ */
    struct fr nsk_fr;
    fr_from_bytes(&nsk_fr, s->wit->nsk);
    size_t nsk_bits[252];
    boolean_vec_le(cs, nsk_bits, 252, &nsk_fr);
    memory_cleanse(&nsk_fr, sizeof(nsk_fr));
    spend_record(s, "6:nsk bits");

    /* ════ Section 7: nk = [nsk] ProofGenerationKeyGenerator (750) ════ */
    struct fr pgg_x, pgg_y;
    sapling_proof_gen_key_generator(&pgg_x, &pgg_y);
    size_t nk_var_x, nk_var_y;
    gadget_fixed_base_mul(cs, nsk_bits, 252, &pgg_x, &pgg_y,
                          &nk_var_x, &nk_var_y);
    if (probe) { probe->nk_x = nk_var_x; probe->nk_y = nk_var_y; }
    s->nk_var_x = nk_var_x;
    s->nk_var_y = nk_var_y;
    spend_record(s, "7:computation of nk");

    /* ════ Section 8: representation of ak (776) ════
     * ivk_preimage starts with ak's 256-bit representation. */
    section_point_repr(cs, s->ak_x_var, s->ak_y_var, &s->ivk_preimage[0],
                       probe ? probe->ak_repr : NULL);
    spend_record(s, "8:representation of ak");

    /* ════ Section 9: representation of nk (776) ════
     * nk's 256-bit representation is used TWICE: it completes the 512-bit
     * ivk preimage and is the whole 256-bit nf preimage. One gadget, two
     * consumers — the bits are shared wires, not re-derived. */
    section_point_repr(cs, nk_var_x, nk_var_y, &s->ivk_preimage[256],
                       probe ? probe->nk_repr : NULL);
    memcpy(s->nf_preimage, &s->ivk_preimage[256], sizeof(s->nf_preimage));
    spend_record(s, "9:representation of nk");
    /* consumed by section 27, the twin blake2s */
    return true;
}

/* Section 10: computation of ivk. */
static bool spend_step_ivk(struct spend_synth *s)
{
    struct constraint_system *cs = s->cs;
    struct spend_wire_probe *probe = s->probe;

    /* ════ Section 10: computation of ivk (21006) ════
     * ivk = BLAKE2s-256("Zcashivk", repr(ak) || repr(nk)), in-circuit. The 512
     * preimage bits are the WIRES sections 8 and 9 produced — shared, never
     * re-derived — wrapped as bellman `Boolean::Is` views (they are already
     * boolean-constrained by gadget_point_repr, so wrapping costs nothing). */
    struct cbit ivk_pre[512];
    for (size_t i = 0; i < 512; i++)
        ivk_pre[i] = cbit_from_var(cs, s->ivk_preimage[i]);

    static const uint8_t CRH_IVK_PERSONALIZATION[8] =
        { 'Z', 'c', 'a', 's', 'h', 'i', 'v', 'k' };
    struct cbit *ivk_bits = s->ivk_bits;
    if (!gadget_blake2s(cs, ivk_pre, 512, CRH_IVK_PERSONALIZATION, ivk_bits)) {
        memory_cleanse(ivk_pre, sizeof(ivk_pre));
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: in-circuit blake2s(CRH^ivk) synthesis failed");
        return false;
    }
    if (probe) {
        for (size_t i = 0; i < 256; i++) {
            probe->ivk_bit[i] = (ivk_bits[i].kind == CBIT_CONSTANT)
                                ? SIZE_MAX : ivk_bits[i].var;
            probe->ivk_bit_negated[i] = (ivk_bits[i].kind == CBIT_NOT);
        }
    }
    /* bellman: `ivk.truncate(Fs::CAPACITY)` — drop the top 5 bits so the digest
     * is a valid Jubjub scalar. A Vec truncate: zero constraints, and the
     * dropped wires stay constrained inside blake2s. */
    memory_cleanse(ivk_pre, sizeof(ivk_pre));
    spend_record(s, "10:computation of ivk");
    return true;
}

/* Sections 11..13: g_d and pk_d. */
static bool spend_step_pkd(struct spend_synth *s)
{
    struct constraint_system *cs = s->cs;
    struct spend_wire_probe *probe = s->probe;

    /* ════ Section 11: witness g_d, on-curve (4) ════
     * g_d = GH("Zcash_gd", diversifier). bellman witnesses it rather than
     * deriving it in-circuit; the note commitment in section 17 is what binds
     * it to the diversifier the recipient published. */
    struct jub_point gd_pt;
    if (!sapling_diversifier_to_gd(&gd_pt, s->wit->diversifier)) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: diversifier does not hash to a Jubjub point "
                     "(g_d would be the identity) — section 11 cannot witness g_d");
        return false;
    }
    struct fr gd_x, gd_y;
    jub_get_x(&gd_x, &gd_pt);
    jub_get_y(&gd_y, &gd_pt);
    size_t gd_x_var, gd_y_var;
    witness_point(cs, &gd_x, &gd_y, &gd_x_var, &gd_y_var);
    if (probe) { probe->gd_x = gd_x_var; probe->gd_y = gd_y_var; }
    s->gd_x_var = gd_x_var;
    s->gd_y_var = gd_y_var;
    spend_record(s, "11:witness g_d");

    /* ════ Section 12: g_d not small order (16) ════
     * Redundant with the Output circuit's own check by construction, and
     * bellman keeps it anyway for defence in depth. Cheap, so do the same. */
    gadget_assert_not_small_order(cs, gd_x_var, gd_y_var);
    spend_record(s, "12:g_d not small order");

    /* ════ Section 13: pk_d = [ivk] g_d (3252) ════
     * The FIRST variable-base multiplication in the circuit — the base is a
     * pair of wires, not a constant, so the windowed fixed-base gadget does not
     * apply and this is plain double-and-add: 13*251 - 11 = 3252. The scalar is
     * section 10's Boolean digest truncated to Fs::CAPACITY bits, consumed as
     * Booleans (a `Not` view costs nothing to multiply by). */
    size_t pkd_x_var, pkd_y_var;
    gadget_variable_base_mul_cbits(cs, gd_x_var, gd_y_var, s->ivk_bits,
                                   SPEND_IVK_TRUNCATED_BITS,
                                   &pkd_x_var, &pkd_y_var);
    if (pkd_x_var == SIZE_MAX || pkd_y_var == SIZE_MAX) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: section 13 [ivk] g_d produced no point "
                     "(variable-base multiplication refused the scalar)");
        return false;
    }
    if (probe) { probe->pkd_x = pkd_x_var; probe->pkd_y = pkd_y_var; }
    s->pkd_x_var = pkd_x_var;
    s->pkd_y_var = pkd_y_var;
    spend_record(s, "13:compute pk_d");
    return true;
}

/* Sections 14..16: value commitment and the note's representations. */
static bool spend_step_note(struct spend_synth *s)
{
    struct constraint_system *cs = s->cs;
    struct spend_wire_probe *probe = s->probe;
    size_t *note_contents = s->note_contents;

    /* ════ Section 14: value commitment (1265) ════
     * Booleanize value + rcv, commit, and bind cv to public inputs 3 and 4.
     * This is the first section that CONSTRAINS a caller-supplied public input
     * other than rk: pass a cv that is not [value]G_v + [rcv]G_rcv and the
     * copy constraint makes the system unsatisfiable, by design. */
    size_t cv_var_x = SIZE_MAX, cv_var_y = SIZE_MAX;
    if (!expose_value_commitment(cs, s->wit->value, s->wit->rcv,
                                 s->in_cv_x, s->in_cv_y,
                                 &note_contents[0], &cv_var_x, &cv_var_y)) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: section 14 value commitment failed");
        return false;
    }
    if (probe) {
        probe->cv_x = cv_var_x;
        probe->cv_y = cv_var_y;
        memcpy(probe->value_bit, &note_contents[0],
               SPEND_NOTE_VALUE_BITS * sizeof(note_contents[0]));
    }
    spend_record(s, "14:value commitment");

    /* ════ Section 15: representation of g_d (776) ════ */
    section_point_repr(cs, s->gd_x_var, s->gd_y_var,
                       &note_contents[SPEND_NOTE_VALUE_BITS],
                       probe ? probe->gd_repr : NULL);
    spend_record(s, "15:representation of g_d");

    /* ════ Section 16: representation of pk_d (776) ════ */
    section_point_repr(cs, s->pkd_x_var, s->pkd_y_var,
                       &note_contents[SPEND_NOTE_VALUE_BITS + 256],
                       probe ? probe->pkd_repr : NULL);
    spend_record(s, "16:representation of pk_d");
    return true;
}

/* Sections 17..20: the note commitment. */
static bool spend_step_cm(struct spend_synth *s)
{
    struct constraint_system *cs = s->cs;
    struct spend_wire_probe *probe = s->probe;

    /* note_contents is now the complete 576-bit note: value || repr(g_d) ||
     * repr(pk_d). Sections 17..20 turn it into the note commitment. */

    /* ════ Section 17: note content hash (982) ════
     * PedersenHash(NoteCommitment, note_contents) — bellman's windowed Pedersen
     * hash over 6 constant personalization bits plus the 576 note wires, i.e.
     * 194 three-bit windows spread over 4 of the 6 Pedersen segments.
     * 982 = 386 window lookups + 570 in-segment Montgomery additions
     * + 8 Montgomery->Edwards conversions + 18 cross-segment Edwards additions.
     * The 386 is not 194*2: windows 0 and 1 are made entirely of the constant
     * personalization bits, so their AND(bit0, bit1) folds away for free.
     * The input wires are the SAME wires sections 14/15/16 produced — the note
     * is opened once, never re-derived. */
    bool note_pers[PEDERSEN_PERSONALIZATION_BITS];
    gadget_pedersen_personalization_note_commitment(note_pers);
    size_t note_hash_x, note_hash_y;
    gadget_pedersen_hash_pers(cs, note_pers, s->note_contents,
                              SPEND_NOTE_CONTENT_BITS,
                              &note_hash_x, &note_hash_y);
    if (note_hash_x >= cs->num_vars || note_hash_y >= cs->num_vars) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: section 17 note content hash produced no point "
                     "(x=%zu y=%zu num_vars=%zu)",
                     note_hash_x, note_hash_y, cs->num_vars);
        return false;
    }
    if (probe) { probe->note_hash_x = note_hash_x;
                 probe->note_hash_y = note_hash_y; }
    spend_record(s, "17:note content hash");

    /* ════ Section 18: rcm into 252 boolean bits (252) ════
     * The same boolean-only decomposition sections 2, 6 and 14 use — rcm is
     * consumed only as bits by the fixed-base multiplication below, so there is
     * no packing constraint back to a field element. */
    struct fr rcm_fr;
    fr_from_bytes(&rcm_fr, s->wit->rcm);
    size_t rcm_bits[252];
    boolean_vec_le(cs, rcm_bits, 252, &rcm_fr);
    memory_cleanse(&rcm_fr, sizeof(rcm_fr));
    spend_record(s, "18:rcm bits");

    /* ════ Section 19: [rcm] NoteCommitmentRandomness (750) ════
     * Identical shape to sections 3 and 7: 84 windows over 252 bits, so
     * 84*3 + 83*6 = 750. The generator MUST be the canonical
     * find_group_hash(b"r", "Zcash_PH") point sapling_compute_cm() uses out of
     * circuit, or the circuit commits to a different note than the wallet. */
    struct fr grcm_x, grcm_y;
    sapling_note_commit_randomness_generator(&grcm_x, &grcm_y);
    size_t rcm_pt_x, rcm_pt_y;
    gadget_fixed_base_mul(cs, rcm_bits, 252, &grcm_x, &grcm_y,
                          &rcm_pt_x, &rcm_pt_y);
    spend_record(s, "19:commitment randomness");

    /* ════ Section 20: cm = note_hash + [rcm] G_rcm (6) ════
     * One Edwards addition. A Pedersen hash is not itself a hiding commitment,
     * so this is the step that makes cm hide the note contents. */
    size_t cm_x_var, cm_y_var;
    gadget_edwards_add(cs, note_hash_x, note_hash_y, rcm_pt_x, rcm_pt_y,
                       &cm_x_var, &cm_y_var);
    if (cm_x_var >= cs->num_vars || cm_y_var >= cs->num_vars) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: section 20 cm wires out of range "
                     "(x=%zu y=%zu num_vars=%zu)", cm_x_var, cm_y_var,
                     cs->num_vars);
        return false;
    }
    if (probe) { probe->cm_x = cm_x_var; probe->cm_y = cm_y_var; }
    s->cm_x_var = cm_x_var;
    s->cm_y_var = cm_y_var;
    spend_record(s, "20:randomization of note commitment");
    return true;
}

/* Sections 21..23: the Merkle path and the conditional anchor. */
static bool spend_step_anchor(struct spend_synth *s)
{
    struct constraint_system *cs = s->cs;

    /* ════ Section 21: 32-level Merkle authentication path (44224) ════
     * The single largest section of the circuit — 45% of all 98777 constraints.
     * The whole body is gadget_merkle_auth_path (sapling/circuit_merkle.h): per
     * level a position bit, a witnessed sibling, bellman's conditionally_reverse,
     * two non-strict 255-bit decompositions and a Pedersen hash under
     * Personalization::MerkleTree(depth) — 1382 each, over 32 levels. Its cost,
     * its anchor value against an out-of-circuit fold, its swap sensitivity and
     * its wire boundness are gated by tests/harness/src/groth16_merkle_path.c.
     *
     * The leaf is section 20's cm.x — the note commitment, straight off the wire
     * that section computed. The reference takes only the x-coordinate here and
     * loses nothing by it: Jubjub's x determines the point up to sign and the
     * tree stores exactly this value (the protocol's `cmu`). */
    size_t anchor_var = SIZE_MAX;
    if (!gadget_merkle_auth_path(cs, s->cm_x_var, s->wit->auth_path,
                                 s->wit->auth_path_bits, &anchor_var,
                                 s->position_bits)) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: section 21 Merkle authentication path failed");
        return false;
    }
    if (s->probe)
        s->probe->anchor = anchor_var;
    s->anchor_var = anchor_var;
    spend_record(s, "21:merkle tree hash 0..31");

    /* ════ Section 22: conditionally enforce correct root (1) ════
     * bellman allocates a SECOND wire for the anchor — the "conditional
     * anchor" rt — and enforces
     *
     *     (cur - rt) * value = 0
     *
     * with EMPTY C. A zero-value note is therefore allowed to carry an anchor
     * unrelated to its fold, which is what makes dummy spend inputs possible;
     * any non-zero value forces cur == rt.
     *
     * `value` here is bellman's `value_num`, a `Num` — a linear combination of
     * the 64 value bits with coefficients 2^i, accumulated as the bits were
     * booleanized in section 14 and costing NO constraint of its own. It is a
     * B-matrix row of 64 terms, not a wire, so there is nothing to allocate.
     * Writing it as a packed wire instead would satisfy the same identity over
     * a different QAP. */
    size_t rt_var = cs_alloc_aux(cs, &s->anchor_fr);
    {
        struct linear_combination la, lb, lcc;
        struct fr one_val, neg_one, coeff;
        fr_one(&one_val);
        fr_neg(&neg_one, &one_val);
        lc_init(&la);
        lc_add_term(&la, anchor_var, &one_val);
        lc_add_term(&la, rt_var, &neg_one);
        lc_init(&lb);
        fr_one(&coeff);
        for (size_t i = 0; i < SPEND_NOTE_VALUE_BITS; i++) {
            lc_add_term(&lb, s->note_contents[i], &coeff);
            fr_add(&coeff, &coeff, &coeff);
        }
        lc_init(&lcc);
        cs_enforce(cs, &la, &lb, &lcc);
        lc_free(&la); lc_free(&lb); lc_free(&lcc);
    }
    s->rt_var = rt_var;
    spend_record(s, "22:conditionally enforce correct root");

    /* ════ Section 23: anchor inputize — bind rt to input slot 5 (1) ════
     * Note WHICH wire is exposed: the conditional anchor rt, not the folded
     * root. That is what lets a zero-value dummy input publish an anchor it
     * cannot prove a path to. */
    enforce_equal(cs, rt_var, s->in_anchor);
    spend_record(s, "23:anchor inputize");
    return true;
}

/* Sections 24..26: g^position, rho and its representation. */
static bool spend_step_rho(struct spend_synth *s)
{
    struct constraint_system *cs = s->cs;

    /* ════ Section 24: g^position (92) ════
     * The 32 position bits section 21 collected, least significant first,
     * against FixedGenerators::NullifierPosition. 32 is not a multiple of 3, so
     * the last of the 11 windows carries ONE constant-false pad bit; bellman
     * folds `Boolean::and` away for it, which drops that window's precomp wire
     * and its constraint. 10*3 + 2 lookups + 10*6 Edwards additions = 92 — the
     * whole circuit's total is 98777 rather than 98778 because of that one. */
    struct fr npg_x, npg_y;
    sapling_nullifier_position_generator(&npg_x, &npg_y);
    size_t pos_pt_x, pos_pt_y;
    gadget_fixed_base_mul(cs, s->position_bits, SAPLING_MERKLE_DEPTH,
                          &npg_x, &npg_y, &pos_pt_x, &pos_pt_y);
    if (pos_pt_x >= cs->num_vars || pos_pt_y >= cs->num_vars) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: section 24 g^position produced no point "
                     "(x=%zu y=%zu num_vars=%zu)",
                     pos_pt_x, pos_pt_y, cs->num_vars);
        return false;
    }
    spend_record(s, "24:g^position");

    /* ════ Section 25: faerie gold prevention (6) ════
     * rho = cm + [position] G_pos. One Edwards addition, and the operand order
     * is cm.add(position) — self is cm, so cm's coordinates are the ones that
     * land in the A side of the "U computation" row. Without this the nullifier
     * would depend only on the note contents, and two notes with identical
     * contents at different tree positions would share a nullifier: one of them
     * would be unspendable ("faerie gold"). */
    size_t rho_x, rho_y;
    gadget_edwards_add(cs, s->cm_x_var, s->cm_y_var, pos_pt_x, pos_pt_y,
                       &rho_x, &rho_y);
    if (rho_x >= cs->num_vars || rho_y >= cs->num_vars) {
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: section 25 rho wires out of range "
                     "(x=%zu y=%zu num_vars=%zu)", rho_x, rho_y, cs->num_vars);
        return false;
    }
    spend_record(s, "25:faerie gold prevention");

    /* ════ Section 26: representation of rho (776) ════
     * Completes the 512-bit nf preimage: repr(nk) from section 9, then
     * repr(rho). Same body as sections 8/9/15/16. */
    memcpy(s->nf_pre_bits, s->nf_preimage, sizeof(s->nf_preimage));
    section_point_repr(cs, rho_x, rho_y, &s->nf_pre_bits[256], NULL);
    spend_record(s, "26:representation of rho");
    return true;
}

/* Section 27: nf computation. */
static bool spend_step_nf(struct spend_synth *s)
{
    struct constraint_system *cs = s->cs;

    /* ════ Section 27: nf computation (21006) ════
     * nf = BLAKE2s-256("Zcash_nf", repr(nk) || repr(rho)) — the SAME gadget as
     * section 10 over a 512-bit all-allocated preimage, so the same 21006.
     * Only the personalization differs, and it enters as constants in the
     * initial state vector. */
    struct cbit nf_pre[512];
    for (size_t i = 0; i < 512; i++)
        nf_pre[i] = cbit_from_var(cs, s->nf_pre_bits[i]);

    static const uint8_t PRF_NF_PERSONALIZATION[8] =
        { 'Z', 'c', 'a', 's', 'h', '_', 'n', 'f' };
    if (!gadget_blake2s(cs, nf_pre, 512, PRF_NF_PERSONALIZATION, s->nf_bits)) {
        memory_cleanse(nf_pre, sizeof(nf_pre));
        LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                     "spend: in-circuit blake2s(PRF^nf) synthesis failed");
        return false;
    }
    memory_cleanse(nf_pre, sizeof(nf_pre));
    spend_record(s, "27:nf computation");
    return true;
}

/* One packing constraint for nf chunk `chunk` covering `n` bits from `bit`. */
static void spend_pack_chunk(struct spend_synth *s, size_t input,
                             size_t bit, size_t n)
{
    struct fr one_val;
    fr_one(&one_val);
    struct linear_combination la, lb, lcc;
    struct fr coeff;
    lc_init(&la);
    fr_one(&coeff);
    for (size_t i = 0; i < n; i++) {
        cbit_lc_add(&la, s->nf_bits[bit + i], &coeff);
        fr_add(&coeff, &coeff, &coeff);
    }
    lc_init(&lb);
    lc_add_term(&lb, CS_ONE, &one_val);
    lc_init(&lcc);
    lc_add_term(&lcc, input, &one_val);
    cs_enforce(s->cs, &la, &lb, &lcc);
    lc_free(&la); lc_free(&lb); lc_free(&lcc);
}

/* Section 28: pack nullifier. */
static bool spend_step_pack(struct spend_synth *s)
{
    /* ════ Section 28: pack nullifier (2) ════
     * multipack::pack_into_inputs — the 256 nf bits little-endian in chunks of
     * Fr::CAPACITY = 254, one packing constraint per chunk (254 + 2 bits).
     * Orientation matters for the QAP: A = the packed-bit LC, B = ONE,
     * C = the public input (the mirror of `inputize`, which puts the input in
     * A). The two inputs were allocated up front so their INDICES match
     * bellman's allocation order; only the constraints land here. */
    const size_t nf_input[2] = { s->in_nf0, s->in_nf1 };
    for (size_t chunk = 0, bit = 0; bit < 256; chunk++) {
        if (chunk >= 2) {
            LOG_ERROR_IN("sapling_spend_synthesize_traced", "circuit_spend",
                         "spend: section 28 wants >2 nf chunks (capacity=%u)",
                         (unsigned)CBIT_FR_CAPACITY);
            return false;
        }
        const size_t n = (256 - bit < CBIT_FR_CAPACITY)
                       ? 256 - bit : CBIT_FR_CAPACITY;
        spend_pack_chunk(s, nf_input[chunk], bit, n);
        bit += n;
    }
    spend_record(s, "28:pack nullifier");
    return true;
}

typedef bool (*spend_step_fn)(struct spend_synth *s);

/* The synthesis steps, in circuit order. */
static const spend_step_fn spend_steps[] = {
    spend_step_inputs, spend_step_rk,   spend_step_nk,     spend_step_ivk,
    spend_step_pkd,    spend_step_note, spend_step_cm,     spend_step_anchor,
    spend_step_rho,    spend_step_nf,   spend_step_pack,
};

bool sapling_spend_synthesize_traced(struct constraint_system *cs,
                                     const struct sapling_spend_witness *wit,
                                     const struct sapling_spend_inputs *pub,
                                     struct spend_section_shape *sections,
                                     size_t max_sections,
                                     size_t *n_sections_out,
                                     struct spend_wire_probe *probe)
{
    if (n_sections_out)
        *n_sections_out = 0;
    probe_reset(probe);

    struct spend_synth s = {
        .cs = cs, .wit = wit, .pub = pub, .sections = sections,
        .max_sections = max_sections, .probe = probe,
    };
    for (size_t i = 0; i < sizeof(spend_steps) / sizeof(spend_steps[0]); i++) {
        if (!spend_steps[i](&s))
            return false;
    }

    if (n_sections_out)
        *n_sections_out = s.nsec;
    return true;
}

bool sapling_spend_synthesize(struct constraint_system *cs,
                               const struct sapling_spend_witness *wit,
                               const struct sapling_spend_inputs *pub)
{
    return sapling_spend_synthesize_traced(cs, wit, pub, NULL, 0, NULL, NULL);
}

/* ── Witness -> public inputs ───────────────────────────────────── */

bool sapling_spend_derive_public(struct sapling_spend_witness *wit,
                                 struct sapling_spend_inputs *pub)
{
    if (!wit || !pub)
        LOG_FAIL("circuit_spend",
                 "derive_public: NULL argument (wit=%p pub=%p)",
                 (const void *)wit, (const void *)pub);

    /* pk_d = [CRH^ivk(ak, nk)] g_d — the value section 13 computes in-circuit.
     * Deriving it here is what keeps cm (and hence the anchor and nf) equal to
     * the circuit's own section-20 wire. */
    uint8_t nk[32], ivk[32];
    sapling_nsk_to_nk(wit->nsk, nk);
    sapling_crh_ivk(wit->ak, nk, ivk);
    if (!sapling_ivk_to_pkd(ivk, wit->diversifier, wit->pk_d))
        LOG_FAIL("circuit_spend",
                 "derive_public: sapling_ivk_to_pkd failed (invalid "
                 "diversifier — g_d would be the identity)");

    if (!sapling_compute_rk(wit->ak, wit->ar, pub->rk))
        LOG_FAIL("circuit_spend", "derive_public: sapling_compute_rk failed");
    if (!sapling_value_commit(wit->value, wit->rcv, pub->cv))
        LOG_FAIL("circuit_spend", "derive_public: sapling_value_commit failed");

    uint8_t cm[32];
    if (!sapling_compute_cm(wit->diversifier, wit->pk_d, wit->value,
                            wit->rcm, cm))
        LOG_FAIL("circuit_spend", "derive_public: sapling_compute_cm failed");

    /* Fold the authentication path exactly as section 21 does: at each depth
     * the position bit decides which side the running value goes on. */
    uint8_t cur[32];
    memcpy(cur, cm, 32);
    uint64_t position = 0;
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        uint8_t next[32];
        if (wit->auth_path_bits[d]) {
            position |= (UINT64_C(1) << d);
            pedersen_merkle_hash(d, wit->auth_path[d], cur, next);
        } else {
            pedersen_merkle_hash(d, cur, wit->auth_path[d], next);
        }
        memcpy(cur, next, 32);
    }
    memcpy(pub->anchor, cur, 32);

    if (!sapling_compute_nf(wit->diversifier, wit->pk_d, wit->value, wit->rcm,
                            wit->ak, nk, position, pub->nullifier))
        LOG_FAIL("circuit_spend", "derive_public: sapling_compute_nf failed");

    memory_cleanse(ivk, sizeof(ivk));
    return true;
}

/* ── Port coverage / typed blocker ──────────────────────────────── */

/* Canonical section roadmap for bellman's Spend::synthesize. Names index the
 * NEXT unimplemented section for the honest blocker; index 0 is section 1, so
 * roadmap[sections_ported] is the first section NOT yet ported. Kept in the
 * production circuit as the authoritative port target (the test-side reference
 * trace in groth16_spend_parity.c is an INDEPENDENT differential fixture, not
 * this list — they must agree, and the parity oracle proves they do). */
static const char *const SPEND_SECTION_ROADMAP[SPEND_CIRCUIT_TOTAL_SECTIONS] = {
    "1:ak witness+on-curve+not-small-order",
    "2:ar bits",
    "3:randomization of signing key",
    "4:computation of rk",
    "5:rk inputize",
    "6:nsk bits",
    "7:computation of nk",
    "8:representation of ak",
    "9:representation of nk",
    "10:computation of ivk",
    "11:witness g_d",
    "12:g_d not small order",
    "13:compute pk_d",
    "14:value commitment",
    "15:representation of g_d",
    "16:representation of pk_d",
    "17:note content hash",
    "18:rcm bits",
    "19:commitment randomness",
    "20:randomization of note commitment",
    "21:merkle tree hash 0..31",
    "22:conditionally enforce correct root",
    "23:anchor inputize",
    "24:g^position",
    "25:faerie gold prevention",
    "26:representation of rho",
    "27:nf computation",
    "28:pack nullifier",
};

/* Build the canonical, deterministic, non-secret coverage-probe witness: a
 * valid ak/rk from a fixed dummy ask/ar, a diversifier that actually hashes to
 * a Jubjub point, and the true value commitment for (value, rcv) — section 14
 * binds cv, so a placeholder point there would make the probe's own circuit
 * unsatisfiable. No proving key and no real spend secrets are touched. */
static bool build_probe_witness(struct sapling_spend_witness *wit,
                                struct sapling_spend_inputs *pub)
{
    memset(wit, 0, sizeof(*wit));
    memset(pub, 0, sizeof(*pub));

    uint8_t ask[32] = {0};
    ask[0] = 0x2a;
    ask[1] = 0x17;
    uint8_t ak[32];
    sapling_ask_to_ak(ask, ak);
    memory_cleanse(ask, sizeof(ask));
    memcpy(wit->ak, ak, 32);
    wit->nsk[0] = 0x11;
    wit->ar[0] = 0x03;
    wit->value = UINT64_C(12345);
    wit->rcv[0] = 0x2f;
    wit->rcv[1] = 0x91;
    /* Section 18 booleanizes rcm and section 19 multiplies by it; a zero rcm
     * would still synthesize, but every window would select the table's
     * identity slot and the probe would exercise none of the arithmetic. */
    wit->rcm[0] = 0x5c;
    wit->rcm[1] = 0x23;
    /* Section 21 decomposes each sibling with a NON-strict 255-bit
     * decomposition, so a sibling only has to be a canonical Fr encoding.
     * Taking each from a Pedersen Merkle hash guarantees that: the output is a
     * Jubjub point's x-coordinate, hence an Fr element by construction. A
     * memset-zero path would synthesize too, but every level would hash the
     * same sibling and a depth-indexing bug would be invisible. */
    for (size_t d = 0; d < SAPLING_MERKLE_DEPTH; d++) {
        uint8_t a[32] = {0}, b[32] = {0};
        a[0] = (uint8_t)(0x10u + d);
        a[1] = 0x5b;
        b[0] = (uint8_t)(d * 7u);
        b[3] = 0x11;
        pedersen_merkle_hash(0, a, b, wit->auth_path[d]);
        wit->auth_path_bits[d] = (((d * 5u) + (d / 3u)) & 1u) != 0u;
    }

    bool have_d = false;
    for (unsigned i = 0; i < 256 && !have_d; i++) {
        memset(wit->diversifier, 0, sizeof(wit->diversifier));
        wit->diversifier[0] = (uint8_t)i;
        have_d = sapling_check_diversifier(wit->diversifier);
    }
    if (!have_d)
        LOG_FAIL("circuit_spend",
                 "coverage probe: no valid diversifier in 256 candidates");

    /* Sections 5, 14, 22 and 28 each bind a public input, so a probe with
     * placeholder public inputs would synthesize an UNSATISFIABLE system. */
    if (!sapling_spend_derive_public(wit, pub))
        LOG_FAIL("circuit_spend",
                 "coverage probe: sapling_spend_derive_public failed");
    return true;
}

void sapling_spend_prover_native_status(struct spend_prover_native_status *out)
{
    if (!out)
        return;
    out->sections_ported = 0;
    out->sections_total = SPEND_CIRCUIT_TOTAL_SECTIONS;
    out->constraints_ported = 0;
    out->constraints_total = SPEND_CIRCUIT_TOTAL_CONSTRAINTS;
    out->roundtrip_ready = false;
    out->next_blocker = SPEND_SECTION_ROADMAP[0];

    struct sapling_spend_witness wit;
    struct sapling_spend_inputs pub;
    if (!build_probe_witness(&wit, &pub)) {
        /* Leave the pessimistic defaults (0/blocked); a failure to build the
         * probe witness is itself an honest "not ready". */
        memory_cleanse(&wit, sizeof(wit));
        return;
    }

    struct spend_section_shape sections[SPEND_CIRCUIT_TOTAL_SECTIONS];
    size_t nsec = 0;
    struct constraint_system cs;
    cs_init(&cs);
    bool synth = sapling_spend_synthesize_traced(
        &cs, &wit, &pub, sections, SPEND_CIRCUIT_TOTAL_SECTIONS, &nsec, NULL);
    if (synth) {
        out->sections_ported = nsec;
        out->constraints_ported = cs.num_constraints;
        if (nsec >= SPEND_CIRCUIT_TOTAL_SECTIONS) {
            out->roundtrip_ready = zclassic_sapling_prover_is_ready();
            out->next_blocker = out->roundtrip_ready ? "none (native proof round-trip ready)"
                : "port complete (round-trip self-test pending)";
        } else {
            out->next_blocker = SPEND_SECTION_ROADMAP[nsec];
        }
    }
    if (cs.witness)
        memory_cleanse(cs.witness, cs.cap_vars * sizeof(struct fr));
    cs_free(&cs);
    memory_cleanse(&wit, sizeof(wit));
}
