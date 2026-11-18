/* Copyright (c) 2014-2017 The Zcash developers
 * Copyright (c) 2012-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * BN-254 (alt_bn128) pairing — pure C23 implementation.
 * Used for PHGR13 zk-SNARK verification (Sprout pre-Sapling).
 *
 * Curve: y^2 = x^3 + 3 over Fq
 * q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
 * r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 */

#ifndef ZCL_SAPLING_BN254_H
#define ZCL_SAPLING_BN254_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Fq: 254-bit prime field, 4 x 64-bit limbs, Montgomery form. */
struct bn_fq {
    uint64_t d[4];
};

void bn_fq_zero(struct bn_fq *r);
void bn_fq_one(struct bn_fq *r);
bool bn_fq_is_zero(const struct bn_fq *a);
bool bn_fq_eq(const struct bn_fq *a, const struct bn_fq *b);

void bn_fq_add(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b);
void bn_fq_sub(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b);
void bn_fq_neg(struct bn_fq *r, const struct bn_fq *a);
void bn_fq_mul(struct bn_fq *r, const struct bn_fq *a, const struct bn_fq *b);
void bn_fq_sq(struct bn_fq *r, const struct bn_fq *a);
void bn_fq_inv(struct bn_fq *r, const struct bn_fq *a);
bool bn_fq_sqrt(struct bn_fq *r, const struct bn_fq *a);
bool bn_fq_from_bytes_be(struct bn_fq *r, const uint8_t s[32]);
void bn_fq_to_bytes_be(uint8_t s[32], const struct bn_fq *a);
void bn_fq_from_u64(struct bn_fq *r, uint64_t v);

/* Fq2 = Fq[u] / (u^2 + 1) */
struct bn_fq2 {
    struct bn_fq c0, c1; /* c0 + c1 * u */
};

void bn_fq2_zero(struct bn_fq2 *r);
void bn_fq2_one(struct bn_fq2 *r);
bool bn_fq2_is_zero(const struct bn_fq2 *a);
bool bn_fq2_eq(const struct bn_fq2 *a, const struct bn_fq2 *b);

void bn_fq2_add(struct bn_fq2 *r, const struct bn_fq2 *a, const struct bn_fq2 *b);
void bn_fq2_sub(struct bn_fq2 *r, const struct bn_fq2 *a, const struct bn_fq2 *b);
void bn_fq2_neg(struct bn_fq2 *r, const struct bn_fq2 *a);
void bn_fq2_mul(struct bn_fq2 *r, const struct bn_fq2 *a, const struct bn_fq2 *b);
void bn_fq2_sq(struct bn_fq2 *r, const struct bn_fq2 *a);
void bn_fq2_inv(struct bn_fq2 *r, const struct bn_fq2 *a);
void bn_fq2_mul_by_nonresidue(struct bn_fq2 *r, const struct bn_fq2 *a);
/* Square root in Fq2. False iff a is not a square (the accept set of libsnark's
 * Fp2_model::sqrt). Which root is returned is unspecified. r may alias a. */
bool bn_fq2_sqrt(struct bn_fq2 *r, const struct bn_fq2 *a);

/* Fq6 = Fq2[v] / (v^3 - xi)  where xi = 9+u */
struct bn_fq6 {
    struct bn_fq2 c0, c1, c2;
};

void bn_fq6_zero(struct bn_fq6 *r);
void bn_fq6_one(struct bn_fq6 *r);
void bn_fq6_add(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b);
void bn_fq6_sub(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b);
void bn_fq6_neg(struct bn_fq6 *r, const struct bn_fq6 *a);
void bn_fq6_mul(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b);
void bn_fq6_sq(struct bn_fq6 *r, const struct bn_fq6 *a);
void bn_fq6_inv(struct bn_fq6 *r, const struct bn_fq6 *a);
void bn_fq6_mul_by_nonresidue(struct bn_fq6 *r, const struct bn_fq6 *a);

/* Fq12 = Fq6[w] / (w^2 - v) */
struct bn_fq12 {
    struct bn_fq6 c0, c1;
};

void bn_fq12_zero(struct bn_fq12 *r);
void bn_fq12_one(struct bn_fq12 *r);
bool bn_fq12_eq(const struct bn_fq12 *a, const struct bn_fq12 *b);
void bn_fq12_mul(struct bn_fq12 *r, const struct bn_fq12 *a, const struct bn_fq12 *b);
void bn_fq12_sq(struct bn_fq12 *r, const struct bn_fq12 *a);
void bn_fq12_inv(struct bn_fq12 *r, const struct bn_fq12 *a);
void bn_fq12_conjugate(struct bn_fq12 *a);
void bn_fq12_frobenius_map(struct bn_fq12 *r, const struct bn_fq12 *a, int power);

/* G1: y^2 = x^3 + 3 over Fq (Jacobian coordinates) */
struct bn_g1 {
    struct bn_fq x, y, z;
};

void bn_g1_identity(struct bn_g1 *p);
bool bn_g1_is_identity(const struct bn_g1 *p);
void bn_g1_neg(struct bn_g1 *r, const struct bn_g1 *p);
void bn_g1_add(struct bn_g1 *r, const struct bn_g1 *a, const struct bn_g1 *b);
void bn_g1_double(struct bn_g1 *r, const struct bn_g1 *a);
void bn_g1_to_affine(struct bn_fq *ax, struct bn_fq *ay, const struct bn_g1 *p);
void bn_g1_scalar_mul(struct bn_g1 *r, const struct bn_g1 *p, const uint64_t scalar[4]);

/* Decode a zclassicd CompressedG1 (33 bytes: lead byte 0x02|y_lsb, then x as
 * 32 big-endian bytes, x < q). Any other lead byte is refused; there is no
 * encoding of the point at infinity (zclassicd Proof.hpp:97-111). */
bool bn_g1_decompress(struct bn_g1 *p, const uint8_t data[33]);

/* G2: y^2 = x^3 + b' over Fq2 (Jacobian coordinates) */
struct bn_g2 {
    struct bn_fq2 x, y, z;
};

void bn_g2_identity(struct bn_g2 *p);
bool bn_g2_is_identity(const struct bn_g2 *p);
void bn_g2_neg(struct bn_g2 *r, const struct bn_g2 *p);
void bn_g2_add(struct bn_g2 *r, const struct bn_g2 *a, const struct bn_g2 *b);
void bn_g2_double(struct bn_g2 *r, const struct bn_g2 *a);
void bn_g2_to_affine(struct bn_fq2 *ax, struct bn_fq2 *ay, const struct bn_g2 *p);
/* Canonical alt_bn128 G2 generator (libsnark G2::one) — single source of
 * truth shared by the PHGR13 verifier and its tests. */
void bn254_g2_one(struct bn_g2 *out);
/* True iff the affine G2 point (z assumed 1) is on the BN254 twist curve. */
bool bn_g2_is_on_curve(const struct bn_g2 *p);

/* Decode a zclassicd CompressedG2 (65 bytes: lead byte 0x0a|y_gt, then x as a
 * 64-byte big-endian FE2IP integer c1*q + c0 < q^2). Refuses any other lead
 * byte, a non-square x^3 + b', and a point outside the order-r subgroup
 * (zclassicd Proof.hpp:147-161, Proof.cpp:147-171). */
bool bn_g2_decompress(struct bn_g2 *p, const uint8_t data[65]);

/* Optimal Ate pairing on BN-254 */
void bn254_pairing(struct bn_fq12 *result,
                   const struct bn_g1 *p,
                   const struct bn_g2 *q);

/* Multi-pairing: computes product of pairings and checks == 1 */
bool bn254_multi_pairing_check(
    const struct bn_g1 *a_pts, const struct bn_g2 *b_pts,
    size_t n_pairs);

/* ── PPZKSNARK (PHGR13) verification ────────────────────────── */

struct ppzksnark_vk {
    struct bn_g2 alpha_a_g2;
    struct bn_g1 alpha_b_g1;
    struct bn_g2 alpha_c_g2;
    struct bn_g2 gamma_g2;
    struct bn_g1 gamma_beta_g1;
    struct bn_g2 gamma_beta_g2;
    struct bn_g2 rc_z_g2;
    struct bn_g1 *ic;        /* IC query (g1 points) */
    size_t ic_len;           /* Number of IC elements */
};

struct ppzksnark_proof {
    struct bn_g1 a;          /* g_A */
    struct bn_g1 a_prime;    /* g_A' */
    struct bn_g2 b;          /* g_B */
    struct bn_g1 b_prime;    /* g_B' */
    struct bn_g1 c;          /* g_C */
    struct bn_g1 c_prime;    /* g_C' */
    struct bn_g1 k;          /* g_K */
    struct bn_g1 h;          /* g_H */
};

/* Read PPZKSNARK proof from 296-byte serialized form */
bool ppzksnark_proof_read(struct ppzksnark_proof *proof, const uint8_t data[296]);

/* Read PPZKSNARK verification key from sprout-verifying.key file */
bool ppzksnark_vk_read(struct ppzksnark_vk *vk, const uint8_t *data, size_t len);

/* Free VK's IC array */
void ppzksnark_vk_free(struct ppzksnark_vk *vk);

/* Verify PPZKSNARK proof (5 pairing checks).
 * public_inputs: Fr scalars (BN-254 scalar field), 4 x uint64_t each.
 * n_inputs must equal vk->ic_len - 1. */
bool ppzksnark_verify(const struct ppzksnark_vk *vk,
                      const struct ppzksnark_proof *proof,
                      const uint64_t (*public_inputs)[4],
                      size_t n_inputs);

/* ── Sprout PHGR13 high-level API ───────────────────────────── */

/* Set the PHGR13 verification key (loaded at boot) */
void sprout_phgr_set_vk(struct ppzksnark_vk *vk);

#ifdef ZCL_TESTING
/* See sapling_test_published_spend_vk in sapling.h. */
const struct ppzksnark_vk *sprout_test_published_phgr_vk(void);
#endif
/* True iff a PHGR13 verification key is installed, i.e. iff a PHGR13
 * JoinSplit proof can actually be CHECKED right now.
 *
 * This is deliberately separate from sapling_params_loaded(): the PHGR13
 * key lives in its own file (sprout-verifying.key) and, off mainnet, a
 * failure to load it is non-fatal — params_init.c still publishes
 * sapling_params_loaded()==true with this key absent. Without this
 * predicate a caller cannot distinguish "this PHGR13 proof is forged"
 * from "we hold no key to judge it with", because sprout_verify_phgr13()
 * fail-closes to the same `false` in both cases. */
bool sprout_phgr_vk_loaded(void);

/* Verify a Sprout PHGR13 JoinSplit proof.
 * proof: 296-byte serialized PHGR13 proof
 * Public inputs: rt, h_sig, {nf,mac}x2, {cm}x2, vpub_old, vpub_new */
bool sprout_verify_phgr13(const uint8_t proof[296],
                          const uint8_t rt[32],
                          const uint8_t h_sig[32],
                          const uint8_t mac1[32],
                          const uint8_t mac2[32],
                          const uint8_t nf1[32],
                          const uint8_t nf2[32],
                          const uint8_t cm1[32],
                          const uint8_t cm2[32],
                          uint64_t vpub_old,
                          uint64_t vpub_new);

#ifdef ZCL_TESTING
/* ── Test hooks (bn254.c, ZCL_TESTING builds only) ─────────────
 *
 * The pairing, decoders and verifier run on one of two instances of the same
 * engine (bn254_engine.inc): the portable multiply and the BMI2+ADX one. The
 * hooks let test_bn254_engine_parity pick the instance and reach the internal
 * operations it compares against the frozen pre-engine implementation. Not
 * thread-safe against concurrent verifiers (the selection is global). */

/* 0 = automatic, 1 = portable, 2 = BMI2+ADX. False (nothing changed) when the
 * instance cannot run on this CPU. */
bool bn254_test_select_engine(int which);
const char *bn254_test_engine_name(void);

/* Product of the Miller loops of n pairs, before the final exponentiation;
 * pairs with an identity operand contribute 1. */
void bn254_test_miller(struct bn_fq12 *r, const struct bn_g1 *p, const struct bn_g2 *q, size_t n);
void bn254_test_final_exp(struct bn_fq12 *f);
bool bn254_test_g2_in_subgroup(const struct bn_g2 *p);

void bn254_test_fq12_mul(struct bn_fq12 *r, const struct bn_fq12 *a, const struct bn_fq12 *b);
void bn254_test_fq12_sqr(struct bn_fq12 *r, const struct bn_fq12 *a);
void bn254_test_fq12_cyc_sqr(struct bn_fq12 *r, const struct bn_fq12 *a);
void bn254_test_fq12_inv(struct bn_fq12 *r, const struct bn_fq12 *a);
void bn254_test_fq12_frob(struct bn_fq12 *r, const struct bn_fq12 *a, int power);
void bn254_test_fq12_mul_by_024(struct bn_fq12 *f, const struct bn_fq2 *x0,
                                const struct bn_fq2 *x4, const struct bn_fq2 *x2);
void bn254_test_fq6_mul(struct bn_fq6 *r, const struct bn_fq6 *a, const struct bn_fq6 *b);
void bn254_test_fq6_sqr(struct bn_fq6 *r, const struct bn_fq6 *a);
void bn254_test_fq_inv(struct bn_fq *r, const struct bn_fq *a);
bool bn254_test_fq_sqrt(struct bn_fq *r, const struct bn_fq *a);

/* acc = ic[0] + sum in[i] * ic[i+1] as ppzksnark_verify computes it. */
void bn254_test_msm(struct bn_g1 *acc, const struct ppzksnark_vk *vk,
                    const uint64_t (*in)[4], size_t n);
#endif

#endif
