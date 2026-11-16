/* Copyright 2026 The Zclassic developers - MIT License
 *
 * Sprout JoinSplit Groth16 circuit, C23 port of sapling-crypto
 * circuit::sprout (librustzcash 06da3b9ac8f278e5d4ae13088cf0a4c03d2c13f5),
 * built on the vendored Z23 Boolean/UInt32/MultiEq layer (circuit_bits.h).
 *
 * The constraint system must be the one sprout-groth16.params was generated
 * for: same variable allocation order, same constraint order, same linear
 * combinations. The only deliberate difference from bellman is WHERE the nine
 * public inputs live in the variable index space: bellman keeps inputs and
 * aux in two separate vectors, Z23's constraint_system uses one flat vector
 * with the inputs at 1..9, so the packed public inputs are computed natively
 * from the witness and allocated FIRST. Every aux variable keeps its bellman
 * relative order (aux k is variable 10 + k), and the nine packing constraints
 * at the end bind the pre-allocated inputs to the in-circuit bits exactly as
 * bellman's pack_into_inputs does. */

#ifndef ZC23_SPROUT_CIRCUIT_H
#define ZC23_SPROUT_CIRCUIT_H

#include "sapling/groth16_prover.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SPROUT_TREE_DEPTH 29u
#define SPROUT_AUTH_LEN (1u + 33u * SPROUT_TREE_DEPTH + 8u) /* 966 */

/* Reference shape (sapling-crypto test_sprout_constraints, and the
 * sprout-groth16.params query lengths). */
#define SPROUT_NUM_CONSTRAINTS 1989085u
#define SPROUT_NUM_INPUTS 9u /* excluding ONE; bellman counts 10 */

struct sprout_js_input {
    uint8_t a_sk[32];
    uint64_t value;
    uint8_t rho[32];
    uint8_t r[32];
    uint8_t sibling[SPROUT_TREE_DEPTH][32]; /* index 0 = leaf layer */
    bool cur_is_right[SPROUT_TREE_DEPTH];
};

struct sprout_js_output {
    uint8_t a_pk[32];
    uint64_t value;
    uint8_t r[32];
};

struct sprout_js_witness {
    uint8_t phi[32];
    uint8_t rt[32];
    uint8_t h_sig[32];
    struct sprout_js_input in[2];
    struct sprout_js_output out[2];
    uint64_t vpub_old;
    uint64_t vpub_new;
};

/* Public values the witness implies (native, out of circuit). */
struct sprout_js_public {
    uint8_t nf[2][32];
    uint8_t mac[2][32];
    uint8_t cm[2][32];
    uint8_t root[2][32]; /* the root each input's path folds to */
};

/* Parse one librustzcash auth blob (depth byte 29, then 29 x {len 32, sibling}
 * root-first, then u64 LE position). Returns false on any layout violation;
 * the ABI entry point turns that into abort() exactly as Rust's assert_eq!
 * does. */
bool sprout_parse_auth(const uint8_t auth[SPROUT_AUTH_LEN],
                       struct sprout_js_input *in);

/* SHA256Compress of one 64-byte block from the standard IV (no padding). */
void sprout_sha256_compress(const uint8_t block[64], uint8_t out[32]);

/* Native PRFs / commitment / tree fold, the out-of-circuit mirror of the
 * gadgets. */
void sprout_compute_public(const struct sprout_js_witness *w,
                           struct sprout_js_public *pub);

/* cm of an input note: note_comm(PRF_addr(a_sk), value, rho, r). */
void sprout_input_note_commitment(const uint8_t a_sk[32], uint64_t value,
                                  const uint8_t rho[32], const uint8_t r[32],
                                  uint8_t cm[32]);

/* The packed public inputs (9 Fr elements), exactly as the verifier packs
 * rt || h_sig || nf1 || mac1 || nf2 || mac2 || cm1 || cm2 || vpub_old_le ||
 * vpub_new_le. */
void sprout_pack_inputs(const uint8_t rt[32], const uint8_t h_sig[32],
                        const uint8_t nf[2][32], const uint8_t mac[2][32],
                        const uint8_t cm[2][32], uint64_t vpub_old,
                        uint64_t vpub_new, struct fr out[SPROUT_NUM_INPUTS]);

/* Synthesize the JoinSplit circuit into a freshly cs_init'ed system.
 * Returns false only on an internal failure (OOM, shape mismatch). It does
 * NOT check satisfaction; call cs_is_satisfied afterwards. */
bool sprout_synthesize(struct constraint_system *cs,
                       const struct sprout_js_witness *w);

#endif
