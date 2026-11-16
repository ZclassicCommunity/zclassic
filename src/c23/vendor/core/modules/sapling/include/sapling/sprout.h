/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sprout JoinSplit Groth16 proof verification — pure C23. */

#ifndef ZCL_SAPLING_SPROUT_H
#define ZCL_SAPLING_SPROUT_H

#include <stdint.h>
#include <stdbool.h>

struct groth16_vk;

void sprout_set_vk(struct groth16_vk *vk);

#ifdef ZCL_TESTING
/* See sapling_test_published_spend_vk in sapling.h. */
const struct groth16_vk *sprout_test_published_vk(void);
#endif

/* Compute h_sig = BLAKE2b-256("ZcashComputehSig", randomSeed || nf0 || nf1 || joinSplitPubKey) */
void sprout_h_sig(const uint8_t random_seed[32],
                  const uint8_t nf0[32],
                  const uint8_t nf1[32],
                  const uint8_t joinsplit_pubkey[32],
                  uint8_t h_sig[32]);

/* Verify a Sprout JoinSplit Groth16 proof (post-Sapling encoding).
 * Public inputs: rt, h_sig, {nf, mac}x2, {cm}x2, vpub_old, vpub_new
 * packed via multipack into Fr scalars. */
bool sprout_verify_groth16(const uint8_t proof[192],
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

#endif
