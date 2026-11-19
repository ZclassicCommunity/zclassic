/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sprout JoinSplit Groth16 proof verification — pure C23. */

#include "sapling/sprout.h"
#include "sapling/bls12_381.h"
#include "crypto/blake2b.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <string.h>

static struct groth16_vk *sprout_vk = NULL;

void sprout_set_vk(struct groth16_vk *vk)
{
    sprout_vk = vk;
}

#ifdef ZCL_TESTING
const struct groth16_vk *sprout_test_published_vk(void) { return sprout_vk; }
#endif

static const uint8_t HSIG_PERSONAL[16] = {
    'Z','c','a','s','h','C','o','m','p','u','t','e','h','S','i','g'
};

void sprout_h_sig(const uint8_t random_seed[32],
                  const uint8_t nf0[32],
                  const uint8_t nf1[32],
                  const uint8_t joinsplit_pubkey[32],
                  uint8_t h_sig[32])
{
    struct blake2b_ctx state;
    blake2b_init_salt_personal(&state, 32, NULL, 0, NULL, HSIG_PERSONAL);
    blake2b_update(&state, random_seed, 32);
    blake2b_update(&state, nf0, 32);
    blake2b_update(&state, nf1, 32);
    blake2b_update(&state, joinsplit_pubkey, 32);
    blake2b_final(&state, h_sig, 32);
    memory_cleanse(&state, sizeof(state));
}

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
                           uint64_t vpub_new)
{
    if (!sprout_vk)
        LOG_FAIL("sprout",
                 "verify_groth16: sprout_vk is NULL (params not loaded) — "
                 "refusing to accept JoinSplit");

    struct groth16_proof gp;
    if (!groth16_proof_read(&gp, proof))
        LOG_FAIL("sprout", "verify_groth16: groth16_proof_read failed");

    /* Construct input bytes: rt || h_sig || nf1 || mac1 || nf2 || mac2
     *                        || cm1 || cm2 || vpub_old_le || vpub_new_le */
    uint8_t input[272];
    memcpy(input,       rt,    32);
    memcpy(input + 32,  h_sig, 32);
    memcpy(input + 64,  nf1,   32);
    memcpy(input + 96,  mac1,  32);
    memcpy(input + 128, nf2,   32);
    memcpy(input + 160, mac2,  32);
    memcpy(input + 192, cm1,   32);
    memcpy(input + 224, cm2,   32);

    for (int i = 0; i < 8; i++) {
        input[256 + i] = (uint8_t)(vpub_old >> (i * 8));
        input[264 + i] = (uint8_t)(vpub_new >> (i * 8));
    }

    /* Pack into Fr scalars (253 bits per scalar, BE bit order for Sprout) */
    uint64_t public_inputs[16][4];
    size_t n_inputs;
    multipack_bytes_to_fr_be(public_inputs, &n_inputs, input, 272);

    if (n_inputs != sprout_vk->ic_len - 1)
        LOG_FAIL("sprout",
                 "verify_groth16: public-input count mismatch: got=%zu expected=%zu",
                 n_inputs, sprout_vk->ic_len - 1);

    return groth16_verify(sprout_vk, &gp, public_inputs, n_inputs);
}
