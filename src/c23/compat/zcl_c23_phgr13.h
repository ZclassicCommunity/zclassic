/* zclassicd-owned. The only door between zclassicd's Sprout PHGR13 JoinSplit
 * verification (src/zcash/JoinSplit.cpp) and the vendored Z23 BN254 verifier
 * (core/modules/sapling/src/bn254.c, sprout_verify_phgr13). It replaces the
 * libsnark r1cs_ppzksnark verifier that zclassicd linked before.
 *
 * The inputs are exactly what JoinSplitCircuit::verify handed libsnark:
 *   - the 296 wire bytes of the PHGRProof (CompressedG1/G2 as serialized in the
 *     transaction; the lead bytes are checked at deserialization, not here),
 *   - rt, h_sig, macs, nullifiers, commitments in their uint256 byte order,
 *   - vpub_old, vpub_new.
 * The verifying key is the 1449-byte sprout-verifying.key, loaded once.
 *
 * Every function is callable from any thread once zcl_c23_phgr13_load_vk has
 * returned (the vendored engine initialises its tables with pthread_once and a
 * mutex; see c23/compat/WIRING.md "PHGR13"). */
#ifndef ZCL_C23_PHGR13_H
#define ZCL_C23_PHGR13_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_C23_PHGR13_PROOF_SIZE 296u

/* Parse sprout-verifying.key (libsnark binary, uncompressed Montgomery points)
 * and install it as the process-wide PHGR13 key. The caller has already
 * checked the file's SHA-256 against the compiled pin (init.cpp). Loading the
 * same bytes again is a no-op that returns true; a different key replaces the
 * installed one (tests only; the old key is intentionally not freed because a
 * concurrent verifier may still hold it). False, nothing installed, when the
 * bytes do not parse. */
bool zcl_c23_phgr13_load_vk(const unsigned char *data, size_t len);

/* True once a key is installed. */
bool zcl_c23_phgr13_vk_loaded(void);

/* The decoding half of verification: every point of the 296-byte proof is
 * decompressed with libsnark's exact rules (x < q, square root exists, y
 * parity, G2 x = FE2IP integer < q^2, G2 point in the order-r subgroup).
 * This is all that remains of JoinSplitCircuit::verify when proofs are not
 * checked (ProofVerifier::Disabled): libsnark still decompressed the proof
 * there, and a point that fails to decode made verify() return false. */
bool zcl_c23_phgr13_proof_decodes(const unsigned char proof[ZCL_C23_PHGR13_PROOF_SIZE]);

/* Full verification: decode, then the five pairing checks. Same argument order
 * as librustzcash_sprout_verify. False for any malformed or invalid proof, and
 * when no key is installed. */
bool zcl_c23_phgr13_verify(const unsigned char proof[ZCL_C23_PHGR13_PROOF_SIZE],
                           const unsigned char *rt,
                           const unsigned char *h_sig,
                           const unsigned char *mac1,
                           const unsigned char *mac2,
                           const unsigned char *nf1,
                           const unsigned char *nf2,
                           const unsigned char *cm1,
                           const unsigned char *cm2,
                           uint64_t vpub_old, uint64_t vpub_new);

#ifdef __cplusplus
}
#endif

#endif
