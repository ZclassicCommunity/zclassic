/* Copyright (c) 2026 The Zclassic developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * The hook API the differential gate (phgr13_diff.cpp) calls on the candidate.
 * It is implemented by phgr13_adapter.c / phgr13_adapter_cpp.cpp on top of the
 * files zclassicd actually builds: the vendored bn254.c, the shim
 * src/c23/compat/zcl_c23_phgr13.c, and the daemon's own src/zcash/Proof.cpp.
 * Test-only; nothing here is linked into the daemon. */
#ifndef ZC23_PHGR13_C23_H
#define ZC23_PHGR13_C23_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZC23_PHGR13_PROOF_SIZE 296
#define ZC23_PHGR13_G1_SIZE 33
#define ZC23_PHGR13_G2_SIZE 65

typedef struct zc23_phgr13_vk zc23_phgr13_vk;

/* Install sprout-verifying.key as the process-wide key (the shim's load) and keep
 * a second parse for zc23_phgr13_vk_export. NULL on failure. */
zc23_phgr13_vk *zc23_phgr13_vk_load(const uint8_t *data, size_t len);
void zc23_phgr13_vk_free(zc23_phgr13_vk *vk);

/* The daemon's accept set: the proof deserialized as in a transaction (lead bytes),
 * then the body of JoinSplitCircuit::verify with ProofVerifier::Strict(). h_sig is
 * the caller's. */
bool zc23_phgr13_verify(const zc23_phgr13_vk *vk,
                        const uint8_t proof[ZC23_PHGR13_PROOF_SIZE],
                        const uint8_t rt[32], const uint8_t h_sig[32],
                        const uint8_t nf1[32], const uint8_t nf2[32],
                        const uint8_t mac1[32], const uint8_t mac2[32],
                        const uint8_t cm1[32], const uint8_t cm2[32],
                        uint64_t vpub_old, uint64_t vpub_new);

/* Point decoders and the Fq2 square root, canonical big-endian output (G1 x||y,
 * G2 x.c0||x.c1||y.c0||y.c1). */
bool zc23_phgr13_g1_decode(const uint8_t in[ZC23_PHGR13_G1_SIZE], uint8_t out_xy[64]);
bool zc23_phgr13_g2_decode(const uint8_t in[ZC23_PHGR13_G2_SIZE], uint8_t out_xy[128]);
bool zc23_phgr13_fq2_sqrt(const uint8_t a[64], uint8_t out[64]);

/* The 9 packed Fr public inputs (the vendored packing function), little-endian limbs. */
void zc23_phgr13_pack_inputs(uint64_t out[9][4],
                             const uint8_t rt[32], const uint8_t h_sig[32],
                             const uint8_t nf1[32], const uint8_t nf2[32],
                             const uint8_t mac1[32], const uint8_t mac2[32],
                             const uint8_t cm1[32], const uint8_t cm2[32],
                             uint64_t vpub_old, uint64_t vpub_new);

/* The key's points as canonical big-endian affine coordinates in libsnark order. */
size_t zc23_phgr13_vk_export(const zc23_phgr13_vk *vk, uint8_t *out, size_t cap);

/* The shim's verify without the C++ lead-byte check in front of it ("raw"). */
bool zc23_phgr13_verify_z23_raw(const zc23_phgr13_vk *vk,
                                const uint8_t proof[ZC23_PHGR13_PROOF_SIZE],
                                const uint8_t rt[32], const uint8_t h_sig[32],
                                const uint8_t nf1[32], const uint8_t nf2[32],
                                const uint8_t mac1[32], const uint8_t mac2[32],
                                const uint8_t cm1[32], const uint8_t cm2[32],
                                uint64_t vpub_old, uint64_t vpub_new);

#ifdef __cplusplus
}
#endif

#endif
