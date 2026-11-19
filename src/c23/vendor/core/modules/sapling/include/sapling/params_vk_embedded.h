/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Embedded Groth16 / PHGR13 verifying keys.
 *
 * A Zcash parameter file is a verifying key followed by a proving key.
 * Validation — checking the shielded proofs in blocks other nodes produced —
 * consumes only the verifying-key prefix, which is
 *     868 + ic_len * 96
 * bytes for a Groth16 key (see groth16_vk_read_raw in bls12_381.c), plus the
 * standalone 1449-byte PHGR13 key in sprout-verifying.key. That is 6357 bytes
 * in total, against 777 MB of parameter files.
 *
 * Those 6357 bytes are consensus constants — every node must agree on them or
 * it is validating a different network — so they live in the source tree
 * exactly as the checkpoint table does, rather than being fetched at runtime
 * from a host nobody in this project controls.
 *
 * Consequence: a node with an empty $HOME can sync, validate every shielded
 * proof, and serve peers with nothing downloaded. The 777 MB parameter set is
 * needed only to CREATE shielded transactions.
 */

#ifndef ZCL_SAPLING_PARAMS_VK_EMBEDDED_H
#define ZCL_SAPLING_PARAMS_VK_EMBEDDED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_EMBEDDED_VK_COUNT 4

/* One embedded verifying key: the bytes, and the SHA-256 they must hash to.
 * The digest is checked before the bytes are parsed, so a build with patched
 * key material fails closed instead of validating proofs against it. */
struct zcl_embedded_vk {
    const char *name;
    const uint8_t *bytes;
    size_t len;
    const char *sha256_hex;
};

extern const struct zcl_embedded_vk zcl_embedded_vks[ZCL_EMBEDDED_VK_COUNT];

/* Verify every embedded blob against its pinned SHA-256, parse the four
 * verifying keys, and install them as the process-wide consensus verifying
 * keys — the same globals sapling_init_params() would install from a full
 * parameter directory, holding the same values.
 *
 * Returns false, loudly, if any digest or parse fails; the caller must treat
 * that as fatal, because a node that cannot verify shielded proofs must not
 * pretend to validate the chain.
 *
 * Installs verifying keys only. It does not make the prover ready: with no
 * proving keys loaded the prover stays NATIVE_PROVER_UNINITIALIZED and the
 * wallet refuses to build a shielded output rather than emitting a bad one.
 *
 * Idempotent, and a no-op returning true if full parameters are already
 * loaded. */
bool sapling_install_embedded_vks(void);

/* True when the consensus verifying keys came from the embedded blobs rather
 * than from a full parameter directory — i.e. the node can validate but not
 * prove. Surfaced by the readiness controller so "no shielded spend" is a
 * reported state and never a silent one. */
bool sapling_vks_are_embedded(void);

#ifdef ZCL_TESTING
/* Test hook: run the real embedded-blob integrity check over caller-supplied
 * bytes, so a planted bad blob exercises the production comparison. */
bool sapling_test_embedded_vk_sha256_ok(const char *name, const uint8_t *bytes,
                                        size_t len, const char *sha256_hex);
#endif

#endif /* ZCL_SAPLING_PARAMS_VK_EMBEDDED_H */
