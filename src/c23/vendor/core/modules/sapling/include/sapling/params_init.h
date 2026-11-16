/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Load Zcash zkSNARK verification keys from params files. */

#ifndef ZCL_SAPLING_PARAMS_INIT_H
#define ZCL_SAPLING_PARAMS_INIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Load a full parameter directory: the Sapling and Sprout Groth16 verifying
 * keys, and the proving keys that make shielded SENDING possible. Every file
 * is checked against its compiled-in SHA-512 before a byte of it is used, and
 * a directory that fails any of those pins is refused whole.
 *
 * CALL IT WHENEVER THE PARAMETERS ARRIVE — including on a running node.
 *
 * A node that booted with no parameter directory installed the compiled-in
 * verifying keys (sapling_install_embedded_vks) and has been validating and
 * serving ever since; the one thing it cannot do is create a shielded
 * transaction. When the proving parameters land — a fetch that completed
 * (net/params_service.h), an operator copying files in — this is the call that
 * turns that capability on, with no restart:
 *
 *     if (sapling_init_params(params_dir) &&
 *         zclassic_sapling_prover_is_ready()) { ... shielded send is armed ... }
 *
 * Both halves matter. The first says the pinned parameter set loaded; the
 * second says the prover proved a real Spend + Output + binding bundle that
 * this node's own consensus verifier accepted. Only the second one gates
 * sending.
 *
 * Thread rules. Safe to call from any thread and safe to call concurrently:
 * the loaders are serialised internally, and a late load only ADDS the proving
 * keys — it never re-parses, replaces or frees a verifying key that consensus
 * threads are reading. But it reads ~777 MB and runs a Groth16 self-test, so
 * call it from a BACKGROUND thread. Never from a P2P message handler, and
 * never while holding a lock a message handler takes.
 *
 * Returns false if the directory is unusable; the keys already published stay
 * published and the node keeps validating. */
bool sapling_init_params(const char *params_dir);


/* Proving readiness, for an app to show. Carries no path, key or file content.
 *   none          no proving parameters installed
 *   pair_present  both Sapling proving files are in the noted directory at
 *                 their exact sizes; nothing is loaded yet
 *   pair_armed    a send is in progress with the pair loaded and self-tested
 *   full_set      the four-file set is loaded by sapling_init_params */
enum sapling_proving_status {
    SAPLING_PROVING_NONE = 0,
    SAPLING_PROVING_PAIR_PRESENT,
    SAPLING_PROVING_PAIR_ARMED,
    SAPLING_PROVING_FULL_SET,
};

enum sapling_proving_status sapling_proving_status(void);
const char *sapling_proving_status_name(void);

/* Sapling-only proving for devices that cannot carry the 725 MB Sprout Groth16
 * parameters. Nothing is loaded at boot.
 *
 * sapling_note_proving_pair_dir records the directory and nothing else; call
 * it at boot and whenever the directory changes. sapling_proving_available is
 * true when proving is armed or both Sapling files are in the noted directory
 * at their exact sizes; it reads no file content, so it is the cheap check a
 * send path makes before any work.
 *
 * The session pair brackets a send. Acquire arms proving if it is not armed:
 * SHA-512 pin of each file, compiled-in verifying-key prefix of each, then the
 * prover self-test, which is skipped when the same files (same device, inode,
 * size and times) already passed it in this process. It returns false with sapling_proving_last_refusal() set
 * to a short reason code when any step fails, leaving the node running.
 * Release frees the proving bytes and disarms a pair-armed backend once the
 * last session ends. A full set loaded by sapling_init_params is unaffected.
 * zclassic_sapling_proving_ctx_init/_free call these, so a send needs nothing
 * more. Verifying keys, verification and consensus paths are untouched. */
void sapling_note_proving_pair_dir(const char *params_dir);
bool sapling_proving_available(void);
bool sapling_proving_session_acquire(void);
void sapling_proving_session_release(void);

/* Why the last pair arming was refused, or NULL. A static string. */
const char *sapling_proving_last_refusal(void);

/* True once the VERIFYING keys are published and shielded proof VALIDATION is
 * armed — by a parameter directory or by the compiled-in fallback. It says
 * nothing about proving: use zclassic_sapling_prover_is_ready() for that.
 * Safe to read from reducer/validation threads while the boot loader thread is
 * still parsing the large params files. */
bool sapling_params_loaded(void);

/* Get raw proving key data for Sapling output/spend proofs.
 * Returns pointer to mmap'd file data. NULL if not loaded. */
const uint8_t *sapling_get_output_pk(size_t *len);
const uint8_t *sapling_get_spend_pk(size_t *len);

/* Free all loaded verification keys. */
void sapling_free_params(void);

#ifdef ZCL_TESTING
/* Test-only: the pair loader's verifying-key prefix comparison. */
bool sapling_test_pair_arm_buffers(const uint8_t *spend, size_t spend_len,
                                   const uint8_t *output, size_t output_len);
bool sapling_test_pair_prefix_ok(const uint8_t *spend, size_t spend_len,
                                 const uint8_t *output, size_t output_len);
#endif

#endif
