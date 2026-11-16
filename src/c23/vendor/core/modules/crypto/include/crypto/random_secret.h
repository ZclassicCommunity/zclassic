/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Defense-in-depth wrapper around `core/random.GetRandBytes` for
 * secret material (RNG hygiene).
 *
 * Why this exists:
 *   `GetRandBytes` in `core/modules/core/src/random.c` opens /dev/urandom and
 *   silently zero-fills the output buffer if open() fails (for example
 *   inside a chroot or container without /dev mounted). Every secret
 *   in core/modules/sapling and core/modules/crypto sources its randomness through that
 *   function, so a quiet open() failure becomes a key=0 catastrophe:
 *   ephemeral DH secrets, Sapling note rcm/rcv, RedJubjub signing
 *   nonces, and Groth16 proof blinding factors would all be all-zero
 *   simultaneously.
 *
 *   This wrapper rejects the all-zero case (probability of legitimate
 *   all-zero output for n>=16 is ~2^-128) and forces callers to handle
 *   the failure rather than silently encrypt under a known key.
 *
 *   The root-cause fix belongs in core/random.c and is flagged for
 *   the network/runtime owner; this wrapper is the in-lane mitigation.
 *
 * Usage:
 *     uint8_t key[32];
 *     if (!zcl_random_secret_bytes(key, 32, "esk"))
 *         return false;  // wrapper has logged + zeroed key
 */

#ifndef ZCL_CRYPTO_RANDOM_SECRET_H
#define ZCL_CRYPTO_RANDOM_SECRET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Fill `buf[0..n)` with cryptographically strong random bytes.
 * Returns true on success. On failure: zeros buf, logs a LOG_FAIL-style
 * line that includes the caller-provided `label` (a short identifier
 * for the secret being generated, never the bytes themselves), and
 * returns false. */
bool zcl_random_secret_bytes(uint8_t *buf, size_t n, const char *label);

#endif /* ZCL_CRYPTO_RANDOM_SECRET_H */
