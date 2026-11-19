/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * FF1 format-preserving encryption (NIST SP 800-38G) with AES-256.
 * Used by ZIP 32 for diversifier derivation on 88-bit binary numeral strings. */

#ifndef ZCL_SAPLING_FF1_H
#define ZCL_SAPLING_FF1_H

#include <stdint.h>
#include <stddef.h>

/* FF1 encrypt: binary numeral string (radix=2).
 * key: 32-byte AES-256 key
 * tweak: optional tweak (can be NULL if tweak_len == 0)
 * data: input/output buffer (little-endian bytes, n bits)
 * n: number of bits (must be >= 2) */
void ff1_aes256_encrypt(const uint8_t key[32],
                        const uint8_t *tweak, size_t tweak_len,
                        uint8_t *data, size_t n);

#endif
