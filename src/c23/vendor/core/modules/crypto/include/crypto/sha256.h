/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_CRYPTO_SHA256_H
#define BITCOIN_CRYPTO_SHA256_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define SHA256_OUTPUT_SIZE 32
#define SHA256_BLOCK_SIZE 64

struct sha256_ctx {
    uint32_t s[8];
    unsigned char buf[SHA256_BLOCK_SIZE];
    size_t bytes;
};

/* Streaming SHA-256 (FIPS 180-4). init → write* → finalize yields the
 * 32-byte digest of the concatenation of all write() data; write() accepts
 * arbitrary lengths and may be called repeatedly. The compression transform
 * is the ISA's hardware tier when available and verified (see
 * sha256_selftest) — Intel SHA-NI on x86, the ARMv8 SHA extension on arm64 —
 * else portable C. All tiers produce identical output. */
void sha256_init(struct sha256_ctx *ctx);
void sha256_write(struct sha256_ctx *ctx, const unsigned char *data, size_t len);
void sha256_finalize(struct sha256_ctx *ctx, unsigned char hash[SHA256_OUTPUT_SIZE]);

/* Emit the current internal state (the 8 chaining words, big-endian) as the
 * 32-byte `hash` WITHOUT appending the SHA-256 length/0x80 padding. This is
 * NOT a SHA-256 digest — it exposes the raw compression-function output, for
 * midstate / single-block constructions that do their own padding (e.g.
 * BIP-340-style tagged hashing). When `enforce_compression` is nonzero it
 * requires exactly one 64-byte block to have been absorbed (ctx->bytes==64)
 * and returns -1 (logging) otherwise; with it 0 the check is skipped.
 * Returns 0 on success. */
int sha256_finalize_no_padding(struct sha256_ctx *ctx, unsigned char hash[SHA256_OUTPUT_SIZE],
                               int enforce_compression);

/* Runtime self-test: verifies the selected hardware transform matches
 * portable. Returns true if OK. Call once at startup. If false, the hardware
 * tier is auto-disabled. */
bool sha256_selftest(void);

/* The active tier: "SHA-NI (hardware)" or "ARMv8 SHA (hardware)" when a
 * verified hardware transform is installed, else "portable C". */
const char *sha256_implementation(void);

/* True when the host has SHA-NI *and* it passed the known-answer test against
 * the portable reference. False on non-x86 (on arm64 the hardware tier is
 * reported through sha256_implementation() instead), on CPUs without the
 * instruction, and after a failed self-test. */
bool sha256_shani_available(void);

/* Force the compression transform. PORTABLE always succeeds. SHANI and AUTO
 * both re-run the probe + known-answer test and fall back to PORTABLE when
 * the host cannot supply a verified hardware transform — SHANI is a request
 * (the ARMv8 SHA extension on arm64), never an override of a failed
 * self-test. Returns the impl actually installed (SHA256_IMPL_PORTABLE or
 * SHA256_IMPL_SHANI).
 *
 * Both transforms produce identical output by construction (that is what the
 * sha256_isa_parity test group proves), so this only ever changes speed. It
 * exists for the differential parity oracle and the benchmark; production code
 * should leave the dispatch on AUTO. Not thread-safe against concurrent
 * hashing. */
enum sha256_impl { SHA256_IMPL_AUTO = -1, SHA256_IMPL_PORTABLE = 0, SHA256_IMPL_SHANI = 1 };
int sha256_select_impl(enum sha256_impl which);

#endif
