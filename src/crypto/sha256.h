// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA256_H
#define BITCOIN_CRYPTO_SHA256_H

#include <stdint.h>
#include <stdlib.h>
#include <string>

#include "c23/glue/zcl_c23_sha256.h"

/** A hasher class for SHA-256.
 *
 * The compression function is the vendored Z23 C23 implementation
 * (src/c23/vendor/core/modules/crypto/src/sha256.c), which selects Intel
 * SHA-NI, the ARMv8 SHA extension or portable C at run time. Output is
 * FIPS 180-4 SHA-256 on every backend. */
class CSHA256
{
public:
    static const size_t OUTPUT_SIZE = 32;

    CSHA256();
    CSHA256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    void FinalizeNoPadding(unsigned char hash[OUTPUT_SIZE]) {
    	FinalizeNoPadding(hash, true);
    };
    CSHA256& Reset();

private:
    // s[8], buf[64], bytes: the same state CSHA256 always carried.
    struct zcl_c23_sha256_state st;
    void FinalizeNoPadding(unsigned char hash[OUTPUT_SIZE], bool enforce_compression);
};

/** Probe the CPU, run the known-answer self-test and install the fastest
 *  verified SHA-256 backend. Returns its name for the startup log. A hardware
 *  backend that disagrees with the portable code is disabled, and the name
 *  then says so. Call once at startup before threads are started; the backend
 *  is otherwise chosen on first use (atomically). */
std::string SHA256AutoDetect();

/** Test and benchmark hook: force a backend. "portable" always succeeds;
 *  "hardware" falls back to portable when the CPU has no verified hardware
 *  SHA-256; anything else selects automatically. Returns the installed
 *  backend's name. Not for production code; do not call while other threads
 *  hash. */
std::string SHA256SelectBackendForTesting(const std::string& which);

#endif // BITCOIN_CRYPTO_SHA256_H
