// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/sha256.h"

#include <stdexcept>

// The SHA-256 implementation itself is the vendored Z23 C23 code reached
// through c23/glue/zcl_c23_sha256.h. The previous portable C++ transform is
// kept as the reference in gtest/sha256_reference.h and compared against this
// class by gtest/test_sha256_differential.cpp.

namespace
{
// Select the backend during static initialisation, before main() and before
// any thread exists. A CSHA256 used by an earlier static initialiser is still
// correct: the C code probes atomically on first use.
const int g_sha256_backend_probed = zcl_c23_sha256_autodetect();
} // namespace

////// SHA-256

CSHA256::CSHA256()
{
    zcl_c23_sha256_init(&st);
}

CSHA256& CSHA256::Write(const unsigned char* data, size_t len)
{
    zcl_c23_sha256_write(&st, data, len);
    return *this;
}

void CSHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    zcl_c23_sha256_finalize(&st, hash);
}

void CSHA256::FinalizeNoPadding(unsigned char hash[OUTPUT_SIZE], bool enforce_compression)
{
    if (enforce_compression && st.bytes != 64) {
        throw std::length_error("SHA256Compress should be invoked with a 512-bit block");
    }
    zcl_c23_sha256_midstate(&st, hash);
}

CSHA256& CSHA256::Reset()
{
    zcl_c23_sha256_init(&st);
    return *this;
}

std::string SHA256AutoDetect()
{
    (void)g_sha256_backend_probed;
    const bool ok = zcl_c23_sha256_autodetect() != 0;
    std::string name(zcl_c23_sha256_backend_name());
    if (!ok) {
        name += " (hardware SHA-256 failed its self-test and was disabled)";
    }
    return name;
}

std::string SHA256SelectBackendForTesting(const std::string& which)
{
    enum zcl_c23_sha256_backend want = ZCL_C23_SHA256_AUTO;
    if (which == "portable") {
        want = ZCL_C23_SHA256_PORTABLE;
    } else if (which == "hardware") {
        want = ZCL_C23_SHA256_HARDWARE;
    }
    (void)zcl_c23_sha256_select(want);
    return std::string(zcl_c23_sha256_backend_name());
}
