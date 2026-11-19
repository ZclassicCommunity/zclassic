// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Opt-in fuzz target (not part of the default build; see README.md).
// Block header and full block decoding plus the context-free checks.

#include "chainparams.h"
#include "consensus/validation.h"
#include "crypto/common.h"
#include "key.h"
#include "main.h"
#include "primitives/block.h"
#include "streams.h"
#include "version.h"
#include "zcash/Proof.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ios>

static const size_t MAX_FUZZ_INPUT = 2 * 1024 * 1024;

namespace {
struct FuzzInit {
    FuzzInit()
    {
        if (init_and_check_sodium() == -1) abort();
        ECC_Start();
        SelectParams(CBaseChainParams::MAIN);
    }
};
const FuzzInit g_fuzz_init;
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > MAX_FUZZ_INPUT) return 0;
    try {
        CBlockHeader header;
        {
            CDataStream ss((const char*)data, (const char*)data + size, SER_NETWORK, PROTOCOL_VERSION);
            ss >> header;
            CValidationState state;
            CheckBlockHeader(header, state, false);
        }
        CBlock block;
        {
            CDataStream ss((const char*)data, (const char*)data + size, SER_NETWORK, PROTOCOL_VERSION);
            ss >> block;
            CValidationState state;
            auto verifier = libzcash::ProofVerifier::Disabled();
            CheckBlock(block, state, verifier, false, true);
        }
    } catch (const std::ios_base::failure&) {
        // Malformed input rejected by the decoder: expected.
    }
    return 0;
}
