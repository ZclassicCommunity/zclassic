// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Opt-in fuzz target (not part of the default build; see README.md).
// Transaction decoding, context-free checks, sigop counting and sighash.
// No proof or signature verification.

#include "amount.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "crypto/common.h"
#include "key.h"
#include "main.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "script/standard.h"
#include "streams.h"
#include "version.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ios>
#include <stdexcept>

static const size_t MAX_FUZZ_INPUT = 2 * 1024 * 1024;
static const uint32_t SAPLING_BRANCH_ID = 0x76b809bb;

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
        CDataStream ss((const char*)data, (const char*)data + size, SER_NETWORK, PROTOCOL_VERSION);
        CTransaction tx;
        ss >> tx;

        CValidationState state;
        CheckTransactionWithoutProofVerification(tx, state, false);
        (void)GetLegacySigOpCount(tx, STANDARD_SCRIPT_VERIFY_FLAGS);

        try {
            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                (void)SignatureHash(tx.vin[i].scriptSig, tx, i, SigHashType(SIGHASH_ALL),
                                    CAmount(0), SAPLING_BRANCH_ID);
            }
        } catch (const std::logic_error&) {
            // SignatureHash rejects out-of-range indexes and the like.
        }
    } catch (const std::ios_base::failure&) {
        // Malformed input rejected by the decoder: expected.
    }
    return 0;
}
