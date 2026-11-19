// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Opt-in fuzz target (not part of the default build; see README.md).
// P2P message payload decoding with the same types the main.cpp handlers
// use. The first input byte (mod 10) selects the message; no CNode is involved:
// 0 inv, 1 getdata, 2 addr, 3 headers, 4 getblocks, 5 filterload,
// 6 filteradd, 7 merkleblock, 8 tx, 9 block.

#include "bloom.h"
#include "chainparams.h"
#include "crypto/common.h"
#include "key.h"
#include "main.h"
#include "merkleblock.h"
#include "net.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "protocol.h"
#include "streams.h"
#include "uint256.h"
#include "version.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ios>
#include <vector>

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

namespace {
// One decoder per message, each reading vRecv with the types the matching
// ProcessMessage handler uses. Only std::ios_base::failure may escape.

void DecodeInvOrGetdata(CDataStream& vRecv)
{
    std::vector<CInv> v;
    vRecv >> v;
    for (const CInv& inv : v) (void)inv.IsKnownType();
}

void DecodeAddr(CDataStream& vRecv)
{
    std::vector<CAddress> v;
    vRecv >> v;
    for (const CAddress& a : v) (void)a.ToString();
}

void DecodeHeaders(CDataStream& vRecv)
{
    // ReadCompactSize loop as in main.cpp
    std::vector<CBlockHeader> headers;
    unsigned int nCount = ReadCompactSize(vRecv);
    if (nCount > MAX_HEADERS_RESULTS) return;
    headers.resize(nCount);
    for (unsigned int n = 0; n < nCount; n++) {
        vRecv >> headers[n];
        ReadCompactSize(vRecv); // tx count, ignored by the handler
    }
}

void DecodeGetblocks(CDataStream& vRecv)
{
    // locator + stop hash
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;
}

void DecodeFilterload(CDataStream& vRecv)
{
    CBloomFilter filter;
    vRecv >> filter;
    (void)filter.IsWithinSizeConstraints();
}

void DecodeFilteradd(CDataStream& vRecv)
{
    std::vector<unsigned char> vData;
    vRecv >> vData;
}

void DecodeMerkleblock(CDataStream& vRecv)
{
    CMerkleBlock mb;
    vRecv >> mb;
}

void DecodeTx(CDataStream& vRecv)
{
    CTransaction tx;
    vRecv >> tx;
}

void DecodeBlock(CDataStream& vRecv)
{
    CBlock block;
    vRecv >> block;
}

typedef void (*PayloadDecoder)(CDataStream& vRecv);

/** Indexed by the selector (first input byte mod 10). */
const PayloadDecoder DECODERS[10] = {
    DecodeInvOrGetdata, // 0 inv
    DecodeInvOrGetdata, // 1 getdata
    DecodeAddr,         // 2 addr
    DecodeHeaders,      // 3 headers
    DecodeGetblocks,    // 4 getblocks
    DecodeFilterload,   // 5 filterload
    DecodeFilteradd,    // 6 filteradd
    DecodeMerkleblock,  // 7 merkleblock
    DecodeTx,           // 8 tx
    DecodeBlock,        // 9 block
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > MAX_FUZZ_INPUT) return 0;
    const uint8_t selector = data[0] % 10;
    CDataStream vRecv((const char*)data + 1, (const char*)data + size, SER_NETWORK, PROTOCOL_VERSION);
    try {
        DECODERS[selector](vRecv);
    } catch (const std::ios_base::failure&) {
        // Malformed payload rejected by the decoder: expected.
    }
    return 0;
}
