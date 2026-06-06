// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP message bridge — a thin C++ wrapper around the plain-C slp_parse() so
// the rest of the daemon never has to include zslp/slp.h directly.
//
// WHY THIS EXISTS: the protocol library's uint256_c.h declares a plain-C
// `struct uint256`, which is the *same identifier* as the daemon's
// `class uint256` (src/uint256.h). The two cannot coexist in one translation
// unit (redefinition error). This bridge is compiled against ONLY the C SLP
// header and exposes a parsed result using plain byte arrays, so callers
// (the indexer, tests) can freely use the daemon's uint256.

#ifndef BITCOIN_ZSLP_ZSLPMSG_H
#define BITCOIN_ZSLP_ZSLPMSG_H

#include <stdint.h>
#include <cstddef>
#include <string>

/** SLP message kinds (mirror enum slp_tx_type, but daemon-side). */
enum ZSLPMsgType {
    ZSLPMSG_INVALID = 0,
    ZSLPMSG_GENESIS = 1,
    ZSLPMSG_MINT    = 2,
    ZSLPMSG_SEND    = 3,
};

/** Parsed SLP message in a daemon-friendly POD form (no struct uint256). */
struct ZSLPMessage {
    ZSLPMsgType type;

    // GENESIS
    std::string ticker;
    std::string name;
    std::string documentUrl;
    bool hasDocumentHash;
    uint8_t documentHash[32];
    uint8_t decimals;
    uint8_t mintBatonVout;     // 0 = none
    uint64_t initialQuantity;

    // MINT / SEND share tokenId (big-endian display order, as on chain).
    uint8_t tokenId[32];
    uint64_t additionalQuantity;     // MINT

    // SEND
    uint64_t outputQuantities[20];
    int numOutputs;

    ZSLPMessage() : type(ZSLPMSG_INVALID), hasDocumentHash(false),
                    decimals(0), mintBatonVout(0), initialQuantity(0),
                    additionalQuantity(0), numOutputs(0)
    {
        for (int i = 0; i < 32; ++i) { documentHash[i] = 0; tokenId[i] = 0; }
        for (int i = 0; i < 20; ++i) outputQuantities[i] = 0;
    }
};

/**
 * Parse a raw OP_RETURN scriptPubKey into an SLP message.
 * Returns true and fills `out` when the script is a valid SLP message.
 */
bool ZSLPParseScript(const uint8_t* script, size_t scriptLen, ZSLPMessage& out);

#endif // BITCOIN_ZSLP_ZSLPMSG_H
