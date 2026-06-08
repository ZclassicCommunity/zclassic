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
#include <vector>

/** SLP message kinds (mirror enum slp_tx_type, but daemon-side). */
enum ZSLPMsgType {
    ZSLPMSG_INVALID = 0,
    ZSLPMSG_GENESIS = 1,
    ZSLPMSG_MINT    = 2,
    ZSLPMSG_SEND    = 3,
};

/** Canonical SEND output-quantity cap (R-SEND-1 / R-12). Daemon-side mirror of
 *  slp.h's ZSLP_SEND_MAX_OUTPUTS, kept in sync by a static_assert in
 *  zslpmsg.cpp (which is the one place that includes the C header). One number
 *  in the parser, this bridge, and the store; >this => message INVALID. */
static const int ZSLP_MAX_SEND_OUTPUTS = 19;

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
    // GENESIS field 10 (OPTIONAL): collection parent group_id (big-endian /
    // display order, as on chain — same order as tokenId). hasGroupId is false
    // for a legacy/ungrouped GENESIS. A spec-v2 child-collection feature.
    bool hasGroupId;
    uint8_t groupId[32];

    // MINT / SEND share tokenId (big-endian display order, as on chain).
    uint8_t tokenId[32];
    uint64_t additionalQuantity;     // MINT

    // SEND
    uint64_t outputQuantities[ZSLP_MAX_SEND_OUTPUTS];
    int numOutputs;

    ZSLPMessage() : type(ZSLPMSG_INVALID), hasDocumentHash(false),
                    decimals(0), mintBatonVout(0), initialQuantity(0),
                    hasGroupId(false),
                    additionalQuantity(0), numOutputs(0)
    {
        for (int i = 0; i < 32; ++i) {
            documentHash[i] = 0; tokenId[i] = 0; groupId[i] = 0;
        }
        for (int i = 0; i < ZSLP_MAX_SEND_OUTPUTS; ++i) outputQuantities[i] = 0;
    }
};

/**
 * Parse a raw OP_RETURN scriptPubKey into an SLP message.
 * Returns true and fills `out` when the script is a valid SLP message.
 */
bool ZSLPParseScript(const uint8_t* script, size_t scriptLen, ZSLPMessage& out);

// ── Build direction (write path) ────────────────────────────────────
//
// Thin C++ wrappers around slp_build_genesis / slp_build_mint / slp_build_send.
// They live HERE (the one TU that may include the C header) for the same reason
// the parse bridge does: callers (wallet/zslpwallet.cpp, rpc/zslp.cpp) must never
// include slp.h (struct uint256 vs class uint256 clash).
//
// Each returns the COMPLETE OP_RETURN script bytes (leading 0x6a included), or
// an EMPTY vector on ANY failure (encoder returned 0 = buffer/limit/invalid, or
// the produced script exceeds the MAX_OP_RETURN_RELAY 223-byte relay cap). An
// empty return MUST be treated by the caller as "metadata too large / invalid"
// and the build aborted (R-WALLET, doc/nft/MINT_TRANSFER_SPEC.md §2.6).
//
// `tokenId` for MINT/SEND is the 32-byte token id in ON-CHAIN big-endian /
// display order (i.e. the daemon uint256's bytes REVERSED — the inverse of the
// indexer's TokenIdToUint256). The caller is responsible for that reversal; the
// bridge passes the 32 bytes straight through to slp_build_*.

/** GENESIS: ticker/name/documentUrl may be empty (encoded as empty pushes).
 *  documentHash, if non-NULL, points at exactly 32 raw bytes (on-chain order,
 *  NOT reversed). mintBatonVout is emitted only when >= 2. groupId, if non-NULL,
 *  points at exactly 32 raw bytes (on-chain order, NOT reversed) and is emitted
 *  as the optional trailing field-10 push so this GENESIS declares membership in
 *  the collection whose genesis txid is groupId; NULL omits it (legacy GENESIS).
 *  An over-cap (>223-byte) result still returns EMPTY (fails closed). */
std::vector<unsigned char> ZSLPBuildGenesis(
    const std::string& ticker, const std::string& name,
    const std::string& documentUrl,
    const uint8_t* documentHash /* 32 bytes or NULL */,
    uint8_t decimals, uint8_t mintBatonVout, uint64_t initialQuantity,
    const uint8_t* groupId /* 32 bytes or NULL */ = NULL);

/** MINT: tokenIdBE is exactly 32 bytes (on-chain BE order). */
std::vector<unsigned char> ZSLPBuildMint(
    const uint8_t* tokenIdBE /* 32 bytes */,
    uint8_t mintBatonVout, uint64_t additionalQuantity);

/** SEND: tokenIdBE is 32 bytes (BE); quantities are positional (qty[j] ->
 *  vout[1+j]); 1..ZSLP_MAX_SEND_OUTPUTS entries (else empty result). */
std::vector<unsigned char> ZSLPBuildSend(
    const uint8_t* tokenIdBE /* 32 bytes */,
    const std::vector<uint64_t>& quantities);

#endif // BITCOIN_ZSLP_ZSLPMSG_H
