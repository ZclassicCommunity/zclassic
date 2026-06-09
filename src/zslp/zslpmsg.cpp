// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP message bridge implementation. This translation unit includes ONLY the
// plain-C SLP header (which declares `struct uint256`) and MUST NOT include
// the daemon's src/uint256.h (`class uint256`) — the two share an identifier
// and would clash. Keep this file's includes minimal.

#include "zslp/zslpmsg.h"

#include <cstring>

extern "C" {
#include "zslp/slp.h"
}

// The bridge's daemon-side cap MUST equal the C parser's canonical cap, or the
// two layers would disagree on the SEND output bound and fork the ledger
// (R-SEND-1 / R-12). This is the only TU that sees both constants.
static_assert(ZSLP_MAX_SEND_OUTPUTS == ZSLP_SEND_MAX_OUTPUTS,
              "ZSLP SEND output cap mismatch between bridge and parser");

bool ZSLPParseScript(const uint8_t* script, size_t scriptLen, ZSLPMessage& out)
{
    struct slp_message msg;
    if (!slp_parse(script, scriptLen, &msg))
        return false;

    out = ZSLPMessage();

    switch (msg.type) {
    case SLP_TX_GENESIS:
        out.type = ZSLPMSG_GENESIS;
        out.ticker = msg.ticker;
        out.name = msg.name;
        out.documentUrl = msg.document_url;
        out.hasDocumentHash = msg.has_document_hash;
        if (msg.has_document_hash)
            memcpy(out.documentHash, msg.document_hash, 32);
        out.decimals = msg.decimals;
        out.mintBatonVout = msg.mint_baton_vout;
        out.initialQuantity = msg.initial_quantity;
        out.hasGroupId = msg.has_group_id;
        if (msg.has_group_id)
            memcpy(out.groupId, msg.group_id, 32);
        return true;
    case SLP_TX_MINT:
        out.type = ZSLPMSG_MINT;
        memcpy(out.tokenId, msg.token_id.data, 32);
        out.mintBatonVout = msg.mint_baton_vout;
        out.additionalQuantity = msg.additional_quantity;
        return true;
    case SLP_TX_SEND:
        out.type = ZSLPMSG_SEND;
        memcpy(out.tokenId, msg.token_id.data, 32);
        // The parser guarantees 1..ZSLP_SEND_MAX_OUTPUTS; copy them all (the
        // bound is identical on both sides per the static_assert above).
        out.numOutputs = msg.num_outputs;
        for (int i = 0; i < msg.num_outputs && i < ZSLP_MAX_SEND_OUTPUTS; ++i)
            out.outputQuantities[i] = msg.output_quantities[i];
        return true;
    default:
        return false;
    }
}

// ── Build direction ─────────────────────────────────────────────────

// Relay cap mirrored locally: this TU cannot include script/standard.h (it
// pulls in the daemon's class uint256, which clashes with slp.h's struct
// uint256). Kept equal to MAX_OP_RETURN_RELAY (script/standard.h:34).
static const size_t ZSLP_BRIDGE_MAX_OP_RETURN_RELAY = 223;

// A 256-byte scratch buffer comfortably exceeds the 223-byte relay cap, so an
// over-cap GENESIS is detected by the length check below rather than truncating.
static const size_t ZSLP_BUILD_BUF = 256;

// Wrap the raw encoder output (which already includes the leading 0x6a) into a
// daemon-side vector, returning EMPTY on encoder failure (return 0) or when the
// produced script would exceed the relay cap.
static std::vector<unsigned char> FinishBuild(const uint8_t* buf, size_t n)
{
    if (n == 0)
        return std::vector<unsigned char>(); // encoder failure / invalid input
    if (n > ZSLP_BRIDGE_MAX_OP_RETURN_RELAY)
        return std::vector<unsigned char>(); // too large for one relayed OP_RETURN
    return std::vector<unsigned char>(buf, buf + n);
}

std::vector<unsigned char> ZSLPBuildGenesis(
    const std::string& ticker, const std::string& name,
    const std::string& documentUrl,
    const uint8_t* documentHash,
    uint8_t decimals, uint8_t mintBatonVout, uint64_t initialQuantity,
    const uint8_t* groupId)
{
    uint8_t buf[ZSLP_BUILD_BUF];
    size_t n = slp_build_genesis(buf, sizeof(buf),
                                 ticker.empty() ? NULL : ticker.c_str(),
                                 name.empty() ? NULL : name.c_str(),
                                 documentUrl.empty() ? NULL : documentUrl.c_str(),
                                 documentHash, decimals, mintBatonVout,
                                 initialQuantity, groupId);
    return FinishBuild(buf, n);
}

std::vector<unsigned char> ZSLPBuildMint(
    const uint8_t* tokenIdBE, uint8_t mintBatonVout, uint64_t additionalQuantity)
{
    struct uint256 tid;
    memcpy(tid.data, tokenIdBE, 32);
    uint8_t buf[ZSLP_BUILD_BUF];
    size_t n = slp_build_mint(buf, sizeof(buf), &tid, mintBatonVout,
                              additionalQuantity);
    return FinishBuild(buf, n);
}

std::vector<unsigned char> ZSLPBuildSend(
    const uint8_t* tokenIdBE, const std::vector<uint64_t>& quantities)
{
    // slp_build_send rejects <1 or >ZSLP_SEND_MAX_OUTPUTS itself (returns 0),
    // which FinishBuild maps to an empty result — but guard here too so we never
    // pass a stray pointer for an empty vector.
    if (quantities.empty() || (int)quantities.size() > ZSLP_SEND_MAX_OUTPUTS)
        return std::vector<unsigned char>();
    struct uint256 tid;
    memcpy(tid.data, tokenIdBE, 32);
    uint8_t buf[ZSLP_BUILD_BUF];
    size_t n = slp_build_send(buf, sizeof(buf), &tid, quantities.data(),
                              (int)quantities.size());
    return FinishBuild(buf, n);
}
