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
        out.numOutputs = msg.num_outputs;
        for (int i = 0; i < msg.num_outputs && i < 20; ++i)
            out.outputQuantities[i] = msg.output_quantities[i];
        return true;
    default:
        return false;
    }
}
