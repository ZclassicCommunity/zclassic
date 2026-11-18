// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "znam/znamresolve.h"

#include "key_io.h"
#include "script/standard.h"
#include "utilstrencodings.h"
#include "zcash/Address.hpp"

#include "c23/services/glue/zcl_znam_index.h"

#include <algorithm>

namespace znam {

bool ValidName(const std::string& name)
{
    return name.find('\0') == std::string::npos && zcl_znam_validate_name(name.c_str()) != 0;
}

const char* PayKindName(PayKind k)
{
    switch (k) {
    case PAY_TRANSPARENT: return "transparent";
    case PAY_SAPLING: return "sapling";
    case PAY_SPROUT: return "sprout";
    default: return "none";
    }
}

PayKind ClassifyAddress(unsigned int type, const std::string& value, std::string& why)
{
    why.clear();
    if (type != TYPE_TADDR && type != TYPE_ZADDR) {
        why = std::string("a ") + TypeName(type) + " record is not a ZClassic address";
        return PAY_NONE;
    }
    if (value.empty() || value.size() > 120) {
        why = "the record is empty or too long to be an address";
        return PAY_NONE;
    }
    // The decoders skip surrounding white space and accept alternative spellings. An answer is shown to a person and
    // handed on as text, so only the canonical spelling counts: decode, encode again, and the text must be unchanged.
    const CTxDestination dest = DecodeDestination(value);
    const bool isT = IsValidDestination(dest) && EncodeDestination(dest) == value;
    const libzcash::PaymentAddress z = DecodePaymentAddress(value);
    const bool isZ = IsValidPaymentAddress(z) && EncodePaymentAddress(z) == value;
    if (type == TYPE_TADDR) {
        if (isT)
            return PAY_TRANSPARENT;
        why = isZ ? "the record is declared a t-address but holds a z-address"
                  : "the record is declared a t-address but is not a valid t-address of this chain";
        return PAY_NONE;
    }
    if (isZ)
        return boost::get<libzcash::SaplingPaymentAddress>(&z) ? PAY_SAPLING : PAY_SPROUT;
    why = isT ? "the record is declared a z-address but holds a t-address"
              : "the record is declared a z-address but is not a valid z-address of this chain";
    return PAY_NONE;
}

namespace {

Candidate Make(unsigned int type, const std::string& value, bool fromRecord, int height, const uint256& txid)
{
    Candidate c;
    c.type = type;
    c.value = value;
    c.fromRecord = fromRecord;
    c.height = height;
    c.txid = txid;
    c.kind = ClassifyAddress(type, value, c.why);
    return c;
}

} // namespace

Resolution Resolve(const ZnamIndex& index, const std::string& name, unsigned int wantType, int tipHeight, int recentBlocks)
{
    Resolution r;
    if (!ValidName(name)) {
        r.status = Resolution::MALFORMED;
        return r;
    }
    if (!index.GetName(name, r.entry)) {
        r.status = Resolution::ABSENT;
        return r;
    }
    const Entry& e = r.entry;
    r.candidates.push_back(Make(e.type, e.value, false, e.changeHeight, e.changeTxid));
    std::vector<AddrRecord> recs = index.GetAddrRecords(name);
    for (size_t i = 0; i < recs.size(); i++)
        r.candidates.push_back(Make(recs[i].type, recs[i].value, true, recs[i].height, recs[i].txid));

    r.selected = -1;
    if (wantType == 0) {
        // Paying: the primary target when it is payable, then a t-address record, then a z-address record.
        const unsigned int order[2] = {TYPE_TADDR, TYPE_ZADDR};
        if (r.candidates[0].kind != PAY_NONE)
            r.selected = 0;
        for (int o = 0; o < 2 && r.selected < 0; o++)
            for (size_t i = 1; i < r.candidates.size(); i++)
                if (r.candidates[i].type == order[o] && r.candidates[i].kind != PAY_NONE) {
                    r.selected = (int)i;
                    break;
                }
    } else {
        // Z23's name_resolve with a type: the primary target of that type, else the record of that type.
        if (r.candidates[0].type == wantType && !r.candidates[0].value.empty())
            r.selected = 0;
        for (size_t i = 1; i < r.candidates.size() && r.selected < 0; i++)
            if (r.candidates[i].type == wantType && !r.candidates[i].value.empty())
                r.selected = (int)i;
        if (r.selected < 0 && wantType == TYPE_ONION) {
            // Z23 also honours an "onion" text record for the onion type.
            std::vector<TextRecord> texts = index.GetTextRecords(name);
            for (size_t i = 0; i < texts.size(); i++)
                if (texts[i].key == "onion" && !texts[i].value.empty()) {
                    r.candidates.push_back(Make(TYPE_ONION, texts[i].value, true, texts[i].height, texts[i].txid));
                    r.selected = (int)r.candidates.size() - 1;
                    break;
                }
        }
    }

    r.changeHeight = e.changeHeight;
    r.changeTxid = e.changeTxid;
    if (r.selected > 0 && r.candidates[r.selected].fromRecord && r.candidates[r.selected].height > r.changeHeight) {
        r.changeHeight = r.candidates[r.selected].height;
        r.changeTxid = r.candidates[r.selected].txid;
    }
    r.blocksSinceChange = std::max(0, tipHeight - r.changeHeight);
    r.recent = recentBlocks > 0 && r.blocksSinceChange < recentBlocks;
    r.expired = e.expiryHeight < tipHeight;

    if (r.selected < 0) {
        r.status = Resolution::NO_TARGET;
        return r;
    }
    r.status = Resolution::OK;
    const Candidate& c = r.candidates[r.selected];
    if (wantType == 0 && c.kind == PAY_NONE)
        r.warnings.push_back("the selected record is not a payable address");
    if (wantType != 0 && (wantType == TYPE_TADDR || wantType == TYPE_ZADDR) && c.kind == PAY_NONE)
        r.warnings.push_back("the record is not a payable address: " + c.why);
    if (r.recent)
        r.warnings.push_back("this name's address or owner changed " + std::to_string(r.blocksSinceChange) +
                             " block(s) ago (block " + std::to_string(r.changeHeight) +
                             "): confirm the address with the recipient over another channel before paying");
    if (r.expired)
        r.warnings.push_back("the registration term of this name has lapsed; ZNAM still resolves it, and anyone can renew it");
    return r;
}

} // namespace znam
