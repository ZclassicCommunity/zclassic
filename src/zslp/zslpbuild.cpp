// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zslp/zslpbuild.h"

#include "amount.h"
#include "script/standard.h"
#include "tinyformat.h"

#include "c23/services/glue/zcl_token_guard.h"

#include <string.h>

namespace zslp {

namespace {

bool IsDigit(char c) { return c >= '0' && c <= '9'; }
bool IsAlnum(char c) { return IsDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

bool Fail(std::string& err, const std::string& why)
{
    err = why;
    return false;
}

/** A P2PKH output script, only to size the dust threshold. */
CScript SampleP2PKH()
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0) << OP_EQUALVERIFY << OP_CHECKSIG;
}

CTxOut TokenOut(const CScript& script, CAmount dust)
{
    return CTxOut(dust, script);
}

bool ScriptIsSpendableDestination(const CScript& script)
{
    // only P2PKH and P2SH hold tokens: SLP is transparent, and the index folds nothing else into an address
    return script.IsPayToScriptHash() ||
           (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 && script[2] == 20 &&
            script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG);
}

} // namespace

CAmount TokenDust(const CFeeRate& minRelay)
{
    const CAmount policy = CTxOut(0, SampleP2PKH()).GetDustThreshold(minRelay);
    return policy > TOKEN_DUST ? policy : TOKEN_DUST;
}

bool ParseUnits(const std::string& text, unsigned int decimals, uint64_t& units, std::string& err)
{
    units = 0;
    if (text.empty())
        return Fail(err, "the amount is empty");
    if (decimals > 18)
        return Fail(err, "decimals out of range");
    size_t dot = std::string::npos;
    for (size_t i = 0; i < text.size(); i++) {
        const char c = text[i];
        if (IsDigit(c))
            continue;
        if (c == '.' && dot == std::string::npos) {
            dot = i;
            continue;
        }
        return Fail(err, "the amount must be a plain decimal number such as 12 or 12.5 (no sign, exponent, spaces or separators)");
    }
    const std::string whole = dot == std::string::npos ? text : text.substr(0, dot);
    const std::string frac = dot == std::string::npos ? "" : text.substr(dot + 1);
    if (whole.empty())
        return Fail(err, "the amount needs digits before the decimal point (write 0.5, not .5)");
    if (dot != std::string::npos && frac.empty())
        return Fail(err, "the amount has a decimal point but no digits after it");
    if (frac.size() > decimals)
        return Fail(err, strprintf("the amount has %u decimal places but this token allows only %u; nothing is rounded",
                                   (unsigned)frac.size(), decimals));
    // value = whole * 10^decimals + frac * 10^(decimals - frac.size()), all in unsigned 64-bit with overflow checks
    uint64_t v = 0;
    const std::string digits = whole + frac + std::string(decimals - frac.size(), '0');
    for (size_t i = 0; i < digits.size(); i++) {
        const unsigned d = (unsigned)(digits[i] - '0');
        if (v > (UINT64_MAX - d) / 10)
            return Fail(err, "the amount is too large (it does not fit in 64 bits of base units)");
        v = v * 10 + d;
    }
    units = v;
    return true;
}

bool ParsePositiveQuantity(const std::string& text, unsigned int decimals, uint64_t& units, std::string& err)
{
    if (!ParseUnits(text, decimals, units, err))
        return false;
    if (units == 0)
        return Fail(err, "the amount must be greater than zero");
    if (units > MAX_QUANTITY)
        return Fail(err, strprintf("the amount is above %llu base units, which the token rules treat as unknown",
                                   (unsigned long long)MAX_QUANTITY));
    return true;
}

void WireTokenId(const uint256& token, unsigned char out[32])
{
    for (int i = 0; i < 32; i++)
        out[i] = token.begin()[31 - i];
}

bool ValidateGenesis(const GenesisParams& p, std::string& err)
{
    if (p.ticker.empty() || p.ticker.size() > MAX_TICKER_LEN)
        return Fail(err, "ticker must be 1-10 alphanumeric characters");
    for (size_t i = 0; i < p.ticker.size(); i++)
        if (!IsAlnum(p.ticker[i]))
            return Fail(err, "ticker must be alphanumeric (A-Z, a-z, 0-9)");
    if (p.name.empty() || p.name.size() > MAX_NAME_LEN)
        return Fail(err, "name must be 1-64 characters");
    for (size_t i = 0; i < p.name.size(); i++) {
        const char c = p.name[i];
        if (!IsAlnum(c) && c != ' ' && c != '-' && c != '_' && c != '.' && c != '/')
            return Fail(err, "name may only contain letters, digits, space and - _ . /");
    }
    if (p.documentUrl.size() > 255)
        return Fail(err, "documenturl is longer than 255 bytes");
    for (size_t i = 0; i < p.documentUrl.size(); i++) {
        const unsigned char c = (unsigned char)p.documentUrl[i];
        if (c < 0x21 || c > 0x7e)
            return Fail(err, "documenturl may only contain visible ASCII characters without spaces");
    }
    if (p.decimals > MAX_DECIMALS)
        return Fail(err, "decimals must be between 0 and 8");
    if (p.quantity == 0)
        return Fail(err, "initialquantity must be greater than zero");
    if (p.quantity > MAX_GENESIS_SUPPLY)
        return Fail(err, strprintf("initialquantity exceeds the maximum of %llu base units", (unsigned long long)MAX_GENESIS_SUPPLY));
    return true;
}

bool BuildGenesisScript(const GenesisParams& p, CScript& script, std::string& err)
{
    if (!ValidateGenesis(p, err))
        return false;
    unsigned char buf[600];
    const size_t n = zcl_token_guard_build_genesis(buf, sizeof(buf), p.ticker.c_str(), p.name.c_str(),
                                                   p.documentUrl.c_str(), p.hasDocumentHash ? p.documentHash : NULL,
                                                   (uint8_t)p.decimals, p.baton ? 2 : 0, p.quantity);
    if (n == 0)
        return Fail(err, "the GENESIS message does not fit");
    script = CScript(buf, buf + n);
    return true;
}

bool BuildMintScript(const uint256& token, uint64_t quantity, bool baton, CScript& script, std::string& err)
{
    if (quantity == 0 || quantity > MAX_QUANTITY)
        return Fail(err, "the mint quantity must be between 1 and 2^63-1 base units");
    unsigned char id[32], buf[600];
    WireTokenId(token, id);
    const size_t n = zcl_token_guard_build_mint(buf, sizeof(buf), id, baton ? 2 : 0, quantity);
    if (n == 0)
        return Fail(err, "the MINT message does not fit");
    script = CScript(buf, buf + n);
    return true;
}

bool BuildSendScript(const uint256& token, const std::vector<uint64_t>& quantities, CScript& script, std::string& err)
{
    if (quantities.empty() || quantities.size() > MAX_SEND_OUTPUTS)
        return Fail(err, "a SEND carries 1 to 19 token outputs");
    unsigned char id[32], buf[600];
    WireTokenId(token, id);
    const size_t n = zcl_token_guard_build_send(buf, sizeof(buf), id, &quantities[0], (int)quantities.size());
    if (n == 0)
        return Fail(err, "the SEND message does not fit");
    script = CScript(buf, buf + n);
    return true;
}

bool LayoutSend(const uint256& token, const std::vector<Recipient>& recipients, uint64_t inputUnits,
                const CScript& changeScript, CAmount dust, TokenLayout& out, std::string& err)
{
    out = TokenLayout();
    if (recipients.empty())
        return Fail(err, "there is no recipient");
    uint64_t total = 0;
    for (size_t i = 0; i < recipients.size(); i++) {
        if (recipients[i].units == 0)
            return Fail(err, "every recipient amount must be greater than zero");
        if (!ScriptIsSpendableDestination(recipients[i].script))
            return Fail(err, "tokens can only be sent to transparent P2PKH or P2SH addresses");
        if (total > MAX_QUANTITY - recipients[i].units)
            return Fail(err, "the total amount is above 2^63-1 base units");
        total += recipients[i].units;
    }
    if (total > inputUnits)
        return Fail(err, "the amount is more than the token inputs hold (the message would be invalid)");
    if (!ScriptIsSpendableDestination(changeScript))
        return Fail(err, "the token change address is not a P2PKH or P2SH address");
    const uint64_t change = inputUnits - total;
    const size_t outputs = recipients.size() + (change > 0 ? 1 : 0);
    if (outputs > MAX_SEND_OUTPUTS)
        return Fail(err, strprintf("a SEND carries at most %u token outputs (including the change)", (unsigned)MAX_SEND_OUTPUTS));

    for (size_t i = 0; i < recipients.size(); i++)
        out.quantities.push_back(recipients[i].units);
    if (change > 0)
        out.quantities.push_back(change);
    CScript message;
    if (!BuildSendScript(token, out.quantities, message, err))
        return false;
    out.vout.push_back(CTxOut(0, message));
    for (size_t i = 0; i < recipients.size(); i++)
        out.vout.push_back(TokenOut(recipients[i].script, dust));
    if (change > 0)
        out.vout.push_back(TokenOut(changeScript, dust));
    out.tokenChange = change;
    return true;
}

bool LayoutBurn(const uint256& token, uint64_t burnUnits, uint64_t inputUnits, const CScript& changeScript,
                CAmount dust, TokenLayout& out, std::string& err)
{
    out = TokenLayout();
    if (burnUnits == 0)
        return Fail(err, "the burn amount must be greater than zero");
    if (burnUnits > inputUnits)
        return Fail(err, "the burn amount is more than the token inputs hold");
    if (!ScriptIsSpendableDestination(changeScript))
        return Fail(err, "the token change address is not a P2PKH or P2SH address");
    const uint64_t change = inputUnits - burnUnits;
    out.quantities.push_back(change);
    CScript message;
    if (!BuildSendScript(token, out.quantities, message, err))
        return false;
    out.vout.push_back(CTxOut(0, message));
    // quantity 0 still names vout[1]; give it a real dust output so the ZCL change, which follows, is not in a token slot
    out.vout.push_back(TokenOut(changeScript, dust));
    out.tokenChange = change;
    out.burned = burnUnits;
    return true;
}

bool LayoutGenesis(const GenesisParams& p, const CScript& ownerScript, const CScript& batonScript, CAmount dust,
                   TokenLayout& out, std::string& err)
{
    out = TokenLayout();
    CScript message;
    if (!BuildGenesisScript(p, message, err))
        return false;
    if (!ScriptIsSpendableDestination(ownerScript) || (p.baton && !ScriptIsSpendableDestination(batonScript)))
        return Fail(err, "token and baton addresses must be transparent P2PKH or P2SH addresses");
    out.vout.push_back(CTxOut(0, message));
    out.vout.push_back(TokenOut(ownerScript, dust));
    if (p.baton)
        out.vout.push_back(TokenOut(batonScript, dust));
    return true;
}

bool LayoutMint(const uint256& token, uint64_t quantity, const CScript& recipientScript, bool hasBaton,
                const CScript& batonScript, CAmount dust, TokenLayout& out, std::string& err)
{
    out = TokenLayout();
    CScript message;
    if (!BuildMintScript(token, quantity, hasBaton, message, err))
        return false;
    if (!ScriptIsSpendableDestination(recipientScript) || (hasBaton && !ScriptIsSpendableDestination(batonScript)))
        return Fail(err, "token and baton addresses must be transparent P2PKH or P2SH addresses");
    out.vout.push_back(CTxOut(0, message));
    out.vout.push_back(TokenOut(recipientScript, dust));
    if (hasBaton)
        out.vout.push_back(TokenOut(batonScript, dust));
    return true;
}

} // namespace zslp
