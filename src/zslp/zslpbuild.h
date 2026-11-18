// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ZSLP token transaction layout: the pure part of token creation, minting,
// sending and burning. No wallet, no chain, no I/O: exact amount parsing, the
// SLP messages (built by Z23's own builders, vendored under src/c23/services)
// and the output ORDER of a token transaction. The wallet side that picks
// inputs, signs and broadcasts is src/wallet/zslpsend.cpp.
//
// Layout (the one Z23's contexts/market/services/src/zslp_command_service.c
// writes, and the SLP Token Type 1 layout):
//
//   vout[0]      OP_RETURN <SLP message>, value 0
//   vout[1..n]   the token outputs, each ZSLP_TOKEN_DUST zatoshi:
//                  GENESIS  vout[1] the initial quantity, vout[2] the mint baton (optional)
//                  MINT     vout[1] the new quantity,     vout[2] the new mint baton (optional)
//                  SEND     vout[i+1] is quantity i: the recipients in the order given, then the
//                           token change (to the address of the first token input)
//   vout[n+1]    the ZCL change, LAST, so it can never take a token slot
//
// Nothing here is consensus, mempool policy or relay.

#ifndef BITCOIN_ZSLP_ZSLPBUILD_H
#define BITCOIN_ZSLP_ZSLPBUILD_H

#include "amount.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "uint256.h"

#include <stdint.h>
#include <string>
#include <vector>

namespace zslp {

//! Value of every token and baton output: Z23's ZSLP_DUST_ZAT (the SLP convention). zclassicd's default
//! -minrelaytxfee (100 zatoshi/kB) puts the P2PKH dust threshold at 54, so 546 relays; TokenDust() raises it
//! when the local policy asks for more (a -minrelaytxfee above 0.00001 ZCL/kB).
static const CAmount TOKEN_DUST = 546;

//! Z23's creation limits (zslp_service.h): ticker 1..10 alphanumeric, name 1..64, decimals 0..8,
//! initial supply at most 2.1e15 base units.
static const size_t MAX_TICKER_LEN = 10;
static const size_t MAX_NAME_LEN = 64;
static const unsigned int MAX_DECIMALS = 8;
static const uint64_t MAX_GENESIS_SUPPLY = 2100000000000000ULL;
//! A quantity or sum above this is UNKNOWN to Z23's validity rules (it does not fit a signed 64-bit number).
static const uint64_t MAX_QUANTITY = 9223372036854775807ULL;
//! A SEND names at most this many outputs (vout[1]..vout[19]).
static const size_t MAX_SEND_OUTPUTS = 19;

/** The dust value to give token outputs under the current -minrelaytxfee: TOKEN_DUST, or more if the node's
 *  own dust threshold for a P2PKH output is higher. */
CAmount TokenDust(const CFeeRate& minRelay);

/**
 * Parse a decimal string into base units with `decimals` fractional digits, exactly.
 * Accepts "12", "12.5", "0.00000001", ".5" is refused. No sign, no exponent, no spaces, no separators.
 * Refuses more fractional digits than `decimals` (nothing is rounded), a value of 2^64 or more, and an
 * empty string. A zero value is returned as 0 (callers decide whether zero is allowed).
 */
bool ParseUnits(const std::string& text, unsigned int decimals, uint64_t& units, std::string& err);

/** The same value as a base-unit integer, requiring 1 <= units <= MAX_QUANTITY. */
bool ParsePositiveQuantity(const std::string& text, unsigned int decimals, uint64_t& units, std::string& err);

/** The 32 bytes of an SLP message token id: the GENESIS txid as displayed (the reverse of the internal byte order). */
void WireTokenId(const uint256& token, unsigned char out[32]);

struct GenesisParams {
    std::string ticker, name, documentUrl;
    bool hasDocumentHash;
    unsigned char documentHash[32];
    unsigned int decimals;
    uint64_t quantity; //! initial quantity, base units, > 0 (as Z23)
    bool baton;        //! create a mint baton at vout[2]
    GenesisParams() : hasDocumentHash(false), decimals(0), quantity(0), baton(true)
    {
        for (int i = 0; i < 32; i++) documentHash[i] = 0;
    }
};

/** Z23's creation rules (zslp_service_validate_create_request) plus the limits of the message itself. */
bool ValidateGenesis(const GenesisParams& p, std::string& err);

/** The SLP messages, as the OP_RETURN scriptPubKey. All use Z23's builders; false (with err) when invalid input. */
bool BuildGenesisScript(const GenesisParams& p, CScript& script, std::string& err);
bool BuildMintScript(const uint256& token, uint64_t quantity, bool baton, CScript& script, std::string& err);
bool BuildSendScript(const uint256& token, const std::vector<uint64_t>& quantities, CScript& script, std::string& err);

struct Recipient {
    CScript script; //! P2PKH or P2SH
    uint64_t units;
    Recipient() : units(0) {}
};

/** A planned token transaction: the outputs in order (vout[0] is the OP_RETURN), without the ZCL change. */
struct TokenLayout {
    std::vector<CTxOut> vout;
    std::vector<uint64_t> quantities; //! SEND: quantity of vout[i+1]; empty otherwise
    uint64_t tokenChange;             //! SEND/BURN: units returned to the wallet
    uint64_t burned;                  //! units destroyed on purpose (BURN), 0 otherwise
    TokenLayout() : tokenChange(0), burned(0) {}
};

/**
 * SEND: recipients first (in order), then the token change when inputUnits exceeds the total sent.
 * Refuses a zero recipient amount, no recipients, more than MAX_SEND_OUTPUTS token outputs, and a total
 * above inputUnits (it would be INVALID) or above MAX_QUANTITY.
 */
bool LayoutSend(const uint256& token, const std::vector<Recipient>& recipients, uint64_t inputUnits,
                const CScript& changeScript, CAmount dust, TokenLayout& out, std::string& err);

/**
 * BURN, the only deliberate burn: a SEND whose outputs add up to inputUnits - burnUnits. The change goes to
 * changeScript. When the whole selection is burned the message still needs one quantity (0); vout[1] is then a
 * dust output to changeScript so that the ZCL change can not take the (protected) zero-quantity slot.
 */
bool LayoutBurn(const uint256& token, uint64_t burnUnits, uint64_t inputUnits, const CScript& changeScript,
                CAmount dust, TokenLayout& out, std::string& err);

/** GENESIS: vout[1] to ownerScript, vout[2] (when p.baton) to batonScript. */
bool LayoutGenesis(const GenesisParams& p, const CScript& ownerScript, const CScript& batonScript, CAmount dust,
                   TokenLayout& out, std::string& err);

/** MINT: vout[1] to recipientScript, vout[2] (when hasBaton) to batonScript. */
bool LayoutMint(const uint256& token, uint64_t quantity, const CScript& recipientScript, bool hasBaton,
                const CScript& batonScript, CAmount dust, TokenLayout& out, std::string& err);

} // namespace zslp

#endif // BITCOIN_ZSLP_ZSLPBUILD_H
