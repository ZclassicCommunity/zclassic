// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RPC surface of ZSLP token creation, minting, sending and burning (wallet side).
// The read-only token index commands are in rpc/zslp.cpp; this file is part of the wallet
// library, registered by RegisterWalletRPCCommands, and answers with the same clear
// error while the index is off (-zslpindex=0, the default).

#include "rpc/server.h"

#include "init.h"
#include "main.h"
#include "univalue.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "wallet/wallet.h"
#include "wallet/zslpsend.h"
#include "zslp/zslpindex.h"
#include "zslp/zslpservice.h"

#include <stdint.h>
#include <string>

using namespace std;
using namespace zslp;

namespace {

ZslpService& RequireIndex()
{
    if (!pzslpService)
        throw JSONRPCError(RPC_MISC_ERROR,
                           "The ZSLP token index is disabled. Start zclassicd with -zslpindex=1 (it builds in the background "
                           "and does not touch consensus or wallet.dat). See doc/zslp.md.");
    return *pzslpService;
}

UniValue Amount(uint64_t v, unsigned int decimals) { return UniValue(FormatAmount(v, decimals)); }

} // namespace


namespace {

/** An amount that must be a JSON string: a JSON number could be rounded by the client before it reaches us. */
string AmountString(const UniValue& v, const string& what)
{
    if (!v.isStr())
        throw JSONRPCError(RPC_INVALID_PARAMETER, what + " must be a string holding a decimal number, such as \"12.5\"");
    return v.get_str();
}

bool WantBool(const UniValue& v, const string& what)
{
    if (!v.isBool())
        throw JSONRPCError(RPC_INVALID_PARAMETER, what + " must be true or false");
    return v.get_bool();
}

CAmount FeeParam(const UniValue& v)
{
    if (v.isNull())
        return -1;
    const CAmount fee = AmountFromValue(v);
    if (fee < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "fee must not be negative");
    return fee;
}

int MinconfParam(const UniValue& v)
{
    if (v.isNull())
        return 1;
    if (!v.isNum())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "minconf must be a number");
    return v.get_int();
}

/** Common preconditions: the wallet, the index, an unlocked wallet. */
ZslpService& RequireTokenWallet()
{
    ZslpService& svc = RequireIndex();
    if (!pwalletMain)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (wallet disabled)");
    EnsureWalletIsUnlocked();
    return svc;
}

[[noreturn]] void ThrowWalletErr(const string& err, WalletErrKind kind)
{
    int code = RPC_WALLET_ERROR;
    if (kind == ERRK_PARAM) code = RPC_INVALID_PARAMETER;
    else if (kind == ERRK_TOKEN_FUNDS || kind == ERRK_ZCL_FUNDS) code = RPC_WALLET_INSUFFICIENT_FUNDS;
    throw JSONRPCError(code, err);
}

UniValue TokenTxJson(const TokenTxResult& r)
{
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("txid", r.txid.GetHex()));
    o.push_back(Pair("tokenid", r.token.GetHex()));
    o.push_back(Pair("type", r.kind));
    o.push_back(Pair("broadcast", r.broadcast));
    o.push_back(Pair("amount", Amount(r.units, r.decimals)));
    if (r.kind == "send" || r.kind == "burn") {
        o.push_back(Pair("tokenchange", Amount(r.tokenChange, r.decimals)));
        o.push_back(Pair("changeaddress", r.tokenChange > 0 ? UniValue(r.changeAddress) : UniValue()));
    }
    if (r.kind == "burn")
        o.push_back(Pair("burned", Amount(r.burned, r.decimals)));
    o.push_back(Pair("tokeninputs", (int)r.tokenInputs));
    o.push_back(Pair("fee", ValueFromAmount(r.fee)));
    if (!r.hex.empty())
        o.push_back(Pair("hex", r.hex));
    return o;
}

} // namespace

UniValue zslp_send(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
            "zslp_send \"tokenid\" [{\"address\":\"t1...\",\"amount\":\"1.5\"},...] ( minconf fee dryrun )\n"
            "\nSend ZSLP tokens to one or more transparent addresses (requires -zslpindex=1, synced).\n"
            "The tokens come from this wallet's own CONFIRMED outputs of that token that the index lists as valid;\n"
            "any token change returns to the address of the first token input. The ZCL for the fee and for the\n"
            "546-zatoshi token outputs comes from ordinary coins: token outputs and mint batons are never used for it.\n"
            "Before anything is sent the transaction is judged by the token rules; one that would be invalid, or burn\n"
            "anything, is refused. Use zslp_burn to destroy tokens on purpose.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"tokenid\"    (string, required) the GENESIS txid\n"
            "2. recipients   (array, required) [{\"address\":\"t1...\",\"amount\":\"1.50\"}]. A transparent address; the\n"
            "                amount is a decimal STRING with at most the token's decimals (nothing is rounded).\n"
            "3. minconf      (numeric, optional, default=1) minimum confirmations of the token outputs (at least 1)\n"
            "4. fee          (numeric or string, optional) the ZCL fee to pay instead of the wallet's normal fee\n"
            "5. dryrun       (boolean, optional, default=false) build and check, do not broadcast; the signed hex is returned\n"
            "\nResult:\n"
            "{ \"txid\", \"tokenid\", \"type\": \"send\", \"broadcast\": true|false, \"amount\" (sent), \"tokenchange\",\n"
            "  \"changeaddress\"|null, \"tokeninputs\": n, \"fee\" (ZCL), \"hex\" (dry run only) }\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_send", "\"tokenid\" \"[{\\\"address\\\":\\\"t1...\\\",\\\"amount\\\":\\\"1.5\\\"}]\"")
            + HelpExampleRpc("zslp_send", "\"tokenid\", [{\"address\":\"t1...\",\"amount\":\"1.5\"}]")
        );
    ZslpService& svc = RequireTokenWallet();
    SendRequest req;
    req.token = ParseHashV(params[0], "tokenid");
    if (!params[1].isArray() || params[1].size() == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "recipients must be a non-empty array of {\"address\",\"amount\"} objects");
    for (size_t i = 0; i < params[1].size(); i++) {
        const UniValue& e = params[1][i];
        if (!e.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "every recipient must be an object {\"address\",\"amount\"}");
        const vector<string> keys = e.getKeys();
        for (size_t k = 0; k < keys.size(); k++)
            if (keys[k] != "address" && keys[k] != "amount")
                throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown recipient field: " + keys[k]);
        const UniValue& a = find_value(e, "address");
        if (!a.isStr())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "every recipient needs an \"address\" string");
        req.to.push_back(make_pair(a.get_str(), AmountString(find_value(e, "amount"), "amount")));
    }
    if (params.size() > 2) req.minconf = MinconfParam(params[2]);
    if (params.size() > 3) req.fee = FeeParam(params[3]);
    if (params.size() > 4) req.dryRun = WantBool(params[4], "dryrun");
    TokenTxResult res;
    string err;
    WalletErrKind kind = ERRK_NONE;
    if (!WalletTokenSend(pwalletMain, svc, req, res, err, kind))
        ThrowWalletErr(err, kind);
    return TokenTxJson(res);
}

UniValue zslp_genesis(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "zslp_genesis {\"ticker\":\"TST\",\"name\":\"Test token\",\"decimals\":2,\"initialquantity\":\"1000.00\",...}\n"
            "\nCreate a ZSLP token (requires -zslpindex=1, synced). The token id is the txid of this transaction.\n"
            "The rules are Z23's: ticker 1-10 letters or digits, name 1-64 characters, decimals 0-8, a positive\n"
            "initial quantity of at most 2100000000000000 base units. The initial tokens and the mint baton go to\n"
            "fresh addresses of this wallet unless you name others.\n"
            + HelpRequiringPassphrase() +
            "\nArgument: an object with\n"
            "  \"ticker\"           (string, required)\n"
            "  \"name\"             (string, required)\n"
            "  \"decimals\"         (numeric, required) 0..8\n"
            "  \"initialquantity\"  (string, required) a decimal string with at most `decimals` fractional digits\n"
            "  \"documenturl\"      (string, optional) visible ASCII, at most 255 bytes\n"
            "  \"documenthash\"     (string|null, optional) 64 hex characters\n"
            "  \"batonaddress\"     (string|null, optional) where the mint baton goes. null: NO baton, the supply is\n"
            "                     fixed for good. Absent: a fresh address of this wallet.\n"
            "  \"address\"          (string, optional) where the initial tokens go (default: a fresh wallet address)\n"
            "  \"fee\"              (numeric or string, optional) ZCL fee\n"
            "  \"dryrun\"           (boolean, optional) build and check only\n"
            "\nResult: { \"txid\", \"tokenid\", \"type\": \"genesis\", \"broadcast\", \"amount\", \"tokeninputs\", \"fee\", \"hex\" (dry run) }\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_genesis", "\"{\\\"ticker\\\":\\\"TST\\\",\\\"name\\\":\\\"Test\\\",\\\"decimals\\\":2,\\\"initialquantity\\\":\\\"1000.00\\\"}\"")
        );
    ZslpService& svc = RequireTokenWallet();
    if (!params[0].isObject())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "the argument must be an object");
    const UniValue& o = params[0];
    static const char* known[] = {"ticker", "name", "decimals", "initialquantity", "documenturl", "documenthash",
                                  "batonaddress", "address", "fee", "dryrun"};
    const vector<string> keys = o.getKeys();
    for (size_t k = 0; k < keys.size(); k++) {
        bool ok = false;
        for (size_t j = 0; j < sizeof(known) / sizeof(known[0]); j++)
            ok = ok || keys[k] == known[j];
        if (!ok)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown field: " + keys[k]);
    }
    GenesisRequest req;
    const UniValue& ticker = find_value(o, "ticker");
    const UniValue& name = find_value(o, "name");
    const UniValue& decimals = find_value(o, "decimals");
    const UniValue& qty = find_value(o, "initialquantity");
    if (!ticker.isStr() || !name.isStr())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ticker and name must be strings");
    if (!decimals.isNum())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "decimals must be a number between 0 and 8");
    const int dec = decimals.get_int();
    if (dec < 0 || dec > (int)MAX_DECIMALS)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "decimals must be between 0 and 8");
    req.ticker = ticker.get_str();
    req.name = name.get_str();
    req.decimals = (unsigned int)dec;
    req.quantity = AmountString(qty, "initialquantity");
    const UniValue& url = find_value(o, "documenturl");
    if (!url.isNull()) {
        if (!url.isStr()) throw JSONRPCError(RPC_INVALID_PARAMETER, "documenturl must be a string");
        req.documentUrl = url.get_str();
    }
    const UniValue& dh = find_value(o, "documenthash");
    if (!dh.isNull()) {
        if (!dh.isStr()) throw JSONRPCError(RPC_INVALID_PARAMETER, "documenthash must be a hex string or null");
        req.documentHashHex = dh.get_str();
    }
    if (o.exists("batonaddress")) {
        const UniValue& b = find_value(o, "batonaddress");
        if (b.isNull() || (b.isStr() && b.get_str() == "null")) {
            req.hasBaton = false;
        } else if (b.isStr() && !b.get_str().empty()) {
            req.batonAddress = b.get_str();
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "batonaddress must be an address or null");
        }
    }
    const UniValue& addr = find_value(o, "address");
    if (!addr.isNull()) {
        if (!addr.isStr()) throw JSONRPCError(RPC_INVALID_PARAMETER, "address must be a string");
        req.address = addr.get_str();
    }
    req.fee = FeeParam(find_value(o, "fee"));
    if (o.exists("dryrun")) req.dryRun = WantBool(find_value(o, "dryrun"), "dryrun");
    TokenTxResult res;
    string err;
    WalletErrKind kind = ERRK_NONE;
    if (!WalletTokenGenesis(pwalletMain, svc, req, res, err, kind))
        ThrowWalletErr(err, kind);
    return TokenTxJson(res);
}

UniValue zslp_mint(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "zslp_mint \"tokenid\" \"amount\" ( \"batonaddress\"|null {options} )\n"
            "\nMint more of a token whose mint baton this wallet holds, confirmed (requires -zslpindex=1, synced).\n"
            "The baton is spent and a new one is created, at the address the old one was at unless you name another;\n"
            "pass null to create NO new baton, which closes the supply for good. The minted tokens go to a fresh\n"
            "address of this wallet unless options.address says otherwise.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"tokenid\"         (string, required)\n"
            "2. \"amount\"          (string, required) a decimal string with at most the token's decimals\n"
            "3. \"batonaddress\"    (string or null, optional) where the new baton goes; null (or the string \"null\"): none\n"
            "4. options           (object, optional) {\"address\":\"t1..\" (minted tokens), \"minconf\":n, \"fee\":x, \"dryrun\":bool}\n"
            "\nResult: { \"txid\", \"tokenid\", \"type\": \"mint\", \"broadcast\", \"amount\", \"tokeninputs\", \"fee\", \"hex\" (dry run) }\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_mint", "\"tokenid\" \"100.00\"")
        );
    ZslpService& svc = RequireTokenWallet();
    MintRequest req;
    req.token = ParseHashV(params[0], "tokenid");
    req.quantity = AmountString(params[1], "amount");
    if (params.size() > 2) {
        if (params[2].isNull() || (params[2].isStr() && params[2].get_str() == "null"))
            req.hasBaton = false;
        else if (params[2].isStr() && !params[2].get_str().empty())
            req.batonAddress = params[2].get_str();
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "batonaddress must be an address or null");
    }
    if (params.size() > 3) {
        const UniValue& o = params[3];
        if (!o.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
        const vector<string> keys = o.getKeys();
        for (size_t k = 0; k < keys.size(); k++)
            if (keys[k] != "address" && keys[k] != "minconf" && keys[k] != "fee" && keys[k] != "dryrun")
                throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown option: " + keys[k]);
        const UniValue& a = find_value(o, "address");
        if (!a.isNull()) {
            if (!a.isStr()) throw JSONRPCError(RPC_INVALID_PARAMETER, "address must be a string");
            req.address = a.get_str();
        }
        req.minconf = MinconfParam(find_value(o, "minconf"));
        req.fee = FeeParam(find_value(o, "fee"));
        if (o.exists("dryrun")) req.dryRun = WantBool(find_value(o, "dryrun"), "dryrun");
    }
    TokenTxResult res;
    string err;
    WalletErrKind kind = ERRK_NONE;
    if (!WalletTokenMint(pwalletMain, svc, req, res, err, kind))
        ThrowWalletErr(err, kind);
    return TokenTxJson(res);
}

UniValue zslp_burn(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "zslp_burn \"tokenid\" \"amount\" confirm ( {options} )\n"
            "\nDestroy tokens on purpose. This is the ONLY way this wallet burns tokens, and it is irreversible: the\n"
            "burned units no longer exist. The tokens come from this wallet's confirmed outputs of that token and\n"
            "the rest returns to the wallet as token change. confirm must be true (a dry run does not need it).\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"tokenid\"   (string, required)\n"
            "2. \"amount\"    (string, required) decimal string with at most the token's decimals\n"
            "3. confirm     (boolean, required) true: I want these tokens destroyed\n"
            "4. options     (object, optional) {\"minconf\":n, \"fee\":x, \"dryrun\":bool}\n"
            "\nResult: { \"txid\", \"tokenid\", \"type\": \"burn\", \"broadcast\", \"amount\", \"burned\", \"tokenchange\",\n"
            "          \"changeaddress\", \"tokeninputs\", \"fee\", \"hex\" (dry run) }\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_burn", "\"tokenid\" \"5\" true")
        );
    ZslpService& svc = RequireTokenWallet();
    BurnRequest req;
    req.token = ParseHashV(params[0], "tokenid");
    req.quantity = AmountString(params[1], "amount");
    bool confirm = false;
    if (params.size() > 2 && !params[2].isNull())
        confirm = WantBool(params[2], "confirm");
    if (params.size() > 3) {
        const UniValue& o = params[3];
        if (!o.isObject())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
        const vector<string> keys = o.getKeys();
        for (size_t k = 0; k < keys.size(); k++)
            if (keys[k] != "minconf" && keys[k] != "fee" && keys[k] != "dryrun")
                throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown option: " + keys[k]);
        req.minconf = MinconfParam(find_value(o, "minconf"));
        req.fee = FeeParam(find_value(o, "fee"));
        if (o.exists("dryrun")) req.dryRun = WantBool(find_value(o, "dryrun"), "dryrun");
    }
    if (!req.dryRun && !confirm)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "burning destroys tokens for good; pass confirm=true to do it (nothing was sent)");
    TokenTxResult res;
    string err;
    WalletErrKind kind = ERRK_NONE;
    if (!WalletTokenBurn(pwalletMain, svc, req, res, err, kind))
        ThrowWalletErr(err, kind);
    return TokenTxJson(res);
}
