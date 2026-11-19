// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RPC surface of the ZSLP token index (read-only). Every command answers with a
// clear error while the index is off (-zslpindex=0, the default).

#include "rpc/server.h"

#include "init.h"
#include "main.h"
#include "script/standard.h"
#include "univalue.h"
#include "util.h"
#include "utilstrencodings.h"
#include "zslp/zslpindex.h"
#include "zslp/zslpservice.h"
#ifdef ENABLE_WALLET
#include "wallet/tokenguard.h"
#include "wallet/wallet.h"
#endif

#include <boost/assign/list_of.hpp>
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

/** A string that is certain to be valid UTF-8: tickers and names are arbitrary bytes chosen by the token creator. */
string Utf8Clean(const string& s)
{
    string out;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = (unsigned char)s[i];
        size_t n = c < 0x80 ? 1 : (c >= 0xc2 && c <= 0xdf) ? 2 : (c >= 0xe0 && c <= 0xef) ? 3 : (c >= 0xf0 && c <= 0xf4) ? 4 : 0;
        bool ok = n != 0 && i + n <= s.size();
        for (size_t k = 1; ok && k < n; k++)
            ok = ((unsigned char)s[i + k] & 0xc0) == 0x80;
        if (ok && n == 3) {
            unsigned char d = (unsigned char)s[i + 1];
            ok = !(c == 0xe0 && d < 0xa0) && !(c == 0xed && d >= 0xa0);
        }
        if (ok && n == 4) {
            unsigned char d = (unsigned char)s[i + 1];
            ok = !(c == 0xf0 && d < 0x90) && !(c == 0xf4 && d >= 0x90);
        }
        if (ok && n == 1 && c < 0x20)
            ok = false;
        if (ok) {
            out.append(s, i, n);
            i += n;
        } else {
            out += "?";
            i++;
        }
    }
    return out;
}

UniValue Amount(uint64_t v, unsigned int decimals) { return UniValue(FormatAmount(v, decimals)); }

UniValue TokenJson(const TokenInfo& t)
{
    UniValue o(UniValue::VOBJ);
    uint64_t burned = t.sendBurned;
    bool overflow = t.supplyOverflow;
    if (t.spentBurned > UINT64_MAX - burned) {
        overflow = true;
        burned = UINT64_MAX;
    } else {
        burned += t.spentBurned;
    }
    o.push_back(Pair("tokenid", t.id.GetHex()));
    o.push_back(Pair("ticker", Utf8Clean(t.ticker)));
    o.push_back(Pair("name", Utf8Clean(t.name)));
    o.push_back(Pair("decimals", (int)t.decimals));
    o.push_back(Pair("documenturi", Utf8Clean(t.documentUrl)));
    o.push_back(Pair("documenthash", t.hasDocumentHash ? UniValue(HexStr(t.documentHash.begin(), t.documentHash.end())) : UniValue()));
    o.push_back(Pair("genesisheight", t.genesisHeight));
    o.push_back(Pair("totalminted", Amount(t.minted, t.decimals)));
    o.push_back(Pair("totalburned", Amount(burned, t.decimals)));
    o.push_back(Pair("burnedinsends", Amount(t.sendBurned, t.decimals)));
    o.push_back(Pair("burnedbyspending", Amount(t.spentBurned, t.decimals)));
    o.push_back(Pair("circulating", overflow || burned > t.minted ? UniValue() : Amount(t.minted - burned, t.decimals)));
    o.push_back(Pair("supplyoverflow", overflow));
    if (t.hasBaton) {
        UniValue b(UniValue::VOBJ);
        b.push_back(Pair("txid", t.batonTx.GetHex()));
        b.push_back(Pair("vout", (int)t.batonVout));
        o.push_back(Pair("mintbaton", b));
    } else {
        o.push_back(Pair("mintbaton", UniValue()));
    }
    o.push_back(Pair("transactions", (int)t.nTx));
    return o;
}

const char* StatusName(int s) { return s == STATUS_VALID ? "valid" : s == STATUS_INVALID ? "invalid" : "unknown"; }
const char* RoleName(int r) { return r == ROLE_TOKEN ? "token" : "mintbaton"; }
const char* TypeName(int t) { return t == 1 ? "GENESIS" : t == 2 ? "MINT" : t == 3 ? "SEND" : "NONE"; }

UniValue ServiceJson(ZslpService& svc)
{
    ServiceInfo si = svc.GetInfo();
    IndexStats st = svc.Index().GetStats();
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("enabled", true));
    o.push_back(Pair("running", si.running));
    o.push_back(Pair("synced", si.synced));
    o.push_back(Pair("startheight", si.startHeight));
    o.push_back(Pair("indexedheight", si.hasIndexed ? UniValue(si.indexedHeight) : UniValue()));
    o.push_back(Pair("indexedblock", si.hasIndexed ? UniValue(si.indexedHash.GetHex()) : UniValue()));
    o.push_back(Pair("chainheight", si.chainHeight));
    double progress = 1.0;
    if (si.chainHeight >= si.startHeight) {
        const double total = (double)(si.chainHeight - si.startHeight + 1);
        const double done = si.hasIndexed ? (double)(si.indexedHeight - si.startHeight + 1) : 0.0;
        progress = done >= total ? 1.0 : done < 0 ? 0.0 : done / total;
    }
    o.push_back(Pair("progress", progress));
    o.push_back(Pair("error", si.error.empty() ? UniValue() : UniValue(si.error)));
    o.push_back(Pair("tokens", (int64_t)st.tokens));
    o.push_back(Pair("validtransactions", (int64_t)st.txValid));
    o.push_back(Pair("invalidtransactions", (int64_t)st.txInvalid));
    o.push_back(Pair("unknowntransactions", (int64_t)st.txUnknown));
    o.push_back(Pair("burntransactions", (int64_t)st.txBurn));
    o.push_back(Pair("genesismessages", (int64_t)st.nGenesis));
    o.push_back(Pair("mintmessages", (int64_t)st.nMint));
    o.push_back(Pair("sendmessages", (int64_t)st.nSend));
    o.push_back(Pair("unrepresentablequantities", (int64_t)st.nUnrepresentable));
    o.push_back(Pair("overflowingquantities", (int64_t)st.nOverflow));
    o.push_back(Pair("unspentoutputs", (int64_t)st.unspentOutputs));
    return o;
}

string TickerOf(const ZslpIndex& idx, const uint256& token, unsigned int& decimals)
{
    TokenInfo t;
    decimals = 0;
    if (!idx.GetToken(token, t))
        return "";
    decimals = t.decimals;
    return Utf8Clean(t.ticker);
}

} // namespace

UniValue zslp_getindexinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "zslp_getindexinfo\n"
            "\nProgress and counters of the ZSLP token index (requires -zslpindex=1).\n"
            "\nResult:\n"
            "{\n"
            "  \"enabled\": true,\n"
            "  \"running\": true|false,       (boolean) the background worker is alive\n"
            "  \"synced\": true|false,        (boolean) the index tip is the chain tip\n"
            "  \"startheight\": n,            (numeric) first block the index reads (the first SLP block on mainnet)\n"
            "  \"indexedheight\": n|null,     (numeric) height of the last block applied\n"
            "  \"indexedblock\": \"hash\"|null,\n"
            "  \"chainheight\": n,\n"
            "  \"progress\": x,               (numeric) 0..1\n"
            "  \"error\": \"text\"|null,        (string) a problem the worker is retrying\n"
            "  \"tokens\": n, \"validtransactions\": n, \"invalidtransactions\": n, \"unknowntransactions\": n,\n"
            "  \"burntransactions\": n,       (numeric) ordinary transactions that spent token outputs\n"
            "  \"unspentoutputs\": n,\n"
            "  \"genesismessages\": n, \"mintmessages\": n, \"sendmessages\": n,   (numeric) every parsed SLP message, valid or not\n"
            "  \"unrepresentablequantities\": n,   (numeric) unknown: a quantity or sum above 2^63-1\n"
            "  \"overflowingquantities\": n        (numeric) invalid: a sum above 2^64-1\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_getindexinfo", "")
            + HelpExampleRpc("zslp_getindexinfo", "")
        );
    return ServiceJson(RequireIndex());
}

UniValue zslp_listtokens(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "zslp_listtokens ( skip count )\n"
            "\nList ZSLP tokens with a valid GENESIS, ordered by token id (requires -zslpindex=1).\n"
            "\nArguments:\n"
            "1. skip     (numeric, optional, default=0)\n"
            "2. count    (numeric, optional, default=100, max 1000)\n"
            "\nResult: array of token objects, as in zslp_gettoken. Amounts are decimal strings.\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_listtokens", "0 20")
            + HelpExampleRpc("zslp_listtokens", "0, 20")
        );
    ZslpService& svc = RequireIndex();
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM)(UniValue::VNUM));
    int skip = params.size() > 0 ? params[0].get_int() : 0;
    int count = params.size() > 1 ? params[1].get_int() : 100;
    if (skip < 0 || count < 1 || count > 1000)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "skip must be >= 0 and count 1..1000");
    UniValue r(UniValue::VARR);
    vector<TokenInfo> v = svc.Index().ListTokens((size_t)skip, (size_t)count);
    for (size_t i = 0; i < v.size(); i++)
        r.push_back(TokenJson(v[i]));
    return r;
}

UniValue zslp_gettoken(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "zslp_gettoken \"tokenid\" ( holders )\n"
            "\nOne ZSLP token (requires -zslpindex=1). The token id is the txid of its GENESIS.\n"
            "\nArguments:\n"
            "1. \"tokenid\"   (string, required)\n"
            "2. holders     (numeric, optional, default=0) list up to this many holders (max 1000)\n"
            "\nResult:\n"
            "{\n"
            "  \"tokenid\", \"ticker\", \"name\", \"decimals\", \"documenturi\", \"documenthash\"|null, \"genesisheight\",\n"
            "  \"totalminted\", \"totalburned\", \"burnedinsends\", \"burnedbyspending\", \"circulating\",   (strings)\n"
            "  \"supplyoverflow\",       (boolean) a sum exceeded 2^64-1\n"
            "  \"mintbaton\": {\"txid\", \"vout\"}|null,\n"
            "  \"transactions\": n,\n"
            "  \"holders\": [{\"address\", \"amount\"}]   (only when asked)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_gettoken", "\"txid\"")
            + HelpExampleRpc("zslp_gettoken", "\"txid\"")
        );
    ZslpService& svc = RequireIndex();
    uint256 id = ParseHashV(params[0], "tokenid");
    int nHolders = params.size() > 1 ? params[1].get_int() : 0;
    if (nHolders < 0 || nHolders > 1000)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "holders must be 0..1000");
    TokenInfo t;
    if (!svc.Index().GetToken(id, t))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No ZSLP token with this id in the index (it may not be indexed yet: see zslp_getindexinfo)");
    UniValue o = TokenJson(t);
    if (nHolders > 0) {
        UniValue h(UniValue::VARR);
        vector<HolderBalance> v = svc.Index().GetHolders(id, 0, (size_t)nHolders);
        for (size_t i = 0; i < v.size(); i++) {
            UniValue e(UniValue::VOBJ);
            e.push_back(Pair("address", AddrKeyToString(v[i].addr)));
            e.push_back(Pair("amount", Amount(v[i].amount, t.decimals)));
            h.push_back(e);
        }
        o.push_back(Pair("holders", h));
    }
    return o;
}

UniValue zslp_listtransactions(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "zslp_listtransactions \"tokenid\" ( skip count )\n"
            "\nThe SLP transactions that name one token, valid or not, oldest first (requires -zslpindex=1).\n"
            "\nArguments:\n"
            "1. \"tokenid\"   (string, required)\n"
            "2. skip        (numeric, optional, default=0)\n"
            "3. count       (numeric, optional, default=100, max 1000)\n"
            "\nResult: [{\"txid\", \"height\", \"type\": \"GENESIS|MINT|SEND|NONE\", \"validity\": \"valid|invalid|unknown|burn\"}]\n"
            "NONE/burn is an ordinary transaction that spent outputs of this token.\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_listtransactions", "\"txid\" 0 20")
            + HelpExampleRpc("zslp_listtransactions", "\"txid\", 0, 20")
        );
    ZslpService& svc = RequireIndex();
    uint256 id = ParseHashV(params[0], "tokenid");
    int skip = params.size() > 1 ? params[1].get_int() : 0;
    int count = params.size() > 2 ? params[2].get_int() : 100;
    if (skip < 0 || count < 1 || count > 1000)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "skip must be >= 0 and count 1..1000");
    UniValue r(UniValue::VARR);
    vector<TxRef> v = svc.Index().ListTokenTransactions(id, (size_t)skip, (size_t)count);
    for (size_t i = 0; i < v.size(); i++) {
        UniValue e(UniValue::VOBJ);
        e.push_back(Pair("txid", v[i].txid.GetHex()));
        e.push_back(Pair("height", v[i].height));
        e.push_back(Pair("type", TypeName(v[i].type)));
        e.push_back(Pair("validity", v[i].type == 0 ? "burn" : StatusName(v[i].status)));
        r.push_back(e);
    }
    return r;
}

UniValue zslp_getbalances(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "zslp_getbalances \"address\"\n"
            "\nUnspent ZSLP token balances held by one transparent address (requires -zslpindex=1).\n"
            "\nArguments:\n"
            "1. \"address\"   (string, required) a t-address, or \"script:<hash160>\" for a non-standard script\n"
            "\nResult:\n"
            "{\n"
            "  \"address\": \"...\",\n"
            "  \"synced\": true|false,   (boolean) false while the index is still building\n"
            "  \"balances\": [{\"tokenid\", \"ticker\", \"decimals\", \"amount\"}]   (amount is a decimal string)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_getbalances", "\"t1...\"")
            + HelpExampleRpc("zslp_getbalances", "\"t1...\"")
        );
    ZslpService& svc = RequireIndex();
    string key;
    if (!AddrKeyFromString(params[0].get_str(), key))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid ZClassic transparent address");
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("address", params[0].get_str()));
    o.push_back(Pair("synced", svc.GetInfo().synced));
    UniValue b(UniValue::VARR);
    vector<HolderBalance> v = svc.Index().GetBalances(key);
    for (size_t i = 0; i < v.size(); i++) {
        unsigned int dec = 0;
        string ticker = TickerOf(svc.Index(), v[i].token, dec);
        UniValue e(UniValue::VOBJ);
        e.push_back(Pair("tokenid", v[i].token.GetHex()));
        e.push_back(Pair("ticker", ticker));
        e.push_back(Pair("decimals", (int)dec));
        e.push_back(Pair("amount", Amount(v[i].amount, dec)));
        b.push_back(e);
    }
    o.push_back(Pair("balances", b));
    return o;
}

UniValue zslp_gettransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "zslp_gettransaction \"txid\"\n"
            "\nThe token view of one transaction: its SLP message type, validity, and the token outputs it\n"
            "spent and created (requires -zslpindex=1). A transaction the index never saw as a token\n"
            "transaction, and that spent no token output, is an error.\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\", \"type\": \"GENESIS|MINT|SEND|NONE\", \"validity\": \"valid|invalid|unknown\", \"reason\",\n"
            "  \"tokenid\"|null, \"height\", \"inputamount\", \"outputamount\", \"mintedamount\", \"burnedamount\",\n"
            "  \"inputs\": [{\"txid\", \"vout\", \"tokenid\", \"role\", \"amount\"}],\n"
            "  \"outputs\": [{\"vout\", \"tokenid\", \"role\", \"amount\", \"address\"}]\n"
            "}\n"
            "A type of NONE is an ordinary transaction that spent token outputs, burning them.\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_gettransaction", "\"txid\"")
            + HelpExampleRpc("zslp_gettransaction", "\"txid\"")
        );
    ZslpService& svc = RequireIndex();
    uint256 txid = ParseHashV(params[0], "txid");
    TxInfo t;
    if (!svc.Index().GetTx(txid, t))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Not a ZSLP transaction in the index (it may not be indexed yet: see zslp_getindexinfo)");
    unsigned int dec = 0;
    if (t.type != 0)
        TickerOf(svc.Index(), t.token, dec);
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("txid", txid.GetHex()));
    o.push_back(Pair("type", TypeName(t.type)));
    o.push_back(Pair("validity", t.type == 0 ? "burn" : StatusName(t.status)));
    o.push_back(Pair("reason", t.reason));
    o.push_back(Pair("tokenid", t.type == 0 ? UniValue() : UniValue(t.token.GetHex())));
    o.push_back(Pair("height", t.height));
    o.push_back(Pair("inputamount", Amount(t.inputUnits, dec)));
    o.push_back(Pair("outputamount", Amount(t.outputUnits, dec)));
    o.push_back(Pair("mintedamount", Amount(t.mintedUnits, dec)));
    o.push_back(Pair("burnedamount", t.type == 0 ? UniValue() : Amount(t.burnedUnits, dec)));
    UniValue ins(UniValue::VARR), outs(UniValue::VARR);
    for (size_t i = 0; i < t.inputs.size(); i++) {
        unsigned int d = 0;
        TickerOf(svc.Index(), t.inputs[i].token, d);
        UniValue e(UniValue::VOBJ);
        e.push_back(Pair("txid", t.inputs[i].txid.GetHex()));
        e.push_back(Pair("vout", (int)t.inputs[i].vout));
        e.push_back(Pair("tokenid", t.inputs[i].token.GetHex()));
        e.push_back(Pair("role", RoleName(t.inputs[i].role)));
        e.push_back(Pair("amount", Amount(t.inputs[i].amount, d)));
        ins.push_back(e);
    }
    for (size_t i = 0; i < t.outputs.size(); i++) {
        UniValue e(UniValue::VOBJ);
        e.push_back(Pair("vout", (int)t.outputs[i].vout));
        e.push_back(Pair("tokenid", t.outputs[i].token.GetHex()));
        e.push_back(Pair("role", RoleName(t.outputs[i].role)));
        e.push_back(Pair("amount", Amount(t.outputs[i].amount, dec)));
        e.push_back(Pair("address", AddrKeyToString(t.outputs[i].addr)));
        outs.push_back(e);
    }
    o.push_back(Pair("inputs", ins));
    o.push_back(Pair("outputs", outs));
    return o;
}

#ifdef ENABLE_WALLET
UniValue zslp_listunspent(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "zslp_listunspent ( minconf )\n"
            "\nThe wallet's unspent ZSLP token outputs and mint batons, from the token index (requires -zslpindex=1).\n"
            "These outputs are protected: the wallet never spends them as ordinary funds, because that would burn the\n"
            "tokens. This command only reads.\n"
            "\nArguments:\n"
            "1. minconf   (numeric, optional, default=1)\n"
            "\nResult:\n"
            "{\n"
            "  \"synced\": true|false,\n"
            "  \"outputs\": [{\"txid\", \"vout\", \"address\", \"tokenid\", \"ticker\", \"decimals\", \"role\": \"token|mintbaton\",\n"
            "                 \"amount\", \"confirmations\", \"protected\": true}],\n"
            "  \"balances\": [{\"tokenid\", \"ticker\", \"decimals\", \"amount\"}]   (sum of the token outputs above)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_listunspent", "")
            + HelpExampleRpc("zslp_listunspent", "")
        );
    ZslpService& svc = RequireIndex();
    if (!pwalletMain)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (wallet disabled)");
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM));
    int nMinDepth = params.size() > 0 ? params[0].get_int() : 1;

    const bool fSynced = svc.GetInfo().synced;
    UniValue outputs(UniValue::VARR);
    map<uint256, uint64_t> totals;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    vector<COutput> coins;
    pwalletMain->AvailableCoins(coins, false, NULL, true);
    for (size_t i = 0; i < coins.size(); i++) {
        const COutput& c = coins[i];
        if (c.nDepth < nMinDepth)
            continue;
        OutInfo oi;
        if (!svc.Index().GetOutput(c.tx->GetHash(), c.i, oi))
            continue;
        unsigned int dec = 0;
        string ticker = TickerOf(svc.Index(), oi.token, dec);
        UniValue e(UniValue::VOBJ);
        e.push_back(Pair("txid", c.tx->GetHash().GetHex()));
        e.push_back(Pair("vout", c.i));
        e.push_back(Pair("address", AddrKeyToString(oi.addr)));
        e.push_back(Pair("tokenid", oi.token.GetHex()));
        e.push_back(Pair("ticker", ticker));
        e.push_back(Pair("decimals", (int)dec));
        e.push_back(Pair("role", RoleName(oi.role)));
        e.push_back(Pair("amount", Amount(oi.amount, dec)));
        e.push_back(Pair("confirmations", c.nDepth));
        e.push_back(Pair("protected", TokenGuardOutputRole(*c.tx, c.i) != TOKEN_ROLE_NONE));
        outputs.push_back(e);
        if (oi.role == ROLE_TOKEN) {
            uint64_t& sum = totals[oi.token];
            sum = oi.amount > UINT64_MAX - sum ? UINT64_MAX : sum + oi.amount; // saturate, never wrap
        }
    }
    UniValue balances(UniValue::VARR);
    for (map<uint256, uint64_t>::const_iterator it = totals.begin(); it != totals.end(); ++it) {
        unsigned int dec = 0;
        string ticker = TickerOf(svc.Index(), it->first, dec);
        UniValue e(UniValue::VOBJ);
        e.push_back(Pair("tokenid", it->first.GetHex()));
        e.push_back(Pair("ticker", ticker));
        e.push_back(Pair("decimals", (int)dec));
        e.push_back(Pair("amount", Amount(it->second, dec)));
        balances.push_back(e);
    }
    UniValue r(UniValue::VOBJ);
    r.push_back(Pair("synced", fSynced));
    r.push_back(Pair("outputs", outputs));
    r.push_back(Pair("balances", balances));
    return r;
}
#endif // ENABLE_WALLET

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "zslp",               "zslp_getindexinfo",      &zslp_getindexinfo,      true  },
    { "zslp",               "zslp_listtokens",        &zslp_listtokens,        true  },
    { "zslp",               "zslp_gettoken",          &zslp_gettoken,          true  },
    { "zslp",               "zslp_listtransactions",  &zslp_listtransactions,  true  },
    { "zslp",               "zslp_getbalances",       &zslp_getbalances,       true  },
    { "zslp",               "zslp_gettransaction",    &zslp_gettransaction,    true  },
#ifdef ENABLE_WALLET
    { "zslp",               "zslp_listunspent",       &zslp_listunspent,       true  },
#endif
};

void RegisterZslpRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
