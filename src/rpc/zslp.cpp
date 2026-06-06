// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP read-only RPCs. All commands here are pure reads of the ZSLP token
// store (populated by the NON-consensus indexer). They never construct,
// sign, or broadcast transactions and never touch validation/PoW.
//
//   zslp_gettoken      "token_id"            -> token metadata
//   zslp_listtokens    (count, from)         -> bounded token list
//   zslp_listtransfers "token_id" (count, from) -> bounded transfer list
//   zslp_listmytokens                        -> tokens with balance>0 at the
//                                               wallet's t-addresses

#include "rpc/server.h"

#include "key_io.h"
#include "rpc/protocol.h"
#include "script/standard.h"
#include "util.h"
#include "zslp/zslpindexer.h"
#include "zslp/zslpstore.h"

#ifdef ENABLE_WALLET
#include "init.h"          // pwalletMain
#include "main.h"          // cs_main
#include "wallet/wallet.h"
#endif

#include <stdint.h>
#include <univalue.h>

// Return the active store or throw a friendly error when the index is off.
static CZSLPStore* GetZSLPStoreOrThrow()
{
    if (g_zslpIndexer == NULL || g_zslpIndexer->Store() == NULL)
        throw JSONRPCError(RPC_MISC_ERROR,
            "ZSLP index is not enabled. Start zclassicd with -zslpindex.");
    return g_zslpIndexer->Store();
}

static UniValue TokenToJSON(const CZSLPToken& t)
{
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("tokenid", t.tokenId.GetHex()));
    o.push_back(Pair("ticker", t.ticker));
    o.push_back(Pair("name", t.name));
    o.push_back(Pair("documenturl", t.documentUrl));
    o.push_back(Pair("documenthash",
                     t.hasDocumentHash ? t.documentHash.GetHex() : std::string("")));
    o.push_back(Pair("decimals", (int)t.decimals));
    o.push_back(Pair("genesisheight", (int64_t)t.genesisHeight));
    o.push_back(Pair("totalminted", (int64_t)t.totalMinted));
    o.push_back(Pair("mintbatonvout", (int)t.mintBatonVout));
    o.push_back(Pair("hasmintbaton", t.mintBatonVout >= 2));
    return o;
}

static const char* TxTypeName(uint8_t t)
{
    switch (t) {
    case ZSLP_TX_GENESIS: return "GENESIS";
    case ZSLP_TX_MINT:    return "MINT";
    case ZSLP_TX_SEND:    return "SEND";
    default:              return "UNKNOWN";
    }
}

UniValue zslp_gettoken(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "zslp_gettoken \"token_id\"\n"
            "\nReturns metadata for a ZSLP token (read-only).\n"
            "\nArguments:\n"
            "1. \"token_id\"   (string, required) the token id (genesis txid, hex)\n"
            "\nResult:\n"
            "{\n"
            "  \"tokenid\": \"hex\",\n"
            "  \"ticker\": \"...\",\n"
            "  \"name\": \"...\",\n"
            "  \"documenturl\": \"...\",\n"
            "  \"documenthash\": \"hex\",\n"
            "  \"decimals\": n,\n"
            "  \"genesisheight\": n,\n"
            "  \"totalminted\": n,\n"
            "  \"mintbatonvout\": n,\n"
            "  \"hasmintbaton\": true|false\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_gettoken", "\"<txid>\"")
            + HelpExampleRpc("zslp_gettoken", "\"<txid>\""));

    CZSLPStore* store = GetZSLPStoreOrThrow();
    uint256 tokenId = ParseHashV(params[0], "token_id");

    CZSLPToken token;
    if (!store->GetToken(tokenId, token))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Token not found");
    return TokenToJSON(token);
}

UniValue zslp_listtokens(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw std::runtime_error(
            "zslp_listtokens ( count from )\n"
            "\nLists known ZSLP tokens (read-only, bounded).\n"
            "\nArguments:\n"
            "1. count   (numeric, optional, default=100) max tokens to return (<=" + std::to_string(ZSLP_LIST_MAX) + ")\n"
            "2. from    (numeric, optional, default=0) number of tokens to skip\n"
            "\nResult: [ { token... }, ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_listtokens", "100 0")
            + HelpExampleRpc("zslp_listtokens", "100, 0"));

    CZSLPStore* store = GetZSLPStoreOrThrow();

    int count = 100;
    int from = 0;
    if (params.size() > 0)
        count = params[0].get_int();
    if (params.size() > 1)
        from = params[1].get_int();
    if (count < 0) count = 0;
    if (count > ZSLP_LIST_MAX) count = ZSLP_LIST_MAX;
    if (from < 0) from = 0;

    std::vector<CZSLPToken> tokens;
    store->ListTokens(from, count, tokens);

    UniValue arr(UniValue::VARR);
    for (size_t i = 0; i < tokens.size(); ++i)
        arr.push_back(TokenToJSON(tokens[i]));
    return arr;
}

UniValue zslp_listtransfers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "zslp_listtransfers \"token_id\" ( count from )\n"
            "\nLists transfers for a ZSLP token, newest first (read-only, bounded).\n"
            "\nArguments:\n"
            "1. \"token_id\"  (string, required) the token id (hex)\n"
            "2. count       (numeric, optional, default=100) max rows (<=" + std::to_string(ZSLP_LIST_MAX) + ")\n"
            "3. from        (numeric, optional, default=0) rows to skip\n"
            "\nResult: [ { \"txid\", \"tokenid\", \"type\", \"amount\", \"vout\",\n"
            "             \"height\", \"blockhash\", \"address\" }, ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_listtransfers", "\"<txid>\" 100 0")
            + HelpExampleRpc("zslp_listtransfers", "\"<txid>\", 100, 0"));

    CZSLPStore* store = GetZSLPStoreOrThrow();
    uint256 tokenId = ParseHashV(params[0], "token_id");

    int count = 100;
    int from = 0;
    if (params.size() > 1)
        count = params[1].get_int();
    if (params.size() > 2)
        from = params[2].get_int();
    if (count < 0) count = 0;
    if (count > ZSLP_LIST_MAX) count = ZSLP_LIST_MAX;
    if (from < 0) from = 0;

    std::vector<CZSLPTransfer> xfers;
    store->ListTransfers(tokenId, from, count, xfers);

    UniValue arr(UniValue::VARR);
    for (size_t i = 0; i < xfers.size(); ++i) {
        const CZSLPTransfer& x = xfers[i];
        UniValue o(UniValue::VOBJ);
        o.push_back(Pair("txid", x.txid.GetHex()));
        o.push_back(Pair("tokenid", x.tokenId.GetHex()));
        o.push_back(Pair("type", TxTypeName(x.txType)));
        o.push_back(Pair("amount", (int64_t)x.amount));
        o.push_back(Pair("vout", (int)x.vout));
        o.push_back(Pair("height", (int64_t)x.blockHeight));
        o.push_back(Pair("blockhash", x.blockHash.GetHex()));
        o.push_back(Pair("address", x.address));
        arr.push_back(o);
    }
    return arr;
}

UniValue zslp_listmytokens(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "zslp_listmytokens\n"
            "\nLists ZSLP tokens with a positive balance at any of this\n"
            "wallet's transparent addresses (read-only). ZSLP rides\n"
            "transparent dust, so only t-addresses are considered.\n"
            "\nResult: [ { \"tokenid\", \"ticker\", \"name\", \"decimals\",\n"
            "             \"balance\", \"addresses\": [ ... ] }, ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_listmytokens", "")
            + HelpExampleRpc("zslp_listmytokens", ""));

    CZSLPStore* store = GetZSLPStoreOrThrow();

    UniValue arr(UniValue::VARR);

#ifdef ENABLE_WALLET
    if (pwalletMain == NULL)
        return arr; // no wallet: nothing to intersect

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // Collect this wallet's t-addresses.
    std::set<CKeyID> keyids;
    pwalletMain->GetKeys(keyids);
    std::vector<std::string> myAddrs;
    myAddrs.reserve(keyids.size());
    for (std::set<CKeyID>::const_iterator it = keyids.begin();
         it != keyids.end(); ++it) {
        myAddrs.push_back(EncodeDestination(CTxDestination(*it)));
    }

    // Aggregate balances per token across all my addresses.
    std::map<uint256, int64_t> totals;
    std::map<uint256, UniValue> tokenAddrs;
    for (size_t i = 0; i < myAddrs.size(); ++i) {
        std::vector<std::pair<uint256, int64_t> > rows;
        store->GetTokensForAddress(myAddrs[i], rows);
        for (size_t j = 0; j < rows.size(); ++j) {
            const uint256& tid = rows[j].first;
            int64_t bal = rows[j].second;
            totals[tid] += bal;
            if (tokenAddrs.find(tid) == tokenAddrs.end())
                tokenAddrs[tid] = UniValue(UniValue::VARR);
            UniValue a(UniValue::VOBJ);
            a.push_back(Pair("address", myAddrs[i]));
            a.push_back(Pair("balance", bal));
            tokenAddrs[tid].push_back(a);
        }
    }

    for (std::map<uint256, int64_t>::const_iterator it = totals.begin();
         it != totals.end(); ++it) {
        if (it->second <= 0)
            continue;
        if ((int)arr.size() >= ZSLP_LIST_MAX)
            break; // bound the response size (wallet-size-bound), matching the other list RPCs
        CZSLPToken token;
        store->GetToken(it->first, token);
        UniValue o(UniValue::VOBJ);
        o.push_back(Pair("tokenid", it->first.GetHex()));
        o.push_back(Pair("ticker", token.ticker));
        o.push_back(Pair("name", token.name));
        o.push_back(Pair("decimals", (int)token.decimals));
        o.push_back(Pair("balance", it->second));
        o.push_back(Pair("addresses", tokenAddrs[it->first]));
        arr.push_back(o);
    }
#else
    throw JSONRPCError(RPC_MISC_ERROR,
        "zslp_listmytokens requires a wallet-enabled build");
#endif

    return arr;
}

static const CRPCCommand commands[] =
{ //  category   name                  actor (function)     okSafeMode
  //  ---------  --------------------  -------------------  ----------
    { "zslp",    "zslp_gettoken",      &zslp_gettoken,      true },
    { "zslp",    "zslp_listtokens",    &zslp_listtokens,    true },
    { "zslp",    "zslp_listtransfers", &zslp_listtransfers, true },
    { "zslp",    "zslp_listmytokens",  &zslp_listmytokens,  true },
};

void RegisterZSLPRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
