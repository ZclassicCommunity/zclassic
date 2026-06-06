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
#include "utilstrencodings.h"
#include "zslp/zslpindexer.h"
#include "zslp/zslpstore.h"

#ifdef ENABLE_WALLET
#include "init.h"          // pwalletMain
#include "main.h"          // cs_main
#include "wallet/wallet.h"
#include "wallet/zslpwallet.h"
#include "zslp/zslpmsg.h"  // ZSLPBuild{Genesis,Mint,Send}
// EnsureWalletIsAvailable is file-extern in wallet/rpcwallet.cpp (not in a
// header); declare it here. EnsureWalletIsUnlocked is in rpc/server.h.
extern bool EnsureWalletIsAvailable(bool avoidException);
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

#ifdef ENABLE_WALLET

// ── Write-path helpers ──────────────────────────────────────────────

// TokenIdToBE moved to wallet/zslpwallet.h as the shared inline ZSLPTokenIdToBE
// (DRY: rpc/nftoffer.cpp's sell template needs the exact same reversal). Keep a
// local alias so the existing mint/send call sites read unchanged.
static inline void TokenIdToBE(const uint256& tokenId, uint8_t out[32])
{
    ZSLPTokenIdToBE(tokenId, out);
}

// Parse a uint64 quantity from a JSON value that is a STRING or a small integer.
// Rejects negatives, non-digits, overflow, and the high bit (>= 2^63) which the
// SLP parser/store treat as INVALID (R-INT-1). Throws on any violation.
static uint64_t ParseQuantity(const UniValue& v, const std::string& field)
{
    std::string s;
    if (v.isStr())
        s = v.get_str();
    else if (v.isNum())
        s = v.getValStr(); // exact integer text, no double rounding
    else
        throw JSONRPCError(RPC_TYPE_ERROR, field + " must be a string or integer");
    if (s.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, field + " is empty");
    for (size_t i = 0; i < s.size(); ++i)
        if (s[i] < '0' || s[i] > '9')
            throw JSONRPCError(RPC_INVALID_PARAMETER, field + " must be a non-negative integer");
    errno = 0;
    char* end = NULL;
    unsigned long long q = strtoull(s.c_str(), &end, 10);
    if (errno != 0 || end == NULL || *end != '\0')
        throw JSONRPCError(RPC_INVALID_PARAMETER, field + " is not a valid integer");
    if (q >> 63)
        throw JSONRPCError(RPC_INVALID_PARAMETER, field + " exceeds the maximum (2^63-1)");
    return (uint64_t)q;
}

// Decode a t-address to a P2PKH/P2SH script, throwing on an invalid address.
static CScript ScriptForTAddr(const std::string& addr)
{
    CTxDestination dest = DecodeDestination(addr);
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid transparent address: " + addr);
    return GetScriptForDestination(dest);
}

// Reserve a fresh wallet t-address script (for default recipient / token-change).
static CScript FreshWalletScript()
{
    CPubKey vchPubKey;
    if (!pwalletMain->GetKeyFromPool(vchPubKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT,
                           "Keypool ran out, call keypoolrefill first");
    return GetScriptForDestination(vchPubKey.GetID());
}

UniValue zslp_genesis(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "zslp_genesis '{\"ticker\":?,\"name\":?,\"document_url\":?,"
            "\"document_hash\":?(64hex),\"decimals\":?(0..9,def 0),"
            "\"quantity\":?(string,def 1),\"mint_baton_vout\":?(>=2),"
            "\"to\":?(t-addr),\"nft\":?(bool)}'\n"
            "\nMint a ZSLP token. An NFT is nft=true (decimals 0, quantity 1, no baton).\n"
            "Builds ONE OP_RETURN at vout[0] plus a 546-sat token output at vout[1]\n"
            "(and a baton output if requested); unchanged nodes relay and mine it.\n"
            "The tx is self-validated against the overlay ledger before broadcast.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"params\"   (object, required)\n"
            "     ticker          (string, optional) short symbol\n"
            "     name            (string, optional) display name\n"
            "     document_url    (string, optional) short URL/URI\n"
            "     document_hash   (string, optional) 64 hex chars (32 bytes), file fingerprint\n"
            "     decimals        (numeric, optional, default 0) 0..9\n"
            "     quantity        (string|numeric, optional, default 1) initial supply (<2^63)\n"
            "     mint_baton_vout (numeric, optional) >=2 to issue a re-issue baton\n"
            "     to              (string, optional) recipient t-address (default: a fresh wallet address)\n"
            "     nft             (bool, optional) force decimals 0, quantity 1, no baton\n"
            "\nResult:\n{ \"txid\": \"hex\", \"tokenid\": \"hex\" }   (tokenid == txid)\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_genesis",
                "'{\"nft\":true,\"name\":\"My Photo #1\",\"document_hash\":\"<64hex>\"}'")
            + HelpExampleRpc("zslp_genesis",
                "{\"ticker\":\"GOLD\",\"decimals\":2,\"quantity\":\"100000\",\"mint_baton_vout\":2}"));

    GetZSLPStoreOrThrow(); // fail CLOSED if -zslpindex off
    LOCK2(cs_main, pwalletMain->cs_wallet);

    const UniValue& o = params[0].get_obj();

    bool nft = false;
    {
        const UniValue& v = find_value(o, "nft");
        if (!v.isNull()) nft = v.get_bool();
    }

    std::string ticker, name, docUrl;
    { const UniValue& v = find_value(o, "ticker");       if (v.isStr()) ticker = v.get_str(); }
    { const UniValue& v = find_value(o, "name");         if (v.isStr()) name   = v.get_str(); }
    { const UniValue& v = find_value(o, "document_url"); if (v.isStr()) docUrl = v.get_str(); }

    // document_hash: empty or exactly 64 hex (32 raw bytes, NOT reversed).
    bool hasHash = false;
    uint8_t hash32[32];
    {
        const UniValue& v = find_value(o, "document_hash");
        if (v.isStr() && !v.get_str().empty()) {
            std::string h = v.get_str();
            if (h.size() != 64 || !IsHex(h))
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "document_hash must be 64 hex characters (32 bytes)");
            std::vector<unsigned char> raw = ParseHex(h);
            memcpy(hash32, raw.data(), 32);
            hasHash = true;
        }
    }

    int decimals = 0;
    { const UniValue& v = find_value(o, "decimals"); if (!v.isNull()) decimals = v.get_int(); }

    uint64_t quantity = 1; // default = NFT-style single unit
    { const UniValue& v = find_value(o, "quantity"); if (!v.isNull()) quantity = ParseQuantity(v, "quantity"); }

    int batonVout = 0; // 0/1 = none
    { const UniValue& v = find_value(o, "mint_baton_vout"); if (!v.isNull()) batonVout = v.get_int(); }

    if (nft) {
        // NFT preset: a 1-of-1, indivisible, non-reissuable token. Reject
        // conflicting explicit values rather than silently overriding.
        if (find_value(o, "decimals").isNull()) decimals = 0;
        else if (decimals != 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "an NFT must have decimals 0");
        if (find_value(o, "quantity").isNull()) quantity = 1;
        else if (quantity != 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "an NFT must have quantity 1");
        if (!find_value(o, "mint_baton_vout").isNull() && batonVout >= 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "an NFT cannot have a mint baton");
        batonVout = 0;
    }

    if (decimals < 0 || decimals > 9)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "decimals must be 0..9");
    if (batonVout == 1)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mint_baton_vout 1 collides with the token output at vout[1]; use 0 (none) or >=2");

    // Recipient script (vout[1]).
    CScript toScript;
    { const UniValue& v = find_value(o, "to");
      if (v.isStr() && !v.get_str().empty()) toScript = ScriptForTAddr(v.get_str());
      else toScript = FreshWalletScript(); }

    // Layout: vout[1] = token recipient; if a baton is requested, it is the next
    // token output (vout[2]). The encoder's mint_baton_vout MUST equal that index.
    uint8_t batonVoutOut = 0;
    if (batonVout >= 2) {
        batonVoutOut = 2; // baton placed at vout[2], immediately after the recipient
    }

    EnsureWalletIsUnlocked();

    std::vector<unsigned char> opret = ZSLPBuildGenesis(
        ticker, name, docUrl, hasHash ? hash32 : NULL,
        (uint8_t)decimals, batonVoutOut, quantity);
    if (opret.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "metadata too large for one OP_RETURN (max 223 bytes); shorten name/ticker/url or move data off-chain");

    ZSLPBuildReq req;
    req.opret = CScript(opret.begin(), opret.end());
    ZSLPTokenOut recip; recip.dest = toScript; recip.dustSats = SLP_TOKEN_DUST;
    req.tokenOuts.push_back(recip);
    if (batonVoutOut >= 2) {
        ZSLPTokenOut baton; baton.dest = FreshWalletScript(); baton.dustSats = SLP_TOKEN_DUST;
        req.tokenOuts.push_back(baton); // becomes vout[2]
    }
    req.tokenInputs.clear();              // GENESIS has no token inputs
    req.isGenesis = true;

    CWalletTx wtx;
    std::string err;
    if (!BuildAndCommitZSLP(pwalletMain, req, wtx, err))
        throw JSONRPCError(RPC_WALLET_ERROR, err);

    UniValue ret(UniValue::VOBJ);
    std::string txid = wtx.GetHash().GetHex();
    ret.push_back(Pair("txid", txid));
    ret.push_back(Pair("tokenid", txid)); // tokenid == genesis txid
    return ret;
}

UniValue zslp_mint(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error(
            "zslp_mint \"tokenid\" amount ( baton_vout )\n"
            "\nIssue additional supply of an existing fungible token by spending its\n"
            "live mint baton (the wallet must hold the baton UTXO). NFTs never use MINT.\n"
            "Builds an OP_RETURN at vout[0] + a 546-sat output at vout[1] (and a\n"
            "continued baton if baton_vout>=2); self-validated before broadcast.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"tokenid\"   (string, required) the token id (hex)\n"
            "2. amount      (string|numeric, required) additional quantity (<2^63)\n"
            "3. baton_vout  (numeric, optional, default 2) >=2 to continue the baton; 0 to end it\n"
            "\nResult:\n{ \"txid\": \"hex\" }\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_mint", "\"<tokenid>\" \"1000\"")
            + HelpExampleRpc("zslp_mint", "\"<tokenid>\", \"1000\", 2"));

    CZSLPStore* store = GetZSLPStoreOrThrow();
    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint256 tokenId = ParseHashV(params[0], "tokenid");
    CZSLPToken token;
    if (!store->GetToken(tokenId, token))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Token not found");

    uint64_t amount = ParseQuantity(params[1], "amount");
    if (amount == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be > 0");

    int batonVout = 2; // default: continue the baton at vout[2]
    if (params.size() > 2)
        batonVout = params[2].get_int();
    if (batonVout == 1)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "baton_vout 1 collides with the mint output; use 0 (end) or >=2");

    EnsureWalletIsUnlocked();

    // Find the live baton UTXO in the wallet (anti-burn intersection).
    std::vector<ZSLPWalletUtxo> batons;
    std::string ferr;
    if (!ZSLPFindWalletTokenUtxos(pwalletMain, tokenId, /*wantBaton=*/true, batons, ferr))
        throw JSONRPCError(RPC_WALLET_ERROR, ferr);
    if (batons.empty())
        throw JSONRPCError(RPC_WALLET_ERROR,
            "This wallet does not hold the mint baton for that token (cannot mint)");

    uint8_t tidBE[32]; TokenIdToBE(tokenId, tidBE);
    uint8_t batonVoutOut = (batonVout >= 2) ? 2 : 0; // continued baton at vout[2]

    std::vector<unsigned char> opret = ZSLPBuildMint(tidBE, batonVoutOut, amount);
    if (opret.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build MINT OP_RETURN");

    ZSLPBuildReq req;
    req.opret = CScript(opret.begin(), opret.end());
    ZSLPTokenOut recip; recip.dest = FreshWalletScript(); recip.dustSats = SLP_TOKEN_DUST;
    req.tokenOuts.push_back(recip); // vout[1] = new supply
    if (batonVoutOut >= 2) {
        ZSLPTokenOut nb; nb.dest = FreshWalletScript(); nb.dustSats = SLP_TOKEN_DUST;
        req.tokenOuts.push_back(nb); // vout[2] = continued baton
    }
    req.tokenInputs.push_back(batons[0].outpoint); // pin the baton input
    req.selfValidateTokenId = tokenId;
    req.isGenesis = false;

    CWalletTx wtx;
    std::string err;
    if (!BuildAndCommitZSLP(pwalletMain, req, wtx, err))
        throw JSONRPCError(RPC_WALLET_ERROR, err);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("txid", wtx.GetHash().GetHex()));
    return ret;
}

UniValue zslp_send(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw std::runtime_error(
            "zslp_send \"tokenid\" \"to_address\" ( amount change_address )\n"
            "\nTransfer ZSLP token amounts (an NFT gift defaults to amount 1). Selects\n"
            "the wallet's token UTXOs of tokenid, conserves supply (token-change goes\n"
            "to a fresh own t-address, or change_address if given), pins token inputs +\n"
            "anti-burn-filters fee coins, and self-validates before broadcast. Rejects\n"
            "(clear error) on insufficient token balance — it never burns the token.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"tokenid\"        (string, required) the token id (hex)\n"
            "2. \"to_address\"     (string, required) recipient t-address\n"
            "3. amount           (string|numeric, optional, default 1) amount to send (<2^63)\n"
            "4. \"change_address\" (string, optional) token-change t-address (default: fresh own address)\n"
            "\nResult:\n{ \"txid\": \"hex\" }\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_send", "\"<tokenid>\" \"t1...\" 1")
            + HelpExampleRpc("zslp_send", "\"<tokenid>\", \"t1...\", \"5\""));

    CZSLPStore* store = GetZSLPStoreOrThrow();
    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint256 tokenId = ParseHashV(params[0], "tokenid");
    CZSLPToken token;
    if (!store->GetToken(tokenId, token))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Token not found");

    CScript toScript = ScriptForTAddr(params[1].get_str());

    uint64_t amount = 1;
    if (params.size() > 2)
        amount = ParseQuantity(params[2], "amount");
    if (amount == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be > 0");

    bool haveChangeAddr = false;
    CScript changeScript;
    if (params.size() > 3 && !params[3].get_str().empty()) {
        changeScript = ScriptForTAddr(params[3].get_str());
        haveChangeAddr = true;
    }

    EnsureWalletIsUnlocked();

    // Enumerate + greedily select token UTXOs (deterministic order).
    std::vector<ZSLPWalletUtxo> utxos;
    std::string ferr;
    if (!ZSLPFindWalletTokenUtxos(pwalletMain, tokenId, /*wantBaton=*/false, utxos, ferr))
        throw JSONRPCError(RPC_WALLET_ERROR, ferr);

    int64_t availIn = 0;
    std::vector<COutPoint> chosen;
    for (size_t i = 0; i < utxos.size(); ++i) {
        chosen.push_back(utxos[i].outpoint);
        availIn += utxos[i].amount;
        if (availIn >= (int64_t)amount)
            break;
    }
    if (availIn < (int64_t)amount)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient token balance: have %d, need %d", availIn, (int64_t)amount));

    int64_t tokenChange = availIn - (int64_t)amount;

    // Quantities array: recipient first, then (if any) token-change to self.
    // recipients(1) + change(0/1) <= ZSLP_SEND_MAX_OUTPUTS.
    std::vector<uint64_t> quantities;
    quantities.push_back(amount);
    if (tokenChange > 0)
        quantities.push_back((uint64_t)tokenChange);
    if ((int)quantities.size() > ZSLP_MAX_SEND_OUTPUTS)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "too many SEND outputs");

    uint8_t tidBE[32]; TokenIdToBE(tokenId, tidBE);
    std::vector<unsigned char> opret = ZSLPBuildSend(tidBE, quantities);
    if (opret.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build SEND OP_RETURN");

    ZSLPBuildReq req;
    req.opret = CScript(opret.begin(), opret.end());
    ZSLPTokenOut recip; recip.dest = toScript; recip.dustSats = SLP_TOKEN_DUST;
    req.tokenOuts.push_back(recip);                 // vout[1] = recipient
    if (tokenChange > 0) {
        ZSLPTokenOut chg;
        chg.dest = haveChangeAddr ? changeScript : FreshWalletScript();
        chg.dustSats = SLP_TOKEN_DUST;
        req.tokenOuts.push_back(chg);               // vout[2] = token-change to self
    }
    req.tokenInputs = chosen;
    req.selfValidateTokenId = tokenId;
    req.isGenesis = false;

    CWalletTx wtx;
    std::string err;
    if (!BuildAndCommitZSLP(pwalletMain, req, wtx, err))
        throw JSONRPCError(RPC_WALLET_ERROR, err);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("txid", wtx.GetHash().GetHex()));
    return ret;
}

#endif // ENABLE_WALLET

static const CRPCCommand commands[] =
{ //  category   name                  actor (function)     okSafeMode
  //  ---------  --------------------  -------------------  ----------
    { "zslp",    "zslp_gettoken",      &zslp_gettoken,      true },
    { "zslp",    "zslp_listtokens",    &zslp_listtokens,    true },
    { "zslp",    "zslp_listtransfers", &zslp_listtransfers, true },
    { "zslp",    "zslp_listmytokens",  &zslp_listmytokens,  true },
#ifdef ENABLE_WALLET
    { "zslp",    "zslp_genesis",       &zslp_genesis,       false },
    { "zslp",    "zslp_mint",          &zslp_mint,          false },
    { "zslp",    "zslp_send",          &zslp_send,          false },
#endif
};

void RegisterZSLPRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
