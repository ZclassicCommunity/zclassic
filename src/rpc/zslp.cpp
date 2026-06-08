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

#include "core_io.h"       // DecodeHexTx (zslp_decode, no wallet needed)
#include "key_io.h"
#include "primitives/transaction.h"
#include "rpc/protocol.h"
#include "script/standard.h"
#include "util.h"
#include "utilstrencodings.h"
#include "zslp/contentfingerprint.h"  // ZSLPHash{Bytes,File} (filefingerprint/verifyfile)
#include "zslp/zslpindexer.h"
#include "zslp/zslpmsg.h"  // ZSLPParseScript + ZSLPBuild{Genesis,Mint,Send}
#include "zslp/zslpstore.h"

#ifdef ENABLE_WALLET
#include "init.h"          // pwalletMain
#include "main.h"          // cs_main
#include "wallet/wallet.h"
#include "wallet/zslpwallet.h"
// EnsureWalletIsAvailable is file-extern in wallet/rpcwallet.cpp (not in a
// header); declare it here. EnsureWalletIsUnlocked is in rpc/server.h.
extern bool EnsureWalletIsAvailable(bool avoidException);
#endif

#include <algorithm>
#include <cctype>
#include <limits>
#include <stdint.h>
#include <univalue.h>

// Store-or-throw + t-addr script/addr helpers + the amount parser are shared
// (B-1/B-2): ONE canonical copy in wallet/zslpwallet.{h,cpp} (alongside
// ZSLPTokenIdToBE), used by both this file and rpc/nftoffer.cpp. For builds
// WITHOUT a wallet the wallet header still declares ZSLPStoreOrThrow, but the
// implementation TU (zslpwallet.cpp) is wallet-only — so provide a local
// store-or-throw for the read-only (non-wallet) commands here.
#ifdef ENABLE_WALLET
// wallet/zslpwallet.h is included above (line ~27); it declares ZSLPStoreOrThrow.
static inline CZSLPStore* GetZSLPStoreOrThrow() { return ZSLPStoreOrThrow(); }
#else
static CZSLPStore* GetZSLPStoreOrThrow()
{
    if (g_zslpIndexer == NULL || g_zslpIndexer->Store() == NULL)
        throw JSONRPCError(RPC_MISC_ERROR,
            "ZSLP index is not enabled. Start zclassicd with -zslpindex.");
    return g_zslpIndexer->Store();
}
#endif

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
    // Group / child collection (spec-v2). `group` is the parent collection id
    // (hex) ONLY for an AUTHORIZED child; "" otherwise — so a name-squatter's
    // claimed-but-unauthorized token never surfaces a group. `group_claimed`
    // exposes the raw on-chain claim for transparency, but it is NEVER membership.
    o.push_back(Pair("group",
                     t.groupAuthorized ? t.groupId.GetHex() : std::string("")));
    o.push_back(Pair("group_authorized", t.groupAuthorized));
    o.push_back(Pair("group_claimed", t.hasGroup));
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

// Resolve a {"path":...} OR {"hexdata":...} JSON object into a content
// descriptor (shared by zslp_filefingerprint / zslp_verifyfile). Exactly one of
// path/hexdata must be present. Throws RPC_INVALID_PARAMETER on any violation
// (missing/both, bad hex, unreadable file).
static void ZSLPDescriptorFromArg(const UniValue& o, ZSLPContentDescriptor& out)
{
    const UniValue& vp = find_value(o, "path");
    const UniValue& vh = find_value(o, "hexdata");
    bool havePath = vp.isStr() && !vp.get_str().empty();
    bool haveHex  = vh.isStr() && !vh.get_str().empty();

    if (havePath == haveHex) // both or neither
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Provide exactly one of \"path\" or \"hexdata\"");

    if (havePath) {
        if (!ZSLPHashFile(vp.get_str(), out))
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Cannot open/read file: " + vp.get_str());
    } else {
        const std::string& h = vh.get_str();
        if (!IsHex(h))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "hexdata is not valid hex");
        std::vector<unsigned char> raw = ParseHex(h);
        ZSLPHashBytes(raw.empty() ? NULL : raw.data(), raw.size(), out);
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
            "  \"hasmintbaton\": true|false,\n"
            "  \"group\": \"hex\",            (parent collection id if an AUTHORIZED child, else \"\")\n"
            "  \"group_authorized\": true|false, (verified collection member)\n"
            "  \"group_claimed\": true|false     (named a group on-chain; NOT membership)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_gettoken", "\"<txid>\"")
            + HelpExampleRpc("zslp_gettoken", "\"<txid>\""));

    CZSLPStore* store = GetZSLPStoreOrThrow();
    uint256 tokenId = ParseHashV(params[0], "token_id");

    CZSLPToken token;
    if (!store->GetToken(tokenId, token))
        // A-4: align with the nft_* not-found paths (the arg names a thing that
        // does not exist) — RPC_INVALID_PARAMETER, not RPC_INVALID_ADDRESS_OR_KEY.
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Token not found");
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
            "\nEach entry is the FULL token object (identical shape to\n"
            "zslp_gettoken / zslp_listtokens: tokenid, ticker, name,\n"
            "documenturl, documenthash, decimals, genesisheight, totalminted,\n"
            "mintbatonvout, hasmintbaton, group, group_authorized, group_claimed)\n"
            "PLUS this wallet's aggregate\n"
            "\"balance\" and the per-address \"addresses\" breakdown.\n"
            "\nResult: [ { ...full token..., \"balance\", \"addresses\": [ ... ] }, ... ]\n"
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
        // A-3: embed the FULL token object (same shape as zslp_gettoken /
        // zslp_listtokens) so the GUI can drop its per-token zslp_gettoken
        // fan-out, then append the per-wallet balance + addresses[]. tokenid/
        // ticker/name/decimals remain present (TokenToJSON emits them).
        UniValue o = TokenToJSON(token);
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

// ── B. zslp_filefingerprint ─────────────────────────────────────────

UniValue zslp_filefingerprint(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || !params[0].isObject())
        throw std::runtime_error(
            "zslp_filefingerprint '{\"path\":\"/abs/file\"}'\n"
            "\nCompute the ZSLP content fingerprint (document_hash) of a file or of\n"
            "raw bytes, using the SAME 1 MiB-chunk Merkle anchor the GUI uses — so a\n"
            "CLI mint produces the identical document_hash the wallet would. The file\n"
            "is streamed (never fully loaded), so multi-GB inputs are safe. Read-only.\n"
            "\nArguments:\n"
            "1. \"params\"  (object, required) exactly ONE of:\n"
            "     path     (string) absolute path to a local file\n"
            "     hexdata  (string) raw bytes as hex (for small inline data)\n"
            "\nResult:\n"
            "{\n"
            "  \"document_hash\": \"hex\",   (the anchor to put on-chain)\n"
            "  \"merkle_root\": \"hex\",     (\"\" for an empty input)\n"
            "  \"sha256\": \"hex\",          (whole-input SHA-256)\n"
            "  \"file_size\": n,\n"
            "  \"chunk_size\": " + std::to_string(ZSLP_CONTENT_CHUNK_BYTES) + ",\n"
            "  \"chunk_count\": n\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_filefingerprint", "'{\"path\":\"/home/me/photo.png\"}'")
            + HelpExampleRpc("zslp_filefingerprint", "{\"path\":\"/home/me/photo.png\"}"));

    ZSLPContentDescriptor d;
    ZSLPDescriptorFromArg(params[0].get_obj(), d);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("document_hash", d.anchorHex));
    ret.push_back(Pair("merkle_root", d.merkleRootHex));
    ret.push_back(Pair("sha256", d.sha256WholeHex));
    ret.push_back(Pair("file_size", (int64_t)d.fileSize));
    ret.push_back(Pair("chunk_size", (int64_t)d.chunkSize));
    ret.push_back(Pair("chunk_count", (int64_t)d.chunkCount));
    return ret;
}

// ── C. zslp_verifyfile ──────────────────────────────────────────────

UniValue zslp_verifyfile(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || !params[0].isObject())
        throw std::runtime_error(
            "zslp_verifyfile '{\"token_id\":\"hex\",\"path\":\"/abs/file\"}'\n"
            "\nCheck whether a local file (or raw bytes) matches a token's recorded\n"
            "document_hash. The expected hash comes from EITHER an indexed token_id\n"
            "OR an explicit document_hash. A match holds if the file's chunk-Merkle\n"
            "anchor OR its whole-file SHA-256 equals the expected hash (the GUI's\n"
            "verify badge accepts either form). Read-only; the file is streamed.\n"
            "\nArguments:\n"
            "1. \"params\"  (object, required) one expected source + one content source:\n"
            "     token_id       (string) an indexed token id (uses its document_hash), OR\n"
            "     document_hash  (string, 64 hex) the expected hash directly\n"
            "     path           (string) absolute path to a local file, OR\n"
            "     hexdata        (string) raw bytes as hex\n"
            "\nResult:\n"
            "{\n"
            "  \"match\": true|false,\n"
            "  \"computed_anchor\": \"hex\",\n"
            "  \"computed_sha256\": \"hex\",\n"
            "  \"expected\": \"hex\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_verifyfile",
                "'{\"token_id\":\"<txid>\",\"path\":\"/home/me/photo.png\"}'")
            + HelpExampleRpc("zslp_verifyfile",
                "{\"document_hash\":\"<64hex>\",\"path\":\"/home/me/photo.png\"}"));

    const UniValue& o = params[0].get_obj();

    // Resolve the EXPECTED hash from token_id (preferred) or document_hash.
    std::string expected;
    const UniValue& vtid = find_value(o, "token_id");
    const UniValue& vdh  = find_value(o, "document_hash");
    if (vtid.isStr() && !vtid.get_str().empty()) {
        CZSLPStore* store = GetZSLPStoreOrThrow();
        uint256 tokenId = ParseHashV(vtid, "token_id");
        CZSLPToken token;
        if (!store->GetToken(tokenId, token))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Token not found");
        if (!token.hasDocumentHash)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Token has no document_hash to verify against");
        expected = token.documentHash.GetHex(); // on-chain display order, lowercase
    } else if (vdh.isStr() && !vdh.get_str().empty()) {
        std::string h = vdh.get_str();
        if (h.size() != 64 || !IsHex(h))
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "document_hash must be 64 hex characters (32 bytes)");
        expected = h;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Provide either \"token_id\" or \"document_hash\"");
    }

    ZSLPContentDescriptor d;
    ZSLPDescriptorFromArg(o, d);

    // Case-insensitive compare (lowercase both); accept either anchor form.
    std::string exp = expected;
    std::transform(exp.begin(), exp.end(), exp.begin(), ::tolower);
    bool match = (exp == d.anchorHex) || (exp == d.sha256WholeHex);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("match", match));
    ret.push_back(Pair("computed_anchor", d.anchorHex));
    ret.push_back(Pair("computed_sha256", d.sha256WholeHex));
    ret.push_back(Pair("expected", exp));
    return ret;
}

// ── D1. zslp_getbalance ─────────────────────────────────────────────

UniValue zslp_getbalance(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "zslp_getbalance \"tokenid\" \"address\"\n"
            "\nReturns the ZSLP token balance held at a transparent address\n"
            "(read-only). ZSLP rides transparent dust, so only t-addresses hold a\n"
            "token balance; an address with none returns 0.\n"
            "\nArguments:\n"
            "1. \"tokenid\"  (string, required) the token id (hex)\n"
            "2. \"address\"  (string, required) a transparent (t-) address\n"
            "\nResult:\n"
            "{ \"tokenid\": \"hex\", \"address\": \"...\", \"balance\": n }\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_getbalance", "\"<tokenid>\" \"t1...\"")
            + HelpExampleRpc("zslp_getbalance", "\"<tokenid>\", \"t1...\""));

    CZSLPStore* store = GetZSLPStoreOrThrow();
    uint256 tokenId = ParseHashV(params[0], "tokenid");

    // Throw "Token not found" first, for parity with the other token RPCs.
    CZSLPToken token;
    if (!store->GetToken(tokenId, token))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Token not found");

    std::string address = params[1].get_str();
    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid transparent address");

    int64_t balance = store->GetBalance(tokenId, address);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("tokenid", tokenId.GetHex()));
    ret.push_back(Pair("address", address));
    ret.push_back(Pair("balance", balance));
    return ret;
}

// ── D2. zslp_listholders ────────────────────────────────────────────

UniValue zslp_listholders(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "zslp_listholders \"tokenid\" ( count from )\n"
            "\nLists the transparent addresses holding a positive balance of a ZSLP\n"
            "token (read-only, bounded).\n"
            "\nArguments:\n"
            "1. \"tokenid\"  (string, required) the token id (hex)\n"
            "2. count      (numeric, optional, default=100) max holders (<=" + std::to_string(ZSLP_LIST_MAX) + ")\n"
            "3. from       (numeric, optional, default=0) holders to skip\n"
            "\nResult: [ { \"address\": \"...\", \"balance\": n }, ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_listholders", "\"<tokenid>\" 100 0")
            + HelpExampleRpc("zslp_listholders", "\"<tokenid>\", 100, 0"));

    CZSLPStore* store = GetZSLPStoreOrThrow();
    uint256 tokenId = ParseHashV(params[0], "tokenid");

    CZSLPToken token;
    if (!store->GetToken(tokenId, token))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Token not found");

    int count = 100;
    int from = 0;
    if (params.size() > 1)
        count = params[1].get_int();
    if (params.size() > 2)
        from = params[2].get_int();
    if (count < 0) count = 0;
    if (count > ZSLP_LIST_MAX) count = ZSLP_LIST_MAX;
    if (from < 0) from = 0;

    // O(count) windowing: skip `from` and take `count` IN the store prefix-scan
    // (peak memory is O(count), independent of `from`), instead of materializing
    // every holder and slicing here.
    std::vector<std::pair<std::string, int64_t> > holders;
    store->GetHoldersForToken(tokenId, from, count, holders);

    UniValue arr(UniValue::VARR);
    for (size_t i = 0; i < holders.size(); ++i) {
        UniValue o(UniValue::VOBJ);
        o.push_back(Pair("address", holders[i].first));
        o.push_back(Pair("balance", holders[i].second));
        arr.push_back(o);
    }
    return arr;
}

// ── D3. zslp_decode ─────────────────────────────────────────────────

UniValue zslp_decode(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "zslp_decode \"hex\"\n"
            "\nDecode a ZSLP OP_RETURN message (read-only, no chain state). The hex\n"
            "may be EITHER a raw transaction (its vout[0] script is decoded) OR a\n"
            "bare scriptPubKey. Returns { \"valid\": false } when the script is not a\n"
            "well-formed ZSLP message.\n"
            "\nArguments:\n"
            "1. \"hex\"   (string, required) a raw transaction OR a scriptPubKey, hex\n"
            "\nResult (valid GENESIS):\n"
            "{ \"valid\":true, \"type\":\"GENESIS\", \"ticker\", \"name\",\n"
            "  \"documenturl\", \"documenthash\", \"decimals\", \"mint_baton_vout\",\n"
            "  \"initial_quantity\", \"tokenid\"(only if a full tx was supplied) }\n"
            "\nResult (valid MINT):\n"
            "{ \"valid\":true, \"type\":\"MINT\", \"tokenid\", \"additional_quantity\",\n"
            "  \"mint_baton_vout\" }\n"
            "\nResult (valid SEND):\n"
            "{ \"valid\":true, \"type\":\"SEND\", \"tokenid\",\n"
            "  \"outputs\":[ { \"vout\":n, \"amount\":n }, ... ] }\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_decode", "\"6a04...\"")
            + HelpExampleRpc("zslp_decode", "\"6a04...\""));

    std::string hex = params[0].get_str();
    if (!IsHex(hex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Argument is not valid hex");

    // Try a full transaction first; fall back to treating the hex as a bare
    // scriptPubKey. A full tx lets us report the GENESIS tokenid (== its txid).
    bool haveTx = false;
    uint256 txid;
    CScript script;
    CTransaction tx;
    if (DecodeHexTx(tx, hex) && !tx.vout.empty()) {
        haveTx = true;
        txid = tx.GetHash();
        script = tx.vout[0].scriptPubKey;
    } else {
        std::vector<unsigned char> raw = ParseHex(hex);
        script = CScript(raw.begin(), raw.end());
    }

    std::vector<unsigned char> sbytes(script.begin(), script.end());
    ZSLPMessage msg;
    UniValue ret(UniValue::VOBJ);
    if (sbytes.empty() || !ZSLPParseScript(sbytes.data(), sbytes.size(), msg)) {
        ret.push_back(Pair("valid", false));
        return ret;
    }

    ret.push_back(Pair("valid", true));
    switch (msg.type) {
    case ZSLPMSG_GENESIS: {
        ret.push_back(Pair("type", "GENESIS"));
        ret.push_back(Pair("ticker", msg.ticker));
        ret.push_back(Pair("name", msg.name));
        ret.push_back(Pair("documenturl", msg.documentUrl));
        // documentHash[32] is already in on-chain/display order: a plain HexStr
        // is the correct dump (do NOT reverse). "" when no hash was present.
        ret.push_back(Pair("documenthash",
            msg.hasDocumentHash ? HexStr(msg.documentHash, msg.documentHash + 32)
                                : std::string("")));
        ret.push_back(Pair("decimals", (int)msg.decimals));
        ret.push_back(Pair("mint_baton_vout", (int)msg.mintBatonVout));
        ret.push_back(Pair("initial_quantity", (int64_t)msg.initialQuantity));
        // group_id[32] is on-chain/display order (plain HexStr, do NOT reverse);
        // "" when this GENESIS named no collection. This is the raw on-chain
        // CLAIM only — authorization is computed by the overlay store, not here.
        ret.push_back(Pair("group_id",
            msg.hasGroupId ? HexStr(msg.groupId, msg.groupId + 32)
                           : std::string("")));
        if (haveTx)
            ret.push_back(Pair("tokenid", txid.GetHex())); // tokenid == genesis txid
        break;
    }
    case ZSLPMSG_MINT: {
        ret.push_back(Pair("type", "MINT"));
        // tokenId[32] is already in on-chain/display order: plain HexStr is correct.
        ret.push_back(Pair("tokenid", HexStr(msg.tokenId, msg.tokenId + 32)));
        ret.push_back(Pair("additional_quantity", (int64_t)msg.additionalQuantity));
        ret.push_back(Pair("mint_baton_vout", (int)msg.mintBatonVout));
        break;
    }
    case ZSLPMSG_SEND: {
        ret.push_back(Pair("type", "SEND"));
        ret.push_back(Pair("tokenid", HexStr(msg.tokenId, msg.tokenId + 32)));
        UniValue outs(UniValue::VARR);
        for (int j = 0; j < msg.numOutputs; ++j) {
            UniValue oo(UniValue::VOBJ);
            oo.push_back(Pair("vout", 1 + j)); // quantity[j] credits vout[1+j]
            oo.push_back(Pair("amount", (int64_t)msg.outputQuantities[j]));
            outs.push_back(oo);
        }
        ret.push_back(Pair("outputs", outs));
        break;
    }
    default:
        // Unreachable: ZSLPParseScript returns false for any non-G/M/S message.
        ret.push_back(Pair("type", "UNKNOWN"));
        break;
    }
    return ret;
}

// ── D4. zslp_listcollectionmembers ──────────────────────────────────

UniValue zslp_listcollectionmembers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "zslp_listcollectionmembers \"group_id\" ( count from )\n"
            "\nLists the AUTHORIZED children of a ZSLP collection (read-only, bounded).\n"
            "A child is authorized ONLY if its GENESIS named this group AND spent a\n"
            "live parent-token UTXO/baton of it (closed/owner-authorized membership).\n"
            "A token that merely NAMES the group without spending a parent input is\n"
            "never returned here (it is a claim, not membership).\n"
            "\nArguments:\n"
            "1. \"group_id\"  (string, required) the collection (parent) genesis txid (hex)\n"
            "2. count       (numeric, optional, default=100) max members (<=" + std::to_string(ZSLP_LIST_MAX) + ")\n"
            "3. from        (numeric, optional, default=0) members to skip\n"
            "\nResult: [ { \"tokenid\", \"name\", \"group_authorized\":true }, ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_listcollectionmembers", "\"<group_id>\" 100 0")
            + HelpExampleRpc("zslp_listcollectionmembers", "\"<group_id>\", 100, 0"));

    CZSLPStore* store = GetZSLPStoreOrThrow();
    uint256 groupId = ParseHashV(params[0], "group_id");

    // The parent collection must exist (parity with the other token RPCs).
    CZSLPToken parent;
    if (!store->GetToken(groupId, parent))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Collection (group) not found");

    int count = 100;
    int from = 0;
    if (params.size() > 1)
        count = params[1].get_int();
    if (params.size() > 2)
        from = params[2].get_int();
    if (count < 0) count = 0;
    if (count > ZSLP_LIST_MAX) count = ZSLP_LIST_MAX;
    if (from < 0) from = 0;

    // O(count) windowing: skip `from` and take `count` IN the store prefix-scan
    // (peak memory is O(count), independent of `from`), instead of materializing
    // every member id and slicing here.
    std::vector<uint256> members; // authorized child tokenIds (leveldb-key order)
    store->GetCollectionMembers(groupId, from, count, members);

    UniValue arr(UniValue::VARR);
    for (size_t i = 0; i < members.size(); ++i) {
        CZSLPToken child;
        UniValue m(UniValue::VOBJ);
        m.push_back(Pair("tokenid", members[i].GetHex()));
        m.push_back(Pair("name", store->GetToken(members[i], child) ? child.name
                                                                     : std::string("")));
        m.push_back(Pair("group_authorized", true)); // only authorized ids are in 'g'
        arr.push_back(m);
    }
    return arr;
}

// ── D5. zslp_collectioninfo ─────────────────────────────────────────

UniValue zslp_collectioninfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "zslp_collectioninfo \"group_id\"\n"
            "\nReturns a ZSLP collection's parent token plus its authorized member\n"
            "count and whether the collection is still OPEN (a live parent UNIT\n"
            "still exists, so the owner can authorize another child while keeping\n"
            "the baton) or sealed (read-only).\n"
            "\nArguments:\n"
            "1. \"group_id\"  (string, required) the collection (parent) genesis txid (hex)\n"
            "\nResult:\n"
            "{\n"
            "  ...parent token fields (as zslp_gettoken)...,\n"
            "  \"member_count\": n,   (authorized children)\n"
            "  \"open\": true|false   (a live parent UNIT still exists -> can authorize more)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_collectioninfo", "\"<group_id>\"")
            + HelpExampleRpc("zslp_collectioninfo", "\"<group_id>\""));

    CZSLPStore* store = GetZSLPStoreOrThrow();
    uint256 groupId = ParseHashV(params[0], "group_id");

    CZSLPToken parent;
    if (!store->GetToken(groupId, parent))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Collection (group) not found");

    // member_count is inherently O(members), but counts WITHOUT materializing the
    // id vector (keys-only prefix-scan, O(1) memory).
    size_t memberCount = store->CountCollectionMembers(groupId);

    // OPEN iff a live parent UNIT still exists anywhere (any holder with a
    // positive balance of the group token), i.e. the owner can authorize another
    // child by spending a unit while KEEPING the baton (so the collection stays
    // open). Detected deterministically via the derived balance index — a pure
    // store read. (A baton-only authorization is possible with allow_baton, but
    // it SEALS the collection, so `open` intentionally reflects unit availability;
    // the token's mintBatonVout mirror is NOT used here because it is not cleared
    // when a child GENESIS burns the baton, so it could read stale.) We only need
    // to know whether ANY holder exists, so window to a single row (O(1) memory).
    bool open = false;
    {
        std::vector<std::pair<std::string, int64_t> > holders;
        store->GetHoldersForToken(groupId, /*from=*/0, /*count=*/1, holders);
        open = !holders.empty();
    }

    UniValue o = TokenToJSON(parent);
    o.push_back(Pair("member_count", (int64_t)memberCount));
    o.push_back(Pair("open", open));
    return o;
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
//
// B-1: the parse/overflow logic now lives ONCE in ZSLPParseAmountField; this is
// a thin shim that pins THIS family's bound (<= 2^63-1) and its exact over-bound
// message ("exceeds the maximum (2^63-1)"). INT64_MAX inclusive == rejecting the
// old `q >> 63` high bit, so behavior is unchanged.
static uint64_t ParseQuantity(const UniValue& v, const std::string& field)
{
    return (uint64_t)ZSLPParseAmountField(
        v, field, std::numeric_limits<int64_t>::max(), "the maximum (2^63-1)");
}

// Decode a t-address to a P2PKH/P2SH script, throwing on an invalid address.
// (B-2) shared with rpc/nftoffer.cpp via wallet/zslpwallet.h.
static inline CScript ScriptForTAddr(const std::string& addr)
{
    return ZSLPScriptForTAddr(addr);
}

// Reserve a fresh wallet t-address script (for default recipient / token-change).
// (B-2) shared with rpc/nftoffer.cpp via wallet/zslpwallet.h.
static inline CScript FreshWalletScript()
{
    return ZSLPFreshWalletScript();
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
            "\"to\":?(t-addr),\"nft\":?(bool),\"group_id\":?(64hex),"
            "\"authority\":?({txid,vout}),\"allow_baton\":?(bool)}'\n"
            "\nMint a ZSLP token. An NFT is nft=true (decimals 0, quantity 1, no baton).\n"
            "Builds ONE OP_RETURN at vout[0] plus a 546-sat token output at vout[1]\n"
            "(and a baton output if requested); unchanged nodes relay and mine it.\n"
            "The tx is self-validated against the overlay ledger before broadcast.\n"
            "\nTo mint an AUTHORIZED child of a collection, pass group_id (the parent\n"
            "collection's genesis txid). The wallet spends ONE live SINGLE-UNIT parent-\n"
            "token UTXO of that group as the authorization input; because a child is a\n"
            "GENESIS it cannot return parent-token change, so the spent outpoint is\n"
            "BURNED IN FULL — it MUST hold exactly 1 unit (one unit = one card). A multi-\n"
            "unit authority output is REFUSED (it would burn every unit for one card);\n"
            "split it first with: zslp_send <group_id> '[{\"address\":\"<own t-addr>\",\n"
            "\"amount\":1}, ...]' (up to 19 single-unit recipients per tx). To mint a\n"
            "COLLECTION parent, mint a normal token WITH a mint baton (mint_baton_vout>=2)\n"
            "and quantity = the number of authority units you want, then SPLIT that\n"
            "quantity into single-unit outputs (one zslp_send to self with N recipients\n"
            "of amount 1), and mint each child with group_id set to its tokenid. The\n"
            "baton lets you mint MORE authority units later (zslp_mint).\n"
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
            "     group_id        (string, optional) 64 hex parent collection genesis txid (mint an authorized child)\n"
            "     authority       (object, optional) {\"txid\":hex,\"vout\":n} pin a specific parent authority UTXO (must hold EXACTLY 1 unit)\n"
            "     allow_baton     (bool, optional) permit spending the collection mint baton as authority when no single-unit output exists; this BURNS the baton and SEALS the collection\n"
            "\nResult:\n{ \"txid\": \"hex\", \"tokenid\": \"hex\" }   (tokenid == txid)\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_genesis",
                "'{\"nft\":true,\"name\":\"My Photo #1\",\"document_hash\":\"<64hex>\"}'")
            + HelpExampleCli("zslp_genesis",
                "'{\"nft\":true,\"name\":\"Series 1 Card #1\",\"group_id\":\"<collection_txid>\"}'")
            + HelpExampleRpc("zslp_genesis",
                "{\"ticker\":\"GOLD\",\"decimals\":2,\"quantity\":\"100000\",\"mint_baton_vout\":2}"));

    CZSLPStore* store = GetZSLPStoreOrThrow(); // fail CLOSED if -zslpindex off
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

    // group_id (optional): the parent collection's genesis txid, 64 hex (mirror
    // the document_hash gate). When set, this GENESIS is an authorized child:
    // the wallet spends a live parent-token UTXO of the group as authorization.
    bool hasGroup = false;
    uint256 groupId;            // daemon uint256 (internal LE)
    uint8_t groupIdBE[32];      // on-chain order for the OP_RETURN field
    {
        const UniValue& v = find_value(o, "group_id");
        if (v.isStr() && !v.get_str().empty()) {
            std::string h = v.get_str();
            if (h.size() != 64 || !IsHex(h))
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "group_id must be 64 hex characters (the parent collection genesis txid)");
            groupId = ParseHashV(v, "group_id");
            TokenIdToBE(groupId, groupIdBE);
            hasGroup = true;
        }
    }

    // authority (optional): {txid,vout} pinning a specific parent-token UTXO to
    // spend as the collection authorization. Only meaningful with group_id.
    bool haveAuthorityPin = false;
    COutPoint authorityPin;
    {
        const UniValue& v = find_value(o, "authority");
        if (!v.isNull()) {
            if (!hasGroup)
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "authority is only valid together with group_id");
            if (!v.isObject())
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "authority must be an object {\"txid\":hex,\"vout\":n}");
            const UniValue& vt = find_value(v.get_obj(), "txid");
            const UniValue& vv = find_value(v.get_obj(), "vout");
            if (!vt.isStr() || vv.isNull())
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "authority must have a txid (hex) and a vout (numeric)");
            uint256 atx = ParseHashV(vt, "authority.txid");
            int avout = vv.get_int();
            if (avout < 0)
                throw JSONRPCError(RPC_INVALID_PARAMETER, "authority.vout must be >= 0");
            authorityPin = COutPoint(atx, (uint32_t)avout);
            haveAuthorityPin = true;
        }
    }

    bool allowBaton = false;
    { const UniValue& v = find_value(o, "allow_baton"); if (!v.isNull()) allowBaton = v.get_bool(); }

    if (hasGroup) {
        // The parent collection token MUST exist (a never-genesised id would
        // land the child merely "claimed"; refuse before broadcast).
        CZSLPToken parentTok;
        if (!store->GetToken(groupId, parentTok))
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "group_id names no known collection (parent token not found)");
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
        (uint8_t)decimals, batonVoutOut, quantity,
        hasGroup ? groupIdBE : NULL);
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
    req.tokenInputs.clear();              // ungrouped GENESIS has no token inputs

    // Child collection: pin EXACTLY ONE live SINGLE-UNIT parent-token UTXO of
    // the group as the authorization input. A child is a GENESIS (it describes
    // only the CHILD token), so it CANNOT carry a parent-token CHANGE output —
    // the spent parent outpoint is BURNED IN FULL regardless of how many units
    // it holds. Therefore the authority input MUST hold EXACTLY 1 unit (decimals
    // are 0 for a collection authority, so "1 unit" == amount==1); spending a
    // multi-unit outpoint would silently burn ALL of it for a single card.
    // Pinning into req.tokenInputs (exactly like a SEND's token inputs) keeps the
    // global anti-burn filter + ScopedTokenLock from fencing it AND lets the
    // post-sign anti-burn check permit it (it is the intended/pinned input).
    if (hasGroup) {
        COutPoint chosen;
        if (haveAuthorityPin) {
            // Validate the pinned outpoint is a live parent-token UTXO/baton of G.
            CZSLPTokenUtxo rec;
            if (!store->GetUtxo(authorityPin.hash, (int32_t)authorityPin.n, rec) ||
                rec.tokenId != groupId || (rec.amount <= 0 && !rec.isMintBaton))
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "authority outpoint is not a live parent-token UTXO of the collection");
            if (rec.isMintBaton) {
                // The baton bears no quantity but is itself BURNED when spent in
                // a child GENESIS (it cannot be continued by a GENESIS message),
                // which SEALS the collection. Strictly opt-in.
                if (!allowBaton)
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "authority outpoint is the collection mint baton; spending it in a "
                        "child mint BURNS the baton and SEALS the collection (no more "
                        "authority can be minted). Pass allow_baton:true to do this "
                        "deliberately, or pin a single-unit authority output instead.");
            } else if (rec.amount != 1) {
                // A multi-unit authority outpoint would be burned IN FULL.
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "authority outpoint holds " + std::to_string(rec.amount) +
                    " units of collection " + groupId.GetHex() +
                    "; a child mint is a GENESIS and cannot return parent-token change, "
                    "so it would BURN all " + std::to_string(rec.amount) +
                    " units for one card. Split your authority into single units first "
                    "(zslp_send " + groupId.GetHex() + " to your own address with "
                    "per-recipient amount 1), then pin a 1-unit output.");
            }
            chosen = authorityPin;
        } else {
            // Auto-select: require a non-baton outpoint holding EXACTLY 1 unit, so
            // the burn consumes exactly one authority unit (one unit = one child)
            // and the collection's baton/openness is preserved. NEVER auto-pick a
            // multi-unit outpoint (would over-burn) and NEVER auto-use the baton.
            std::vector<ZSLPWalletUtxo> units;
            std::string ferr;
            if (!ZSLPFindWalletTokenUtxos(pwalletMain, groupId, /*wantBaton=*/false, units, ferr))
                throw JSONRPCError(RPC_WALLET_ERROR, ferr);

            const ZSLPWalletUtxo* single = NULL;
            int64_t heldUnits = 0;            // total spendable non-baton units of G
            for (size_t i = 0; i < units.size(); ++i) {
                heldUnits += units[i].amount;
                if (units[i].amount == 1 && single == NULL)
                    single = &units[i]; // first (deterministic height,txid,vout)
            }

            if (single != NULL) {
                chosen = single->outpoint;
            } else if (heldUnits > 0) {
                // Holds authority units, but ALL of them are bundled in multi-unit
                // outpoint(s): minting would over-burn. Refuse with the split fix.
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "Collection " + groupId.GetHex() + " authority is held in a "
                    "multi-unit output; minting a card would burn all of it. Split "
                    "your authority into single units first (zslp_send " +
                    groupId.GetHex() + " to your own address with per-recipient "
                    "amount 1, up to 19 recipients per tx), then retry. To pin a "
                    "specific 1-unit output use the authority parameter.");
            } else if (allowBaton) {
                // No units at all — fall back to the baton ONLY when explicitly
                // permitted. Spending the baton in a child GENESIS BURNS it and
                // SEALS the collection (a GENESIS cannot continue a baton).
                std::vector<ZSLPWalletUtxo> batons;
                if (!ZSLPFindWalletTokenUtxos(pwalletMain, groupId, /*wantBaton=*/true, batons, ferr))
                    throw JSONRPCError(RPC_WALLET_ERROR, ferr);
                if (batons.empty())
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        "no spendable single-unit authority OR mint baton for collection " +
                        groupId.GetHex());
                chosen = batons[0].outpoint; // burning the baton SEALS the collection
            } else {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "no spendable single-unit authority for collection " + groupId.GetHex() +
                    "; mint more collection authority units (or split a multi-unit output "
                    "into single units with zslp_send ... amount 1), or pass allow_baton "
                    "to seal the collection by burning its baton");
            }
        }
        req.tokenInputs.push_back(chosen);
    }

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
            "zslp_send \"tokenid\" '[{\"address\":\"t1..\",\"amount\":n}, ...]' ( change_address )\n"
            "\nTransfer ZSLP token amounts. TWO forms:\n"
            "  * single recipient: \"to_address\" + optional amount (default 1) + optional\n"
            "    change_address;\n"
            "  * batch: a JSON ARRAY of {address, amount} recipients; the optional 3rd\n"
            "    arg is then the change_address (amount is per-recipient).\n"
            "Selects the wallet's token UTXOs of tokenid covering the TOTAL sent,\n"
            "conserves supply (token-change goes to a fresh own t-address, or\n"
            "change_address if given), pins token inputs + anti-burn-filters fee coins,\n"
            "and self-validates before broadcast. Rejects (clear error) on insufficient\n"
            "token balance — it never burns the token.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"tokenid\"        (string, required) the token id (hex)\n"
            "2. recipient(s)     (string OR array, required)\n"
            "     * string: a recipient t-address (single-recipient form), OR\n"
            "     * array : [ { \"address\":\"t1..\", \"amount\":n }, ... ] (batch form)\n"
            "3. amount/change    (optional)\n"
            "     * single form: amount (string|numeric, default 1) to send (<2^63)\n"
            "     * batch form : change_address (string) token-change t-address\n"
            "4. \"change_address\" (string, optional, single form only) token-change\n"
            "                    t-address (default: a fresh own address)\n"
            "\nThe number of recipients plus a token-change output must be <= "
            + std::to_string(ZSLP_MAX_SEND_OUTPUTS) + ".\n"
            "\nResult:\n{ \"txid\": \"hex\", \"recipients\": n }\n"
            "\nExamples:\n"
            + HelpExampleCli("zslp_send", "\"<tokenid>\" \"t1...\" 1")
            + HelpExampleCli("zslp_send",
                "\"<tokenid>\" '[{\"address\":\"t1aaa...\",\"amount\":5},{\"address\":\"t1bbb...\",\"amount\":3}]'")
            + HelpExampleRpc("zslp_send", "\"<tokenid>\", \"t1...\", \"5\""));

    CZSLPStore* store = GetZSLPStoreOrThrow();
    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint256 tokenId = ParseHashV(params[0], "tokenid");
    CZSLPToken token;
    if (!store->GetToken(tokenId, token))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Token not found");

    // Parallel recipient lists, in output order (recipScripts[j] is paid
    // recipAmounts[j], landing at vout[1+j]). Built once for both forms.
    std::vector<CScript> recipScripts;
    std::vector<uint64_t> recipAmounts;
    bool haveChangeAddr = false;
    CScript changeScript;

    // Detect the BATCH form. Over JSON-RPC (the GUI) params[1] is a real JSON
    // array; over zclassic-cli it arrives as a STRING like "[{...}]" because arg
    // index 1 isn't in the client.cpp conversion table (it can't be force-converted
    // there without breaking the positional address form, since a bare t-address is
    // not valid JSON). A t-address never starts with '[', so a leading '[' is an
    // unambiguous batch marker; parse it here so both transports work.
    UniValue batchArr(UniValue::VARR);
    bool isBatch = false;
    if (params[1].isArray()) {
        batchArr = params[1].get_array();
        isBatch = true;
    } else if (params[1].isStr()) {
        const std::string& bs = params[1].get_str();
        size_t bi = bs.find_first_not_of(" \t\r\n");
        if (bi != std::string::npos && bs[bi] == '[') {
            UniValue tmp;
            if (!tmp.read(bs) || !tmp.isArray())
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "recipients must be a JSON array of {\"address\":..,\"amount\":..} objects");
            batchArr = tmp;
            isBatch = true;
        }
    }

    if (isBatch) {
        // ── BATCH form: [ {address, amount}, ... ]; params[2] = change.
        const UniValue& arr = batchArr;
        if (arr.empty())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "recipients array is empty");
        // Bound the recipient count up front (before summing/selecting). The precise
        // recipients+change <= ZSLP_MAX_SEND_OUTPUTS check is enforced below once
        // change is known; this early cap stops an oversized array from being parsed.
        if (arr.size() > (size_t)ZSLP_MAX_SEND_OUTPUTS)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("too many recipients: %d exceeds the cap of %d",
                          (int)arr.size(), ZSLP_MAX_SEND_OUTPUTS));
        for (size_t i = 0; i < arr.size(); ++i) {
            if (!arr[i].isObject())
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "each recipient must be an object {address, amount}");
            const UniValue& r = arr[i].get_obj();
            const UniValue& va = find_value(r, "address");
            if (!va.isStr() || va.get_str().empty())
                throw JSONRPCError(RPC_INVALID_PARAMETER, "recipient address is required");
            uint64_t amt = ParseQuantity(find_value(r, "amount"), "amount");
            if (amt == 0)
                throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be > 0");
            recipScripts.push_back(ScriptForTAddr(va.get_str()));
            recipAmounts.push_back(amt);
        }
        if (params.size() > 3)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "in batch form the 3rd argument is change_address; there is no 4th argument");
        if (params.size() > 2 && !params[2].get_str().empty()) {
            changeScript = ScriptForTAddr(params[2].get_str());
            haveChangeAddr = true;
        }
    } else {
        // ── SINGLE form: params[1] = to_address; params[2] = amount; params[3] = change.
        recipScripts.push_back(ScriptForTAddr(params[1].get_str()));
        uint64_t amount = 1;
        if (params.size() > 2)
            amount = ParseQuantity(params[2], "amount");
        if (amount == 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be > 0");
        recipAmounts.push_back(amount);
        if (params.size() > 3 && !params[3].get_str().empty()) {
            changeScript = ScriptForTAddr(params[3].get_str());
            haveChangeAddr = true;
        }
    }

    // Sum of all recipient amounts (the total token output to fund). The recipient
    // count is capped at ZSLP_MAX_SEND_OUTPUTS above, but each amount can be up to
    // 2^63-1, so even two entries can exceed int64_t — guard every add explicitly.
    // (The conservation self-check in WouldBeValid re-sums with its own guard; this
    // just fails fast with a clear message instead of relying on signed-overflow UB.)
    int64_t needed = 0;
    for (size_t j = 0; j < recipAmounts.size(); ++j) {
        if (needed > std::numeric_limits<int64_t>::max() - (int64_t)recipAmounts[j])
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "total token amount overflows a 64-bit integer");
        needed += (int64_t)recipAmounts[j];
    }

    EnsureWalletIsUnlocked();

    // Enumerate + greedily select token UTXOs (deterministic order) covering the
    // SUM of all recipient amounts.
    std::vector<ZSLPWalletUtxo> utxos;
    std::string ferr;
    if (!ZSLPFindWalletTokenUtxos(pwalletMain, tokenId, /*wantBaton=*/false, utxos, ferr))
        throw JSONRPCError(RPC_WALLET_ERROR, ferr);

    int64_t availIn = 0;
    std::vector<COutPoint> chosen;
    for (size_t i = 0; i < utxos.size(); ++i) {
        chosen.push_back(utxos[i].outpoint);
        availIn += utxos[i].amount;
        if (availIn >= needed)
            break;
    }
    if (availIn < needed)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient token balance: have %d, need %d", availIn, needed));

    int64_t tokenChange = availIn - needed;

    // Build the parallel lists in the SAME order so outputQuantities[j] -> vout[1+j]
    // stays contiguous from vout[1]: recipients first (N), then (if any) token-change.
    // recipients(N) + change(0/1) <= ZSLP_MAX_SEND_OUTPUTS.
    int nOutputs = (int)recipScripts.size() + (tokenChange > 0 ? 1 : 0);
    if (nOutputs > ZSLP_MAX_SEND_OUTPUTS)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("too many SEND outputs: %d recipients%s exceeds the cap of %d",
                      (int)recipScripts.size(),
                      tokenChange > 0 ? " + change" : "", ZSLP_MAX_SEND_OUTPUTS));

    std::vector<uint64_t> quantities;
    quantities.reserve(nOutputs);
    for (size_t j = 0; j < recipAmounts.size(); ++j)
        quantities.push_back(recipAmounts[j]);
    if (tokenChange > 0)
        quantities.push_back((uint64_t)tokenChange);

    uint8_t tidBE[32]; TokenIdToBE(tokenId, tidBE);
    std::vector<unsigned char> opret = ZSLPBuildSend(tidBE, quantities);
    if (opret.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build SEND OP_RETURN");

    ZSLPBuildReq req;
    req.opret = CScript(opret.begin(), opret.end());
    for (size_t j = 0; j < recipScripts.size(); ++j) {
        ZSLPTokenOut recip; recip.dest = recipScripts[j]; recip.dustSats = SLP_TOKEN_DUST;
        req.tokenOuts.push_back(recip);             // vout[1+j] = recipient j
    }
    if (tokenChange > 0) {
        ZSLPTokenOut chg;
        chg.dest = haveChangeAddr ? changeScript : FreshWalletScript();
        chg.dustSats = SLP_TOKEN_DUST;
        req.tokenOuts.push_back(chg);               // vout[N+1] = token-change to self
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
    ret.push_back(Pair("recipients", (int)recipScripts.size()));
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
    { "zslp",    "zslp_getbalance",    &zslp_getbalance,    true },
    { "zslp",    "zslp_listholders",   &zslp_listholders,   true },
    { "zslp",    "zslp_decode",        &zslp_decode,        true },
    { "zslp", "zslp_filefingerprint",  &zslp_filefingerprint, true },
    { "zslp",    "zslp_verifyfile",    &zslp_verifyfile,    true },
    { "zslp", "zslp_listcollectionmembers", &zslp_listcollectionmembers, true },
    { "zslp",    "zslp_collectioninfo", &zslp_collectioninfo, true },
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
