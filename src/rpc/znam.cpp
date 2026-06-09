// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZNAM (ZCL Names) read-only RPCs. All commands here are pure reads of the ZNAM
// name store (populated by the NON-consensus indexer behind -znamindex). They
// never construct, sign, or broadcast transactions and never touch validation,
// PoW, or the wallet. CONTENT record values are returned opaque — resolving a
// name NEVER fetches or hosts a file.
//
//   name_resolve  "name"                    -> active name + records, or null
//   name_info     "name"                    -> full state (active|grace|free)
//   name_list     (count from)              -> bounded name list
//   name_history  "name" (count from)       -> bounded audit log (incl. no-ops)
//   name_listmine "owner_address"           -> names owned by an address
//
// Wallet-side write commands (name_register/update/transfer/renew/...) that BUILD
// owner-signed OP_RETURN transactions are a separate wallet concern and are added
// in the wallet RPC layer; this file is read-only and wallet-independent.

#include "rpc/server.h"

#include "main.h"          // cs_main, chainActive
#include "rpc/protocol.h"
#include "sync.h"
#include "util.h"
#include "znam/znamindexer.h"
#include "znam/znammsg.h"
#include "znam/znamstore.h"

#include <stdint.h>
#include <string>
#include <vector>

#include <univalue.h>

#ifdef ENABLE_WALLET
#include "init.h"            // pwalletMain
#include "key_io.h"          // DecodeDestination / IsValidDestination
#include "script/standard.h" // CKeyID (P2PKH check for transfer target)
#include "wallet/wallet.h"   // CWallet, CWalletTx, ZNAMBuildReq, BuildAndCommitZNAM
#include "wallet/znamwallet.h" // ZNAMFindOwnerInput
// EnsureWalletIsAvailable is file-extern in wallet/rpcwallet.cpp (no header);
// EnsureWalletIsUnlocked is declared in rpc/server.h.
extern bool EnsureWalletIsAvailable(bool avoidException);
#endif

// Fail CLOSED: if the index is disabled, every ZNAM read RPC throws rather than
// silently returning empty results (which a caller could misread as "no names").
static CZNAMStore* GetZNAMStoreOrThrow()
{
    if (g_znamIndexer == NULL || g_znamIndexer->Store() == NULL)
        throw JSONRPCError(RPC_MISC_ERROR,
            "ZNAM index is not enabled. Start zclassicd with -znamindex.");
    return g_znamIndexer->Store();
}

static std::string TargetTypeName(uint8_t t)
{
    switch (t) {
    case ZNAM_TARGET_ONION:   return "onion";
    case ZNAM_TARGET_ZADDR:   return "zaddr";
    case ZNAM_TARGET_TADDR:   return "taddr";
    case ZNAM_TARGET_BTC:     return "btc";
    case ZNAM_TARGET_LTC:     return "ltc";
    case ZNAM_TARGET_DOGE:    return "doge";
    case ZNAM_TARGET_CONTENT: return "content";
    default:                  return "unknown";
    }
}

static std::string CommandName(uint8_t c)
{
    switch (c) {
    case ZNAMMSG_REGISTER:   return "register";
    case ZNAMMSG_UPDATE:     return "update";
    case ZNAMMSG_TRANSFER:   return "transfer";
    case ZNAMMSG_RENEW:      return "renew";
    case ZNAMMSG_SET_RECORD: return "set_record";
    case ZNAMMSG_SET_TEXT:   return "set_text";
    default:                 return "invalid";
    }
}

static int64_t CurrentHeight()
{
    LOCK(cs_main);
    return (int64_t)chainActive.Height();
}

UniValue name_resolve(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "name_resolve \"name\"\n"
            "\nResolves an ACTIVE ZNAM name to its owner, primary target, and records.\n"
            "Returns null for an unregistered, expired, or grace-period name.\n"
            "CONTENT values are returned opaque; this NEVER fetches a file.\n"
            "\nArguments:\n"
            "1. name   (string, required) the name to resolve\n"
            "\nResult: { name, owner, registeredHeight, expiryHeight, status,\n"
            "          primary:{type,typeName,value}, records:[...], text:[...] } or null\n"
            "\nExamples:\n"
            + HelpExampleCli("name_resolve", "\"alice\"")
            + HelpExampleRpc("name_resolve", "\"alice\""));

    CZNAMStore* store = GetZNAMStoreOrThrow();
    std::string name = params[0].get_str();

    CZNAMResolvedName res;
    if (!store->ResolveName(name, CurrentHeight(), res))
        return NullUniValue;

    UniValue o(UniValue::VOBJ);
    o.pushKV("name", res.name.name);
    o.pushKV("owner", res.name.ownerAddr);
    o.pushKV("registeredHeight", res.name.registeredHeight);
    o.pushKV("expiryHeight", res.name.expiryHeight);
    o.pushKV("status", "active");

    UniValue primary(UniValue::VOBJ);
    primary.pushKV("type", (int)res.name.primaryType);
    primary.pushKV("typeName", TargetTypeName(res.name.primaryType));
    primary.pushKV("value", res.name.primaryValue);
    o.pushKV("primary", primary);

    UniValue recs(UniValue::VARR);
    for (size_t i = 0; i < res.records.size(); ++i) {
        UniValue r(UniValue::VOBJ);
        r.pushKV("type", (int)res.records[i].targetType);
        r.pushKV("typeName", TargetTypeName(res.records[i].targetType));
        r.pushKV("value", res.records[i].value);
        recs.push_back(r);
    }
    o.pushKV("records", recs);

    UniValue txt(UniValue::VARR);
    for (size_t i = 0; i < res.textRecords.size(); ++i) {
        UniValue t(UniValue::VOBJ);
        t.pushKV("key", res.textRecords[i].key);
        t.pushKV("value", res.textRecords[i].value);
        txt.push_back(t);
    }
    o.pushKV("text", txt);
    return o;
}

UniValue name_info(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "name_info \"name\"\n"
            "\nReturns the full ZNAM name state regardless of active/grace/expired.\n"
            "Returns null only for a name that was never registered.\n"
            "\nArguments:\n"
            "1. name   (string, required)\n"
            "\nResult: { name, owner, registeredHeight, expiryHeight, status, graceUntil } or null\n"
            "\nExamples:\n"
            + HelpExampleCli("name_info", "\"alice\"")
            + HelpExampleRpc("name_info", "\"alice\""));

    CZNAMStore* store = GetZNAMStoreOrThrow();
    std::string name = params[0].get_str();

    CZNAMName rec;
    if (!store->GetName(name, rec))
        return NullUniValue;

    int64_t height = CurrentHeight();
    std::string status = CZNAMStore::IsActive(rec, height) ? "active"
                       : (CZNAMStore::IsInGrace(rec, height) ? "grace" : "free");

    UniValue o(UniValue::VOBJ);
    o.pushKV("name", rec.name);
    o.pushKV("owner", rec.ownerAddr);
    o.pushKV("registeredHeight", rec.registeredHeight);
    o.pushKV("expiryHeight", rec.expiryHeight);
    o.pushKV("status", status);
    o.pushKV("graceUntil", rec.expiryHeight + ZNAM_GRACE_BLOCKS);
    o.pushKV("primaryType", (int)rec.primaryType);
    o.pushKV("primaryTypeName", TargetTypeName(rec.primaryType));
    o.pushKV("primaryValue", rec.primaryValue);
    return o;
}

UniValue name_list(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw std::runtime_error(
            "name_list ( count from )\n"
            "\nLists known ZNAM names (read-only, bounded).\n"
            "\nArguments:\n"
            "1. count  (numeric, optional, default=100) max names to return (<=" + std::to_string(ZNAM_LIST_MAX) + ")\n"
            "2. from   (numeric, optional, default=0) number of names to skip\n"
            "\nResult: [ { name, owner, expiryHeight, status }, ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("name_list", "100 0")
            + HelpExampleRpc("name_list", "100, 0"));

    CZNAMStore* store = GetZNAMStoreOrThrow();

    int count = 100, from = 0;
    if (params.size() > 0) count = params[0].get_int();
    if (params.size() > 1) from = params[1].get_int();
    if (count < 0) count = 0;
    if (count > ZNAM_LIST_MAX) count = ZNAM_LIST_MAX;
    if (from < 0) from = 0;

    int64_t height = CurrentHeight();
    std::vector<CZNAMName> names;
    store->ListNames(from, count, names);

    UniValue arr(UniValue::VARR);
    for (size_t i = 0; i < names.size(); ++i) {
        const CZNAMName& n = names[i];
        std::string status = CZNAMStore::IsActive(n, height) ? "active"
                           : (CZNAMStore::IsInGrace(n, height) ? "grace" : "free");
        UniValue o(UniValue::VOBJ);
        o.pushKV("name", n.name);
        o.pushKV("owner", n.ownerAddr);
        o.pushKV("expiryHeight", n.expiryHeight);
        o.pushKV("status", status);
        arr.push_back(o);
    }
    return arr;
}

UniValue name_history(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "name_history \"name\" ( count from )\n"
            "\nReturns the audit log for a name (applied changes AND deterministic no-ops).\n"
            "\nArguments:\n"
            "1. name   (string, required)\n"
            "2. count  (numeric, optional, default=100) max rows (<=" + std::to_string(ZNAM_LIST_MAX) + ")\n"
            "3. from   (numeric, optional, default=0) rows to skip\n"
            "\nResult: [ { txid, blockHash, height, txIndex, command, owner, targetType,\n"
            "            targetValue, textKey, textValue, applied }, ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("name_history", "\"alice\" 100 0")
            + HelpExampleRpc("name_history", "\"alice\", 100, 0"));

    CZNAMStore* store = GetZNAMStoreOrThrow();
    std::string name = params[0].get_str();

    int count = 100, from = 0;
    if (params.size() > 1) count = params[1].get_int();
    if (params.size() > 2) from = params[2].get_int();
    if (count < 0) count = 0;
    if (count > ZNAM_LIST_MAX) count = ZNAM_LIST_MAX;
    if (from < 0) from = 0;

    std::vector<CZNAMHistory> hist;
    store->ListHistory(name, from, count, hist);

    UniValue arr(UniValue::VARR);
    for (size_t i = 0; i < hist.size(); ++i) {
        const CZNAMHistory& h = hist[i];
        UniValue o(UniValue::VOBJ);
        o.pushKV("txid", h.txid.GetHex());
        o.pushKV("blockHash", h.blockHash.GetHex());
        o.pushKV("height", h.blockHeight);
        o.pushKV("txIndex", (int)h.txIndex);
        o.pushKV("command", CommandName(h.command));
        o.pushKV("owner", h.ownerAddr);
        o.pushKV("targetType", (int)h.targetType);
        o.pushKV("targetValue", h.targetValue);
        o.pushKV("textKey", h.textKey);
        o.pushKV("textValue", h.textValue);
        o.pushKV("applied", h.applied);
        arr.push_back(o);
    }
    return arr;
}

UniValue name_listmine(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "name_listmine \"owner_address\" ( count from )\n"
            "\nLists ZNAM names currently owned by a transparent address.\n"
            "(The GUI/wallet passes one of its own t-addresses.)\n"
            "\nArguments:\n"
            "1. owner_address (string, required) the owner t-address\n"
            "2. count         (numeric, optional, default=100) max names (<=" + std::to_string(ZNAM_LIST_MAX) + ")\n"
            "3. from          (numeric, optional, default=0) names to skip\n"
            "\nResult: [ { name, owner, expiryHeight, status }, ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("name_listmine", "\"t1exampleaddress\"")
            + HelpExampleRpc("name_listmine", "\"t1exampleaddress\""));

    CZNAMStore* store = GetZNAMStoreOrThrow();
    std::string owner = params[0].get_str();

    int count = 100, from = 0;
    if (params.size() > 1) count = params[1].get_int();
    if (params.size() > 2) from = params[2].get_int();
    if (count < 0) count = 0;
    if (count > ZNAM_LIST_MAX) count = ZNAM_LIST_MAX;
    if (from < 0) from = 0;

    int64_t height = CurrentHeight();
    std::vector<CZNAMName> names;
    store->ListOwnerNames(owner, from, count, names);

    UniValue arr(UniValue::VARR);
    for (size_t i = 0; i < names.size(); ++i) {
        const CZNAMName& n = names[i];
        std::string status = CZNAMStore::IsActive(n, height) ? "active"
                           : (CZNAMStore::IsInGrace(n, height) ? "grace" : "free");
        UniValue o(UniValue::VOBJ);
        o.pushKV("name", n.name);
        o.pushKV("owner", n.ownerAddr);
        o.pushKV("expiryHeight", n.expiryHeight);
        o.pushKV("status", status);
        arr.push_back(o);
    }
    return arr;
}

#ifdef ENABLE_WALLET
// ── Write path (wallet) ─────────────────────────────────────────────
//
// Each command BUILDS + SIGNS + self-validates + BROADCASTS one ZNAM OP_RETURN
// transaction with the OWNER's UTXO pinned at vin[0] (the FIFS signer). These are
// safe=false (explicit user action). NON-consensus: an invalid record the network
// admits is a deterministic overlay no-op, never a block/tx rejection.

// Validate a target_type (1..7) + value, returning the encoded OP_RETURN or
// throwing. Builders below all funnel through ZNAMBuildAndReturn (locks held).
static UniValue ZNAMBuildAndReturn(const std::string& name, ZNAMMsgCommand cmd,
                                   const std::vector<unsigned char>& opret,
                                   std::string owner /*in: ""=>pick default*/)
{
    if (opret.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "ZNAM metadata too large or invalid for one OP_RETURN");
    COutPoint ownerInput;
    CScript ownerScript;
    std::string ferr;
    if (!ZNAMFindOwnerInput(pwalletMain, owner, ownerInput, ownerScript, ferr))
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, ferr);

    ZNAMBuildReq req;
    req.opret = CScript(opret.begin(), opret.end());
    req.ownerInput = ownerInput;
    req.ownerScript = ownerScript;
    req.expectedName = name;
    req.expectedCommand = (int)cmd;
    req.expectedOwner = owner;

    CWalletTx wtx;
    std::string err;
    if (!BuildAndCommitZNAM(pwalletMain, req, wtx, err))
        throw JSONRPCError(RPC_WALLET_ERROR, err);

    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", wtx.GetHash().GetHex());
    o.pushKV("name", name);
    o.pushKV("owner", owner);
    o.pushKV("command", CommandName((uint8_t)cmd));
    return o;
}

// Resolve the current owner of an existing name, requiring it be active (or in
// grace for RENEW). Throws if unregistered/expired. Caller holds cs_main.
static std::string ZNAMCurrentOwnerOrThrow(const std::string& name, bool allowGrace)
{
    CZNAMStore* store = GetZNAMStoreOrThrow();
    CZNAMName rec;
    if (!store->GetName(name, rec))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "name '" + name + "' is not registered");
    int64_t h = CurrentHeight();
    bool ok = CZNAMStore::IsActive(rec, h) ||
              (allowGrace && CZNAMStore::IsInGrace(rec, h));
    if (!ok)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "name '" + name + "' is expired (re-register it instead)");
    return rec.ownerAddr;
}

static void ZNAMCheckName(const std::string& name)
{
    if (!ZNAMValidateName(name))
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "invalid name: lowercase [a-z0-9-], no leading/trailing "
                           "hyphen, 1..63 bytes");
}

static uint8_t ZNAMCheckType(const UniValue& v)
{
    int t = v.get_int();
    if (t < ZNAM_TARGET_ONION || t > ZNAM_TARGET_CONTENT)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "target_type must be 1..7 (onion/zaddr/taddr/btc/ltc/doge/content)");
    return (uint8_t)t;
}

UniValue name_register(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 4)
        throw std::runtime_error(
            "name_register \"name\" target_type \"target_value\" ( \"owner_address\" )\n"
            "\nRegister a ZCL name (First-In-First-Served). Builds + broadcasts an\n"
            "OP_RETURN tx whose vin[0] is the owner's coin (the owner becomes the\n"
            "vin[0] P2PKH signer). NON-consensus / opt-in (-znamindex to observe).\n"
            "\nArguments:\n"
            "1. name          (string, required) lowercase [a-z0-9-], 1..63 bytes\n"
            "2. target_type   (numeric, required) 1=onion 2=zaddr 3=taddr 4=btc 5=ltc 6=doge 7=content\n"
            "3. target_value  (string, required) the resolver value (<=128 bytes; opaque)\n"
            "4. owner_address (string, optional) a wallet t-address that holds a plain\n"
            "                 spendable coin to own the name; default: the wallet's\n"
            "                 largest plain coin's address\n"
            "\nResult: { txid, name, owner, command }\n"
            "\nExamples:\n"
            + HelpExampleCli("name_register", "\"alice\" 1 \"abcd...xyz.onion\"")
            + HelpExampleRpc("name_register", "\"alice\", 1, \"abcd...xyz.onion\""));
    if (!EnsureWalletIsAvailable(fHelp)) return NullUniValue;

    std::string name = params[0].get_str();
    ZNAMCheckName(name);
    uint8_t type = ZNAMCheckType(params[1]);
    std::string value = params[2].get_str();
    std::string owner = params.size() > 3 ? params[3].get_str() : std::string();

    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    return ZNAMBuildAndReturn(name, ZNAMMSG_REGISTER,
                              ZNAMBuildRegister(name, type, value), owner);
}

UniValue name_update(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "name_update \"name\" target_type \"target_value\"\n"
            "\nUpdate the primary target of a name you own (must be active).\n"
            "\nArguments:\n1. name (string) \n2. target_type (numeric 1..7)\n3. target_value (string <=128)\n"
            "\nResult: { txid, name, owner, command }\n"
            + HelpExampleCli("name_update", "\"alice\" 2 \"zs1...\""));
    if (!EnsureWalletIsAvailable(fHelp)) return NullUniValue;

    std::string name = params[0].get_str();
    ZNAMCheckName(name);
    uint8_t type = ZNAMCheckType(params[1]);
    std::string value = params[2].get_str();

    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    std::string owner = ZNAMCurrentOwnerOrThrow(name, /*allowGrace=*/false);
    return ZNAMBuildAndReturn(name, ZNAMMSG_UPDATE,
                              ZNAMBuildUpdate(name, type, value), owner);
}

UniValue name_transfer(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw std::runtime_error(
            "name_transfer \"name\" \"new_owner\"\n"
            "\nTransfer a name you own to a new transparent (P2PKH) owner address.\n"
            "\nArguments:\n1. name (string)\n2. new_owner (string) a valid ZCL t-address (P2PKH)\n"
            "\nResult: { txid, name, owner, command }\n"
            + HelpExampleCli("name_transfer", "\"alice\" \"t1...\""));
    if (!EnsureWalletIsAvailable(fHelp)) return NullUniValue;

    std::string name = params[0].get_str();
    ZNAMCheckName(name);
    std::string newOwner = params[1].get_str();
    {
        CTxDestination dest = DecodeDestination(newOwner);
        if (!IsValidDestination(dest) || boost::get<CKeyID>(&dest) == NULL)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               "new_owner must be a valid transparent P2PKH address");
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    std::string owner = ZNAMCurrentOwnerOrThrow(name, /*allowGrace=*/false);
    return ZNAMBuildAndReturn(name, ZNAMMSG_TRANSFER,
                              ZNAMBuildTransfer(name, newOwner), owner);
}

UniValue name_renew(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "name_renew \"name\"\n"
            "\nRenew a name you own (active or in its grace period).\n"
            "\nArguments:\n1. name (string)\n"
            "\nResult: { txid, name, owner, command }\n"
            + HelpExampleCli("name_renew", "\"alice\""));
    if (!EnsureWalletIsAvailable(fHelp)) return NullUniValue;

    std::string name = params[0].get_str();
    ZNAMCheckName(name);

    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    std::string owner = ZNAMCurrentOwnerOrThrow(name, /*allowGrace=*/true);
    return ZNAMBuildAndReturn(name, ZNAMMSG_RENEW, ZNAMBuildRenew(name), owner);
}

UniValue name_setrecord(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "name_setrecord \"name\" target_type \"target_value\"\n"
            "\nSet an additional address/content record on a name you own (active).\n"
            "\nArguments:\n1. name (string)\n2. target_type (numeric 1..7)\n3. target_value (string <=128)\n"
            "\nResult: { txid, name, owner, command }\n"
            + HelpExampleCli("name_setrecord", "\"alice\" 4 \"bc1q...\""));
    if (!EnsureWalletIsAvailable(fHelp)) return NullUniValue;

    std::string name = params[0].get_str();
    ZNAMCheckName(name);
    uint8_t type = ZNAMCheckType(params[1]);
    std::string value = params[2].get_str();

    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    std::string owner = ZNAMCurrentOwnerOrThrow(name, /*allowGrace=*/false);
    return ZNAMBuildAndReturn(name, ZNAMMSG_SET_RECORD,
                              ZNAMBuildSetRecord(name, type, value), owner);
}

UniValue name_settext(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw std::runtime_error(
            "name_settext \"name\" \"key\" \"value\"\n"
            "\nSet (or delete, with empty value) a printable text record on a name\n"
            "you own (active). Keys/values are printable ASCII only.\n"
            "\nArguments:\n1. name (string)\n2. key (string, printable, 1..32)\n3. value (string, printable, 0..128; empty deletes)\n"
            "\nResult: { txid, name, owner, command }\n"
            + HelpExampleCli("name_settext", "\"alice\" \"url\" \"https://alice.example\""));
    if (!EnsureWalletIsAvailable(fHelp)) return NullUniValue;

    std::string name = params[0].get_str();
    ZNAMCheckName(name);
    std::string key = params[1].get_str();
    std::string value = params[2].get_str();

    LOCK2(cs_main, pwalletMain->cs_wallet);
    EnsureWalletIsUnlocked();
    std::string owner = ZNAMCurrentOwnerOrThrow(name, /*allowGrace=*/false);
    return ZNAMBuildAndReturn(name, ZNAMMSG_SET_TEXT,
                              ZNAMBuildSetText(name, key, value), owner);
}
#endif // ENABLE_WALLET

static const CRPCCommand commands[] =
{ //  category   name              actor (function)   okSafeMode
  //  ---------  ----------------  -----------------  ----------
    { "znam",    "name_resolve",   &name_resolve,     true },
    { "znam",    "name_info",      &name_info,        true },
    { "znam",    "name_list",      &name_list,        true },
    { "znam",    "name_history",   &name_history,     true },
    { "znam",    "name_listmine",  &name_listmine,    true },
#ifdef ENABLE_WALLET
    { "znam",    "name_register",  &name_register,    false },
    { "znam",    "name_update",    &name_update,      false },
    { "znam",    "name_transfer",  &name_transfer,    false },
    { "znam",    "name_renew",     &name_renew,       false },
    { "znam",    "name_setrecord", &name_setrecord,   false },
    { "znam",    "name_settext",   &name_settext,     false },
#endif
};

void RegisterZNAMRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
