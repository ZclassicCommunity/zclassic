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

static const CRPCCommand commands[] =
{ //  category   name              actor (function)   okSafeMode
  //  ---------  ----------------  -----------------  ----------
    { "znam",    "name_resolve",   &name_resolve,     true },
    { "znam",    "name_info",      &name_info,        true },
    { "znam",    "name_list",      &name_list,        true },
    { "znam",    "name_history",   &name_history,     true },
    { "znam",    "name_listmine",  &name_listmine,    true },
};

void RegisterZNAMRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
