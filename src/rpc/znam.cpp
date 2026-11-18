// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RPC surface of the ZNAM name index. Every command answers with a clear error
// while the index is off (-znamindex=0, the default). The read commands only
// read the index. The three wallet commands build an ordinary transaction that
// carries a ZNAM record in an OP_RETURN output; no command ever sends money to
// a name (see znam_resolve and doc/znam.md).

#include "rpc/server.h"

#include "chain.h"
#include "chainparams.h"
#include "init.h"
#include "key_io.h"
#include "main.h"
#include "script/standard.h"
#include "txmempool.h"
#include "univalue.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "znam/znamindex.h"
#include "znam/znamresolve.h"
#include "znam/znamservice.h"
#ifdef ENABLE_WALLET
#include "coincontrol.h"
#include "wallet/tokenguard.h"
#include "wallet/wallet.h"
#endif

#include "c23/services/glue/zcl_znam_index.h"

#include <boost/assign/list_of.hpp>
#include <stdint.h>
#include <string>

using namespace std;
using namespace znam;

namespace {

const char* const kDisabled =
    "The ZNAM name index is disabled. Start zclassicd with -znamindex=1 (it builds in the background and does not touch "
    "consensus or wallet.dat). See doc/znam.md.";

ZnamService& RequireIndex()
{
    if (!pznamService)
        throw JSONRPCError(RPC_MISC_ERROR, kDisabled);
    return *pznamService;
}

/** Name resolution and the wallet commands depend on an index that has seen every block: a stale one can
 *  miss the UPDATE that moved a name, or the REGISTER that took it. */
ZnamService& RequireSyncedIndex()
{
    ZnamService& svc = RequireIndex();
    ServiceInfo si = svc.GetInfo();
    if (IsInitialBlockDownload()) {
        // "synced" only says the index has seen the local tip; a tip that is itself behind the network can miss the
        // UPDATE or TRANSFER that moved a name.
        int h;
        int64_t age;
        {
            LOCK(cs_main);
            h = chainActive.Height();
            CBlockIndex* tip = chainActive.Tip();
            age = tip ? GetTime() - tip->GetBlockTime() : 0;
        }
        throw JSONRPCError(RPC_MISC_ERROR,
                           strprintf("The node is still catching up with the network (local tip height %d, %d hours old): names cannot "
                                     "be resolved or registered safely until it has. Retry when the node is synced.",
                                     h, (int)(age / 3600)));
    }
    if (!si.synced)
        throw JSONRPCError(RPC_MISC_ERROR,
                           strprintf("The ZNAM index is not synced with the chain tip (indexed height %d of %d%s). Wait for it and "
                                     "retry; see znam_getindexinfo.",
                                     si.hasIndexed ? si.indexedHeight : -1, si.chainHeight,
                                     si.error.empty() ? "" : (", " + si.error).c_str()));
    return svc;
}

int TipHeight()
{
    LOCK(cs_main);
    return chainActive.Height();
}

/** A string that is certain to be valid UTF-8: record values are arbitrary bytes chosen by the name's owner. */
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
        if (ok && n == 1 && (c < 0x20 || c == 0x7f))
            ok = false;
        if (ok && n == 2 && c == 0xc2 && (unsigned char)s[i + 1] < 0xa0)
            ok = false; // C1 control characters (U+0080-U+009F)
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

UniValue EntryJson(const Entry& e, int tipHeight)
{
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("name", e.name));
    o.push_back(Pair("owner", Utf8Clean(e.owner)));
    o.push_back(Pair("type", TypeName(e.type)));
    o.push_back(Pair("value", Utf8Clean(e.value)));
    o.push_back(Pair("registeredheight", e.regHeight));
    o.push_back(Pair("registeredtxid", e.regTxid.GetHex()));
    o.push_back(Pair("lastupdatetxid", e.lastUpdateTxid.GetHex()));
    o.push_back(Pair("expiryheight", e.expiryHeight));
    o.push_back(Pair("expired", e.expiryHeight < tipHeight));
    UniValue c(UniValue::VOBJ);
    c.push_back(Pair("height", e.changeHeight));
    c.push_back(Pair("txid", e.changeTxid.GetHex()));
    c.push_back(Pair("command", CommandName(e.changeCommand)));
    o.push_back(Pair("lastchange", c));
    return o;
}

UniValue ServiceJson(ZnamService& svc)
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
    double progress = 0;
    if (si.synced)
        progress = 1;
    else if (si.hasIndexed && si.chainHeight > si.startHeight)
        progress = double(si.indexedHeight - si.startHeight + 1) / double(si.chainHeight - si.startHeight + 1);
    o.push_back(Pair("progress", progress < 0 ? 0 : progress > 1 ? 1 : progress));
    o.push_back(Pair("error", si.error.empty() ? UniValue() : UniValue(si.error)));
    o.push_back(Pair("names", (int64_t)st.names));
    o.push_back(Pair("messages", (int64_t)st.messages));
    o.push_back(Pair("applied", (int64_t)st.applied));
    o.push_back(Pair("ignored", (int64_t)st.ignored));
    UniValue by(UniValue::VOBJ);
    for (int c = 1; c <= 6; c++)
        by.push_back(Pair(CommandName(c), (int64_t)st.byCommand[c]));
    o.push_back(Pair("appliedbycommand", by));
    return o;
}

UniValue znam_getindexinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "znam_getindexinfo\n"
            "\nProgress and counters of the ZNAM name index. Answers {\"enabled\": false} when the index is off\n"
            "(start zclassicd with -znamindex=1).\n"
            "\nResult:\n"
            "{\n"
            "  \"enabled\": true,\n"
            "  \"running\": true|false,       (boolean) the background worker is alive\n"
            "  \"synced\": true|false,        (boolean) the index tip is the chain tip\n"
            "  \"startheight\": n,            (numeric) first block the index reads\n"
            "  \"indexedheight\": n|null,     (numeric) height of the last block applied\n"
            "  \"indexedblock\": \"hash\"|null,\n"
            "  \"chainheight\": n,\n"
            "  \"progress\": x,               (numeric) 0..1\n"
            "  \"error\": \"text\"|null,        (string) a problem the worker is retrying\n"
            "  \"names\": n,                  (numeric) registered names\n"
            "  \"messages\": n,               (numeric) parsed ZNAM messages, whatever happened to them\n"
            "  \"applied\": n, \"ignored\": n,  (numeric) messages that changed a name / that changed nothing\n"
            "  \"appliedbycommand\": {\"REGISTER\": n, ...}\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("znam_getindexinfo", "")
            + HelpExampleRpc("znam_getindexinfo", "")
        );
    if (!pznamService) {
        UniValue o(UniValue::VOBJ);
        o.push_back(Pair("enabled", false));
        o.push_back(Pair("error", kDisabled));
        return o;
    }
    return ServiceJson(*pznamService);
}

UniValue ErrorBody(const string& name, const char* code, const string& text, bool registered)
{
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("name", name));
    o.push_back(Pair("resolved", false));
    o.push_back(Pair("error_code", code));
    o.push_back(Pair("error", text));
    o.push_back(Pair("registered", registered));
    return o;
}

UniValue CandidateJson(const Candidate& c, bool primary)
{
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("type", TypeName(c.type)));
    o.push_back(Pair("value", Utf8Clean(c.value)));
    o.push_back(Pair("primary", primary));
    o.push_back(Pair("payable", c.kind != PAY_NONE));
    o.push_back(Pair("kind", PayKindName(c.kind)));
    if (c.kind == PAY_NONE && !c.why.empty())
        o.push_back(Pair("why", c.why));
    o.push_back(Pair("height", c.height));
    o.push_back(Pair("txid", c.txid.GetHex()));
    return o;
}

UniValue znam_resolve(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "znam_resolve \"name\" ( \"type\" recentblocks )\n"
            "\nResolve a ZNAM name from the local index (requires -znamindex=1). Nothing is sent to any peer, and\n"
            "nothing is paid: this returns an address for YOU to show and confirm, together with the block and\n"
            "transaction that set it. z_sendmany and sendtoaddress never take a name.\n"
            "\nArguments:\n"
            "1. \"name\"          (string, required) exactly as registered: 1-63 characters a-z 0-9 and '-',\n"
            "                   no leading or trailing '-'. No case folding, no Unicode.\n"
            "2. \"type\"          (string, optional, default=\"pay\") \"pay\": a payable t- or z-address (the primary\n"
            "                   target when it is one, else a t-address record, else a z-address record).\n"
            "                   Or one of onion, zaddr, taddr, btc, ltc, doge, content (Z23's name_resolve).\n"
            "3. recentblocks    (numeric, optional, default=100) a change newer than this many blocks sets\n"
            "                   \"changed_recently\" and adds a warning. 0 disables the flag.\n"
            "\nResult (resolved):\n"
            "{\n"
            "  \"name\", \"resolved\": true,\n"
            "  \"value\": \"...\", \"type\": \"t-address\", \"kind\": \"transparent|sapling|sprout|none\",\n"
            "  \"payable\": true|false,\n"
            "  \"address\": \"...\",                  (only when payable)\n"
            "  \"set_height\", \"set_txid\", \"set_by_record\",   the block and transaction that set the answer\n"
            "  \"blocks_since_change\", \"changed_recently\", \"recent_change_blocks\",\n"
            "  \"owner\", \"registered_height\", \"registered_txid\", \"expiry_height\", \"expired\",\n"
            "  \"warnings\": [\"...\"],\n"
            "  \"records\": [{\"type\", \"value\", \"primary\", \"payable\", \"kind\", \"height\", \"txid\"}],\n"
            "  \"index\": {\"synced\": true, \"height\": n, \"tip\": \"hash\"}\n"
            "}\n"
            "Result (not resolved): {\"resolved\": false, \"error_code\": \"NAME_MALFORMED|NAME_ABSENT|NAME_NO_SUCH_TARGET|\n"
            "NAME_TYPE_UNKNOWN\", \"error\": \"...\", \"registered\": true|false}\n"
            "\nExamples:\n"
            + HelpExampleCli("znam_resolve", "\"alice\"")
            + HelpExampleRpc("znam_resolve", "\"alice\"")
        );
    ZnamService& svc = RequireSyncedIndex();
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VNUM));
    const string name = params[0].get_str();
    string typeStr = params.size() > 1 ? params[1].get_str() : "pay";
    int recentBlocks = params.size() > 2 ? params[2].get_int() : DEFAULT_RECENT_BLOCKS;
    if (recentBlocks < 0 || recentBlocks > 1000000)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "recentblocks must be 0..1000000");
    unsigned int want = 0;
    if (!typeStr.empty() && typeStr != "pay") {
        want = TypeFromName(typeStr);
        if (want == 0)
            return ErrorBody(name, "NAME_TYPE_UNKNOWN", "No such ZNAM target type. Valid types are onion, zaddr, taddr, btc, ltc, doge, content, or pay.", false);
    }
    int tip = TipHeight();
    Resolution r = Resolve(svc.Index(), name, want, tip, recentBlocks);
    switch (r.status) {
    case Resolution::MALFORMED:
        return ErrorBody(name, "NAME_MALFORMED",
                         "That is not a valid ZNAM name. A name is 1-63 characters, lowercase letters, digits and hyphens only "
                         "(no leading or trailing hyphen) - nothing was looked up.", false);
    case Resolution::ABSENT:
        return ErrorBody(name, "NAME_ABSENT", "That name is well-formed but has not been registered on this chain (as far as the index has seen).", false);
    case Resolution::NO_TARGET: {
        UniValue o = ErrorBody(name, "NAME_NO_SUCH_TARGET",
                               want == 0 ? "That name is registered but carries no payable t- or z-address."
                                         : "That name is registered but has no record of the type you asked for.", true);
        o.push_back(Pair("owner", Utf8Clean(r.entry.owner)));
        UniValue recs(UniValue::VARR);
        for (size_t i = 0; i < r.candidates.size(); i++)
            recs.push_back(CandidateJson(r.candidates[i], i == 0));
        o.push_back(Pair("records", recs));
        return o;
    }
    case Resolution::OK:
        break;
    }
    const Candidate& c = r.candidates[r.selected];
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("name", name));
    o.push_back(Pair("resolved", true));
    o.push_back(Pair("value", Utf8Clean(c.value)));
    o.push_back(Pair("type", TypeName(c.type)));
    o.push_back(Pair("kind", PayKindName(c.kind)));
    o.push_back(Pair("payable", c.kind != PAY_NONE));
    if (c.kind != PAY_NONE)
        o.push_back(Pair("address", c.value));
    o.push_back(Pair("set_height", r.changeHeight));
    o.push_back(Pair("set_txid", r.changeTxid.GetHex()));
    o.push_back(Pair("set_by_record", c.fromRecord));
    o.push_back(Pair("blocks_since_change", r.blocksSinceChange));
    o.push_back(Pair("changed_recently", r.recent));
    o.push_back(Pair("recent_change_blocks", recentBlocks));
    o.push_back(Pair("owner", Utf8Clean(r.entry.owner)));
    o.push_back(Pair("registered_height", r.entry.regHeight));
    o.push_back(Pair("registered_txid", r.entry.regTxid.GetHex()));
    o.push_back(Pair("expiry_height", r.entry.expiryHeight));
    o.push_back(Pair("expired", r.expired));
    UniValue w(UniValue::VARR);
    for (size_t i = 0; i < r.warnings.size(); i++)
        w.push_back(r.warnings[i]);
    o.push_back(Pair("warnings", w));
    UniValue recs(UniValue::VARR);
    for (size_t i = 0; i < r.candidates.size(); i++)
        recs.push_back(CandidateJson(r.candidates[i], i == 0));
    o.push_back(Pair("records", recs));
    UniValue ix(UniValue::VOBJ);
    ServiceInfo si = svc.GetInfo();
    ix.push_back(Pair("synced", si.synced));
    ix.push_back(Pair("height", si.indexedHeight));
    ix.push_back(Pair("tip", si.indexedHash.GetHex()));
    o.push_back(Pair("index", ix));
    return o;
}

UniValue EventJson(const Event& e)
{
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("height", e.height));
    o.push_back(Pair("txindex", (int)e.txIndex));
    o.push_back(Pair("txid", e.txid.GetHex()));
    o.push_back(Pair("command", CommandName(e.command)));
    if (!e.actor.empty())
        o.push_back(Pair("signer", Utf8Clean(e.actor)));
    switch (e.command) {
    case CMD_REGISTER:
        o.push_back(Pair("owner", Utf8Clean(e.owner)));
        // fallthrough
    case CMD_UPDATE:
    case CMD_SET_RECORD:
        o.push_back(Pair("type", TypeName(e.type)));
        o.push_back(Pair("value", Utf8Clean(e.value)));
        break;
    case CMD_TRANSFER:
        o.push_back(Pair("newowner", Utf8Clean(e.owner)));
        break;
    case CMD_SET_TEXT:
        o.push_back(Pair("key", Utf8Clean(e.key)));
        o.push_back(Pair("value", Utf8Clean(e.value)));
        break;
    default:
        break;
    }
    if (e.command == CMD_REGISTER || e.command == CMD_RENEW)
        o.push_back(Pair("expiryheight", e.expiryHeight));
    return o;
}

UniValue znam_getname(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "znam_getname \"name\"\n"
            "\nThe full record of one ZNAM name from the local index: owner, primary target, the SET_RECORD address\n"
            "records, the SET_TEXT text records and every message that changed it, oldest first (requires -znamindex=1).\n"
            "\nResult:\n"
            "{ \"name\", \"owner\", \"type\", \"value\", \"registeredheight\", \"registeredtxid\", \"lastupdatetxid\",\n"
            "  \"expiryheight\", \"expired\", \"lastchange\": {\"height\", \"txid\", \"command\"},\n"
            "  \"records\": [{\"type\", \"value\", \"height\", \"txid\"}], \"text\": [{\"key\", \"value\", \"height\", \"txid\"}],\n"
            "  \"history\": [{\"height\", \"txindex\", \"txid\", \"command\", \"signer\", ...}],\n"
            "  \"synced\": true|false }\n"
            "\nExamples:\n"
            + HelpExampleCli("znam_getname", "\"alice\"")
            + HelpExampleRpc("znam_getname", "\"alice\"")
        );
    ZnamService& svc = RequireIndex();
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR));
    const string name = params[0].get_str();
    if (!ValidName(name))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Not a valid ZNAM name: 1-63 characters a-z 0-9 and '-', no leading or trailing '-'");
    Entry e;
    if (!svc.Index().GetName(name, e))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No such name in the index (it may not be indexed yet: see znam_getindexinfo)");
    UniValue o = EntryJson(e, TipHeight());
    UniValue recs(UniValue::VARR);
    vector<AddrRecord> ar = svc.Index().GetAddrRecords(name);
    for (size_t i = 0; i < ar.size(); i++) {
        UniValue r(UniValue::VOBJ);
        r.push_back(Pair("type", TypeName(ar[i].type)));
        r.push_back(Pair("value", Utf8Clean(ar[i].value)));
        r.push_back(Pair("height", ar[i].height));
        r.push_back(Pair("txid", ar[i].txid.GetHex()));
        recs.push_back(r);
    }
    o.push_back(Pair("records", recs));
    UniValue texts(UniValue::VARR);
    vector<TextRecord> tr = svc.Index().GetTextRecords(name);
    for (size_t i = 0; i < tr.size(); i++) {
        UniValue r(UniValue::VOBJ);
        r.push_back(Pair("key", Utf8Clean(tr[i].key)));
        r.push_back(Pair("value", Utf8Clean(tr[i].value)));
        r.push_back(Pair("height", tr[i].height));
        r.push_back(Pair("txid", tr[i].txid.GetHex()));
        texts.push_back(r);
    }
    o.push_back(Pair("text", texts));
    UniValue hist(UniValue::VARR);
    vector<Event> h = svc.Index().GetHistory(name);
    for (size_t i = 0; i < h.size(); i++)
        hist.push_back(EventJson(h[i]));
    o.push_back(Pair("history", hist));
    o.push_back(Pair("synced", svc.GetInfo().synced));
    return o;
}

UniValue znam_listnames(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "znam_listnames ( \"owner\" skip count )\n"
            "\nList names from the local index, in name order (requires -znamindex=1).\n"
            "\nArguments:\n"
            "1. \"owner\"   (string, optional) only the names this address text owns. Z23 renders every owner as a\n"
            "             P2PKH address; \"\" lists all names.\n"
            "2. skip      (numeric, optional, default=0)\n"
            "3. count     (numeric, optional, default=100, max 1000)\n"
            "\nResult: array of {name, owner, type, value, registeredheight, ...} as in znam_getname.\n"
            "\nExamples:\n"
            + HelpExampleCli("znam_listnames", "")
            + HelpExampleCli("znam_listnames", "\"t1...\" 0 20")
            + HelpExampleRpc("znam_listnames", "\"\", 0, 20")
        );
    ZnamService& svc = RequireIndex();
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VNUM)(UniValue::VNUM));
    const string owner = params.size() > 0 ? params[0].get_str() : "";
    int skip = params.size() > 1 ? params[1].get_int() : 0;
    int count = params.size() > 2 ? params[2].get_int() : 100;
    if (skip < 0 || count < 1 || count > 1000)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "skip must be >= 0 and count 1..1000");
    const int tip = TipHeight();
    vector<Entry> v = owner.empty() ? svc.Index().ListNames((size_t)skip, (size_t)count)
                                    : svc.Index().ListByOwner(owner, (size_t)skip, (size_t)count);
    UniValue r(UniValue::VARR);
    for (size_t i = 0; i < v.size(); i++)
        r.push_back(EntryJson(v[i], tip));
    return r;
}

#ifdef ENABLE_WALLET

void RequireWallet()
{
    if (!pwalletMain)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (wallet disabled)");
}

void RequireUnlocked()
{
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
}

/** The txid of a ZNAM transaction for `name` that is waiting in the mempool, if any. */
bool PendingFor(const string& name, uint256& txid)
{
    LOCK(mempool.cs);
    for (CTxMemPool::indexed_transaction_set::const_iterator it = mempool.mapTx.begin(); it != mempool.mapTx.end(); ++it) {
        const CTransaction& tx = it->GetTx();
        for (size_t i = 0; i < tx.vout.size(); i++) {
            const CScript& s = tx.vout[i].scriptPubKey;
            if (s.empty() || s[0] != OP_RETURN)
                continue;
            zcl_znam_parsed m;
            if (zcl_znam_parse_message(&s[0], s.size(), &m) && name == m.name) {
                txid = tx.GetHash();
                return true;
            }
            break; // only the first OP_RETURN of a transaction is its message
        }
    }
    return false;
}

/** A spendable, confirmed, plain P2PKH output of this wallet that is not a ZSLP token or baton. With `want` set,
 *  only an output of that exact address; otherwise the largest. */
bool PickOwnerCoin(const string& want, COutPoint& op, string& ownerOut, CAmount& valueOut, string& why)
{
    vector<COutput> coins;
    pwalletMain->AvailableCoins(coins, true, NULL, false, !Params().GetConsensus().fCoinbaseMustBeProtected);
    const CAmount minValue = 2 * CWallet::GetMinimumFee(1000, 2, mempool);
    bool found = false, sawAddress = false;
    for (size_t i = 0; i < coins.size(); i++) {
        const COutput& c = coins[i];
        const CScript& s = c.tx->vout[c.i].scriptPubKey;
        CTxDestination d;
        if (!c.fSpendable || !ExtractDestination(s, d) || !boost::get<CKeyID>(&d) || s != GetScriptForDestination(d))
            continue; // only an exact P2PKH output: Z23 reads no other form back as an owner you could sign with
        if (TokenGuardOutputRole(*c.tx, c.i) != TOKEN_ROLE_NONE)
            continue;
        const string addr = EncodeDestination(d);
        if (!want.empty() && addr != want)
            continue;
        sawAddress = true;
        const CAmount v = c.tx->vout[c.i].nValue;
        if (v < minValue)
            continue;
        if (!found || v > valueOut) {
            found = true;
            valueOut = v;
            op = COutPoint(c.tx->GetHash(), c.i);
            ownerOut = addr;
        }
    }
    if (!found)
        why = want.empty() ? "the wallet has no confirmed, spendable P2PKH coin big enough to carry a name transaction (a coin of at "
                             "least " + FormatMoney(minValue) + " that is not a token output and not coinbase)"
                           : (sawAddress ? "the coins of the owner address " + want + " are all too small to carry a name transaction (need at least " + FormatMoney(minValue) + " in one coin)"
                                         : "the wallet has no confirmed, spendable P2PKH coin at the owner address " + want);
    return found;
}

struct OwnerSpend {
    COutPoint op;
    string owner;
    CAmount value;
};

/** Build, validate and broadcast one name transaction. The first (and only) input is a coin of `spend.owner`, so
 *  the address Z23 reads back as the signer is exactly that. The record is checked with the vendored parser and
 *  rule set against the index BEFORE anything is signed. */
UniValue SendNameTx(const string& name, int command, const zcl_znam_parsed& wanted, const vector<unsigned char>& script,
                    const OwnerSpend& spend, const Entry* current)
{
    // 1. the record, parsed back by the vendored parser, is the record we meant
    zcl_znam_parsed back;
    if (!zcl_znam_parse_message(script.data(), script.size(), &back) || back.command != command || name != back.name ||
        back.target_type != wanted.target_type || strcmp(back.target_value, wanted.target_value) != 0 ||
        strcmp(back.new_owner, wanted.new_owner) != 0)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "The record does not parse back to what was asked: refusing to sign");
    // 2. the vendored rule set, run against the index, accepts it from this owner
    zcl_znam_entry ze;
    memset(&ze, 0, sizeof(ze));
    if (current) {
        strncpy(ze.owner, current->owner.c_str(), ZCL_ZNAM_OWNER_MAX);
        ze.target_type = (uint8_t)current->type;
        strncpy(ze.target_value, current->value.c_str(), ZCL_ZNAM_VALUE_MAX);
        ze.reg_height = current->regHeight;
        ze.expiry_height = current->expiryHeight;
    }
    zcl_znam_result res;
    zcl_znam_evaluate(&back, current ? 1 : 0, current ? &ze : NULL, 1, spend.owner.c_str(), TipHeight() + 1, &res);
    if (res.effect == ZCL_ZNAM_EFFECT_NONE)
        throw JSONRPCError(RPC_INVALID_PARAMETER, string("Z23's rules would ignore this record: ") + res.reason);

    CCoinControl cc;
    cc.Select(spend.op);
    cc.fAllowOtherInputs = false;
    CTxDestination ownerDest = DecodeDestination(spend.owner);
    cc.destChange = ownerDest;
    vector<CRecipient> send;
    CRecipient rcp = {CScript(script.begin(), script.end()), 0, false};
    send.push_back(rcp);

    CWalletTx wtx;
    CReserveKey reservekey(pwalletMain);
    CAmount fee = 0;
    int changePos = -1;
    string fail;
    if (!pwalletMain->CreateTransaction(send, wtx, reservekey, fee, changePos, fail, &cc))
        throw JSONRPCError(RPC_WALLET_ERROR, "Cannot build the name transaction: " + fail);
    if (wtx.vin.size() != 1 || wtx.vin[0].prevout != spend.op)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "The transaction does not spend exactly the owner's coin: refusing to broadcast");
    if (!pwalletMain->CommitTransaction(wtx, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "The transaction was rejected: the wallet could not commit it (see debug.log)");

    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("txid", wtx.GetHash().GetHex()));
    o.push_back(Pair("name", name));
    o.push_back(Pair("operation", CommandName(command)));
    o.push_back(Pair("owner", spend.owner));
    o.push_back(Pair("fee", ValueFromAmount(fee)));
    o.push_back(Pair("opreturn", HexStr(script)));
    o.push_back(Pair("note", "Broadcast. The name changes when the transaction is mined and the index applies the block: "
                             "names are first come, first served in block order, so check znam_getname after it confirms."));
    return o;
}

/** Fix the target type and text of a REGISTER/UPDATE from the user's arguments. */
void ParseTarget(const UniValue& params, size_t valueIdx, size_t typeIdx, unsigned int& type, string& value)
{
    value = params[valueIdx].get_str();
    if (value.empty() || value.size() > ZCL_ZNAM_VALUE_MAX)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The target must be 1-128 bytes");
    if (params.size() > typeIdx && !params[typeIdx].get_str().empty()) {
        type = TypeFromName(params[typeIdx].get_str());
        if (type == 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown type: use onion, zaddr, taddr, btc, ltc, doge or content");
    } else {
        // detect the two types a wallet can pay, and .onion; anything else needs an explicit type
        string why;
        if (ClassifyAddress(TYPE_TADDR, value, why) != PAY_NONE)
            type = TYPE_TADDR;
        else if (ClassifyAddress(TYPE_ZADDR, value, why) != PAY_NONE)
            type = TYPE_ZADDR;
        else if (value.size() > 6 && value.compare(value.size() - 6, 6, ".onion") == 0)
            type = TYPE_ONION;
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "The target is not a t-address, z-address or .onion address of this chain: pass the type (btc, ltc, doge, content, ...) explicitly");
    }
    // A name that points at a ZClassic address must point at a real one: a typo here is money sent nowhere.
    if (type == TYPE_TADDR || type == TYPE_ZADDR) {
        string why;
        if (ClassifyAddress(type, value, why) == PAY_NONE)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Refusing to record a payable address that is not valid: " + why);
    }
}

UniValue znam_register(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "znam_register \"name\" \"target\" ( \"type\" \"owneraddress\" )\n"
            "\nRegister a ZNAM name: build, sign and broadcast a transaction whose OP_RETURN output carries the\n"
            "record (requires -znamindex=1). First come, first served, in block order. The OWNER of the name is the\n"
            "address of the coin the transaction spends, so it is controlled by that address's key and nothing else.\n"
            "\nArguments:\n"
            "1. \"name\"          (string, required) 1-63 characters a-z 0-9 and '-', no leading or trailing '-'\n"
            "2. \"target\"        (string, required) what the name resolves to: a t-address, a z-address or a .onion\n"
            "                   address (the type is detected), or any other record with an explicit type\n"
            "3. \"type\"          (string, optional) onion, zaddr, taddr, btc, ltc, doge, content\n"
            "4. \"owneraddress\"  (string, optional) a t-address (P2PKH) of this wallet to own the name; default: the\n"
            "                   address of the wallet's largest confirmed P2PKH coin\n"
            "\nResult: {\"txid\", \"name\", \"operation\", \"owner\", \"fee\", \"opreturn\", \"note\"}\n"
            "\nThe command refuses when the index is not synced, the name is taken, or a registration of the same\n"
            "name is already in the mempool.\n"
            "\nExamples:\n"
            + HelpExampleCli("znam_register", "\"alice\" \"t1...\"")
            + HelpExampleRpc("znam_register", "\"alice\", \"t1...\"")
        );
    RequireWallet();
    ZnamService& svc = RequireSyncedIndex();
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR));
    const string name = params[0].get_str();
    if (!ValidName(name))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Not a valid ZNAM name: 1-63 characters a-z 0-9 and '-', no leading or trailing '-' (no upper case, no Unicode)");
    unsigned int type = 0;
    string value;
    ParseTarget(params, 1, 2, type, value);
    const string wantOwner = params.size() > 3 ? params[3].get_str() : "";
    if (!wantOwner.empty()) {
        CTxDestination d = DecodeDestination(wantOwner);
        if (!boost::get<CKeyID>(&d))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "owneraddress must be a t-address (P2PKH) of this chain");
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);
    RequireUnlocked();
    Entry existing;
    if (svc.Index().GetName(name, existing))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The name is already registered (owner " + Utf8Clean(existing.owner) + ", block " + std::to_string(existing.regHeight) + ")");
    uint256 pending;
    if (PendingFor(name, pending))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "A transaction for this name is already waiting in the mempool (" + pending.GetHex() + "): wait for it to confirm");

    uint8_t buf[256];
    size_t len = zcl_znam_build(ZCL_ZNAM_CMD_REGISTER, name.c_str(), (uint8_t)type, value.c_str(), NULL, NULL, NULL, buf, sizeof(buf));
    if (len == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The record does not fit the ZNAM limits (an OP_RETURN of at most 223 bytes)");
    OwnerSpend spend;
    string why;
    if (!PickOwnerCoin(wantOwner, spend.op, spend.owner, spend.value, why))
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, why);
    zcl_znam_parsed wanted;
    memset(&wanted, 0, sizeof(wanted));
    wanted.target_type = (uint8_t)type;
    strncpy(wanted.target_value, value.c_str(), ZCL_ZNAM_VALUE_MAX);
    return SendNameTx(name, ZCL_ZNAM_CMD_REGISTER, wanted, vector<unsigned char>(buf, buf + len), spend, NULL);
}

/** The wallet's spend of the name's current owner, for UPDATE and TRANSFER. */
void OwnerSpendFor(const Entry& e, OwnerSpend& spend)
{
    CTxDestination d = DecodeDestination(e.owner);
    if (!boost::get<CKeyID>(&d))
        throw JSONRPCError(RPC_WALLET_ERROR, "The owner of this name (" + Utf8Clean(e.owner) + ") is not a P2PKH address: this wallet cannot sign for it");
    string why;
    if (!pwalletMain->HaveKey(*boost::get<CKeyID>(&d)))
        throw JSONRPCError(RPC_WALLET_ERROR, "This wallet does not hold the key of the name's owner address " + Utf8Clean(e.owner));
    if (!PickOwnerCoin(e.owner, spend.op, spend.owner, spend.value, why))
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, why);
}

UniValue znam_update(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw runtime_error(
            "znam_update \"name\" \"target\" ( \"type\" )\n"
            "\nReplace a name's primary target (requires -znamindex=1). Only the current owner can: the transaction\n"
            "spends a coin of the owner's address, and the wallet must hold that key.\n"
            "\nArguments:\n"
            "1. \"name\"    (string, required)\n"
            "2. \"target\"  (string, required) a t-address, z-address or .onion (type detected), or any record with a type\n"
            "3. \"type\"    (string, optional) onion, zaddr, taddr, btc, ltc, doge, content\n"
            "\nResult: {\"txid\", \"name\", \"operation\", \"owner\", \"fee\", \"opreturn\", \"note\"}\n"
            "\nExamples:\n"
            + HelpExampleCli("znam_update", "\"alice\" \"t1...\"")
            + HelpExampleRpc("znam_update", "\"alice\", \"t1...\"")
        );
    RequireWallet();
    ZnamService& svc = RequireSyncedIndex();
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR)(UniValue::VSTR));
    const string name = params[0].get_str();
    if (!ValidName(name))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Not a valid ZNAM name");
    unsigned int type = 0;
    string value;
    ParseTarget(params, 1, 2, type, value);

    LOCK2(cs_main, pwalletMain->cs_wallet);
    RequireUnlocked();
    Entry e;
    if (!svc.Index().GetName(name, e))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "The name is not registered");
    uint256 pending;
    if (PendingFor(name, pending))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "A transaction for this name is already waiting in the mempool (" + pending.GetHex() + "): wait for it to confirm");
    OwnerSpend spend;
    OwnerSpendFor(e, spend);
    uint8_t buf[256];
    size_t len = zcl_znam_build(ZCL_ZNAM_CMD_UPDATE, name.c_str(), (uint8_t)type, value.c_str(), NULL, NULL, NULL, buf, sizeof(buf));
    if (len == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The record does not fit the ZNAM limits (an OP_RETURN of at most 223 bytes)");
    zcl_znam_parsed wanted;
    memset(&wanted, 0, sizeof(wanted));
    wanted.target_type = (uint8_t)type;
    strncpy(wanted.target_value, value.c_str(), ZCL_ZNAM_VALUE_MAX);
    return SendNameTx(name, ZCL_ZNAM_CMD_UPDATE, wanted, vector<unsigned char>(buf, buf + len), spend, &e);
}

UniValue znam_transfer(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "znam_transfer \"name\" \"newowner\"\n"
            "\nHand a name to another address (requires -znamindex=1). Only the current owner can. THE NEW OWNER MUST\n"
            "BE A t-address (P2PKH) OF THIS CHAIN: Z23 would store any string, but an owner that is not a P2PKH\n"
            "address text can never sign again, and the name would be lost for good. This command refuses anything\n"
            "else, including P2SH and z-addresses.\n"
            "\nArguments:\n"
            "1. \"name\"      (string, required)\n"
            "2. \"newowner\"  (string, required) a t-address (P2PKH)\n"
            "\nResult: {\"txid\", \"name\", \"operation\", \"owner\", \"fee\", \"opreturn\", \"note\"}\n"
            "\nExamples:\n"
            + HelpExampleCli("znam_transfer", "\"alice\" \"t1...\"")
            + HelpExampleRpc("znam_transfer", "\"alice\", \"t1...\"")
        );
    RequireWallet();
    ZnamService& svc = RequireSyncedIndex();
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VSTR));
    const string name = params[0].get_str();
    const string newOwner = params[1].get_str();
    if (!ValidName(name))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Not a valid ZNAM name");
    CTxDestination nd = DecodeDestination(newOwner);
    if (!boost::get<CKeyID>(&nd))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "newowner must be a t-address (P2PKH) of this chain. A P2SH address, a z-address or any other text would "
                           "make the name unspendable: Z23 reads an owner back as a P2PKH address only.");

    LOCK2(cs_main, pwalletMain->cs_wallet);
    RequireUnlocked();
    Entry e;
    if (!svc.Index().GetName(name, e))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "The name is not registered");
    uint256 pending;
    if (PendingFor(name, pending))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "A transaction for this name is already waiting in the mempool (" + pending.GetHex() + "): wait for it to confirm");
    OwnerSpend spend;
    OwnerSpendFor(e, spend);
    uint8_t buf[256];
    size_t len = zcl_znam_build(ZCL_ZNAM_CMD_TRANSFER, name.c_str(), 0, NULL, newOwner.c_str(), NULL, NULL, buf, sizeof(buf));
    if (len == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The record does not fit the ZNAM limits");
    zcl_znam_parsed wanted;
    memset(&wanted, 0, sizeof(wanted));
    strncpy(wanted.new_owner, newOwner.c_str(), ZCL_ZNAM_OWNER_MAX);
    return SendNameTx(name, ZCL_ZNAM_CMD_TRANSFER, wanted, vector<unsigned char>(buf, buf + len), spend, &e);
}

UniValue znam_listmine(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "znam_listmine\n"
            "\nThe names whose owner address is a key of this wallet (requires -znamindex=1).\n"
            "\nResult: array of {name, owner, type, value, ...} as in znam_getname, plus \"spendable\".\n"
            "\nExamples:\n"
            + HelpExampleCli("znam_listmine", "")
            + HelpExampleRpc("znam_listmine", "")
        );
    RequireWallet();
    ZnamService& svc = RequireIndex();
    const int tip = TipHeight();
    UniValue r(UniValue::VARR);
    LOCK(pwalletMain->cs_wallet);
    set<CKeyID> keys;
    pwalletMain->GetKeys(keys);
    set<string> owners;
    for (set<CKeyID>::const_iterator it = keys.begin(); it != keys.end(); ++it)
        owners.insert(EncodeDestination(*it));
    for (set<string>::const_iterator it = owners.begin(); it != owners.end(); ++it) {
        vector<Entry> v = svc.Index().ListByOwner(*it, 0, 1000);
        for (size_t i = 0; i < v.size(); i++) {
            UniValue e = EntryJson(v[i], tip);
            e.push_back(Pair("spendable", true));
            r.push_back(e);
        }
    }
    return r;
}

#endif // ENABLE_WALLET

} // namespace

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
    //  --------------------- ------------------------  -----------------------  ----------
    { "znam",               "znam_getindexinfo",      &znam_getindexinfo,      true  },
    { "znam",               "znam_resolve",           &znam_resolve,           true  },
    { "znam",               "znam_getname",           &znam_getname,           true  },
    { "znam",               "znam_listnames",         &znam_listnames,         true  },
#ifdef ENABLE_WALLET
    { "znam",               "znam_listmine",          &znam_listmine,          true  },
    { "znam",               "znam_register",          &znam_register,          false },
    { "znam",               "znam_update",            &znam_update,            false },
    { "znam",               "znam_transfer",          &znam_transfer,          false },
#endif
};

void RegisterZnamRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
