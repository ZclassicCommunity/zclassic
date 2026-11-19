// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// getnodestatus: one cheap, poll-safe answer for operators and scripts (state, reasons, lag,
// peers, mempool, indexes, disk). Read-only; it never changes IBD semantics. Locks are taken
// one at a time and never nested: cs_main, then cs_vNodes, then the mempool.

#include "rpc/nodestatus.h"

#include "chain.h"
#include "main.h"
#include "net.h"
#include "rpc/register.h"
#include "rpc/server.h"
#include "sync.h"
#include "txmempool.h"
#include "univalue.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "znam/znamservice.h"
#include "zslp/zslpservice.h"

#include <algorithm>
#include <boost/filesystem.hpp>
#include <string>

using namespace std;

namespace {

UniValue IndexStatusToJSON(const NodeIndexStatus& ix)
{
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("enabled", ix.enabled));
    if (ix.enabled) {
        o.push_back(Pair("synced", ix.synced));
        o.push_back(Pair("indexed_height", ix.indexedHeight));
    }
    return o;
}

const char* NodeStatusState(const NodeStatusInputs& in, bool synced, int behind)
{
    if (in.sync.reindexing) return "reindexing";
    if (in.sync.importing) return "importing";
    if (in.sync.ibd) return "initial_block_download";
    if (in.nInbound + in.nOutbound <= 0) return "no_peers";
    if (!synced && behind > 0) return "syncing";
    if (!synced) return "tip_stale";
    return "ok";
}

int BlocksBehind(const SyncInputs& s)
{
    return std::max(0, std::max(s.nBestPeerHeight, s.nHeaders) - s.nBlocks);
}

/** Reasons that come from the node being busy with something other than following the chain. */
void AddBusyReasons(UniValue& r, const SyncInputs& s)
{
    if (s.reindexing) r.push_back("the block database is being reindexed");
    if (s.importing) r.push_back("blocks are being imported from disk");
    if (s.ibd) r.push_back("the node is in initial block download");
}

/** Reasons that come from the peer set. */
void AddPeerReasons(UniValue& r, const NodeStatusInputs& in)
{
    const SyncInputs& s = in.sync;
    if (in.nInbound + in.nOutbound <= 0) r.push_back("there are no peer connections");
    else if (s.nOutboundConnected <= 0) r.push_back("there are no handshaken outbound peer connections");
    if (s.nOutboundConnected > 0 && s.nBestPeerHeight < 0) r.push_back("no outbound peer has reported its height");
}

/** Reasons the tip is not level with the network. */
void AddLagReasons(UniValue& r, const NodeStatusInputs& in, bool synced, int behind)
{
    const SyncInputs& s = in.sync;
    if (synced) return;
    if (behind > 0) {
        r.push_back("the tip is behind the best known chain");
    } else if (in.nInbound + in.nOutbound > 0 && !s.ibd && !s.reindexing && !s.importing) {
        r.push_back(strprintf("tip is %d s old and no peer reports a higher block", s.tipAgeSeconds));
    }
}

UniValue NodeStatusReasons(const NodeStatusInputs& in, bool synced, int behind)
{
    UniValue r(UniValue::VARR);
    AddBusyReasons(r, in.sync);
    AddPeerReasons(r, in);
    AddLagReasons(r, in, synced, behind);
    return r;
}

} // namespace

UniValue BuildNodeStatus(const NodeStatusInputs& in)
{
    const bool synced = IsSyncedV2(in.sync);
    const int behind = BlocksBehind(in.sync);
    UniValue o(UniValue::VOBJ);
    o.push_back(Pair("state", NodeStatusState(in, synced, behind)));
    o.push_back(Pair("syncphase", ClassifySyncPhaseV2(in.sync)));
    o.push_back(Pair("synced", synced));
    o.push_back(Pair("reasons", NodeStatusReasons(in, synced, behind)));
    o.push_back(Pair("blocks", in.sync.nBlocks));
    o.push_back(Pair("headers", in.sync.nHeaders));
    o.push_back(Pair("best_peer_height", in.sync.nBestPeerHeight));
    o.push_back(Pair("blocks_behind", behind));
    o.push_back(Pair("tip_age_seconds", in.sync.tipAgeSeconds));
    UniValue peers(UniValue::VOBJ);
    peers.push_back(Pair("in", in.nInbound));
    peers.push_back(Pair("out", in.nOutbound));
    o.push_back(Pair("peers", peers));
    UniValue pool(UniValue::VOBJ);
    pool.push_back(Pair("size", (int64_t)in.mempoolSize));
    pool.push_back(Pair("bytes", (int64_t)in.mempoolBytes));
    o.push_back(Pair("mempool", pool));
    o.push_back(Pair("uptime_seconds", in.uptimeSeconds));
    UniValue idx(UniValue::VOBJ);
    idx.push_back(Pair("txindex", in.txindex));
    idx.push_back(Pair("zslpindex", IndexStatusToJSON(in.zslp)));
    idx.push_back(Pair("znamindex", IndexStatusToJSON(in.znam)));
    o.push_back(Pair("indexes", idx));
    o.push_back(Pair("datadir_free_bytes", in.datadirFreeBytes));
    return o;
}

namespace {

/** Chain facts under cs_main only. */
void GatherChainInputs(SyncInputs& s)
{
    LOCK(cs_main);
    s.nBlocks = chainActive.Height();
    const CBlockIndex* tip = chainActive.Tip();
    const int64_t now = GetTime();
    s.tipAgeSeconds = tip ? std::max<int64_t>(0, now - tip->GetBlockTime()) : now;
    s.nHeaders = pindexBestHeader ? pindexBestHeader->nHeight : s.nBlocks;
    s.ibd = IsInitialBlockDownload();
    s.reindexing = fReindex;
    s.importing = fImporting;
}

/** Peer facts under cs_vNodes only. */
void GatherPeerInputs(NodeStatusInputs& in)
{
    int64_t oldest = 0;
    bool any = false;
    LOCK(cs_vNodes);
    for (const CNode* pnode : vNodes) {
        if (pnode->fInbound) {
            in.nInbound++;
            continue;
        }
        in.nOutbound++;
        if (!pnode->fSuccessfullyConnected) continue;
        in.sync.nOutboundConnected++;
        in.sync.nBestPeerHeight = std::max(in.sync.nBestPeerHeight, pnode->nStartingHeight);
        if (!any || pnode->nTimeConnected < oldest) oldest = pnode->nTimeConnected;
        any = true;
    }
    in.sync.nConnections = in.nInbound + in.nOutbound;
    in.sync.connectedForSeconds = any ? std::max<int64_t>(0, GetTime() - oldest) : 0;
}

void GatherPoolInputs(NodeStatusInputs& in)
{
    LOCK(mempool.cs);
    in.mempoolSize = mempool.size();
    in.mempoolBytes = mempool.DynamicMemoryUsage();
}

void GatherIndexInputs(NodeStatusInputs& in)
{
    in.txindex = fTxIndex;
    if (zslp::pzslpService) {
        const zslp::ServiceInfo info = zslp::pzslpService->GetInfo();
        in.zslp.enabled = true;
        in.zslp.synced = info.synced;
        in.zslp.indexedHeight = info.hasIndexed ? info.indexedHeight : -1;
    }
    if (znam::pznamService) {
        const znam::ServiceInfo info = znam::pznamService->GetInfo();
        in.znam.enabled = true;
        in.znam.synced = info.synced;
        in.znam.indexedHeight = info.hasIndexed ? info.indexedHeight : -1;
    }
}

NodeStatusInputs GatherNodeStatusInputs()
{
    NodeStatusInputs in;
    GatherChainInputs(in.sync);
    GatherPeerInputs(in);
    GatherPoolInputs(in);
    in.uptimeSeconds = GetTime() - GetStartupTime();
    GatherIndexInputs(in);
    boost::system::error_code ec;
    const boost::filesystem::space_info sp = boost::filesystem::space(GetDataDir(), ec);
    in.datadirFreeBytes = ec ? -1 : (int64_t)sp.available;
    return in;
}

UniValue getnodestatus(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getnodestatus\n"
            "\nReturns the node state, the reasons for it, sync lag, peers, mempool, indexes and disk space in one\n"
            "cheap answer. It is stricter than getblockchaininfo.syncphase: after a snapshot install the node can leave\n"
            "initial block download while still far behind, and this call keeps saying so until its peers agree.\n"
            "It takes each lock briefly and never nested, so it is safe to poll.\n"
            "\nResult:\n"
            "{\n"
            "  \"state\": \"ok\",              (string) ok, initial_block_download, syncing, tip_stale, no_peers, reindexing or importing\n"
            "  \"syncphase\": \"synced\",      (string) reindexing, importing, waiting_for_peers, downloading_headers, downloading_blocks or synced\n"
            "  \"synced\": true|false,        (boolean) syncphase is synced\n"
            "  \"reasons\": [\"...\"],          (array of strings) why the state is not ok; empty when it is\n"
            "  \"blocks\": n,                 (numeric) height of the active chain\n"
            "  \"headers\": n,                (numeric) height of the best known header\n"
            "  \"best_peer_height\": n,       (numeric) highest height an outbound peer reported at connect, -1 unknown\n"
            "  \"blocks_behind\": n,          (numeric) blocks to the best peer or header, 0 when level\n"
            "  \"tip_age_seconds\": n,        (numeric) seconds since the tip block time\n"
            "  \"peers\": {\"in\": n, \"out\": n},\n"
            "  \"mempool\": {\"size\": n, \"bytes\": n},\n"
            "  \"uptime_seconds\": n,         (numeric) as the uptime call\n"
            "  \"indexes\": {\"txindex\": true|false,\n"
            "              \"zslpindex\": {\"enabled\": b, \"synced\": b, \"indexed_height\": n},\n"
            "              \"znamindex\": {\"enabled\": b, \"synced\": b, \"indexed_height\": n}},\n"
            "  \"datadir_free_bytes\": n      (numeric) free space where the data directory lives, -1 unknown\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getnodestatus", "") + HelpExampleRpc("getnodestatus", ""));
    return BuildNodeStatus(GatherNodeStatusInputs());
}

const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getnodestatus",          &getnodestatus,          true  },
};

} // namespace

void RegisterNodeStatusRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
