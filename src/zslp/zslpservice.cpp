// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zslp/zslpservice.h"

#include "chain.h"
#include "chainparams.h"
#include "init.h"
#include "main.h"
#include "util.h"

#include "utiltime.h"

#include <chrono>

namespace zslp {

ZslpService* pzslpService = NULL;

ZslpService::ZslpService(KV* kvIn, int start)
    : kv(kvIn), index(kvIn), startHeight(start), fStop(false), fRunning(false), chainHeight(-1)
{
}

ZslpService::~ZslpService() { Stop(); }

bool ZslpService::Start(std::string& err)
{
    if (!index.Load(err))
        return false;
    {
        std::lock_guard<std::mutex> g(m);
        fStop = false;
        fRunning = true;
    }
    worker = std::thread(&ZslpService::Run, this);
    return true;
}

void ZslpService::Stop()
{
    {
        std::lock_guard<std::mutex> g(m);
        fStop = true;
    }
    cv.notify_all();
    if (worker.joinable())
        worker.join();
    std::lock_guard<std::mutex> g(m);
    fRunning = false;
}

void ZslpService::ChainTip(const CBlockIndex*, const CBlock*, const SproutMerkleTree&, const SaplingMerkleTree&, bool)
{
    // The worker re-reads the chain itself: this only wakes it.
    cv.notify_all();
}

void ZslpService::SetError(const std::string& e)
{
    std::lock_guard<std::mutex> g(m);
    if (lastError != e)
        LogPrintf("zslp: %s\n", e.empty() ? std::string("recovered") : e);
    lastError = e;
}

ServiceInfo ZslpService::GetInfo() const
{
    ServiceInfo si;
    {
        std::lock_guard<std::mutex> g(m);
        si.running = fRunning;
        si.chainHeight = chainHeight;
        si.error = lastError;
    }
    si.startHeight = startHeight;
    si.hasIndexed = index.GetBest(si.indexedHash, si.indexedHeight);
    uint256 tip;
    int tipHeight = -1;
    {
        LOCK(cs_main);
        if (chainActive.Tip()) {
            tip = chainActive.Tip()->GetBlockHash();
            tipHeight = chainActive.Height();
        }
    }
    si.chainHeight = tipHeight;
    si.synced = si.hasIndexed ? si.indexedHash == tip : tipHeight < startHeight;
    return si;
}

bool ZslpService::Step()
{
    enum { IDLE, CONNECT, DISCONNECT } action = IDLE;
    const CBlockIndex* pindex = NULL;
    uint256 prevHash;
    int prevHeight = -1;
    int tipHeight = -1;

    uint256 best;
    int bestHeight = -1;
    const bool haveBest = index.GetBest(best, bestHeight);
    {
        LOCK(cs_main);
        tipHeight = chainActive.Height();
        if (haveBest) {
            BlockMap::const_iterator mi = mapBlockIndex.find(best);
            if (mi == mapBlockIndex.end()) {
                SetError(strprintf("the index tip %s is not in the block index (reindex in progress, or this index belongs to another chain): waiting", best.GetHex()));
                return false;
            }
            const CBlockIndex* pb = mi->second;
            if (!chainActive.Contains(pb)) {
                action = DISCONNECT;
                pindex = pb;
                if (pb->pprev) {
                    prevHash = pb->pprev->GetBlockHash();
                    prevHeight = pb->pprev->nHeight;
                }
            } else if (const CBlockIndex* next = chainActive.Next(pb)) {
                action = CONNECT;
                pindex = next;
            }
        } else if (tipHeight >= startHeight && chainActive[startHeight]) {
            action = CONNECT;
            pindex = chainActive[startHeight];
        }
    }
    {
        std::lock_guard<std::mutex> g(m);
        chainHeight = tipHeight;
    }

    std::string err;
    if (action == DISCONNECT) {
        if (!index.DisconnectBlock(pindex->GetBlockHash(), prevHash, prevHeight, err)) {
            SetError("disconnect failed: " + err);
            return false;
        }
        SetError("");
        return true;
    }
    if (action == CONNECT) {
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex)) {
            SetError(strprintf("cannot read block %s at height %d (pruned or damaged): waiting", pindex->GetBlockHash().GetHex(), pindex->nHeight));
            return false;
        }
        const bool fSync = tipHeight - pindex->nHeight < 100;
        if (!index.ApplyBlock(block, pindex->GetBlockHash(), pindex->nHeight, fSync, err)) {
            SetError(strprintf("block %d: %s", pindex->nHeight, err));
            return false;
        }
        SetError("");
        return true;
    }
    SetError("");
    return false;
}

void ZslpService::Run()
{
    RenameThread("zcl-zslp");
    LogPrintf("zslp: index worker started (start height %d)\n", startHeight);
    int64_t nLastLog = GetTime();
    while (true) {
        {
            std::lock_guard<std::mutex> g(m);
            if (fStop)
                break;
        }
        bool fWork = false;
        try {
            fWork = Step();
        } catch (const std::exception& e) {
            SetError(std::string("exception: ") + e.what());
        }
        if (fWork) {
            // test aid only (qa/rpc-tests/zslp_index.sh): slow the index down so it can be interrupted mid-build
            const int64_t nDelayMs = GetArg("-zslpindexdelayms", 0);
            if (nDelayMs > 0)
                MilliSleep(nDelayMs);
            int64_t now = GetTime();
            if (now - nLastLog >= 60) {
                ServiceInfo si = GetInfo();
                LogPrintf("zslp: indexed height %d of %d\n", si.indexedHeight, si.chainHeight);
                nLastLog = now;
            }
            continue;
        }
        std::unique_lock<std::mutex> lk(m);
        if (fStop)
            break;
        // an error is retried slowly; an idle worker wakes on ChainTip, with a one second timeout as the safety net
        cv.wait_for(lk, std::chrono::seconds(lastError.empty() ? 1 : 10));
    }
    LogPrintf("zslp: index worker stopped\n");
}

} // namespace zslp

namespace zslp {

// Where a new mainnet index starts reading. Measured on the full chain (3,322,991 blocks): the first
// ZSLP message of any kind (a GENESIS) is in block 652,947, and an index started there reports the
// same 874 GENESIS, 34 MINT and 3,394 SEND messages, the same tokens and the same transactions as
// one built from block 0 (qa/zslp/mainnet_crosscheck.sh). 650,000 leaves a margin. Other networks
// start at the genesis block.
static const int kMainnetFirstSlpHeight = 650000;

int DefaultStartHeight()
{
    return Params().NetworkIDString() == "main" ? kMainnetFirstSlpHeight : 0;
}

bool StartService(std::string& err)
{
    if (pzslpService)
        return true;
    const int64_t start = GetArg("-zslpindexstart", DefaultStartHeight());
    if (start < 0 || start > 0x7fffffff) {
        err = "-zslpindexstart must be a block height";
        return false;
    }
    try {
        std::unique_ptr<ZslpService> svc(new ZslpService(
            new LevelKV((GetDataDir() / "zslpindex").string(), 16 << 20, false, false), (int)start));
        if (!svc->Start(err))
            return false;
        RegisterValidationInterface(svc.get());
        pzslpService = svc.release();
    } catch (const std::exception& e) {
        err = std::string("cannot open the ZSLP index: ") + e.what();
        return false;
    }
    return true;
}

void StopService()
{
    if (!pzslpService)
        return;
    ZslpService* svc = pzslpService;
    pzslpService = NULL;
    UnregisterValidationInterface(svc);
    delete svc;
}

} // namespace zslp
