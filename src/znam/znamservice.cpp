// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "znam/znamservice.h"

#include "c23/services/glue/zcl_znam_index.h"
#include "chain.h"
#include "chainparams.h"
#include "init.h"
#include "main.h"
#include "undo.h"
#include "util.h"
#include "utiltime.h"

#include <chrono>

// main.cpp (read-only). Declared here rather than in main.h so that adding it does not rebuild the whole node.
bool ReadBlockUndoFromDisk(CBlockUndo& blockundo, const CBlockIndex* pindex);

namespace znam {

ZnamService* pznamService = NULL;

ZnamService::ZnamService(KV* kvIn, int start)
    : kv(kvIn), index(kvIn), startHeight(start), fStop(false), fRunning(false), chainHeight(-1)
{
}

ZnamService::~ZnamService() { Stop(); }

bool ZnamService::Start(std::string& err)
{
    if (!index.Load(err))
        return false;
    {
        std::lock_guard<std::mutex> g(m);
        fStop = false;
        fRunning = true;
    }
    worker = std::thread(&ZnamService::Run, this);
    return true;
}

void ZnamService::Stop()
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

void ZnamService::ChainTip(const CBlockIndex*, const CBlock*, const SproutMerkleTree&, const SaplingMerkleTree&, bool)
{
    // The worker re-reads the chain itself: this only wakes it.
    cv.notify_all();
}

void ZnamService::SetError(const std::string& e)
{
    std::lock_guard<std::mutex> g(m);
    if (lastError != e)
        LogPrintf("znam: %s\n", e.empty() ? std::string("recovered") : e);
    lastError = e;
}

ServiceInfo ZnamService::GetInfo() const
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

namespace {

/** The owner of a transaction of one block: the address its first input spends, read from the block's undo data.
 *  The undo data is read on the first call only, so a block without a ZNAM message never touches it. */
class UndoOwners
{
public:
    UndoOwners(const CBlock& b, const CBlockIndex* p) : block(b), pindex(p), tried(false), loaded(false) {}

    int operator()(size_t txIndex, std::string& owner)
    {
        if (txIndex >= block.vtx.size())
            return -1;
        const CTransaction& tx = block.vtx[txIndex];
        if (txIndex == 0 || tx.vin.empty()) // the coinbase, or a shielded-only transaction: no first input
            return 0;
        if (!tried) {
            tried = true;
            loaded = ReadBlockUndoFromDisk(undo, pindex);
        }
        if (!loaded || txIndex - 1 >= undo.vtxundo.size() || undo.vtxundo[txIndex - 1].vprevout.empty())
            return -1;
        const CScript& s = undo.vtxundo[txIndex - 1].vprevout[0].txout.scriptPubKey;
        return OwnerFromScript(s.empty() ? NULL : &s[0], s.size(), owner);
    }

private:
    const CBlock& block;
    const CBlockIndex* pindex;
    bool tried, loaded;
    CBlockUndo undo;
};

} // namespace

bool ZnamService::Step()
{
    enum { IDLE, CONNECT, DISCONNECT, RESET } action = IDLE;
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
            if (mi == mapBlockIndex.end() && chainActive.Height() >= bestHeight) {
                // The index tip is no block of any chain this node knows, and the active chain has already
                // reached that height: the tip will not come back (an unclean shutdown lost it from the block
                // index and the chain moved on, or this index belongs to another chain). The index is derived
                // data: start it again instead of waiting for ever.
                action = RESET;
            } else if (mi == mapBlockIndex.end()) {
                SetError(strprintf("the index tip %s is not in the block index (reindex in progress, or this index belongs to another chain): waiting", best.GetHex()));
                return false;
            } else if (!chainActive.Contains(mi->second)) {
                const CBlockIndex* pb = mi->second;
                action = DISCONNECT;
                pindex = pb;
                if (pb->pprev) {
                    prevHash = pb->pprev->GetBlockHash();
                    prevHeight = pb->pprev->nHeight;
                }
            } else if (const CBlockIndex* next = chainActive.Next(mi->second)) {
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
    if (action == RESET) {
        LogPrintf("znam: the index tip %s is not in the block index and the chain is past its height %d: rebuilding the index from height %d\n",
                  best.GetHex(), bestHeight, startHeight);
        if (!index.Reset(err)) {
            SetError("cannot rebuild the index: " + err);
            return false;
        }
        SetError("");
        return true;
    }
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
        UndoOwners owners(block, pindex);
        if (!index.ApplyBlock(block, std::ref(owners), pindex->GetBlockHash(), pindex->nHeight, fSync, err)) {
            SetError(strprintf("block %d: %s", pindex->nHeight, err));
            return false;
        }
        SetError("");
        return true;
    }
    SetError("");
    return false;
}

void ZnamService::Run()
{
    RenameThread("zcl-znam");
    LogPrintf("znam: index worker started (start height %d)\n", startHeight);
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
            // test aid only (qa/rpc-tests/znam_index.sh): slow the index down so it can be interrupted mid-build
            const int64_t nDelayMs = GetArg("-znamindexdelayms", 0);
            if (nDelayMs > 0)
                MilliSleep(nDelayMs);
            int64_t now = GetTime();
            if (now - nLastLog >= 60) {
                ServiceInfo si = GetInfo();
                LogPrintf("znam: indexed height %d of %d\n", si.indexedHeight, si.chainHeight);
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
    LogPrintf("znam: index worker stopped\n");
}

bool StartService(std::string& err)
{
    if (pznamService)
        return true;
    // Every network starts at the genesis block by default: no name has to be missed, and a block without a ZNAM
    // message costs one block read (no undo data, no store write besides the best block).
    const int64_t start = GetArg("-znamindexstart", 0);
    if (start < 0 || start > 0x7fffffff) {
        err = "-znamindexstart must be a block height";
        return false;
    }
    try {
        std::unique_ptr<ZnamService> svc(new ZnamService(
            new LevelKV((GetDataDir() / "znamindex").string(), 16 << 20, false, false), (int)start));
        if (!svc->Start(err))
            return false;
        RegisterValidationInterface(svc.get());
        pznamService = svc.release();
    } catch (const std::exception& e) {
        err = std::string("cannot open the ZNAM index: ") + e.what();
        return false;
    }
    return true;
}

void StopService()
{
    if (!pznamService)
        return;
    ZnamService* svc = pznamService;
    pznamService = NULL;
    UnregisterValidationInterface(svc);
    delete svc;
}

} // namespace znam
