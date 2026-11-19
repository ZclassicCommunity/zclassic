// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The bodies below were the getblocks, getheaders and mempool branches of
// ProcessMessage in main.cpp; they keep the same locking and the same order.

#include "p2pserve.h"

#include "bloom.h"
#include "chainparams.h"
#include "main.h"
#include "net.h"
#include "txmempool.h"
#include "util.h"

#include <vector>

bool LocatorOverCap(CNode* pfrom, const CBlockLocator& locator, const char* strCommand)
{
    if (locator.vHave.size() <= MAX_LOCATOR_SZ)
        return false;
    LogPrint("net", "%s locator has %u entries, over the cap of %u; disconnecting peer=%d\n",
             strCommand, (unsigned int)locator.vHave.size(), MAX_LOCATOR_SZ, pfrom->id);
    pfrom->fDisconnect = true;
    return true;
}

bool MempoolRequestInCooldown(int64_t nLastServed, int64_t nNow)
{
    // a clock that went backwards ends the cooldown instead of extending it
    return nLastServed != 0 && nNow >= nLastServed && nNow - nLastServed < MEMPOOL_REQUEST_COOLDOWN;
}

void ServeGetBlocks(CNode* pfrom, CDataStream& vRecv, const CChainParams& chainparams)
{
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    if (LocatorOverCap(pfrom, locator, "getblocks"))
        return;

    LOCK(cs_main);

    // Find the last block the caller has in the main chain
    const CBlockIndex* pindex = FindForkInGlobalIndex(chainActive, locator);

    // Send the rest of the chain
    if (pindex)
        pindex = chainActive.Next(pindex);
    int nLimit = 500;
    LogPrint("net", "getblocks %d to %s limit %d from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), nLimit, pfrom->id);
    for (; pindex; pindex = chainActive.Next(pindex))
    {
        if (pindex->GetBlockHash() == hashStop)
        {
            LogPrint("net", "  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            break;
        }
        // If pruning, don't inv blocks unless we have on disk and are likely to still have
        // for some reasonable time window (1 hour) that block relay might require.
        const int nPrunedBlocksLikelyToHave = MIN_BLOCKS_TO_KEEP - 3600 / chainparams.GetConsensus().PoWTargetSpacing(pindex->nHeight);
        if (fPruneMode && (!(pindex->nStatus & BLOCK_HAVE_DATA) || pindex->nHeight <= chainActive.Tip()->nHeight - nPrunedBlocksLikelyToHave))
        {
            LogPrint("net", " getblocks stopping, pruned or too old block at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            break;
        }
        pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
        if (--nLimit <= 0)
        {
            // When this block is requested, we'll send an inv that'll
            // trigger the peer to getblocks the next batch of inventory.
            LogPrint("net", "  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            pfrom->hashContinue = pindex->GetBlockHash();
            break;
        }
    }
}

void ServeGetHeaders(CNode* pfrom, CDataStream& vRecv)
{
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    if (LocatorOverCap(pfrom, locator, "getheaders"))
        return;

    LOCK(cs_main);

    if (IsInitialBlockDownload())
        return;

    const CBlockIndex* pindex = NULL;
    if (locator.IsNull())
    {
        // If locator is null, return the hashStop block
        BlockMap::iterator mi = mapBlockIndex.find(hashStop);
        if (mi == mapBlockIndex.end())
            return;
        pindex = (*mi).second;
    }
    else
    {
        // Find the last block the caller has in the main chain
        pindex = FindForkInGlobalIndex(chainActive, locator);
        if (pindex)
            pindex = chainActive.Next(pindex);
    }

    // we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
    std::vector<CBlock> vHeaders;
    int nLimit = MAX_HEADERS_RESULTS;
    LogPrint("net", "getheaders %d to %s from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString(), pfrom->id);
    for (; pindex; pindex = chainActive.Next(pindex))
    {
        vHeaders.push_back(pindex->GetBlockHeader());
        if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
            break;
    }
    pfrom->PushMessage("headers", vHeaders);
}

void ServeMempool(CNode* pfrom, int currentHeight)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pfrom->cs_filter);

    std::vector<uint256> vtxid;
    mempool.queryHashes(vtxid);
    std::vector<CInv> vInv;
    for (uint256& hash : vtxid) {
        CTransaction tx;
        bool fInMemPool = mempool.lookup(hash, tx);
        if (fInMemPool && IsExpiringSoonTx(tx, currentHeight + 1)) {
            continue;
        }

        CInv inv(MSG_TX, hash);
        if (pfrom->pfilter) {
            if (!fInMemPool) continue; // another thread removed since queryHashes, maybe...
            if (!pfrom->pfilter->IsRelevantAndUpdate(tx)) continue;
        }
        vInv.push_back(inv);
        if (vInv.size() == MAX_INV_SZ) {
            pfrom->PushMessage("inv", vInv);
            vInv.clear();
        }
    }
    if (vInv.size() > 0)
        pfrom->PushMessage("inv", vInv);
}
