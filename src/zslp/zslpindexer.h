// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP indexer — a CValidationInterface that observes block connects and
// disconnects and feeds parsed SLP OP_RETURN messages into the CZSLPStore.
//
// NON-consensus: this is a pure observer. It registers with the validation
// signal bus only to *read* the connected/disconnected block; it never votes
// on validity, never affects PoW, the mempool, or wallet spends. Removing it
// (the -zslpindex flag) changes nothing about consensus.

#ifndef BITCOIN_ZSLP_ZSLPINDEXER_H
#define BITCOIN_ZSLP_ZSLPINDEXER_H

#include "validationinterface.h"

#include "zslp/zslpstore.h" // CZSLPParsedMsg, CZSLPToken (for the testable parse seam)

#include <atomic>
#include <memory>

namespace boost { class thread; }

class CBlock;
class CBlockIndex;
class CTransaction;

/** Global indexer instance, non-NULL when -zslpindex is enabled. */
class CZSLPIndexer;
extern CZSLPIndexer* g_zslpIndexer;

/** Init/shutdown helpers, called from init.cpp behind -zslpindex. */
void StartZSLPIndexer();
void StopZSLPIndexer();

// Interrupt + join the background catch-up thread WITHOUT unregistering/deleting.
// Must be called early in Shutdown() — before the chain DBs (pcoinsTip /
// pblocktree / chainActive) are freed — because the catch-up worker reads them
// under cs_main and must not outlive them on the init-failure path (which skips
// the thread_group join). No-op when the index is disabled or already joined.
// Mirrors InterruptBootstrapValidation()/InterruptBootstrapServeFreeze().
void InterruptZSLPIndexerSync();

class CZSLPIndexer : public CValidationInterface
{
public:
    CZSLPIndexer();
    ~CZSLPIndexer();

    /** Accessor for the read RPCs. May be NULL if the index is disabled. */
    CZSLPStore* Store() { return store.get(); }

    // Canonical, side-effect-free per-transaction PARSE seam (R-PARSE-1/2):
    // parse the SLP message from tx.vout[0] ONLY (vout>=1 OP_RETURNs are
    // ignored; coinbase is skipped by ConnectBlock, not here). Fills `parsed`
    // (+ `genesisMeta`/`haveGenesisMeta` for GENESIS) and returns true IFF
    // vout[0] is a valid SLP message. Static + pure so the vector corpus can
    // pin the exact ledger-fork-critical rules against the REAL indexer code
    // (no CBlockIndex / chain state needed). IndexTransaction is its sole
    // production caller.
    static bool ParseTx(const CTransaction& tx, int64_t height,
                        CZSLPParsedMsg& parsed, CZSLPToken& genesisMeta,
                        bool& haveGenesisMeta);

    // Open the store and run the version-stamp migration (wipe + reindex when the
    // on-disk format is stale/absent). Cheap: no chain scan, no cs_main. Returns
    // true on success. Call before StartBackgroundSync().
    bool OpenStore();

    // Spawn the background worker that catches the store up to the active tip in
    // cs_main-yielding chunks and then registers on the validation bus atomically
    // at the tip. Non-blocking; startup is never stalled by a full (re)index.
    void StartBackgroundSync();

    // Interrupt + join the background worker (idempotent). Does NOT unregister or
    // delete — see InterruptZSLPIndexerSync()/StopZSLPIndexer().
    void InterruptAndJoinSync();

    // True once historical catch-up completed and the indexer went live on the
    // validation bus. While false, the store may hold only a partial index.
    bool IsSynced() const { return m_synced.load(); }

protected:
    // CValidationInterface hook: added=true on connect, false on disconnect.
    // Provides the (dis)connected CBlock directly, so no disk read is needed.
    void ChainTip(const CBlockIndex* pindex, const CBlock* pblock,
                  SproutMerkleTree sproutTree, SaplingMerkleTree saplingTree,
                  bool added) override;

private:
    std::unique_ptr<CZSLPStore> store;

    // Background catch-up worker state.
    boost::thread* m_syncThread;     // owned; NULL when not running
    std::atomic<bool> m_interrupt;   // cooperative stop request
    std::atomic<bool> m_synced;      // true once live on the validation bus

    void ConnectBlock(const CBlockIndex* pindex, const CBlock& block);
    void DisconnectBlock(const CBlockIndex* pindex, const CBlock& block);

    // Per-transaction scan: gather token inputs, find the OP_RETURN, parse SLP,
    // apply conservation. Runs for EVERY tx (a non-SLP tx still burns any token
    // UTXOs it spends).
    void IndexTransaction(const CTransaction& tx, const CBlockIndex* pindex);

    // Background worker entry (sets thread name + exception firewall) and the
    // chunked catch-up loop it runs (replays stored-tip..chainActive in
    // cs_main-yielding chunks, then registers atomically at the tip).
    void SyncWorker();
    void RunCatchUp();
};

#endif // BITCOIN_ZSLP_ZSLPINDEXER_H
