// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstrapvalidation.h"

#include "chain.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "coins.h"
#include "consensus/validation.h"
#include "init.h"
#include "main.h"
#include "scheduler.h"
#include "serialize.h"
#include "sync.h"
#include "txdb.h"
#include "util.h"

#include <atomic>

#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

// Durable record stored in the block tree DB under a single key (one atomic
// write per transition). Holds the latch state, the snapshot tip (H + hash), the
// digest captured at import (S_imported), and the replay progress for resume.
struct CBootstrapValidationRecord
{
    int32_t nState;
    int32_t nHeight;
    uint256 hashBlock;
    uint256 hashSerialized;
    int32_t nProgress;

    CBootstrapValidationRecord() : nState(BVS_DISABLED), nHeight(-1), nProgress(-1) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nState);
        READWRITE(nHeight);
        READWRITE(hashBlock);
        READWRITE(hashSerialized);
        READWRITE(nProgress);
    }
};

static const std::string BOOTSTRAPVAL_DBKEY = "bootstrapvalidation";

static CCriticalSection cs_bsval;
static BootstrapValidationStatus g_status;        // guarded by cs_bsval

// Lock-free mirror of "are we holding finalization?" so the consensus path
// (FindBlockToFinalize, under cs_main) can read it without taking cs_bsval and
// risking a lock-order inversion. Kept in sync with g_status.state under cs_bsval.
static std::atomic<bool> g_finalizationHold(false);

// Dedicated handle for the background validation thread (NOT in the init
// thread_group) so Shutdown() can interrupt+join exactly this thread before the
// chain DBs are freed, on both the normal and the init-failure path.
static boost::thread* g_bsvalThread = NULL;

// Recompute the lock-free finalization-hold flag from the current latch state.
// Hold while an imported snapshot is unvalidated (PROVISIONAL / PROVISIONAL_PRUNED).
static void RefreshFinalizationHoldLocked()
{
    AssertLockHeld(cs_bsval);
    g_finalizationHold.store(
        g_status.state == BVS_PROVISIONAL || g_status.state == BVS_PROVISIONAL_PRUNED,
        std::memory_order_relaxed);
}

static const int64_t BOOTSTRAPVAL_BATCH_MS = 80;          // cs_main per-batch budget
static const size_t BOOTSTRAPVAL_FLUSH_CAP = 300 * (1 << 20); // in-mem coin cache cap

static boost::filesystem::path ScratchDir()
{
    return GetDataDir() / "chainstate-verify";
}

static void PersistRecordLocked(int state, int progress)
{
    AssertLockHeld(cs_bsval);
    CBootstrapValidationRecord rec;
    rec.nState = state;
    rec.nHeight = g_status.height;
    rec.hashBlock = g_status.hashBlock;
    rec.hashSerialized = g_status.commitment;
    rec.nProgress = progress;
    if (pblocktree) {
        pblocktree->Write(BOOTSTRAPVAL_DBKEY, rec);
    }
}

// Persist replay progress (still PROVISIONAL) and mirror it in memory.
static void PersistProgress(int progress)
{
    LOCK(cs_bsval);
    g_status.validatedHeight = progress;
    PersistRecordLocked(BVS_PROVISIONAL, progress);
}

// Persist a terminal latch (VALIDATED or FAILED).
static void SetTerminalState(int state)
{
    LOCK(cs_bsval);
    g_status.state = state;
    RefreshFinalizationHoldLocked();
    PersistRecordLocked(state, g_status.validatedHeight);
}

// In-memory only state change (e.g. PROVISIONAL_PRUNED): the durable record stays
// PROVISIONAL so a later unpruned run can still resume and validate.
static void SetMemoryState(int state)
{
    LOCK(cs_bsval);
    g_status.state = state;
    RefreshFinalizationHoldLocked();
}

void LoadBootstrapValidationState()
{
    LOCK(cs_bsval);
    CBootstrapValidationRecord rec;
    if (pblocktree && pblocktree->Read(BOOTSTRAPVAL_DBKEY, rec)) {
        g_status.state = rec.nState;
        g_status.height = rec.nHeight;
        g_status.hashBlock = rec.hashBlock;
        g_status.commitment = rec.hashSerialized;
        g_status.validatedHeight = rec.nProgress;
    } else {
        g_status = BootstrapValidationStatus();
    }
    RefreshFinalizationHoldLocked();
}

void BeginBootstrapValidation(int height, const uint256& hashBlock, const uint256& sImported)
{
    LOCK(cs_bsval);
    g_status.state = BVS_PROVISIONAL;
    g_status.height = height;
    g_status.hashBlock = hashBlock;
    g_status.commitment = sImported;
    g_status.validatedHeight = 0;
    RefreshFinalizationHoldLocked();
    PersistRecordLocked(BVS_PROVISIONAL, 0);
    LogPrintf("Trustless bootstrap: snapshot at height %d marked provisional; background UTXO validation pending\n", height);
}

BootstrapValidationStatus GetBootstrapValidationStatus()
{
    LOCK(cs_bsval);
    return g_status;
}

bool BootstrapValidationHoldsFinalization()
{
    return g_finalizationHold.load(std::memory_order_relaxed);
}

// Test-only seam (deliberately NOT in the public header): drive a terminal latch
// so unit tests can verify the finalization-hold flag releases on VALIDATED/FAILED
// without standing up a full chain + background thread. Linked via an extern decl
// in the test, matching the other test accessors in this module.
void BootstrapValidationSetTerminalStateForTest(int state)
{
    SetTerminalState(state);
}

// Discard the (forged or unverifiable-as-correct) imported chainstate and queue a
// reindex from local block data on the next start, then shut down. Runs on the
// main/scheduler thread — never on the validation thread.
static void QueueReindexAndShutdown()
{
    LogPrintf("Trustless bootstrap: discarding chainstate and reindexing from local block data\n");
    if (pblocktree) {
        pblocktree->WriteReindexing(true);
    }
    {
        LOCK(cs_bsval);
        // Clear the record so we do not loop after the reindex rebuilds a correct,
        // fully-validated chainstate from the (valid) block files.
        CBootstrapValidationRecord rec;
        if (pblocktree) {
            pblocktree->Write(BOOTSTRAPVAL_DBKEY, rec);
        }
        g_status = BootstrapValidationStatus();
    }
    try {
        boost::filesystem::remove_all(ScratchDir());
    } catch (...) {}
    StartShutdown();
}

// Scheduler poll: when the background thread latches FAILED, trigger the reindex.
static void BootstrapValidationFailedPoll()
{
    int state;
    {
        LOCK(cs_bsval);
        state = g_status.state;
    }
    if (state == BVS_FAILED) {
        QueueReindexAndShutdown();
    }
}

// Scheduler poll: while parked in PROVISIONAL_PRUNED, the node is running on an
// imported UTXO set that has NEVER been re-derived/verified and auto-finalization
// is paused indefinitely (RefreshFinalizationHoldLocked holds for this state).
// There is no operator-visible recurring signal otherwise, so emit a LOUD warning
// at a low duty cycle. Throttled to one line per ~10 minutes so it cannot flood
// the log. A strict no-op for every other state, so normal nodes never see it.
static void BootstrapValidationProvisionalPrunedPoll()
{
    int state;
    {
        LOCK(cs_bsval);
        state = g_status.state;
    }
    if (state != BVS_PROVISIONAL_PRUNED) {
        return;
    }
    static int64_t nLastWarn = 0;
    const int64_t now = GetTime();
    if (now - nLastWarn < 600) {
        return;
    }
    nLastWarn = now;
    LogPrintf("Trustless bootstrap: WARNING: chainstate is PROVISIONAL/UNVERIFIED (background UTXO validation could not complete because block data is pruned/missing); auto-finalization is PAUSED. Run with an unpruned datadir to complete background validation, or re-bootstrap.\n");
}

// Background worker: re-derive the UTXO set from genesis to H into a private
// scratch chainstate and compare its digest to S_imported.
static void ThreadBootstrapUtxoValidation()
{
    RenameThread("zcl-utxoverify");

    // Bail before touching any globals if a shutdown is already in flight. The
    // startup-failure path (bitcoind.cpp) interrupts but does NOT join this
    // thread before Shutdown() frees pblocktree/pcoinsTip/mapBlockIndex, so a
    // late spawn must not race into cs_main / ReadBlockFromDisk against teardown.
    if (ShutdownRequested()) {
        return;
    }

    int H, startProgress;
    uint256 expected, snapshotTip;
    {
        LOCK(cs_bsval);
        H = g_status.height;
        startProgress = g_status.validatedHeight;
        expected = g_status.commitment;
        snapshotTip = g_status.hashBlock;
    }
    if (H < 0) {
        return;
    }

    bool validated = false;
    bool failed = false;
    try {
        const bool wipe = (startProgress <= 0);
        CCoinsViewDB scratchdb(ScratchDir(), 1 << 25, false, wipe);
        CCoinsViewCache view(&scratchdb);

        int progress = startProgress < 0 ? 0 : startProgress;
        if (!wipe) {
            // Reconcile the persisted progress with what the scratch DB actually
            // durably holds, in BOTH directions. The intermittent cache flush
            // below advances the DB's best block independently of the per-batch
            // progress persist, so after a crash the persisted progress can lag
            // the DB. Resuming ABOVE the DB's real best block would trip
            // ConnectBlock's assert(hashPrevBlock == view.GetBestBlock()) on the
            // first connect (an abort-on-every-restart loop); resuming below it
            // would re-connect blocks already in the view. The DB's durable best
            // block is the single source of truth, so align to it unconditionally.
            uint256 best = scratchdb.GetBestBlock();
            if (best.IsNull()) {
                progress = 0;
            } else {
                LOCK(cs_main);
                BlockMap::iterator it = mapBlockIndex.find(best);
                // If the best block somehow isn't in our index (should be
                // impossible — we only ever connect blocks from it), keep the
                // persisted progress rather than risk a genesis-onto-nonempty
                // assert; a later run will re-reconcile.
                if (it != mapBlockIndex.end() && it->second) {
                    progress = it->second->nHeight;
                }
            }
        }

        // progress is the highest height already connected (0 = none yet). When
        // nothing is connected, start at genesis (height 0); ConnectBlock handles
        // the genesis special case and seeds the empty UTXO set.
        int h = (progress <= 0) ? 0 : progress + 1;
        LogPrintf("Trustless bootstrap: background UTXO validation re-deriving genesis..%d (from height %d)\n", H, h);

        // The chain up to the last compiled checkpoint is pinned by hash (the
        // trustless accept gate requires checkpoint agreement), so the only
        // range where a forger could splice a low-difficulty fork is ABOVE it.
        // We re-enforce the difficulty retarget only for those blocks. Doing it
        // at/below the checkpoint would be pointless (already pinned) and would
        // also wrongly trip ContextualCheckBlockHeader's own checkpoint-fork
        // guard (it DoS-rejects nHeight < lastCheckpoint), since the replay
        // necessarily walks up from genesis. Resolve the boundary once; -1 (no
        // checkpoint in the index) means "check every non-genesis block", which
        // is safe because that guard then never fires.
        int lastCheckpointHeight = -1;
        {
            LOCK(cs_main);
            const CBlockIndex* pcp = Checkpoints::GetLastCheckpoint(Params().Checkpoints());
            if (pcp != NULL)
                lastCheckpointHeight = pcp->nHeight;
        }

        while (h <= H) {
            boost::this_thread::interruption_point();
            if (ShutdownRequested()) {
                PersistProgress(h - 1);
                return;
            }
            const int64_t batchStart = GetTimeMillis();
            bool incomplete = false;
            {
                LOCK(cs_main);
                CBlockIndex* tip = chainActive.Tip();
                CBlockIndex* anchorBranch = (tip ? tip->GetAncestor(H) : NULL);
                if (anchorBranch == NULL || anchorBranch->GetBlockHash() != snapshotTip) {
                    // The snapshot tip is not on the active chain's ancestry; we
                    // cannot derive against it. Stay provisional (not a forgery proof).
                    incomplete = true;
                } else {
                    while (h <= H && (GetTimeMillis() - batchStart) < BOOTSTRAPVAL_BATCH_MS) {
                        CBlockIndex* pindex = anchorBranch->GetAncestor(h);
                        if (pindex == NULL) {
                            incomplete = true;
                            break;
                        }
                        CBlock block;
                        if (!ReadBlockFromDisk(block, pindex)) {
                            // Missing/pruned block data: cannot complete. Not evidence
                            // of forgery — only a completed replay with a mismatching
                            // digest is. Stay provisional.
                            incomplete = true;
                            break;
                        }
                        CValidationState cvstate;
                        // ConnectBlock (fScratchView=true) only re-checks context-free
                        // PoW against the block's CLAIMED nBits; it does NOT re-enforce
                        // the difficulty retarget. Re-run the contextual header rules
                        // (notably nBits == GetNextWorkRequired(pprev), main.cpp) for
                        // every block ABOVE the last checkpoint so a low-difficulty
                        // forged fork in that (unpinned) range cannot pass background
                        // validation. pindex is on the active-chain ancestry, so pprev
                        // and the averaging window are intact; genesis (pprev == NULL)
                        // has no retarget and is skipped, and blocks at/below the
                        // checkpoint are skipped (already hash-pinned; see above). A
                        // failure here is a forgery/invalidity proof for a fully-present,
                        // on-ancestry block: handle it exactly like a failed ConnectBlock
                        // (-> FAILED -> auto-reindex).
                        if (pindex->pprev != NULL &&
                            pindex->nHeight > lastCheckpointHeight &&
                            !ContextualCheckBlockHeader(block, cvstate, pindex->pprev)) {
                            failed = true;
                            break;
                        }
                        // fScratchView=true: re-derive into our private view only,
                        // never the live txindex / block index / wallet signals.
                        if (!ConnectBlock(block, cvstate, pindex, view, false, /*fScratchView=*/true)) {
                            failed = true;
                            break;
                        }
                        view.SetBestBlock(pindex->GetBlockHash());
                        boost::this_thread::interruption_point();
                        ++h;
                    }
                }
            }
            // Flush the thread-private scratch view to its thread-private scratch
            // DB OUTSIDE cs_main: this can be a large leveldb write and the view /
            // DB are never touched by any other thread, so holding cs_main across
            // it would only stall the message handler / live block connect for the
            // flush duration. (BatchWrite reads/writes only this view's caches and
            // scratchdb; it takes no global lock and no shared state.)
            if (view.DynamicMemoryUsage() > BOOTSTRAPVAL_FLUSH_CAP) {
                view.Flush();
            }
            if (failed) {
                break;
            }
            if (incomplete) {
                SetMemoryState(BVS_PROVISIONAL_PRUNED);
                PersistProgress(h - 1);
                LogPrintf("Trustless bootstrap: background validation could not complete (missing block data); staying provisional\n");
                return;
            }
            PersistProgress(h - 1);
            boost::this_thread::yield();
        }

        if (!failed) {
            // Final flush of the thread-private scratch view to its thread-private
            // scratch DB: no lock needed (see the in-loop flush note above). The
            // prior LOCK(cs_main) here only stalled live block connect for the
            // duration of this (potentially large) leveldb write.
            view.Flush();
            CCoinsStats stats;
            if (!scratchdb.GetStats(stats)) {
                LogPrintf("Trustless bootstrap: could not hash re-derived chainstate; will retry on restart\n");
                PersistProgress(H);
                return;
            }
            validated = (stats.hashSerialized == expected);
            // Test-only seam: force a mismatch verdict to exercise the
            // discard+reindex fallback without having to forge a self-consistent
            // UTXO set. Honored ONLY on regtest so it can never be toggled on a
            // mainnet/testnet binary (where, worst case, it would force a needless
            // multi-hour reindex).
            if (validated && Params().NetworkIDString() == "regtest" &&
                GetBoolArg("-bootstrapvalidationtestforcefail", false)) {
                LogPrintf("Trustless bootstrap: (test) forcing validation FAILURE\n");
                validated = false;
            }
            failed = !validated;
            if (!validated) {
                LogPrintf("Trustless bootstrap: VALIDATION MISMATCH at height %d: re-derived %s != imported %s\n",
                    H, stats.hashSerialized.ToString(), expected.ToString());
            }
        }
    } catch (const std::exception& e) {
        LogPrintf("Trustless bootstrap: background validation error: %s (will retry on restart)\n", e.what());
        return;
    }

    if (validated) {
        SetTerminalState(BVS_VALIDATED);
        LogPrintf("Trustless bootstrap: snapshot at height %d FULLY VALIDATED (UTXO set re-derived from genesis matches the import)\n", H);
        try {
            boost::filesystem::remove_all(ScratchDir());
        } catch (...) {}
    } else if (failed) {
        SetTerminalState(BVS_FAILED);
        LogPrintf("Trustless bootstrap: snapshot at height %d FAILED validation; chainstate will be discarded and reindexed\n", H);
    }
}

void MaybeStartBootstrapValidation(boost::thread_group& threadGroup, CScheduler& scheduler)
{
    int state;
    {
        LOCK(cs_bsval);
        state = g_status.state;
    }
    if (state == BVS_DISABLED || state == BVS_VALIDATED) {
        return;
    }
    if (state == BVS_FAILED) {
        // A prior run latched FAILED but did not finish the reindex handoff.
        QueueReindexAndShutdown();
        return;
    }
    // PROVISIONAL: a pruned node cannot re-derive from genesis. Keep it provisional
    // (rely on PoW headers + the provisional gate); never auto-reindex on missing data.
    if (fPruneMode) {
        SetMemoryState(BVS_PROVISIONAL_PRUNED);
        LogPrintf("Trustless bootstrap: pruning is enabled; cannot re-derive the UTXO set. Snapshot stays provisional.\n");
        // Never going to run the re-derivation here, so don't leave a partial
        // scratch chainstate from an earlier (unpruned) run sitting on disk.
        try {
            boost::filesystem::remove_all(ScratchDir());
        } catch (...) {}
        // Periodically remind the operator that this node is serving/using an
        // unverified chainstate with finalization paused (no other recurring signal).
        scheduler.scheduleEvery(boost::bind(&BootstrapValidationProvisionalPrunedPoll), 60);
        return;
    }
    // Don't start a background re-derivation if we're already shutting down: the
    // failure path interrupts without joining the init thread_group before the
    // chain databases are freed, so a thread spawned here could outlive them
    // (use-after-free).
    if (ShutdownRequested()) {
        return;
    }
    // Own the thread via a dedicated handle (not the init thread_group) so
    // Shutdown() can interrupt+join EXACTLY this thread before the chain DBs are
    // freed — including on the init-failure path, which skips thread_group join.
    (void)threadGroup;
    if (g_bsvalThread == NULL) {
        g_bsvalThread = new boost::thread(boost::bind(&ThreadBootstrapUtxoValidation));
    }
    scheduler.scheduleEvery(boost::bind(&BootstrapValidationFailedPoll), 5);
    // The re-derivation can itself park in PROVISIONAL_PRUNED mid-run if block
    // data turns out to be missing; in that case the operator must still be warned
    // periodically. The poll is a no-op until/unless the state actually parks there.
    scheduler.scheduleEvery(boost::bind(&BootstrapValidationProvisionalPrunedPoll), 60);
}

void InterruptBootstrapValidation()
{
    if (g_bsvalThread == NULL) {
        return;
    }
    // The worker polls ShutdownRequested() per batch and hits boost interruption
    // points between connects, so interrupt()+join() returns promptly (within one
    // ~80ms batch). Joining here, before Shutdown() frees the chain DBs, closes
    // the use-after-free window the init-failure path would otherwise leave open.
    try {
        g_bsvalThread->interrupt();
        g_bsvalThread->join();
    } catch (...) {}
    delete g_bsvalThread;
    g_bsvalThread = NULL;
}
