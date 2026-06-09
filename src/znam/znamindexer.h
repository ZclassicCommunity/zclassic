// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZNAM indexer skeleton -- a future CValidationInterface observer that projects
// confirmed-chain ZNAM OP_RETURN records into CZNAMStore.
//
// NON-consensus: this observer must only read connected/disconnected blocks.
// It must never reject blocks or transactions, influence mempool acceptance,
// touch wallet spending, or fetch/host files. Invalid, ownerless, unauthorized,
// expired, or malformed records are ignored/no-op in the overlay. CONTENT
// records are opaque resolver values only.

#ifndef BITCOIN_ZNAM_ZNAMINDEXER_H
#define BITCOIN_ZNAM_ZNAMINDEXER_H

#include "validationinterface.h"
#include "znam/znamstore.h"

#include <atomic>
#include <memory>
#include <string>

namespace boost { class thread; }

class CBlock;
class CBlockIndex;
class CBlockUndo;
class CScript;
class CTransaction;

/** Global indexer instance, non-NULL only when future -znamindex plumbing starts it. */
class CZNAMIndexer;
extern CZNAMIndexer* g_znamIndexer;

/** Future init/shutdown helpers. Declared only; not wired into init.cpp yet. */
void StartZNAMIndexer();
void StopZNAMIndexer();
void InterruptZNAMIndexerSync();

class CZNAMIndexer : public CValidationInterface
{
public:
    CZNAMIndexer();
    ~CZNAMIndexer();

    /** Accessor for future read RPCs. May be NULL when the index is disabled. */
    CZNAMStore* Store() { return store.get(); }

    /**
     * Canonical, side-effect-free per-transaction parse seam.
     *
     * Scans outputs in ascending vout order and returns the first script that
     * ZNAMParseScript accepts, matching ZNAM_DETERMINISM_SPEC.md section 5.
     * Coinbase skipping is a ConnectBlock concern, not this function.
     */
    static bool ParseTx(const CTransaction& tx, ZNAMMessage& parsed,
                        int32_t& recordVout);

    /**
     * Testable owner-address seam for vin[0] prevout script handling.
     *
     * Returns true only for a standard transparent P2PKH script under the active
     * chain parameters. P2SH, multisig, non-standard scripts, coinbase/null
     * prevouts, and unresolved prevouts must make the caller ignore the record.
     */
    static bool ExtractP2PKHOwnerFromScript(const CScript& scriptPubKey,
                                            std::string& ownerAddr);

    // Store open / migration and background catch-up lifecycle. Future .cpp
    // should mirror CZSLPIndexer without default-enabling runtime behavior.
    bool OpenStore();
    void StartBackgroundSync();
    void InterruptAndJoinSync();
    bool IsSynced() const { return m_synced.load(); }

protected:
    // CValidationInterface hook: added=true on connect, false on disconnect.
    void ChainTip(const CBlockIndex* pindex, const CBlock* pblock,
                  SproutMerkleTree sproutTree, SaplingMerkleTree saplingTree,
                  bool added) override;

private:
    std::unique_ptr<CZNAMStore> store;

    boost::thread* m_syncThread;
    std::atomic<bool> m_interrupt;
    std::atomic<bool> m_synced;

    void ConnectBlock(const CBlockIndex* pindex, const CBlock& block);
    void DisconnectBlock(const CBlockIndex* pindex, const CBlock& block);

    // Index one non-coinbase transaction. This must parse at most one record
    // (first accepted vout) and derive owner exclusively from confirmed vin[0].
    // blockUndo is the connecting block's undo data (vtxundo[txIndex-1] holds
    // this tx's spent prevouts); empty undo => the record is treated as ownerless.
    void IndexTransaction(const CTransaction& tx, const CBlockIndex* pindex,
                          int32_t txIndex, const CBlockUndo& blockUndo);

    // Resolve vin[0].prevout's spent scriptPubKey from the block undo data and
    // encode the owner P2PKH address, or return false so the ZNAM record is
    // ignored (ownerless / non-P2PKH signer / missing undo).
    bool GetOwnerForTransaction(const CTransaction& tx, int32_t txIndex,
                                const CBlockUndo& blockUndo,
                                std::string& ownerAddr) const;

    void SyncWorker();
    void RunCatchUp();
};

#endif // BITCOIN_ZNAM_ZNAMINDEXER_H
