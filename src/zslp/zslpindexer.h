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

#include <memory>

class CZSLPStore;
class CBlock;
class CBlockIndex;
class CTransaction;

/** Global indexer instance, non-NULL when -zslpindex is enabled. */
class CZSLPIndexer;
extern CZSLPIndexer* g_zslpIndexer;

/** Init/shutdown helpers, called from init.cpp behind -zslpindex. */
void StartZSLPIndexer();
void StopZSLPIndexer();

class CZSLPIndexer : public CValidationInterface
{
public:
    CZSLPIndexer();
    ~CZSLPIndexer();

    /** Accessor for the read RPCs. May be NULL if the index is disabled. */
    CZSLPStore* Store() { return store.get(); }

protected:
    // CValidationInterface hook: added=true on connect, false on disconnect.
    // Provides the (dis)connected CBlock directly, so no disk read is needed.
    void ChainTip(const CBlockIndex* pindex, const CBlock* pblock,
                  SproutMerkleTree sproutTree, SaplingMerkleTree saplingTree,
                  bool added) override;

private:
    std::unique_ptr<CZSLPStore> store;

    void ConnectBlock(const CBlockIndex* pindex, const CBlock& block);
    void DisconnectBlock(const CBlockIndex* pindex, const CBlock& block);

    // Per-transaction scan: find the OP_RETURN, parse SLP, persist.
    void IndexTransaction(const CTransaction& tx, const CBlockIndex* pindex);
};

#endif // BITCOIN_ZSLP_ZSLPINDEXER_H
