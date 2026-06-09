// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZNAM (ZCL Names) indexer implementation. See znamindexer.h.
//
// NON-consensus observer: reads connected/disconnected blocks off the validation
// signal bus and projects ZNAM OP_RETURN records into CZNAMStore. Ownership is
// First-In-First-Served; the owner is the vin[0] P2PKH signer, recovered from the
// block's undo data (the spent prevout's scriptPubKey). An invalid, ownerless,
// unauthorized, expired, or malformed record is a deterministic overlay no-op and
// never affects block/tx validity. Lifecycle + background catch-up mirror the
// ZSLP indexer (zslp/zslpindexer.cpp) exactly; the only divergences are the
// undo-data owner derivation and the default-OFF -znamindex gating.

#include "znam/znamindexer.h"

#include "chain.h"
#include "key_io.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "sync.h"
#include "undo.h"
#include "util.h"
#include "znam/znammsg.h"
#include "znam/znamstore.h"

#include <boost/bind.hpp>
#include <boost/thread.hpp>

CZNAMIndexer* g_znamIndexer = NULL;

// LevelDB cache size for the ZNAM store (modest; auxiliary data).
static const size_t ZNAM_DB_CACHE = 8 << 20; // 8 MiB

void StartZNAMIndexer()
{
    if (g_znamIndexer != NULL)
        return;
    g_znamIndexer = new CZNAMIndexer();
    // Open + migrate the store synchronously (cheap: no chain scan, no cs_main),
    // so the name_* RPCs have a live (initially partial) store immediately.
    if (!g_znamIndexer->OpenStore()) {
        LogPrintf("ZNAM: indexer store open failed; disabling name index\n");
        delete g_znamIndexer;
        g_znamIndexer = NULL;
        return;
    }
    // Heavy historical catch-up runs on a BACKGROUND thread in cs_main-yielding
    // chunks (see CZSLPIndexer for the rationale), registering on the validation
    // bus atomically at the tip so no live block is missed in the hand-off.
    g_znamIndexer->StartBackgroundSync();
    LogPrintf("ZNAM: name indexer store ready; background catch-up running\n");
}

void StopZNAMIndexer()
{
    if (g_znamIndexer == NULL)
        return;
    g_znamIndexer->InterruptAndJoinSync();
    if (g_znamIndexer->IsSynced())
        UnregisterValidationInterface(g_znamIndexer);
    delete g_znamIndexer;
    g_znamIndexer = NULL;
}

void InterruptZNAMIndexerSync()
{
    if (g_znamIndexer != NULL)
        g_znamIndexer->InterruptAndJoinSync();
}

CZNAMIndexer::CZNAMIndexer()
    : m_syncThread(NULL), m_interrupt(false), m_synced(false) {}

CZNAMIndexer::~CZNAMIndexer() {}

// ── Store open / migration ──────────────────────────────────────────

bool CZNAMIndexer::OpenStore()
{
    boost::filesystem::path path = GetDataDir() / "blocks" / "znam";

    store.reset(new CZNAMStore(path, ZNAM_DB_CACHE));
    uint32_t version = 0;
    bool haveVersion = store->ReadIndexVersion(version);
    if (!haveVersion || version < ZNAM_INDEX_VERSION) {
        LogPrintf("ZNAM: index format %s (have %u, want %u) — wiping + reindexing\n",
                  haveVersion ? "outdated" : "absent",
                  haveVersion ? version : 0u, ZNAM_INDEX_VERSION);
        store.reset(); // close before reopening with fWipe
        store.reset(new CZNAMStore(path, ZNAM_DB_CACHE, /*fMemory=*/false,
                                   /*fWipe=*/true));
        // Stamp the version BEFORE reindexing so a crash mid-reindex resumes
        // from the per-block tip rather than re-wiping.
        store->WriteIndexVersion(ZNAM_INDEX_VERSION);
    }
    return store.get() != NULL;
}

// ── Background catch-up ─────────────────────────────────────────────

void CZNAMIndexer::StartBackgroundSync()
{
    m_interrupt.store(false);
    m_synced.store(false);
    m_syncThread = new boost::thread(boost::bind(&CZNAMIndexer::SyncWorker, this));
}

void CZNAMIndexer::InterruptAndJoinSync()
{
    m_interrupt.store(true);
    if (m_syncThread != NULL) {
        m_syncThread->interrupt();
        m_syncThread->join();
        delete m_syncThread;
        m_syncThread = NULL;
    }
}

void CZNAMIndexer::SyncWorker()
{
    RenameThread("zcl-znamsync");
    try {
        RunCatchUp();
    } catch (const boost::thread_interrupted&) {
        LogPrintf("ZNAM: background catch-up interrupted; will resume next start\n");
    } catch (const std::exception& e) {
        LogPrintf("ZNAM: background catch-up error: %s\n", e.what());
    } catch (...) {
        LogPrintf("ZNAM: background catch-up unknown error\n");
    }
}

// Replay missing blocks from the stored tip up to chainActive in bounded
// cs_main-yielding chunks; register on the bus atomically at the tip. See
// CZSLPIndexer::RunCatchUp for the detailed reorg-window note: a reorg below the
// cursor during the unregistered startup window can orphan a few rows; it is
// NON-consensus and self-heals on a ZNAM_INDEX_VERSION bump.
void CZNAMIndexer::RunCatchUp()
{
    static const int kChunk = 128; // blocks per cs_main hold (bounded stall)
    int nextHeight = -1;
    bool announced = false;

    while (!m_interrupt.load()) {
        bool atTip = false;
        {
            LOCK(cs_main);
            CZNAMStore* s = store.get();
            if (s == NULL)
                return;

            if (nextHeight < 0) {
                int64_t storedHeight = -1;
                uint256 storedHash;
                bool haveTip = s->ReadTip(storedHeight, storedHash);
                nextHeight = haveTip ? (int)storedHeight + 1 : 0;
                if (nextHeight < 0)
                    nextHeight = 0;
            }

            int tipHeight = chainActive.Height();
            if (tipHeight < 0) {
                atTip = true; // empty chain: go live and wait for blocks
            } else {
                if (!announced && nextHeight <= tipHeight) {
                    LogPrintf("ZNAM: background catch-up indexing blocks %d..%d\n",
                              nextHeight, tipHeight);
                    announced = true;
                }
                int processed = 0;
                for (; nextHeight <= tipHeight && processed < kChunk;
                       ++nextHeight, ++processed) {
                    const CBlockIndex* pindex = chainActive[nextHeight];
                    if (pindex == NULL)
                        break;
                    CBlock block;
                    if (!ReadBlockFromDisk(block, pindex)) {
                        LogPrintf("ZNAM: catch-up failed to read block %d; "
                                  "disabling name index for this run\n", nextHeight);
                        return; // stays unregistered (disabled); resumes next boot
                    }
                    ConnectBlock(pindex, block);
                }
                if (nextHeight > tipHeight)
                    atTip = true;
            }

            if (atTip) {
                RegisterValidationInterface(this);
                m_synced.store(true);
                LogPrintf("ZNAM: catch-up complete (height %d); now live\n",
                          chainActive.Height());
                return;
            }
        } // release cs_main between chunks

        boost::this_thread::interruption_point();
    }
}

// ── Parse / owner-derivation seams (static, pure) ───────────────────

// Scan outputs ascending and return the FIRST script ZNAMParseScript accepts
// (ZNAM_DETERMINISM_SPEC.md section 5). At most one ZNAM record honored per tx.
// No chain state, so the parser-vector corpus pins this exact behavior.
bool CZNAMIndexer::ParseTx(const CTransaction& tx, ZNAMMessage& parsed,
                           int32_t& recordVout)
{
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const CScript& spk = tx.vout[i].scriptPubKey;
        if (spk.empty())
            continue;
        std::vector<unsigned char> raw(spk.begin(), spk.end());
        ZNAMMessage m;
        if (ZNAMParseScript(raw.data(), raw.size(), m)) {
            parsed = m;
            recordVout = (int32_t)i;
            return true;
        }
    }
    return false;
}

// Owner is the standard transparent P2PKH destination of a spent prevout's
// scriptPubKey. P2SH/multisig/non-standard/null/unresolved => false (the record
// is ignored). Pure function of the scriptPubKey bytes + active CChainParams.
bool CZNAMIndexer::ExtractP2PKHOwnerFromScript(const CScript& scriptPubKey,
                                               std::string& ownerAddr)
{
    CTxDestination dest;
    if (!ExtractDestination(scriptPubKey, dest))
        return false;
    if (!IsValidDestination(dest))
        return false;
    if (boost::get<CKeyID>(&dest) == NULL)
        return false; // P2PKH only (a CKeyID destination)
    ownerAddr = EncodeDestination(dest);
    return true;
}

// vin[0]'s spent prevout scriptPubKey lives in the block's undo data:
// blockUndo.vtxundo[txIndex-1].vprevout[0].txout (vtxundo excludes the coinbase,
// so block-tx index i maps to vtxundo[i-1]). Empty/short undo => no owner.
bool CZNAMIndexer::GetOwnerForTransaction(const CTransaction& tx, int32_t txIndex,
                                          const CBlockUndo& blockUndo,
                                          std::string& ownerAddr)
{
    if (txIndex < 1) // coinbase has only a null prevout; never an owner
        return false;
    size_t idx = (size_t)(txIndex - 1);
    if (idx >= blockUndo.vtxundo.size())
        return false;
    const CTxUndo& txundo = blockUndo.vtxundo[idx];
    if (txundo.vprevout.empty())
        return false;
    return ExtractP2PKHOwnerFromScript(txundo.vprevout[0].txout.scriptPubKey, ownerAddr);
}

// ── Signal hook ────────────────────────────────────────────────────

void CZNAMIndexer::ChainTip(const CBlockIndex* pindex, const CBlock* pblock,
                            SproutMerkleTree, SaplingMerkleTree, bool added)
{
    if (pindex == NULL || pblock == NULL)
        return;
    if (added)
        ConnectBlock(pindex, *pblock);
    else
        DisconnectBlock(pindex, *pblock);
}

// ── Connect ────────────────────────────────────────────────────────

void CZNAMIndexer::ConnectBlock(const CBlockIndex* pindex, const CBlock& block)
{
    CZNAMStore* s = store.get();
    if (s == NULL)
        return;

    const uint256 blockHash = pindex->GetBlockHash();

    // Idempotence guard: skip a re-delivered connect for the current tip.
    int64_t tipHeight = -1;
    uint256 tipHash;
    if (s->ReadTip(tipHeight, tipHash) && tipHash == blockHash)
        return;

    s->ConnectBlockBegin(blockHash);

    // Load the block's undo data ONCE for owner derivation. Empty/missing undo
    // (genesis, or a read failure) leaves all records ownerless (dropped) — the
    // safe NON-consensus behavior; vtxundo[i-1] indexing tolerates an empty vec.
    CBlockUndo blockUndo;
    if (!ReadBlockUndoFromDisk(blockUndo, pindex) && block.vtx.size() > 1)
        LogPrintf("ZNAM: missing undo data for block %d; "
                  "names in it are treated as ownerless\n", pindex->nHeight);

    // Skip the coinbase (vtx[0]): its null prevout can never be a P2PKH owner.
    for (size_t i = 1; i < block.vtx.size(); ++i)
        IndexTransaction(block.vtx[i], pindex, (int32_t)i, blockUndo);

    s->ConnectBlockEnd(pindex->nHeight, blockHash);
}

void CZNAMIndexer::IndexTransaction(const CTransaction& tx,
                                    const CBlockIndex* pindex, int32_t txIndex,
                                    const CBlockUndo& blockUndo)
{
    CZNAMStore* s = store.get();
    if (s == NULL)
        return;

    ZNAMMessage msg;
    int32_t recordVout = -1;
    if (!ParseTx(tx, msg, recordVout))
        return; // no ZNAM record in this tx

    // Owner = vin[0] P2PKH signer (may be "" => the store treats it as ownerless
    // and the record becomes a deterministic no-op).
    std::string ownerAddr;
    GetOwnerForTransaction(tx, txIndex, blockUndo, ownerAddr);

    s->ApplyRecord(msg, ownerAddr, tx.GetHash(), pindex->nHeight, txIndex,
                   pindex->GetBlockHash());
}

// ── Disconnect (reorg) ─────────────────────────────────────────────

void CZNAMIndexer::DisconnectBlock(const CBlockIndex* pindex,
                                   const CBlock& /*block*/)
{
    CZNAMStore* s = store.get();
    if (s == NULL)
        return;

    const uint256 blockHash = pindex->GetBlockHash();
    const CBlockIndex* pprev = pindex->pprev;
    int64_t prevHeight = pprev ? (int64_t)pprev->nHeight : -1;
    uint256 prevHash = pprev ? pprev->GetBlockHash() : uint256();

    // Replay the block's undo log in reverse and move the tip back.
    s->DisconnectBlock(blockHash, prevHeight, prevHash);
}
