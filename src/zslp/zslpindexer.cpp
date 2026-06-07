// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP indexer implementation. See zslpindexer.h.
//
// NON-consensus observer: reads connected/disconnected blocks off the
// validation signal bus and projects ZSLP OP_RETURN messages into the store,
// enforcing the real SLP Token-Type-1 UTXO-bound rules (conservation).

#include "zslp/zslpindexer.h"

#include "chain.h"
#include "key_io.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "sync.h"
#include "util.h"
#include "zslp/zslpmsg.h"
#include "zslp/zslpstore.h"

#include <functional>

CZSLPIndexer* g_zslpIndexer = NULL;

// LevelDB cache size for the ZSLP store (modest; this is auxiliary data).
static const size_t ZSLP_DB_CACHE = 8 << 20; // 8 MiB

void StartZSLPIndexer()
{
    if (g_zslpIndexer != NULL)
        return;
    g_zslpIndexer = new CZSLPIndexer();
    // Open + migrate + catch up the historical chain BEFORE going live, so the
    // replay does not race the validation bus and a re-delivered connect is
    // caught by the per-block tip idempotence guard.
    if (!g_zslpIndexer->Init()) {
        LogPrintf("ZSLP: indexer init failed; disabling token index\n");
        delete g_zslpIndexer;
        g_zslpIndexer = NULL;
        return;
    }
    RegisterValidationInterface(g_zslpIndexer);
    LogPrintf("ZSLP: token indexer started (UTXO-bound SLP conservation)\n");
}

void StopZSLPIndexer()
{
    if (g_zslpIndexer == NULL)
        return;
    UnregisterValidationInterface(g_zslpIndexer);
    delete g_zslpIndexer;
    g_zslpIndexer = NULL;
}

CZSLPIndexer::CZSLPIndexer() {}

CZSLPIndexer::~CZSLPIndexer() {}

// ── Init / migration / catch-up ─────────────────────────────────────

bool CZSLPIndexer::Init()
{
    boost::filesystem::path path = GetDataDir() / "blocks" / "zslp";

    // Open and check the on-disk format stamp. A stale/absent stamp (legacy
    // credit-only index, or never written) triggers a wipe + full reindex; the
    // index is fully derivable and behind -zslpindex, so a clean rebuild is the
    // safe migration.
    store.reset(new CZSLPStore(path, ZSLP_DB_CACHE));
    uint32_t version = 0;
    bool haveVersion = store->ReadIndexVersion(version);
    bool wiped = false;
    if (!haveVersion || version < ZSLP_INDEX_VERSION) {
        LogPrintf("ZSLP: index format %s (have %u, want %u) — wiping + reindexing\n",
                  haveVersion ? "outdated" : "absent",
                  haveVersion ? version : 0u, ZSLP_INDEX_VERSION);
        store.reset(); // close before reopening with fWipe
        store.reset(new CZSLPStore(path, ZSLP_DB_CACHE, /*fMemory=*/false,
                                   /*fWipe=*/true));
        // Stamp the version BEFORE reindexing so a crash mid-reindex resumes
        // from the per-block tip rather than re-wiping.
        store->WriteIndexVersion(ZSLP_INDEX_VERSION);
        wiped = true;
    }
    (void)wiped;

    return CatchUp();
}

bool CZSLPIndexer::CatchUp()
{
    CZSLPStore* s = store.get();
    if (s == NULL)
        return false;

    LOCK(cs_main);

    int64_t storedHeight = -1;
    uint256 storedHash;
    bool haveTip = s->ReadTip(storedHeight, storedHash);

    // Resume one past the stored tip (or from genesis after a wipe / no tip).
    int resumeHeight = haveTip ? (int)storedHeight + 1 : 0;
    if (resumeHeight < 0)
        resumeHeight = 0;

    int tipHeight = chainActive.Height();
    if (tipHeight < 0)
        return true; // empty chain: nothing to index yet

    for (int hh = resumeHeight; hh <= tipHeight; ++hh) {
        const CBlockIndex* pindex = chainActive[hh];
        if (pindex == NULL)
            break;
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex)) {
            LogPrintf("ZSLP: catch-up failed to read block at height %d\n", hh);
            return false;
        }
        ConnectBlock(pindex, block);
    }
    if (tipHeight >= resumeHeight)
        LogPrintf("ZSLP: catch-up indexed blocks %d..%d\n", resumeHeight, tipHeight);
    return true;
}

// ── Address extraction ─────────────────────────────────────────────

// Decode the t-address paid by a given vout's scriptPubKey, or "" if it is
// not a standard pay-to-address output (e.g. the OP_RETURN itself).
//
// DETERMINISM (part of F): the address that keys the derived balance / transfer
// rows MUST be canonical and deterministic so two implementations key the same
// holder. ExtractDestination (script/standard.cpp) is a pure function of the
// scriptPubKey bytes, and EncodeDestination (key_io.cpp) is the canonical
// base58check encoding under the active CChainParams (fixed per network). A
// non-standard / undecodable output deterministically yields "" — an empty
// address never receives a balance credit (recordBalanceDelta skips "") and is
// stored verbatim on the UTXO, so the result is bit-identical everywhere.
static std::string AddressOfVout(const CTransaction& tx, int32_t voutIdx)
{
    if (voutIdx < 0 || (size_t)voutIdx >= tx.vout.size())
        return std::string();
    CTxDestination dest;
    if (!ExtractDestination(tx.vout[voutIdx].scriptPubKey, dest))
        return std::string();
    if (!IsValidDestination(dest))
        return std::string();
    return EncodeDestination(dest);
}

// Convert an SLP message's on-chain token_id (big-endian / display order) to
// the daemon uint256 (internal little-endian) so it matches the genesis txid
// as the daemon computes it.
static uint256 TokenIdToUint256(const uint8_t tokenId[32])
{
    std::vector<unsigned char> v(32);
    for (int i = 0; i < 32; ++i)
        v[i] = tokenId[31 - i];
    return uint256(v);
}

// ── Signal hook ────────────────────────────────────────────────────

void CZSLPIndexer::ChainTip(const CBlockIndex* pindex, const CBlock* pblock,
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

void CZSLPIndexer::ConnectBlock(const CBlockIndex* pindex, const CBlock& block)
{
    CZSLPStore* s = store.get();
    if (s == NULL)
        return;

    const uint256 blockHash = pindex->GetBlockHash();

    // Idempotence guard: if we already advanced past this block, skip. (A
    // re-delivered connect for the current tip would otherwise double-count.)
    int64_t tipHeight = -1;
    uint256 tipHash;
    if (s->ReadTip(tipHeight, tipHash) && tipHash == blockHash)
        return;

    s->ConnectBlockBegin(blockHash);
    // R-PARSE-3: skip the coinbase (vtx[0]) for SLP parsing. A coinbase's only
    // input is the null prevout, which can never reference a token UTXO, so
    // skipping it consumes/burns nothing and creates nothing — the skip is a
    // no-op for conservation but is made explicit (and tested) so a coinbase
    // whose vout[0] happens to begin OP_RETURN is never mistaken for SLP.
    for (size_t i = 1; i < block.vtx.size(); ++i)
        IndexTransaction(block.vtx[i], pindex);
    s->ConnectBlockEnd(pindex->nHeight, blockHash);
}

// R-PARSE-1/2 (BLOCKER): parse the SLP message from tx.vout[0] ONLY. A tx is an
// SLP candidate IFF vout[0] is OP_RETURN and parses as a valid SLP message;
// OP_RETURNs at vout>=1 are irrelevant by construction (this defeats the
// message-position fork and the multi-OP_RETURN fork). If vout[0] is not a valid
// SLP message, the tx has NO SLP message (returns false) — its spent token
// inputs are still burned by the caller.
//
// NOTE: we deliberately do NOT gate on Solver()/TX_NULL_DATA here. The SLP push
// grammar (read_push, R-SCRIPT-1) is the canonical accept set; it is stricter
// and policy-independent (R-PARSE-4) — TX_NULL_DATA's -datacarriersize check is
// consensus-relay policy and must never enter the ledger function.
// ZSLPParseScript already requires the leading 0x6a and rejects non-SLP scripts.
//
// Static + pure (no store / chain state) so the R-VECTORS corpus pins the
// position rules against this exact code.
bool CZSLPIndexer::ParseTx(const CTransaction& tx, int64_t height,
                           CZSLPParsedMsg& parsed, CZSLPToken& genesisMeta,
                           bool& haveGenesisMeta)
{
    haveGenesisMeta = false;
    if (tx.vout.empty())
        return false;

    const uint256 txid = tx.GetHash();
    const CScript& spk = tx.vout[0].scriptPubKey;
    std::vector<unsigned char> raw(spk.begin(), spk.end());

    ZSLPMessage msg;
    if (raw.empty() || !ZSLPParseScript(raw.data(), raw.size(), msg))
        return false;

    switch (msg.type) {
    case ZSLPMSG_GENESIS: {
        parsed.type = ZSLP_MSG_GENESIS;
        parsed.tokenId = txid; // canonical SLP: token id == genesis txid
        parsed.initialQuantity = (int64_t)msg.initialQuantity;
        parsed.mintBatonVout = (int32_t)msg.mintBatonVout;

        genesisMeta.tokenId = txid;
        genesisMeta.ticker = msg.ticker;
        genesisMeta.name = msg.name;
        genesisMeta.documentUrl = msg.documentUrl;
        genesisMeta.hasDocumentHash = msg.hasDocumentHash;
        if (msg.hasDocumentHash) {
            // document_hash is an arbitrary 32-byte hash (not a txid).
            // uint256::GetHex() prints internal bytes reversed, so reverse here
            // to display the on-chain byte order.
            std::vector<unsigned char> dh(32);
            for (int b = 0; b < 32; ++b)
                dh[b] = msg.documentHash[31 - b];
            genesisMeta.documentHash = uint256(dh);
        }
        genesisMeta.decimals = msg.decimals;
        genesisMeta.mintBatonVout = msg.mintBatonVout; // store overwrites
        genesisMeta.genesisHeight = height;
        haveGenesisMeta = true;
        return true;
    }
    case ZSLPMSG_MINT: {
        parsed.type = ZSLP_MSG_MINT;
        parsed.tokenId = TokenIdToUint256(msg.tokenId);
        parsed.additionalQuantity = (int64_t)msg.additionalQuantity;
        parsed.mintBatonVout = (int32_t)msg.mintBatonVout;
        return true;
    }
    case ZSLPMSG_SEND: {
        parsed.type = ZSLP_MSG_SEND;
        parsed.tokenId = TokenIdToUint256(msg.tokenId);
        // The parser guarantees 1..ZSLP_SEND_MAX_OUTPUTS (R-SEND-1); a larger
        // list was already rejected as INVALID, so no clamp is needed — assert
        // the single shared cap holds across layers.
        static_assert(ZSLP_MAX_SEND_OUTPUTS == ZSLP_SEND_MAX_OUTPUTS_STORE,
                      "ZSLP SEND cap mismatch (bridge vs store)");
        int n = msg.numOutputs;
        if (n < 0) n = 0;
        if (n > ZSLP_SEND_MAX_OUTPUTS_STORE)
            n = ZSLP_SEND_MAX_OUTPUTS_STORE; // defensive; parser-bounded
        parsed.numOutputs = n;
        for (int j = 0; j < n; ++j)
            parsed.outputQuantities[j] = (int64_t)msg.outputQuantities[j];
        return true;
    }
    default:
        return false;
    }
}

void CZSLPIndexer::IndexTransaction(const CTransaction& tx,
                                    const CBlockIndex* pindex)
{
    CZSLPStore* s = store.get();
    const int64_t height = pindex->nHeight;
    const uint256 txid = tx.GetHash();

    // (1) Token inputs spent by this tx (prevouts). Even a non-SLP tx must burn
    //     any token UTXO it spends, so we gather these for EVERY tx.
    std::vector<COutPoint> vin;
    vin.reserve(tx.vin.size());
    for (size_t k = 0; k < tx.vin.size(); ++k)
        vin.push_back(tx.vin[k].prevout);

    // (2) Parse the SLP message from vout[0] only (R-PARSE-1/2). See ParseTx.
    CZSLPParsedMsg parsed;
    CZSLPToken genesisMeta;       // only filled for GENESIS
    bool haveGenesisMeta = false;
    bool msgPresent = ParseTx(tx, height, parsed, genesisMeta, haveGenesisMeta);

    // (3) Apply conservation. addrOfVout closes over this tx so the store needs
    //     no script knowledge of its own.
    std::function<std::string(int32_t)> addrOfVout =
        [&tx](int32_t n) -> std::string { return AddressOfVout(tx, n); };

    s->ApplyTransaction(vin, msgPresent ? &parsed : NULL, txid, height,
                        haveGenesisMeta ? &genesisMeta : NULL,
                        addrOfVout, (int32_t)tx.vout.size());
}

// ── Disconnect (reorg) ─────────────────────────────────────────────

void CZSLPIndexer::DisconnectBlock(const CBlockIndex* pindex,
                                   const CBlock& /*block*/)
{
    CZSLPStore* s = store.get();
    if (s == NULL)
        return;

    const uint256 blockHash = pindex->GetBlockHash();
    const CBlockIndex* pprev = pindex->pprev;
    int64_t prevHeight = pprev ? (int64_t)pprev->nHeight : -1;
    uint256 prevHash = pprev ? pprev->GetBlockHash() : uint256();

    // Replays the block's undo log in reverse and moves the tip back. If the
    // block left no undo log (it carried no ZSLP records) this is a no-op
    // except for the tip-marker rewind, which keeps crash-resume consistent.
    s->DisconnectBlock(blockHash, prevHeight, prevHash);
}
