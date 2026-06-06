// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP indexer implementation. See zslpindexer.h.
//
// NON-consensus observer: reads connected/disconnected blocks off the
// validation signal bus and projects ZSLP OP_RETURN messages into the store.

#include "zslp/zslpindexer.h"

#include "chain.h"
#include "key_io.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "util.h"
#include "zslp/zslpmsg.h"
#include "zslp/zslpstore.h"

CZSLPIndexer* g_zslpIndexer = NULL;

// LevelDB cache size for the ZSLP store (modest; this is auxiliary data).
static const size_t ZSLP_DB_CACHE = 8 << 20; // 8 MiB

void StartZSLPIndexer()
{
    if (g_zslpIndexer != NULL)
        return;
    g_zslpIndexer = new CZSLPIndexer();
    RegisterValidationInterface(g_zslpIndexer);
    LogPrintf("ZSLP: token indexer started (read-only OP_RETURN observation)\n");
}

void StopZSLPIndexer()
{
    if (g_zslpIndexer == NULL)
        return;
    UnregisterValidationInterface(g_zslpIndexer);
    delete g_zslpIndexer;
    g_zslpIndexer = NULL;
}

CZSLPIndexer::CZSLPIndexer()
{
    boost::filesystem::path path = GetDataDir() / "blocks" / "zslp";
    store.reset(new CZSLPStore(path, ZSLP_DB_CACHE));
}

CZSLPIndexer::~CZSLPIndexer() {}

// ── Address extraction ─────────────────────────────────────────────

// Decode the t-address paid by a given vout's scriptPubKey, or "" if it is
// not a standard pay-to-address output (e.g. the OP_RETURN itself).
static std::string AddressOfVout(const CTransaction& tx, uint32_t voutIdx)
{
    if (voutIdx >= tx.vout.size())
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
    for (size_t i = 0; i < block.vtx.size(); ++i)
        IndexTransaction(block.vtx[i], pindex);
    s->ConnectBlockEnd(pindex->nHeight, blockHash);
}

void CZSLPIndexer::IndexTransaction(const CTransaction& tx,
                                    const CBlockIndex* pindex)
{
    CZSLPStore* s = store.get();
    const int64_t height = pindex->nHeight;
    const uint256 txid = tx.GetHash();

    // Find the first OP_RETURN (TX_NULL_DATA) output and try to parse it.
    for (size_t vo = 0; vo < tx.vout.size(); ++vo) {
        const CScript& spk = tx.vout[vo].scriptPubKey;
        txnouttype whichType;
        std::vector<std::vector<unsigned char> > solutions;
        if (!Solver(spk, whichType, solutions) || whichType != TX_NULL_DATA)
            continue;

        // Raw script bytes for the SLP parser.
        std::vector<unsigned char> raw(spk.begin(), spk.end());
        if (raw.empty())
            continue;

        ZSLPMessage msg;
        if (!ZSLPParseScript(raw.data(), raw.size(), msg))
            continue; // not an SLP message; keep scanning other vouts

        switch (msg.type) {
        case ZSLPMSG_GENESIS: {
            // Token id == the genesis transaction id (canonical SLP rule).
            // Minted quantity is paid to vout[1]; baton (if any) to its vout.
            CZSLPToken token;
            token.tokenId = txid;
            token.ticker = msg.ticker;
            token.name = msg.name;
            token.documentUrl = msg.documentUrl;
            token.hasDocumentHash = msg.hasDocumentHash;
            if (msg.hasDocumentHash) {
                // document_hash is an arbitrary 32-byte hash (not a txid).
                // uint256::GetHex() prints internal bytes reversed, so reverse
                // here to make the RPC display the on-chain byte order.
                std::vector<unsigned char> dh(32);
                for (int b = 0; b < 32; ++b)
                    dh[b] = msg.documentHash[31 - b];
                token.documentHash = uint256(dh);
            }
            token.decimals = msg.decimals;
            token.mintBatonVout = msg.mintBatonVout;
            token.genesisHeight = height;

            std::string recipient = AddressOfVout(tx, 1);
            s->ApplyGenesis(token, recipient, txid, 1,
                            (int64_t)msg.initialQuantity);
            return; // one SLP message per tx
        }
        case ZSLPMSG_MINT: {
            uint256 tokenId = TokenIdToUint256(msg.tokenId);
            std::string recipient = AddressOfVout(tx, 1);
            bool batonMoved = (msg.mintBatonVout >= 2);
            s->ApplyMint(tokenId, recipient, txid, height, 1,
                         (int64_t)msg.additionalQuantity, batonMoved,
                         msg.mintBatonVout);
            return;
        }
        case ZSLPMSG_SEND: {
            uint256 tokenId = TokenIdToUint256(msg.tokenId);
            // outputQuantities[j] is paid to vout[1+j].
            for (int j = 0; j < msg.numOutputs; ++j) {
                uint64_t qty = msg.outputQuantities[j];
                if (qty == 0)
                    continue;
                uint32_t voutIdx = (uint32_t)(j + 1);
                std::string recipient = AddressOfVout(tx, voutIdx);
                s->ApplySend(tokenId, recipient, txid, height,
                             (int32_t)voutIdx, (int64_t)qty);
            }
            return;
        }
        default:
            return;
        }
    }
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
