// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP token store implementation — LevelDB (CDBWrapper) backing for the
// SLP token data model. See zslpstore.h for the schema and contract.
//
// NON-consensus: read-only observation. Never touches validation/PoW/wallet.

#include "zslp/zslpstore.h"

#include "util.h"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <boost/scoped_ptr.hpp>

// Record-type discriminators (first key byte).
static const char DB_TOKEN    = 't';
static const char DB_TRANSFER = 'x';
static const char DB_BALANCE  = 'b';
static const char DB_UNDO     = 'r';
static const char DB_TIP      = 'T';

namespace {

// Composite keys. std::tuple has no serializer in this tree, and nested
// std::pair keys are error-prone, so we use tiny explicit key structs.
// Field order defines the leveldb sort order (uint256 serializes its raw
// bytes, and std::string serializes a length prefix then the bytes — fine
// for grouping by token then address since the discriminator + tokenId
// prefix is identical for one token).

struct BalanceKey {
    char prefix;
    uint256 tokenId;
    std::string address;
    BalanceKey() : prefix(DB_BALANCE) {}
    BalanceKey(const uint256& t, const std::string& a)
        : prefix(DB_BALANCE), tokenId(t), address(a) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(tokenId);
        READWRITE(address);
    }
};

struct UndoKey {
    char prefix;
    uint256 blockHash;
    uint32_t seq;
    UndoKey() : prefix(DB_UNDO), seq(0) {}
    UndoKey(const uint256& h, uint32_t s) : prefix(DB_UNDO), blockHash(h), seq(s) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(blockHash);
        // Big-endian seq so the undo log iterates in append order.
        if (ser_action.ForRead()) {
            uint8_t b[4];
            for (int i = 0; i < 4; ++i) READWRITE(b[i]);
            seq = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
                  ((uint32_t)b[2] << 8) | (uint32_t)b[3];
        } else {
            uint8_t b[4] = {
                (uint8_t)((seq >> 24) & 0xff), (uint8_t)((seq >> 16) & 0xff),
                (uint8_t)((seq >> 8) & 0xff),  (uint8_t)(seq & 0xff) };
            for (int i = 0; i < 4; ++i) READWRITE(b[i]);
        }
    }
};

// Transfer key: 'x' + tokenId + BE(height) + txid + BE(vout). Big-endian
// height/vout make lexicographic leveldb order match numeric order, so all of
// one token's transfers are contiguous and height-ascending. We serialize
// fields directly (no length prefixes), so a Seek to a TransferPrefix is a
// true byte-prefix of the full keys (unlike a length-prefixed std::vector).
struct TransferKey {
    char prefix;
    uint256 tokenId;
    int64_t height;
    uint256 txid;
    int32_t vout;
    TransferKey() : prefix(DB_TRANSFER), height(0), vout(0) {}
    TransferKey(const uint256& t, int64_t h, const uint256& x, int32_t v)
        : prefix(DB_TRANSFER), tokenId(t), height(h), txid(x), vout(v) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(tokenId);
        if (ser_action.ForRead()) {
            uint8_t hb[8], vb[4];
            for (int i = 0; i < 8; ++i) READWRITE(hb[i]);
            READWRITE(txid);
            for (int i = 0; i < 4; ++i) READWRITE(vb[i]);
            uint64_t hu = 0; for (int i = 0; i < 8; ++i) hu = (hu << 8) | hb[i];
            uint32_t vu = 0; for (int i = 0; i < 4; ++i) vu = (vu << 8) | vb[i];
            height = (int64_t)hu;
            vout = (int32_t)vu;
        } else {
            uint64_t hu = (uint64_t)height;
            uint32_t vu = (uint32_t)vout;
            uint8_t hb[8], vb[4];
            for (int i = 7; i >= 0; --i) { hb[i] = (uint8_t)(hu & 0xff); hu >>= 8; }
            for (int i = 3; i >= 0; --i) { vb[i] = (uint8_t)(vu & 0xff); vu >>= 8; }
            for (int i = 0; i < 8; ++i) READWRITE(hb[i]);
            READWRITE(txid);
            for (int i = 0; i < 4; ++i) READWRITE(vb[i]);
        }
    }
};

// Prefix used only for Seek: 'x' + tokenId. Serializes the same leading bytes
// as TransferKey, so the iterator lands at this token's first transfer.
struct TransferPrefix {
    char prefix;
    uint256 tokenId;
    explicit TransferPrefix(const uint256& t) : prefix(DB_TRANSFER), tokenId(t) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(tokenId);
    }
};

} // namespace

CZSLPStore::CZSLPStore(const boost::filesystem::path& path, size_t nCacheSize,
                       bool fMemory, bool fWipe)
    : db(path, nCacheSize, fMemory, fWipe), nUndoSeq(0)
{
    hashConnecting.SetNull();
}

// ── Tip marker ─────────────────────────────────────────────────────

bool CZSLPStore::WriteTip(int64_t height, const uint256& blockHash)
{
    return db.Write(std::make_pair(DB_TIP, (char)0),
                    std::make_pair(height, blockHash));
}

bool CZSLPStore::ReadTip(int64_t& height, uint256& blockHash) const
{
    std::pair<int64_t, uint256> val;
    if (!db.Read(std::make_pair(DB_TIP, (char)0), val))
        return false;
    height = val.first;
    blockHash = val.second;
    return true;
}

// ── Token helpers ──────────────────────────────────────────────────

bool CZSLPStore::readToken(const uint256& tokenId, CZSLPToken& out) const
{
    return db.Read(std::make_pair(DB_TOKEN, tokenId), out);
}

bool CZSLPStore::GetToken(const uint256& tokenId, CZSLPToken& out) const
{
    return readToken(tokenId, out);
}

void CZSLPStore::writeTokenBatch(CDBBatch& batch, const CZSLPToken& token)
{
    batch.Write(std::make_pair(DB_TOKEN, token.tokenId), token);
}

int64_t CZSLPStore::readBalance(const uint256& tokenId,
                                const std::string& address) const
{
    int64_t bal = 0;
    db.Read(BalanceKey(tokenId, address), bal);
    return bal;
}

int64_t CZSLPStore::GetBalance(const uint256& tokenId,
                               const std::string& address) const
{
    return readBalance(tokenId, address);
}

int64_t CZSLPStore::TokenCount() const
{
    int64_t n = 0;
    boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
    for (it->Seek(std::make_pair(DB_TOKEN, uint256())); it->Valid(); it->Next()) {
        std::pair<char, uint256> key;
        if (!it->GetKey(key) || key.first != DB_TOKEN)
            break;
        ++n;
    }
    return n;
}

// ── Undo log ───────────────────────────────────────────────────────

void CZSLPStore::appendUndo(CDBBatch& batch, const CZSLPUndoOp& op)
{
    batch.Write(UndoKey(hashConnecting, nUndoSeq), op);
    nUndoSeq++;
}

// ── Connect path ───────────────────────────────────────────────────

void CZSLPStore::ConnectBlockBegin(const uint256& blockHash)
{
    hashConnecting = blockHash;
    nUndoSeq = 0;
}

bool CZSLPStore::ApplyGenesis(const CZSLPToken& tokenIn,
                              const std::string& recipient,
                              const uint256& txid, int32_t vout,
                              int64_t initialQty)
{
    // GENESIS for an already-known token is a no-op (first genesis wins),
    // mirroring the reference's INSERT OR IGNORE on the token row.
    CZSLPToken existing;
    if (readToken(tokenIn.tokenId, existing))
        return true;

    CDBBatch batch(db);

    CZSLPToken token = tokenIn;
    token.totalMinted = initialQty;
    writeTokenBatch(batch, token);

    CZSLPUndoOp tok;
    tok.kind = UNDO_TOKEN_PUT;
    tok.tokenId = token.tokenId;
    appendUndo(batch, tok);

    // Transfer record for the genesis mint output.
    CZSLPTransfer xfer;
    xfer.tokenId = token.tokenId;
    xfer.txid = txid;
    xfer.blockHash = hashConnecting;
    xfer.blockHeight = token.genesisHeight;
    xfer.txType = ZSLP_TX_GENESIS;
    xfer.amount = initialQty;
    xfer.vout = vout;
    xfer.address = recipient;

    batch.Write(TransferKey(token.tokenId, token.genesisHeight, txid, vout), xfer);
    CZSLPUndoOp xu;
    xu.kind = UNDO_TRANSFER_PUT;
    xu.tokenId = token.tokenId;
    xu.txid = txid;
    xu.blockHeight = token.genesisHeight;
    xu.vout = vout;
    appendUndo(batch, xu);

    // Credit the recipient balance (skip empty/undecodable addresses).
    if (!recipient.empty() && initialQty > 0) {
        int64_t bal = readBalance(token.tokenId, recipient);
        if (bal <= std::numeric_limits<int64_t>::max() - initialQty) {
            batch.Write(BalanceKey(token.tokenId, recipient), bal + initialQty);
            CZSLPUndoOp bu;
            bu.kind = UNDO_BALANCE_ADD;
            bu.tokenId = token.tokenId;
            bu.address = recipient;
            bu.amount = initialQty;
            appendUndo(batch, bu);
        }
    }

    return db.WriteBatch(batch);
}

bool CZSLPStore::ApplyMint(const uint256& tokenId, const std::string& recipient,
                           const uint256& txid, int64_t blockHeight,
                           int32_t vout, int64_t addQty, bool batonMoved,
                           uint8_t newBatonVout)
{
    CZSLPToken token;
    if (!readToken(tokenId, token))
        return false; // MINT of an unknown token: ignore (reference no-ops too)

    CDBBatch batch(db);

    // total_minted += addQty (overflow-guarded).
    if (addQty > 0 &&
        token.totalMinted <= std::numeric_limits<int64_t>::max() - addQty) {
        token.totalMinted += addQty;
        CZSLPUndoOp mu;
        mu.kind = UNDO_MINTED_ADD;
        mu.tokenId = tokenId;
        mu.amount = addQty;
        appendUndo(batch, mu);
    }

    if (batonMoved && token.mintBatonVout != newBatonVout) {
        CZSLPUndoOp bsu;
        bsu.kind = UNDO_BATON_SET;
        bsu.tokenId = tokenId;
        bsu.prevBaton = token.mintBatonVout;
        appendUndo(batch, bsu);
        token.mintBatonVout = newBatonVout;
    }

    writeTokenBatch(batch, token);

    CZSLPTransfer xfer;
    xfer.tokenId = tokenId;
    xfer.txid = txid;
    xfer.blockHash = hashConnecting;
    xfer.blockHeight = blockHeight;
    xfer.txType = ZSLP_TX_MINT;
    xfer.amount = addQty;
    xfer.vout = vout;
    xfer.address = recipient;
    batch.Write(TransferKey(tokenId, blockHeight, txid, vout), xfer);
    CZSLPUndoOp xu;
    xu.kind = UNDO_TRANSFER_PUT;
    xu.tokenId = tokenId;
    xu.txid = txid;
    xu.blockHeight = blockHeight;
    xu.vout = vout;
    appendUndo(batch, xu);

    if (!recipient.empty() && addQty > 0) {
        int64_t bal = readBalance(tokenId, recipient);
        if (bal <= std::numeric_limits<int64_t>::max() - addQty) {
            batch.Write(BalanceKey(tokenId, recipient), bal + addQty);
            CZSLPUndoOp bu;
            bu.kind = UNDO_BALANCE_ADD;
            bu.tokenId = tokenId;
            bu.address = recipient;
            bu.amount = addQty;
            appendUndo(batch, bu);
        }
    }

    return db.WriteBatch(batch);
}

bool CZSLPStore::ApplySend(const uint256& tokenId, const std::string& recipient,
                           const uint256& txid, int64_t blockHeight,
                           int32_t vout, int64_t amount)
{
    // Only record SENDs of a known token (genesis must have been seen).
    if (!db.Exists(std::make_pair(DB_TOKEN, tokenId)))
        return false;

    CDBBatch batch(db);

    CZSLPTransfer xfer;
    xfer.tokenId = tokenId;
    xfer.txid = txid;
    xfer.blockHash = hashConnecting;
    xfer.blockHeight = blockHeight;
    xfer.txType = ZSLP_TX_SEND;
    xfer.amount = amount;
    xfer.vout = vout;
    xfer.address = recipient;
    batch.Write(TransferKey(tokenId, blockHeight, txid, vout), xfer);
    CZSLPUndoOp xu;
    xu.kind = UNDO_TRANSFER_PUT;
    xu.tokenId = tokenId;
    xu.txid = txid;
    xu.blockHeight = blockHeight;
    xu.vout = vout;
    appendUndo(batch, xu);

    if (!recipient.empty() && amount > 0) {
        int64_t bal = readBalance(tokenId, recipient);
        if (bal <= std::numeric_limits<int64_t>::max() - amount) {
            batch.Write(BalanceKey(tokenId, recipient), bal + amount);
            CZSLPUndoOp bu;
            bu.kind = UNDO_BALANCE_ADD;
            bu.tokenId = tokenId;
            bu.address = recipient;
            bu.amount = amount;
            appendUndo(batch, bu);
        }
    }

    return db.WriteBatch(batch);
}

bool CZSLPStore::ConnectBlockEnd(int64_t height, const uint256& blockHash)
{
    hashConnecting.SetNull();
    nUndoSeq = 0;
    return WriteTip(height, blockHash);
}

// ── Disconnect path (reorg) ────────────────────────────────────────

bool CZSLPStore::DisconnectBlock(const uint256& blockHash, int64_t prevHeight,
                                 const uint256& prevHash)
{
    // Gather the block's undo ops (ascending seq), then replay in reverse.
    std::vector<CZSLPUndoOp> ops;
    std::vector<uint32_t> seqs;
    {
        boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
        for (it->Seek(UndoKey(blockHash, 0)); it->Valid(); it->Next()) {
            UndoKey key;
            if (!it->GetKey(key))
                break;
            if (key.prefix != DB_UNDO || key.blockHash != blockHash)
                break;
            CZSLPUndoOp op;
            if (!it->GetValue(op))
                return false;
            ops.push_back(op);
            seqs.push_back(key.seq);
        }
    }

    CDBBatch batch(db);

    // Accumulate per-token and per-balance changes in memory and write each
    // record exactly ONCE. A single block can log multiple undo ops against the
    // same record (a MINT logs both UNDO_MINTED_ADD and UNDO_BATON_SET; several
    // mints can credit one address). readToken/readBalance see only the committed
    // DB — not this pending batch — so a per-op read-modify-write would clobber
    // a sibling op's change (e.g. the baton revert lost behind the minted revert).
    std::map<uint256, CZSLPToken> tokenMods;
    std::set<uint256> tokenErased;
    std::map<std::pair<uint256, std::string>, int64_t> balMods;

    for (int i = (int)ops.size() - 1; i >= 0; --i) {
        const CZSLPUndoOp& op = ops[i];
        switch (op.kind) {
        case UNDO_TOKEN_PUT:
            batch.Erase(std::make_pair(DB_TOKEN, op.tokenId));
            tokenMods.erase(op.tokenId);
            tokenErased.insert(op.tokenId);
            break;
        case UNDO_TRANSFER_PUT:
            batch.Erase(TransferKey(op.tokenId, op.blockHeight, op.txid, op.vout));
            break;
        case UNDO_BALANCE_ADD: {
            std::pair<uint256, std::string> bk(op.tokenId, op.address);
            std::map<std::pair<uint256, std::string>, int64_t>::iterator bit = balMods.find(bk);
            if (bit == balMods.end())
                bit = balMods.insert(std::make_pair(bk, readBalance(op.tokenId, op.address))).first;
            bit->second -= op.amount;
            break;
        }
        case UNDO_MINTED_ADD: {
            if (tokenErased.count(op.tokenId))
                break;
            std::map<uint256, CZSLPToken>::iterator mit = tokenMods.find(op.tokenId);
            if (mit == tokenMods.end()) {
                CZSLPToken t;
                if (!readToken(op.tokenId, t))
                    break;
                mit = tokenMods.insert(std::make_pair(op.tokenId, t)).first;
            }
            mit->second.totalMinted -= op.amount;
            if (mit->second.totalMinted < 0)
                mit->second.totalMinted = 0;
            break;
        }
        case UNDO_BATON_SET: {
            if (tokenErased.count(op.tokenId))
                break;
            std::map<uint256, CZSLPToken>::iterator mit = tokenMods.find(op.tokenId);
            if (mit == tokenMods.end()) {
                CZSLPToken t;
                if (!readToken(op.tokenId, t))
                    break;
                mit = tokenMods.insert(std::make_pair(op.tokenId, t)).first;
            }
            mit->second.mintBatonVout = op.prevBaton;
            break;
        }
        default:
            break;
        }
    }

    // Write each accumulated token modification once (siblings already merged).
    for (std::map<uint256, CZSLPToken>::const_iterator it2 = tokenMods.begin();
         it2 != tokenMods.end(); ++it2)
        writeTokenBatch(batch, it2->second);

    // Write each accumulated balance once (erase if depleted to <= 0).
    for (std::map<std::pair<uint256, std::string>, int64_t>::const_iterator it3 = balMods.begin();
         it3 != balMods.end(); ++it3) {
        if (it3->second <= 0)
            batch.Erase(BalanceKey(it3->first.first, it3->first.second));
        else
            batch.Write(BalanceKey(it3->first.first, it3->first.second), it3->second);
    }

    // Drop the undo log for this block.
    for (size_t i = 0; i < seqs.size(); ++i)
        batch.Erase(UndoKey(blockHash, seqs[i]));

    // Move the tip marker back.
    batch.Write(std::make_pair(DB_TIP, (char)0),
                std::make_pair(prevHeight, prevHash));

    return db.WriteBatch(batch);
}

// ── Read / list API ────────────────────────────────────────────────

int CZSLPStore::ListTokens(int from, int count,
                           std::vector<CZSLPToken>& out) const
{
    out.clear();
    if (count <= 0)
        return 0;
    if (count > ZSLP_LIST_MAX)
        count = ZSLP_LIST_MAX;
    if (from < 0)
        from = 0;

    int skipped = 0;
    boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
    for (it->Seek(std::make_pair(DB_TOKEN, uint256()));
         it->Valid() && (int)out.size() < count; it->Next()) {
        std::pair<char, uint256> key;
        if (!it->GetKey(key) || key.first != DB_TOKEN)
            break;
        if (skipped < from) {
            ++skipped;
            continue;
        }
        CZSLPToken token;
        if (it->GetValue(token))
            out.push_back(token);
    }
    return (int)out.size();
}

int CZSLPStore::ListTransfers(const uint256& tokenId, int from, int count,
                              std::vector<CZSLPTransfer>& out) const
{
    out.clear();
    if (count <= 0)
        return 0;
    if (count > ZSLP_LIST_MAX)
        count = ZSLP_LIST_MAX;
    if (from < 0)
        from = 0;

    // Keys are 'x'+tokenId+BE(height)+txid+BE(vout): ascending height. We want
    // newest-first, so gather all for this token then reverse and window.
    std::vector<CZSLPTransfer> all;
    {
        boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
        for (it->Seek(TransferPrefix(tokenId)); it->Valid(); it->Next()) {
            // The key deserializes as a TransferKey; stop when we leave this
            // token's contiguous keyspace (or hit a non-transfer record).
            TransferKey key;
            if (!it->GetKey(key) || key.prefix != DB_TRANSFER)
                break;
            if (key.tokenId != tokenId)
                break;
            CZSLPTransfer xfer;
            if (!it->GetValue(xfer))
                break;
            all.push_back(xfer);
        }
    }

    // Newest-first.
    std::reverse(all.begin(), all.end());
    for (size_t i = (size_t)from; i < all.size() && (int)out.size() < count; ++i)
        out.push_back(all[i]);
    return (int)out.size();
}

void CZSLPStore::GetTokensForAddress(
    const std::string& address,
    std::vector<std::pair<uint256, int64_t> >& out) const
{
    out.clear();
    if (address.empty())
        return;

    boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
    for (it->Seek(BalanceKey(uint256(), std::string()));
         it->Valid(); it->Next()) {
        BalanceKey key;
        if (!it->GetKey(key) || key.prefix != DB_BALANCE)
            break;
        if (key.address != address)
            continue;
        int64_t bal = 0;
        if (it->GetValue(bal) && bal > 0)
            out.push_back(std::make_pair(key.tokenId, bal));
    }
}
