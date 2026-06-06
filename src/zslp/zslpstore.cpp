// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP token store implementation — LevelDB (CDBWrapper) backing for the
// SLP token data model. See zslpstore.h for the schema and contract.
//
// NON-consensus: read-only observation. Never touches validation/PoW/wallet.
//
// The model is real SLP Token-Type-1, UTXO-bound: a (txid,vout)->UTXO map is
// the source of truth, the per-address balance is a derived view kept in sync
// by signed deltas, and conservation is enforced per transaction — a SEND can
// only move tokens carried by spent inputs, a MINT needs the baton on a spent
// input. Forgery (crediting yourself, duplicating an NFT) is impossible.

#include "zslp/zslpstore.h"

#include "util.h"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <boost/optional.hpp>
#include <boost/scoped_ptr.hpp>

// Record-type discriminators (first key byte).
static const char DB_TOKEN    = 't';
static const char DB_TRANSFER = 'x';
static const char DB_BALANCE  = 'b';
static const char DB_UNDO     = 'r';
static const char DB_TIP      = 'T';
static const char DB_UTXO     = 'u';
static const char DB_META     = 'M';

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

// Token-UTXO key: 'u' + txid + BE(vout). Direct-serialized like TransferKey so
// db.Read(UtxoKey(prevout.hash, prevout.n)) is an O(1) point read and a Seek to
// 'u'+txid is a true byte-prefix of all that tx's outputs.
struct UtxoKey {
    char prefix;
    uint256 txid;
    int32_t vout;
    UtxoKey() : prefix(DB_UTXO), vout(0) {}
    UtxoKey(const uint256& t, int32_t v) : prefix(DB_UTXO), txid(t), vout(v) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(txid);
        if (ser_action.ForRead()) {
            uint8_t vb[4];
            for (int i = 0; i < 4; ++i) READWRITE(vb[i]);
            uint32_t vu = 0; for (int i = 0; i < 4; ++i) vu = (vu << 8) | vb[i];
            vout = (int32_t)vu;
        } else {
            uint32_t vu = (uint32_t)vout;
            uint8_t vb[4];
            for (int i = 3; i >= 0; --i) { vb[i] = (uint8_t)(vu & 0xff); vu >>= 8; }
            for (int i = 0; i < 4; ++i) READWRITE(vb[i]);
        }
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

// ── Format version stamp ────────────────────────────────────────────

bool CZSLPStore::ReadIndexVersion(uint32_t& out) const
{
    return db.Read(std::make_pair(DB_META, (char)0), out);
}

bool CZSLPStore::WriteIndexVersion(uint32_t version)
{
    return db.Write(std::make_pair(DB_META, (char)0), version);
}

// ── Token / UTXO / balance helpers ──────────────────────────────────

bool CZSLPStore::readToken(const uint256& tokenId, CZSLPToken& out) const
{
    return db.Read(std::make_pair(DB_TOKEN, tokenId), out);
}

bool CZSLPStore::GetToken(const uint256& tokenId, CZSLPToken& out) const
{
    return readToken(tokenId, out);
}

bool CZSLPStore::readUtxo(const uint256& txid, int32_t vout,
                          CZSLPTokenUtxo& out) const
{
    return db.Read(UtxoKey(txid, vout), out);
}

bool CZSLPStore::GetUtxo(const uint256& txid, int32_t vout,
                         CZSLPTokenUtxo& out) const
{
    return readUtxo(txid, vout, out);
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

int64_t CZSLPStore::UtxoCount() const
{
    int64_t n = 0;
    boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
    for (it->Seek(UtxoKey(uint256(), 0)); it->Valid(); it->Next()) {
        UtxoKey key;
        if (!it->GetKey(key) || key.prefix != DB_UTXO)
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

// ── DRY mutation helpers — the ONLY places that touch 'u', 'b', 'x' ──

// Create a token UTXO, credit its derived balance (if it carries quantity at a
// decodable address), and append the matching transfer row + undo ops. The
// transfer row is written ONLY for valid (created) outputs, so listtransfers
// never shows a forged/failed transfer.
void CZSLPStore::createUtxo(CDBBatch& batch, BalDeltaMap& bal,
                            const uint256& txid, int32_t vout,
                            const uint256& tokenId, int64_t amount,
                            bool isMintBaton, const std::string& address,
                            int64_t height, uint8_t txType)
{
    CZSLPTokenUtxo rec;
    rec.tokenId = tokenId;
    rec.amount = isMintBaton ? 0 : amount; // baton bears no quantity
    rec.isMintBaton = isMintBaton;
    rec.address = address;
    rec.height = height;
    batch.Write(UtxoKey(txid, vout), rec);

    CZSLPUndoOp cu;
    cu.kind = UNDO_UTXO_CREATE;
    cu.txid = txid;
    cu.utxoVout = vout;
    appendUndo(batch, cu);

    if (!isMintBaton && amount > 0)
        recordBalanceDelta(batch, bal, tokenId, address, amount);

    // Audit-log row for the valid output (batons too — amount 0, type MINT/GENESIS).
    CZSLPTransfer xfer;
    xfer.tokenId = tokenId;
    xfer.txid = txid;
    xfer.blockHash = hashConnecting;
    xfer.blockHeight = height;
    xfer.txType = txType;
    xfer.amount = rec.amount;
    xfer.vout = vout;
    xfer.address = address;
    batch.Write(TransferKey(tokenId, height, txid, vout), xfer);

    CZSLPUndoOp xu;
    xu.kind = UNDO_TRANSFER_PUT;
    xu.tokenId = tokenId;
    xu.txid = txid;
    xu.blockHeight = height;
    xu.vout = vout;
    appendUndo(batch, xu);
}

// Consume (erase) a token UTXO: remove the 'u' record, reverse its derived
// balance credit, and log a CONSUME undo that carries the FULL record so a
// disconnect can reconstruct it.
void CZSLPStore::consumeUtxo(CDBBatch& batch, BalDeltaMap& bal,
                             const uint256& txid, int32_t vout,
                             const CZSLPTokenUtxo& rec)
{
    batch.Erase(UtxoKey(txid, vout));

    CZSLPUndoOp op;
    op.kind = UNDO_UTXO_CONSUME;
    op.txid = txid;
    op.utxoVout = vout;
    op.tokenId = rec.tokenId;
    op.amount = rec.amount;
    op.isMintBaton = rec.isMintBaton;
    op.address = rec.address;
    op.blockHeight = rec.height;
    appendUndo(batch, op);

    if (!rec.isMintBaton && rec.amount > 0)
        recordBalanceDelta(batch, bal, rec.tokenId, rec.address, -rec.amount);
}

// Accumulate a SIGNED derived-balance delta in memory and append the matching
// signed UNDO_BALANCE_ADD undo op immediately. The undo op is per-delta (the
// disconnect path nets them); the committed 'b' write is deferred to
// flushBalances() so several deltas to one address in a single tx net first.
void CZSLPStore::recordBalanceDelta(CDBBatch& batch, BalDeltaMap& bal,
                                    const uint256& tokenId,
                                    const std::string& address, int64_t delta)
{
    if (address.empty() || delta == 0)
        return;
    bal[std::make_pair(tokenId, address)] += delta;

    CZSLPUndoOp bu;
    bu.kind = UNDO_BALANCE_ADD;
    bu.tokenId = tokenId;
    bu.address = address;
    bu.amount = delta; // SIGNED
    appendUndo(batch, bu);
}

// Commit the netted per-address balance deltas: read each committed balance
// ONCE, apply the net delta, and write (or erase at <= 0). The single place
// that mutates the committed 'b' record on the connect path.
void CZSLPStore::flushBalances(CDBBatch& batch, const BalDeltaMap& bal)
{
    for (BalDeltaMap::const_iterator it = bal.begin(); it != bal.end(); ++it) {
        int64_t delta = it->second;
        if (delta == 0)
            continue;
        int64_t cur = readBalance(it->first.first, it->first.second);
        // Overflow guard on the positive direction; negatives only subtract a
        // value previously added, so they cannot underflow below 0 in practice.
        if (delta > 0 && cur > std::numeric_limits<int64_t>::max() - delta)
            continue;
        int64_t newBal = cur + delta;
        if (newBal > 0)
            batch.Write(BalanceKey(it->first.first, it->first.second), newBal);
        else
            batch.Erase(BalanceKey(it->first.first, it->first.second));
    }
}

// ── Connect path ───────────────────────────────────────────────────

void CZSLPStore::ConnectBlockBegin(const uint256& blockHash)
{
    hashConnecting = blockHash;
    nUndoSeq = 0;
}

bool CZSLPStore::ApplyTransaction(
    const std::vector<COutPoint>& vin,
    const CZSLPParsedMsg* msg,
    const uint256& txid, int64_t height,
    const CZSLPToken* genesisMeta,
    const std::function<std::string(int32_t)>& addrOfVout,
    int32_t voutCount)
{
    // One batch per tx, committed before the indexer's next tx, so a later tx
    // in the SAME block sees the 'u'/'b' rows an earlier tx wrote (CDBBatch is
    // write-only; db.Read sees only committed data — dbwrapper.h).
    CDBBatch batch(db);

    // Net the derived-balance changes of THIS tx in memory; flush once at the
    // end. Required because readBalance() sees only committed data, so a consume
    // (-amount) followed by a same-address change credit (+amount) within one tx
    // would otherwise read the same committed value twice and lose one delta.
    BalDeltaMap balDeltas;

    // (a) GATHER + CONSUME the token UTXOs spent by this tx (every tx, SLP or
    //     not). Any consumed input not re-assigned by a valid SLP message of
    //     its tokenId is thereby BURNED.
    std::map<uint256, int64_t> availByToken;       // summed input quantity per token
    std::map<uint256, bool> batonInputPresent;     // a baton input for this token?
    for (size_t k = 0; k < vin.size(); ++k) {
        CZSLPTokenUtxo rec;
        if (!readUtxo(vin[k].hash, (int32_t)vin[k].n, rec))
            continue; // not a token-carrying input
        if (rec.isMintBaton)
            batonInputPresent[rec.tokenId] = true;
        else
            availByToken[rec.tokenId] += rec.amount;
        consumeUtxo(batch, balDeltas, vin[k].hash, (int32_t)vin[k].n, rec);
    }

    // (b) DISPATCH on the parsed message (NULL => non-SLP tx; inputs already
    //     burned, nothing created).
    if (msg != NULL) {
        switch (msg->type) {
        case ZSLP_MSG_GENESIS: {
            const uint256 tokenId = txid; // canonical SLP: token id == genesis txid
            // First-genesis-wins: only INSERT the token row if absent. The
            // input-consume in (a) already happened regardless.
            CZSLPToken existing;
            if (genesisMeta != NULL && !readToken(tokenId, existing)) {
                CZSLPToken token = *genesisMeta;
                token.tokenId = tokenId;
                // R-GEN-3 (FIX): totalMinted counts ONLY quantity ACTUALLY
                // created as a UTXO, not declared-but-uncreated. The initial
                // quantity is created at vout[1] iff vout[1] exists; a GENESIS
                // with no vout[1] creates nothing and reports supply 0. (The
                // high-bit / >=2^63 case is already rejected at parse, so
                // initialQuantity here is a non-negative int64.)
                bool createInitial = (msg->initialQuantity > 0 && voutCount > 1);
                token.totalMinted = createInitial ? msg->initialQuantity : 0;
                // Baton display-mirror reflects the live baton UTXO below.
                token.mintBatonVout = 0;
                bool batonIssued = (msg->mintBatonVout >= 2 &&
                                    msg->mintBatonVout < voutCount);
                if (batonIssued)
                    token.mintBatonVout = (uint8_t)msg->mintBatonVout;
                writeTokenBatch(batch, token);
                CZSLPUndoOp tok;
                tok.kind = UNDO_TOKEN_PUT;
                tok.tokenId = tokenId;
                appendUndo(batch, tok);

                // Mint output at vout[1] (only when it exists — R-GEN-3).
                if (createInitial) {
                    createUtxo(batch, balDeltas, txid, 1, tokenId, msg->initialQuantity,
                               false, addrOfVout(1), height, ZSLP_TX_GENESIS);
                }
                // Baton output at its declared vout.
                if (batonIssued) {
                    createUtxo(batch, balDeltas, txid, msg->mintBatonVout, tokenId, 0, true,
                               addrOfVout(msg->mintBatonVout), height,
                               ZSLP_TX_GENESIS);
                }
            }
            break;
        }
        case ZSLP_MSG_MINT: {
            const uint256 tokenId = msg->tokenId;
            CZSLPToken token;
            if (!readToken(tokenId, token))
                break; // MINT of an unknown token: invalid, no outputs.
            // VALID iff a mint baton for this token was on a spent input.
            if (!batonInputPresent.count(tokenId))
                break; // no baton => create nothing; consumed inputs stay burned.

            // R-MINT-3 (FIX): total_minted += additionalQuantity ONLY for
            // quantity ACTUALLY created as a UTXO (i.e. vout[1] exists), to
            // match R-GEN-3 — a MINT with no vout[1] creates nothing and must
            // not bump supply. Overflow-guarded; the high-bit / >=2^63 case is
            // already rejected at parse. The undo op is appended IFF the bump
            // happens, so DisconnectBlock reverses exactly what was applied.
            bool createAdditional =
                (msg->additionalQuantity > 0 && voutCount > 1);
            if (createAdditional &&
                token.totalMinted <=
                    std::numeric_limits<int64_t>::max() - msg->additionalQuantity) {
                token.totalMinted += msg->additionalQuantity;
                CZSLPUndoOp mu;
                mu.kind = UNDO_MINTED_ADD;
                mu.tokenId = tokenId;
                mu.amount = msg->additionalQuantity;
                appendUndo(batch, mu);
            } else {
                // Overflow (or nothing to create): supply unchanged, no UTXO.
                createAdditional = false;
            }

            bool batonContinues = (msg->mintBatonVout >= 2 &&
                                   msg->mintBatonVout < voutCount);
            uint8_t newBaton = batonContinues ? (uint8_t)msg->mintBatonVout : 0;
            if (token.mintBatonVout != newBaton) {
                CZSLPUndoOp bsu;
                bsu.kind = UNDO_BATON_SET;
                bsu.tokenId = tokenId;
                bsu.prevBaton = token.mintBatonVout;
                appendUndo(batch, bsu);
                token.mintBatonVout = newBaton;
            }
            writeTokenBatch(batch, token);

            if (createAdditional) {
                createUtxo(batch, balDeltas, txid, 1, tokenId, msg->additionalQuantity,
                           false, addrOfVout(1), height, ZSLP_TX_MINT);
            }
            if (batonContinues) {
                createUtxo(batch, balDeltas, txid, msg->mintBatonVout, tokenId, 0, true,
                           addrOfVout(msg->mintBatonVout), height, ZSLP_TX_MINT);
            }
            break;
        }
        case ZSLP_MSG_SEND: {
            const uint256 tokenId = msg->tokenId;
            std::map<uint256, int64_t>::const_iterator ait =
                availByToken.find(tokenId);
            int64_t availIn = (ait == availByToken.end()) ? 0 : ait->second;

            // requiredOut = Σ outputQuantities (overflow-guarded => INVALID).
            // The parser already enforced 1..ZSLP_SEND_MAX_OUTPUTS_STORE
            // (R-SEND-1 / R-12); clamp defensively to the SAME single cap (was
            // 20, a fork bug vs the parser's 19) so the loop never reads past
            // the array bound even if a future caller supplies a stray count.
            int64_t requiredOut = 0;
            bool overflow = false;
            int n = msg->numOutputs;
            if (n < 0) n = 0;
            if (n > ZSLP_SEND_MAX_OUTPUTS_STORE)
                n = ZSLP_SEND_MAX_OUTPUTS_STORE;
            for (int j = 0; j < n; ++j) {
                int64_t q = msg->outputQuantities[j];
                if (q < 0) { overflow = true; break; }
                if (requiredOut > std::numeric_limits<int64_t>::max() - q) {
                    overflow = true; break;
                }
                requiredOut += q;
            }

            if (!overflow && availIn >= requiredOut) {
                // Positional mapping j -> vout[1+j] preserved across zero-qty
                // outputs (a zero-qty output consumes a slot, creates nothing).
                for (int j = 0; j < n; ++j) {
                    int64_t qty = msg->outputQuantities[j];
                    if (qty <= 0)
                        continue;
                    int32_t voutIdx = 1 + j;
                    if (voutIdx >= voutCount)
                        continue; // output vout doesn't exist => that qty burned
                    createUtxo(batch, balDeltas, txid, voutIdx, tokenId, qty, false,
                               addrOfVout(voutIdx), height, ZSLP_TX_SEND);
                }
                // (availIn - requiredOut) is burned implicitly (never created).
            }
            // availIn < requiredOut (or overflow) => INVALID: create nothing;
            // all that-token inputs already burned in (a).
            break;
        }
        default:
            break;
        }
    }

    // Commit the netted derived-balance deltas once each.
    flushBalances(batch, balDeltas);

    return db.WriteBatch(batch);
}

bool CZSLPStore::ConnectBlockEnd(int64_t height, const uint256& blockHash)
{
    hashConnecting.SetNull();
    nUndoSeq = 0;
    return WriteTip(height, blockHash);
}

// READ-ONLY mirror of ApplyTransaction's accept/conservation logic. Every check
// and overflow guard below is intentionally identical to the corresponding line
// in ApplyTransaction (a divergence here would let the wallet broadcast a tx the
// live indexer rejects). It only ever calls readUtxo()/readToken() (point reads)
// and NEVER stages a batch write.
bool CZSLPStore::WouldBeValid(
    const std::vector<COutPoint>& vin,
    const CZSLPParsedMsg* msg,
    const uint256& txid,
    const CZSLPToken* genesisMeta,
    int32_t voutCount,
    std::string& reason) const
{
    if (msg == NULL) {
        reason = "no SLP message at vout[0]";
        return false;
    }

    // (a) Recompute availIn / baton presence from spent inputs (mirror
    //     ApplyTransaction step (a); batons contribute 0, non-token inputs are
    //     skipped). Read-only: readUtxo() instead of consumeUtxo().
    std::map<uint256, int64_t> availByToken;
    std::map<uint256, bool> batonInputPresent;
    for (size_t k = 0; k < vin.size(); ++k) {
        CZSLPTokenUtxo rec;
        if (!readUtxo(vin[k].hash, (int32_t)vin[k].n, rec))
            continue; // not a token-carrying input
        if (rec.isMintBaton)
            batonInputPresent[rec.tokenId] = true;
        else
            availByToken[rec.tokenId] += rec.amount;
    }

    switch (msg->type) {
    case ZSLP_MSG_GENESIS: {
        const uint256 tokenId = txid; // canonical SLP: token id == genesis txid
        if (genesisMeta == NULL) {
            reason = "GENESIS without metadata";
            return false;
        }
        // First-genesis-wins: a GENESIS whose txid already names a token would
        // create NOTHING (the indexer only inserts when absent) — that is a
        // builder bug (it cannot happen for a freshly-built tx, txid is the
        // genesis hash), so treat a collision as invalid.
        CZSLPToken existing;
        if (readToken(tokenId, existing)) {
            reason = "GENESIS token id already exists";
            return false;
        }
        // The mint output is created at vout[1] IFF vout[1] exists (R-GEN-3);
        // an NFT/fungible mint that declares a quantity but provides no vout[1]
        // silently creates supply 0 — never what a builder intends.
        if (msg->initialQuantity < 0) { reason = "GENESIS quantity negative/overflow"; return false; }
        if (msg->initialQuantity > 0 && voutCount <= 1) {
            reason = "GENESIS declares quantity but has no vout[1] to carry it";
            return false;
        }
        // A declared baton (mintBatonVout>=2) must reference an existing output.
        if (msg->mintBatonVout >= 2 && msg->mintBatonVout >= voutCount) {
            reason = "GENESIS baton vout out of range";
            return false;
        }
        return true;
    }
    case ZSLP_MSG_MINT: {
        const uint256 tokenId = msg->tokenId;
        CZSLPToken token;
        if (!readToken(tokenId, token)) {
            reason = "MINT of unknown token";
            return false;
        }
        if (!batonInputPresent.count(tokenId)) {
            reason = "MINT requires the live mint baton as an input";
            return false;
        }
        if (msg->additionalQuantity < 0) { reason = "MINT quantity negative/overflow"; return false; }
        if (msg->additionalQuantity > 0 && voutCount <= 1) {
            reason = "MINT declares quantity but has no vout[1] to carry it";
            return false;
        }
        // Overflow of the issued-supply counter (mirror ApplyTransaction's guard)
        if (msg->additionalQuantity > 0 &&
            token.totalMinted > std::numeric_limits<int64_t>::max() - msg->additionalQuantity) {
            reason = "MINT would overflow total minted supply";
            return false;
        }
        if (msg->mintBatonVout >= 2 && msg->mintBatonVout >= voutCount) {
            reason = "MINT baton vout out of range";
            return false;
        }
        return true;
    }
    case ZSLP_MSG_SEND: {
        const uint256 tokenId = msg->tokenId;
        std::map<uint256, int64_t>::const_iterator ait = availByToken.find(tokenId);
        int64_t availIn = (ait == availByToken.end()) ? 0 : ait->second;

        // requiredOut = Σ outputQuantities with the SAME overflow guard as
        // ApplyTransaction. Also assert every nonzero quantity lands on an
        // existing output (so the builder never burns a declared quantity by
        // omitting its recipient vout — that is the silent-burn class R-WALLET-9
        // must catch).
        int64_t requiredOut = 0;
        int n = msg->numOutputs;
        if (n < 1) { reason = "SEND has no output quantities"; return false; }
        if (n > ZSLP_SEND_MAX_OUTPUTS_STORE) {
            reason = "SEND exceeds the maximum output count";
            return false;
        }
        for (int j = 0; j < n; ++j) {
            int64_t q = msg->outputQuantities[j];
            if (q < 0) { reason = "SEND quantity negative/overflow"; return false; }
            if (requiredOut > std::numeric_limits<int64_t>::max() - q) {
                reason = "SEND output total overflows";
                return false;
            }
            requiredOut += q;
            // A nonzero quantity whose target vout doesn't exist is an
            // unintended burn of that quantity.
            if (q > 0 && (int32_t)(1 + j) >= voutCount) {
                reason = "SEND quantity maps to a nonexistent output (would burn)";
                return false;
            }
        }
        if (availIn < requiredOut) {
            reason = "SEND inputs do not cover outputs (would burn the token)";
            return false;
        }
        // availIn > requiredOut is allowed by the ledger (surplus burned), but
        // the BUILDER must add a token-change output so nothing is silently
        // burned; we therefore require exact conservation here. A surplus means
        // the builder forgot the change output.
        if (availIn != requiredOut) {
            reason = "SEND would burn token surplus (missing token-change output)";
            return false;
        }
        return true;
    }
    default:
        reason = "unknown SLP message type";
        return false;
    }
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

    // Accumulate per-token / per-balance / per-utxo changes in memory and write
    // each record exactly ONCE. A single block can log multiple undo ops against
    // the same record (a MINT logs UNDO_MINTED_ADD + UNDO_BATON_SET; many deltas
    // can hit one address balance; a UTXO can be created then consumed in the
    // same block). readToken/readBalance/readUtxo see only the committed DB —
    // not this pending batch — so a per-op read-modify-write would clobber a
    // sibling op's change.
    std::map<uint256, CZSLPToken> tokenMods;
    std::set<uint256> tokenErased;
    std::map<std::pair<uint256, std::string>, int64_t> balMods;
    // boost::none => erase the 'u' record; a value => write that full record.
    std::map<std::pair<uint256, int32_t>, boost::optional<CZSLPTokenUtxo> > utxoMods;

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
            bit->second -= op.amount; // op.amount is a SIGNED delta; reversal is sign-agnostic
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
        case UNDO_UTXO_CREATE: {
            // Reverse of create: erase the 'u' record. (Reverse-order replay
            // means a same-block create+consume nets to erase: CONSUME is seen
            // first and stages a write, then CREATE stages an erase — last
            // writer per key in this loop wins, and CREATE has the lower seq so
            // it is processed later here, leaving the erase.)
            utxoMods[std::make_pair(op.txid, op.utxoVout)] = boost::none;
            break;
        }
        case UNDO_UTXO_CONSUME: {
            CZSLPTokenUtxo rec;
            rec.tokenId = op.tokenId;
            rec.amount = op.amount;
            rec.isMintBaton = op.isMintBaton;
            rec.address = op.address;
            rec.height = op.blockHeight;
            utxoMods[std::make_pair(op.txid, op.utxoVout)] = rec;
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

    // Write each accumulated UTXO modification once.
    for (std::map<std::pair<uint256, int32_t>, boost::optional<CZSLPTokenUtxo> >::const_iterator
             it4 = utxoMods.begin(); it4 != utxoMods.end(); ++it4) {
        if (!it4->second)
            batch.Erase(UtxoKey(it4->first.first, it4->first.second));
        else
            batch.Write(UtxoKey(it4->first.first, it4->first.second), *it4->second);
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

    // R-24 (FIX): bound PEAK MEMORY to O(count) — INDEPENDENT of `from` — and never
    // O(total transfers for the token). Keys are 'x'+tokenId+BE(height)+txid+BE(vout)
    // in ASCENDING (oldest-first) order; the result is newest-first, skipping `from`
    // then taking `count`.
    //
    // A previous ring-buffer attempt sized its window to (from+count). Because the
    // RPC clamps `from` only to >=0 (UniValue get_int() admits up to INT_MAX), a
    // single `zslp_listtransfers "tid" 1 2000000000` would allocate ~2e9 rows and
    // OOM the daemon — WORSE than the chain-bounded O(total) CPU it replaced. The
    // intended cap there was a no-op (count<=ZSLP_LIST_MAX makes from+count never
    // exceed from+ZSLP_LIST_MAX), so `from` flowed straight into the allocation.
    //
    // CDBIterator exposes no Prev()/SeekToLast(), so instead we make TWO forward
    // passes:
    //   pass 1 counts N rows for this token (keys only, no value deserialization);
    //   pass 2 deserializes ONLY the (<= count) rows in the target ascending window
    //          [lo, hi] = [max(0, N-from-count), N-1-from], then emits newest-first.
    // Peak allocation is O(count) regardless of `from` or N, fully closing the
    // one-cheap-tx -> expensive-RPC amplification (T15). Both passes run under
    // cs_main, where the index mutates only on ChainTip, so N is stable between
    // them. CPU stays O(N) (chain-bounded; pass 2 stops at `hi`), and value
    // deserialization drops from O(N) to O(count). R-RPC-2 ordering (height-
    // ascending key order, reversed to newest-first) is preserved bit-for-bit.

    // Pass 1: count rows in this token's contiguous keyspace (keys only).
    int64_t total = 0;
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
            ++total;
        }
    }
    if (total == 0 || (int64_t)from >= total)
        return 0;

    // Ascending-index window to collect: [lo, hi], at most `count` rows. hi>=0
    // here because from < total. lo floors at 0 when fewer than `count` remain.
    const int64_t hi = total - 1 - (int64_t)from; // newest row we emit (first out)
    int64_t lo = hi - (int64_t)count + 1;         // oldest row we emit (last out)
    if (lo < 0)
        lo = 0;
    const size_t take = (size_t)(hi - lo + 1);    // <= count

    // Pass 2: deserialize ONLY ascending rows in [lo, hi]; stop past hi.
    std::vector<CZSLPTransfer> asc;
    asc.reserve(take);
    {
        int64_t idx = 0;
        boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
        for (it->Seek(TransferPrefix(tokenId)); it->Valid(); it->Next(), ++idx) {
            TransferKey key;
            if (!it->GetKey(key) || key.prefix != DB_TRANSFER)
                break;
            if (key.tokenId != tokenId)
                break;
            if (idx < lo)
                continue;
            if (idx > hi)
                break;
            CZSLPTransfer xfer;
            if (!it->GetValue(xfer))
                break;
            asc.push_back(xfer);
        }
    }

    // Emit newest-first: reverse the ascending window (hi..lo).
    out.reserve(asc.size());
    for (std::vector<CZSLPTransfer>::reverse_iterator rit = asc.rbegin();
         rit != asc.rend(); ++rit)
        out.push_back(*rit);
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
