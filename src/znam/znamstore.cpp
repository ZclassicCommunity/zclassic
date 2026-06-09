// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZNAM (ZCL Names) name store implementation — LevelDB (CDBWrapper) backing for
// the name registry. See znamstore.h for the schema and contract.
//
// NON-consensus: read-only observation of the confirmed chain. Never touches
// validation/PoW/wallet/mempool. An invalid, ownerless, unauthorized, expired,
// or malformed record is a deterministic overlay NO-OP (still audited in the
// history log) and never makes a block or transaction invalid. CONTENT values
// are opaque resolver bytes only and never trigger file hosting or fetching.
//
// The model is First-In-First-Served: ownership is the vin[0] P2PKH signer of
// the registering/updating tx (derived by the indexer from confirmed undo data
// and passed in as ownerAddr). The 'n' name row is the source of truth; the
// per-block undo log ('u') lets a reorg restore byte-identical prior state.
// Mirrors the zslp/zslpstore.cpp discipline (persist-what-you-roll-back, never
// recompute on rollback; per-tx batch commit for intra-block visibility; reverse
// LIFO replay with in-memory accumulation so each record is written exactly once).

#include "znam/znamstore.h"

#include "key_io.h"
#include "script/standard.h"
#include "util.h"

#include <algorithm>
#include <map>
#include <set>
#include <utility>

#include <boost/optional.hpp>
#include <boost/scoped_ptr.hpp>

// Record-type discriminators (first key byte). Disjoint leveldb dir from zslp,
// so these never collide with the token store.
static const char DB_NAME    = 'n'; // 'n' + name                     -> CZNAMName
static const char DB_RECORD  = 'r'; // 'r' + name + targetType        -> CZNAMRecord
static const char DB_TEXT    = 'x'; // 'x' + name + textKey           -> CZNAMTextRecord
static const char DB_HISTORY = 'h'; // 'h' + name + BE(height) + txid -> CZNAMHistory
static const char DB_OWNER   = 'o'; // 'o' + ownerAddr + name         -> empty (reverse index)
static const char DB_UNDO    = 'u'; // 'u' + blockHash + BE(seq)      -> CZNAMUndoOp
static const char DB_TIP      = 'T'; // 'T' + 0                        -> (height, blockHash)
static const char DB_META     = 'V'; // 'V' + 0                        -> uint32 index version

namespace {

// Composite key structs. Field order defines leveldb sort order. uint256
// serializes its raw bytes (a true byte-prefix for Seek); std::string serializes
// a length prefix then the bytes (which still groups all keys sharing a string
// prefix contiguously, since the length+bytes are identical for one name). For
// numeric fields that must iterate in numeric order we encode BIG-ENDIAN by hand,
// exactly as zslpstore.cpp's UndoKey/TransferKey do.

struct NameKey {
    char prefix;
    std::string name;
    NameKey() : prefix(DB_NAME) {}
    explicit NameKey(const std::string& n) : prefix(DB_NAME), name(n) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(name);
    }
};

struct RecordKey {
    char prefix;
    std::string name;
    uint8_t targetType;
    RecordKey() : prefix(DB_RECORD), targetType(0) {}
    RecordKey(const std::string& n, uint8_t t)
        : prefix(DB_RECORD), name(n), targetType(t) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(name);
        READWRITE(targetType);
    }
};

// Seek prefix: 'r' + name (same leading bytes as RecordKey, minus targetType).
struct RecordPrefix {
    char prefix;
    std::string name;
    explicit RecordPrefix(const std::string& n) : prefix(DB_RECORD), name(n) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(name);
    }
};

struct TextKey {
    char prefix;
    std::string name;
    std::string key;
    TextKey() : prefix(DB_TEXT) {}
    TextKey(const std::string& n, const std::string& k)
        : prefix(DB_TEXT), name(n), key(k) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(name);
        READWRITE(key);
    }
};

// Seek prefix: 'x' + name.
struct TextPrefix {
    char prefix;
    std::string name;
    explicit TextPrefix(const std::string& n) : prefix(DB_TEXT), name(n) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(name);
    }
};

// 'h' + name + BE(height) + txid. BE height makes lexicographic order ==
// height-ascending order so a name's history reads oldest-first.
struct HistoryKey {
    char prefix;
    std::string name;
    int64_t height;
    uint256 txid;
    HistoryKey() : prefix(DB_HISTORY), height(0) {}
    HistoryKey(const std::string& n, int64_t h, const uint256& x)
        : prefix(DB_HISTORY), name(n), height(h), txid(x) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(name);
        if (ser_action.ForRead()) {
            uint8_t hb[8];
            for (int i = 0; i < 8; ++i) READWRITE(hb[i]);
            uint64_t hu = 0; for (int i = 0; i < 8; ++i) hu = (hu << 8) | hb[i];
            height = (int64_t)hu;
            READWRITE(txid);
        } else {
            uint64_t hu = (uint64_t)height;
            uint8_t hb[8];
            for (int i = 7; i >= 0; --i) { hb[i] = (uint8_t)(hu & 0xff); hu >>= 8; }
            for (int i = 0; i < 8; ++i) READWRITE(hb[i]);
            READWRITE(txid);
        }
    }
};

// Seek prefix: 'h' + name.
struct HistoryPrefix {
    char prefix;
    std::string name;
    explicit HistoryPrefix(const std::string& n) : prefix(DB_HISTORY), name(n) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(name);
    }
};

struct OwnerKey {
    char prefix;
    std::string ownerAddr;
    std::string name;
    OwnerKey() : prefix(DB_OWNER) {}
    OwnerKey(const std::string& o, const std::string& n)
        : prefix(DB_OWNER), ownerAddr(o), name(n) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(ownerAddr);
        READWRITE(name);
    }
};

// Seek prefix: 'o' + ownerAddr.
struct OwnerPrefix {
    char prefix;
    std::string ownerAddr;
    explicit OwnerPrefix(const std::string& o) : prefix(DB_OWNER), ownerAddr(o) {}
    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(prefix);
        READWRITE(ownerAddr);
    }
};

// 'u' + blockHash + BE(seq). BE seq so the undo log iterates in append order.
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

// Is a byte printable per the SET_TEXT allowlist?
//   key bytes:   0x21..0x7e (printable, no space)
//   value bytes: 0x20..0x7e (printable, space allowed)
bool IsPrintableKey(const std::string& s)
{
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x21 || c > 0x7e) return false;
    }
    return true;
}

bool IsPrintableValue(const std::string& s)
{
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7e) return false;
    }
    return true;
}

// Is newOwner a valid transparent P2PKH base58check address under the active
// CChainParams? (TRANSFER target rule — anything else makes TRANSFER a no-op.)
bool IsValidP2PKHAddress(const std::string& addr)
{
    if (addr.empty())
        return false;
    CTxDestination dest = DecodeDestination(addr);
    if (!IsValidDestination(dest))
        return false;
    return boost::get<CKeyID>(&dest) != NULL; // P2PKH only
}

} // namespace

CZNAMStore::CZNAMStore(const boost::filesystem::path& path, size_t nCacheSize,
                       bool fMemory, bool fWipe)
    : db(path, nCacheSize, fMemory, fWipe), nUndoSeq(0)
{
    hashConnecting.SetNull();
}

// ── Tip marker ─────────────────────────────────────────────────────

bool CZNAMStore::WriteTip(int64_t height, const uint256& blockHash)
{
    return db.Write(std::make_pair(DB_TIP, (char)0),
                    std::make_pair(height, blockHash));
}

bool CZNAMStore::ReadTip(int64_t& height, uint256& blockHash) const
{
    std::pair<int64_t, uint256> val;
    if (!db.Read(std::make_pair(DB_TIP, (char)0), val))
        return false;
    height = val.first;
    blockHash = val.second;
    return true;
}

// ── Format version stamp ────────────────────────────────────────────

bool CZNAMStore::ReadIndexVersion(uint32_t& out) const
{
    return db.Read(std::make_pair(DB_META, (char)0), out);
}

bool CZNAMStore::WriteIndexVersion(uint32_t version)
{
    return db.Write(std::make_pair(DB_META, (char)0), version);
}

// ── Internal helpers ────────────────────────────────────────────────

bool CZNAMStore::readName(const std::string& name, CZNAMName& out) const
{
    return db.Read(NameKey(name), out);
}

void CZNAMStore::appendUndo(CDBBatch& batch, const CZNAMUndoOp& op)
{
    batch.Write(UndoKey(hashConnecting, nUndoSeq), op);
    nUndoSeq++;
}

// ── Expiry predicates (pure height functions; no wall clock) ────────

bool CZNAMStore::IsActive(const CZNAMName& rec, int64_t height)
{
    return !rec.name.empty() && height < rec.expiryHeight;
}

bool CZNAMStore::IsInGrace(const CZNAMName& rec, int64_t height)
{
    return !rec.name.empty() &&
           rec.expiryHeight <= height &&
           height < rec.expiryHeight + ZNAM_GRACE_BLOCKS;
}

bool CZNAMStore::IsFreeOrExpired(const CZNAMName& rec, int64_t height)
{
    return rec.name.empty() ||
           height >= rec.expiryHeight + ZNAM_GRACE_BLOCKS;
}

// ── Connect ─────────────────────────────────────────────────────────

void CZNAMStore::ConnectBlockBegin(const uint256& blockHash)
{
    hashConnecting = blockHash;
    nUndoSeq = 0;
}

bool CZNAMStore::ConnectBlockEnd(int64_t height, const uint256& blockHash)
{
    hashConnecting.SetNull();
    nUndoSeq = 0;
    return WriteTip(height, blockHash);
}

// Apply one parsed ZNAM record. ownerAddr is the indexer-derived vin[0] P2PKH
// owner ("" if the tx had no P2PKH signer). Every parsed record — applied or
// no-op — writes a history row and logs the matching undo ops, so a reorg's
// reverse replay restores byte-identical prior state. One batch per call gives
// a later tx in the SAME block visibility of an earlier tx's writes.
bool CZNAMStore::ApplyRecord(const ZNAMMessage& msg, const std::string& ownerAddr,
                             const uint256& txid, int64_t height, int32_t txIndex,
                             const uint256& blockHash)
{
    CDBBatch batch(db);

    CZNAMName cur;
    bool exists = readName(msg.name, cur);

    bool applied = false;

    switch (msg.command) {
    case ZNAMMSG_REGISTER: {
        // Ownerless registration is dropped; only a P2PKH signer can own a name.
        if (!ownerAddr.empty() && (!exists || IsFreeOrExpired(cur, height))) {
            // A fresh registration RESETS the name: wipe any stale overlay rows
            // and the prior owner index left by an expired prior registration.
            if (exists) {
                // Erase all prior 'r' records (carry prevValue so disconnect re-writes).
                boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
                for (it->Seek(RecordPrefix(msg.name)); it->Valid(); it->Next()) {
                    RecordKey rk;
                    if (!it->GetKey(rk) || rk.prefix != DB_RECORD || rk.name != msg.name)
                        break;
                    CZNAMRecord rrec;
                    if (!it->GetValue(rrec))
                        break;
                    batch.Erase(RecordKey(msg.name, rk.targetType));
                    CZNAMUndoOp u;
                    u.kind = UNDO_RECORD_ERASE;
                    u.name = msg.name;
                    u.targetType = rk.targetType;
                    u.prevValue = rrec.value;
                    u.hadPrev = true;
                    appendUndo(batch, u);
                }
                // Erase all prior 'x' text records.
                boost::scoped_ptr<CDBIterator> it2(const_cast<CDBWrapper&>(db).NewIterator());
                for (it2->Seek(TextPrefix(msg.name)); it2->Valid(); it2->Next()) {
                    TextKey tk;
                    if (!it2->GetKey(tk) || tk.prefix != DB_TEXT || tk.name != msg.name)
                        break;
                    CZNAMTextRecord trec;
                    if (!it2->GetValue(trec))
                        break;
                    batch.Erase(TextKey(msg.name, tk.key));
                    CZNAMUndoOp u;
                    u.kind = UNDO_TEXT_ERASE;
                    u.name = msg.name;
                    u.textKey = tk.key;
                    u.prevValue = trec.value;
                    u.hadPrev = true;
                    appendUndo(batch, u);
                }
                // Erase the prior owner's reverse-index row.
                batch.Erase(OwnerKey(cur.ownerAddr, msg.name));
                CZNAMUndoOp uo;
                uo.kind = UNDO_OWNER_INDEX_ERASE;
                uo.name = msg.name;
                uo.ownerAddr = cur.ownerAddr;
                appendUndo(batch, uo);
            }

            CZNAMName fresh;
            fresh.name = msg.name;
            fresh.ownerAddr = ownerAddr;
            fresh.registeredHeight = height;
            fresh.expiryHeight = height + ZNAM_REGISTRATION_DURATION_BLOCKS;
            fresh.primaryType = msg.targetType;
            fresh.primaryValue = msg.targetValue;
            batch.Write(NameKey(msg.name), fresh);

            CZNAMUndoOp un;
            un.name = msg.name;
            if (exists) {
                un.kind = UNDO_NAME_UPDATE; // restore the stale-expired prior row
                un.prevName = cur;
                un.hadPrev = true;
            } else {
                un.kind = UNDO_NAME_PUT;    // disconnect erases the new row
            }
            appendUndo(batch, un);

            batch.Write(OwnerKey(ownerAddr, msg.name), (char)0);
            CZNAMUndoOp up;
            up.kind = UNDO_OWNER_INDEX_PUT;
            up.name = msg.name;
            up.ownerAddr = ownerAddr;
            appendUndo(batch, up);

            applied = true;
        }
        break;
    }
    case ZNAMMSG_UPDATE: {
        if (exists && IsActive(cur, height) && cur.ownerAddr == ownerAddr &&
            !ownerAddr.empty()) {
            CZNAMName next = cur;
            next.primaryType = msg.targetType;
            next.primaryValue = msg.targetValue;
            batch.Write(NameKey(msg.name), next);
            CZNAMUndoOp u;
            u.kind = UNDO_NAME_UPDATE;
            u.name = msg.name;
            u.prevName = cur;
            u.hadPrev = true;
            appendUndo(batch, u);
            applied = true;
        }
        break;
    }
    case ZNAMMSG_TRANSFER: {
        if (exists && IsActive(cur, height) && cur.ownerAddr == ownerAddr &&
            !ownerAddr.empty() && IsValidP2PKHAddress(msg.newOwner)) {
            // Move the owner reverse-index row from old -> new owner.
            batch.Erase(OwnerKey(cur.ownerAddr, msg.name));
            CZNAMUndoOp ue;
            ue.kind = UNDO_OWNER_INDEX_ERASE;
            ue.name = msg.name;
            ue.ownerAddr = cur.ownerAddr;
            appendUndo(batch, ue);

            CZNAMName next = cur;
            next.ownerAddr = msg.newOwner;
            batch.Write(NameKey(msg.name), next);
            CZNAMUndoOp un;
            un.kind = UNDO_NAME_UPDATE;
            un.name = msg.name;
            un.prevName = cur;
            un.hadPrev = true;
            appendUndo(batch, un);

            batch.Write(OwnerKey(msg.newOwner, msg.name), (char)0);
            CZNAMUndoOp up;
            up.kind = UNDO_OWNER_INDEX_PUT;
            up.name = msg.name;
            up.ownerAddr = msg.newOwner;
            appendUndo(batch, up);

            applied = true;
        }
        break;
    }
    case ZNAMMSG_RENEW: {
        if (exists && (IsActive(cur, height) || IsInGrace(cur, height)) &&
            cur.ownerAddr == ownerAddr && !ownerAddr.empty()) {
            CZNAMName next = cur;
            int64_t base = std::max(cur.expiryHeight, height);
            int64_t extended = base + ZNAM_REGISTRATION_DURATION_BLOCKS;
            int64_t cap = height + ZNAM_MAX_REGISTRATION_BLOCKS;
            next.expiryHeight = std::min(extended, cap);
            batch.Write(NameKey(msg.name), next);
            CZNAMUndoOp u;
            u.kind = UNDO_NAME_UPDATE;
            u.name = msg.name;
            u.prevName = cur;
            u.hadPrev = true;
            appendUndo(batch, u);
            applied = true;
        }
        break;
    }
    case ZNAMMSG_SET_RECORD: {
        if (exists && IsActive(cur, height) && cur.ownerAddr == ownerAddr &&
            !ownerAddr.empty() &&
            msg.targetType >= ZNAM_TARGET_ONION && msg.targetType <= ZNAM_TARGET_CONTENT) {
            std::string prevValue;
            bool hadPrev = GetRecord(msg.name, msg.targetType, prevValue);
            CZNAMRecord rrec;
            rrec.name = msg.name;
            rrec.targetType = msg.targetType;
            rrec.value = msg.targetValue;
            batch.Write(RecordKey(msg.name, msg.targetType), rrec);
            CZNAMUndoOp u;
            u.kind = UNDO_RECORD_SET;
            u.name = msg.name;
            u.targetType = msg.targetType;
            u.prevValue = prevValue;
            u.hadPrev = hadPrev;
            appendUndo(batch, u);
            applied = true;
        }
        break;
    }
    case ZNAMMSG_SET_TEXT: {
        if (exists && IsActive(cur, height) && cur.ownerAddr == ownerAddr &&
            !ownerAddr.empty() &&
            IsPrintableKey(msg.textKey) && !msg.textKey.empty() &&
            IsPrintableValue(msg.textValue)) {
            std::string prevValue;
            bool hadPrev = GetTextRecord(msg.name, msg.textKey, prevValue);
            if (msg.textValue.empty()) {
                // Length-0 value == deletion.
                if (hadPrev) {
                    batch.Erase(TextKey(msg.name, msg.textKey));
                    CZNAMUndoOp u;
                    u.kind = UNDO_TEXT_ERASE;
                    u.name = msg.name;
                    u.textKey = msg.textKey;
                    u.prevValue = prevValue;
                    u.hadPrev = true;
                    appendUndo(batch, u);
                }
                // Deleting an absent key is a benign no-op; still counts as applied
                // (an authorized owner action that left the overlay unchanged).
                applied = true;
            } else {
                CZNAMTextRecord trec;
                trec.name = msg.name;
                trec.key = msg.textKey;
                trec.value = msg.textValue;
                batch.Write(TextKey(msg.name, msg.textKey), trec);
                CZNAMUndoOp u;
                u.kind = UNDO_TEXT_SET;
                u.name = msg.name;
                u.textKey = msg.textKey;
                u.prevValue = prevValue;
                u.hadPrev = hadPrev;
                appendUndo(batch, u);
                applied = true;
            }
        }
        break;
    }
    default:
        break;
    }

    // History row for EVERY parsed record (applied or no-op), so name_history is
    // a complete audit and the reverse replay erases it deterministically.
    CZNAMHistory hist;
    hist.name = msg.name;
    hist.txid = txid;
    hist.blockHash = blockHash;
    hist.blockHeight = height;
    hist.txIndex = txIndex;
    hist.command = (uint8_t)msg.command;
    hist.ownerAddr = ownerAddr;
    hist.targetType = msg.targetType;
    hist.targetValue = msg.targetValue;
    hist.textKey = msg.textKey;
    hist.textValue = msg.textValue;
    hist.applied = applied;
    batch.Write(HistoryKey(msg.name, height, txid), hist);

    CZNAMUndoOp uh;
    uh.kind = UNDO_HISTORY_PUT;
    uh.name = msg.name;
    uh.txid = txid;
    uh.blockHeight = height;
    appendUndo(batch, uh);

    return db.WriteBatch(batch);
}

// ── Disconnect (reorg) ──────────────────────────────────────────────

bool CZNAMStore::DisconnectBlock(const uint256& blockHash, int64_t prevHeight,
                                 const uint256& prevHash)
{
    // Gather the block's undo ops (ascending seq), then replay in reverse.
    std::vector<CZNAMUndoOp> ops;
    std::vector<uint32_t> seqs;
    {
        boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
        for (it->Seek(UndoKey(blockHash, 0)); it->Valid(); it->Next()) {
            UndoKey key;
            if (!it->GetKey(key))
                break;
            if (key.prefix != DB_UNDO || key.blockHash != blockHash)
                break;
            CZNAMUndoOp op;
            if (!it->GetValue(op))
                return false;
            ops.push_back(op);
            seqs.push_back(key.seq);
        }
    }

    CDBBatch batch(db);

    // Accumulate per-record changes in memory and write each key exactly ONCE.
    // readName/GetRecord see only the committed DB (not this pending batch), so a
    // per-op read-modify-write would clobber a sibling op. Reverse-order replay
    // makes a same-block create+update net to the pre-block state: the lower-seq
    // op is processed LAST and its accumulator write wins.
    //   value present => write; boost::none => erase.
    std::map<std::string, boost::optional<CZNAMName> > nameMods;
    std::map<std::pair<std::string, uint8_t>, boost::optional<std::string> > recMods;
    std::map<std::pair<std::string, std::string>, boost::optional<std::string> > textMods;
    std::map<std::pair<std::string, std::string>, bool> ownerMods; // true=write, false=erase

    for (int i = (int)ops.size() - 1; i >= 0; --i) {
        const CZNAMUndoOp& op = ops[i];
        switch (op.kind) {
        case UNDO_NAME_PUT:
            nameMods[op.name] = boost::none; // erase the row we created
            break;
        case UNDO_NAME_UPDATE:
            nameMods[op.name] = op.prevName; // restore the prior row
            break;
        case UNDO_NAME_ERASE:
            nameMods[op.name] = op.prevName; // restore a row we erased
            break;
        case UNDO_RECORD_SET: {
            std::pair<std::string, uint8_t> k(op.name, op.targetType);
            recMods[k] = op.hadPrev ? boost::optional<std::string>(op.prevValue)
                                    : boost::optional<std::string>();
            break;
        }
        case UNDO_RECORD_ERASE: {
            std::pair<std::string, uint8_t> k(op.name, op.targetType);
            recMods[k] = boost::optional<std::string>(op.prevValue); // re-write
            break;
        }
        case UNDO_TEXT_SET: {
            std::pair<std::string, std::string> k(op.name, op.textKey);
            textMods[k] = op.hadPrev ? boost::optional<std::string>(op.prevValue)
                                     : boost::optional<std::string>();
            break;
        }
        case UNDO_TEXT_ERASE: {
            std::pair<std::string, std::string> k(op.name, op.textKey);
            textMods[k] = boost::optional<std::string>(op.prevValue); // re-write
            break;
        }
        case UNDO_OWNER_INDEX_PUT:
            ownerMods[std::make_pair(op.ownerAddr, op.name)] = false; // erase
            break;
        case UNDO_OWNER_INDEX_ERASE:
            ownerMods[std::make_pair(op.ownerAddr, op.name)] = true; // re-add
            break;
        case UNDO_HISTORY_PUT:
            // History keys are unique per (name, blockHeight, txid); erase directly.
            batch.Erase(HistoryKey(op.name, op.blockHeight, op.txid));
            break;
        default:
            break;
        }
    }

    for (std::map<std::string, boost::optional<CZNAMName> >::const_iterator it = nameMods.begin();
         it != nameMods.end(); ++it) {
        if (it->second)
            batch.Write(NameKey(it->first), *it->second);
        else
            batch.Erase(NameKey(it->first));
    }
    for (std::map<std::pair<std::string, uint8_t>, boost::optional<std::string> >::const_iterator
             it = recMods.begin(); it != recMods.end(); ++it) {
        if (it->second) {
            CZNAMRecord rrec;
            rrec.name = it->first.first;
            rrec.targetType = it->first.second;
            rrec.value = *it->second;
            batch.Write(RecordKey(it->first.first, it->first.second), rrec);
        } else {
            batch.Erase(RecordKey(it->first.first, it->first.second));
        }
    }
    for (std::map<std::pair<std::string, std::string>, boost::optional<std::string> >::const_iterator
             it = textMods.begin(); it != textMods.end(); ++it) {
        if (it->second) {
            CZNAMTextRecord trec;
            trec.name = it->first.first;
            trec.key = it->first.second;
            trec.value = *it->second;
            batch.Write(TextKey(it->first.first, it->first.second), trec);
        } else {
            batch.Erase(TextKey(it->first.first, it->first.second));
        }
    }
    for (std::map<std::pair<std::string, std::string>, bool>::const_iterator
             it = ownerMods.begin(); it != ownerMods.end(); ++it) {
        if (it->second)
            batch.Write(OwnerKey(it->first.first, it->first.second), (char)0);
        else
            batch.Erase(OwnerKey(it->first.first, it->first.second));
    }

    // Drop this block's undo log.
    for (size_t i = 0; i < seqs.size(); ++i)
        batch.Erase(UndoKey(blockHash, seqs[i]));

    // Move the tip marker back.
    batch.Write(std::make_pair(DB_TIP, (char)0),
                std::make_pair(prevHeight, prevHash));

    return db.WriteBatch(batch);
}

// ── Read / list API ─────────────────────────────────────────────────

bool CZNAMStore::GetName(const std::string& name, CZNAMName& out) const
{
    return readName(name, out);
}

bool CZNAMStore::ResolveName(const std::string& name, int64_t currentHeight,
                             CZNAMResolvedName& out) const
{
    CZNAMName rec;
    if (!readName(name, rec))
        return false;
    if (!IsActive(rec, currentHeight))
        return false; // NXDOMAIN for expired/grace/unregistered

    out.name = rec;
    out.records.clear();
    out.textRecords.clear();

    {
        boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
        for (it->Seek(RecordPrefix(name)); it->Valid(); it->Next()) {
            RecordKey rk;
            if (!it->GetKey(rk) || rk.prefix != DB_RECORD || rk.name != name)
                break;
            CZNAMRecord rrec;
            if (it->GetValue(rrec))
                out.records.push_back(rrec);
        }
    }
    {
        boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
        for (it->Seek(TextPrefix(name)); it->Valid(); it->Next()) {
            TextKey tk;
            if (!it->GetKey(tk) || tk.prefix != DB_TEXT || tk.name != name)
                break;
            CZNAMTextRecord trec;
            if (it->GetValue(trec))
                out.textRecords.push_back(trec);
        }
    }
    return true;
}

bool CZNAMStore::GetRecord(const std::string& name, uint8_t targetType,
                           std::string& value) const
{
    CZNAMRecord rrec;
    if (!db.Read(RecordKey(name, targetType), rrec))
        return false;
    value = rrec.value;
    return true;
}

bool CZNAMStore::GetTextRecord(const std::string& name, const std::string& key,
                               std::string& value) const
{
    CZNAMTextRecord trec;
    if (!db.Read(TextKey(name, key), trec))
        return false;
    value = trec.value;
    return true;
}

int CZNAMStore::ListNames(int from, int count, std::vector<CZNAMName>& out) const
{
    out.clear();
    if (count <= 0)
        return 0;
    if (count > ZNAM_LIST_MAX)
        count = ZNAM_LIST_MAX;
    if (from < 0)
        from = 0;

    int skipped = 0;
    boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
    for (it->Seek(NameKey(std::string()));
         it->Valid() && (int)out.size() < count; it->Next()) {
        NameKey key;
        if (!it->GetKey(key) || key.prefix != DB_NAME)
            break;
        if (skipped < from) {
            ++skipped;
            continue;
        }
        CZNAMName rec;
        if (it->GetValue(rec))
            out.push_back(rec);
    }
    return (int)out.size();
}

int CZNAMStore::ListOwnerNames(const std::string& ownerAddr, int from, int count,
                               std::vector<CZNAMName>& out) const
{
    out.clear();
    if (count <= 0 || ownerAddr.empty())
        return 0;
    if (count > ZNAM_LIST_MAX)
        count = ZNAM_LIST_MAX;
    if (from < 0)
        from = 0;

    int skipped = 0;
    boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
    for (it->Seek(OwnerPrefix(ownerAddr));
         it->Valid() && (int)out.size() < count; it->Next()) {
        OwnerKey key;
        if (!it->GetKey(key) || key.prefix != DB_OWNER || key.ownerAddr != ownerAddr)
            break;
        if (skipped < from) {
            ++skipped;
            continue;
        }
        CZNAMName rec;
        if (readName(key.name, rec))
            out.push_back(rec);
    }
    return (int)out.size();
}

int CZNAMStore::ListHistory(const std::string& name, int from, int count,
                            std::vector<CZNAMHistory>& out) const
{
    out.clear();
    if (count <= 0)
        return 0;
    if (count > ZNAM_LIST_MAX)
        count = ZNAM_LIST_MAX;
    if (from < 0)
        from = 0;

    int skipped = 0;
    boost::scoped_ptr<CDBIterator> it(const_cast<CDBWrapper&>(db).NewIterator());
    for (it->Seek(HistoryPrefix(name));
         it->Valid() && (int)out.size() < count; it->Next()) {
        HistoryKey key;
        if (!it->GetKey(key) || key.prefix != DB_HISTORY || key.name != name)
            break;
        if (skipped < from) {
            ++skipped;
            continue;
        }
        CZNAMHistory hist;
        if (it->GetValue(hist))
            out.push_back(hist);
    }
    return (int)out.size();
}
