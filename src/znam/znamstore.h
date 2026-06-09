// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZNAM name store skeleton -- LevelDB-backed confirmed-chain projection for
// ZCL Names. This header is intentionally declarations-first: beta7 prep can
// compile against the planned API without wiring runtime init behavior yet.
//
// NON-consensus: this store records what the ZNAM indexer observes on the
// confirmed chain. It must never participate in block/transaction validation,
// mempool acceptance, wallet spending, PoW, or file/network fetching. Invalid
// and unauthorized ZNAM records are ignored/no-op in the overlay; they never
// make a block or transaction invalid. ZNAM CONTENT values are opaque records
// only and must not trigger file hosting or fetching.

#ifndef BITCOIN_ZNAM_ZNAMSTORE_H
#define BITCOIN_ZNAM_ZNAMSTORE_H

#include "dbwrapper.h"
#include "serialize.h"
#include "uint256.h"
#include "znam/znammsg.h"

#include <stdint.h>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>

/** Default upper bound for paginated ZNAM read APIs. */
static const int ZNAM_LIST_MAX = 1000;

/** On-disk ZNAM index format version. Bump to wipe + rebuild the derived index. */
static const uint32_t ZNAM_INDEX_VERSION = 1;

/** Proposed non-consensus policy constants from ZNAM_DETERMINISM_SPEC.md. */
static const int64_t ZNAM_REGISTRATION_DURATION_BLOCKS = 210000;
static const int64_t ZNAM_GRACE_BLOCKS = 52500;
static const int64_t ZNAM_MAX_REGISTRATION_BLOCKS = 2100000;
static const int64_t ZNAM_RESERVE_BURN_ZATS = 0;

/** Persisted current state for one registered name. */
class CZNAMName
{
public:
    std::string name;
    std::string ownerAddr;     //!< canonical ZCL transparent P2PKH address
    int64_t registeredHeight;
    int64_t expiryHeight;
    uint8_t primaryType;       //!< ZNAM_TARGET_*, 0 when absent
    std::string primaryValue;  //!< opaque resolver value

    CZNAMName() { SetNull(); }

    void SetNull()
    {
        name.clear();
        ownerAddr.clear();
        registeredHeight = 0;
        expiryHeight = 0;
        primaryType = 0;
        primaryValue.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(name);
        READWRITE(ownerAddr);
        READWRITE(registeredHeight);
        READWRITE(expiryHeight);
        READWRITE(primaryType);
        READWRITE(primaryValue);
    }
};

/** Additional address/content resolver record keyed by (name, targetType). */
class CZNAMRecord
{
public:
    std::string name;
    uint8_t targetType;
    std::string value;

    CZNAMRecord() { SetNull(); }

    void SetNull()
    {
        name.clear();
        targetType = 0;
        value.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(name);
        READWRITE(targetType);
        READWRITE(value);
    }
};

/** Printable SET_TEXT resolver record keyed by (name, textKey). */
class CZNAMTextRecord
{
public:
    std::string name;
    std::string key;
    std::string value;

    CZNAMTextRecord() { SetNull(); }

    void SetNull()
    {
        name.clear();
        key.clear();
        value.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(name);
        READWRITE(key);
        READWRITE(value);
    }
};

/** Audit/history row. Both applied changes and deterministic no-ops are logged. */
class CZNAMHistory
{
public:
    std::string name;
    uint256 txid;
    uint256 blockHash;
    int64_t blockHeight;
    int32_t txIndex;
    uint8_t command;          //!< ZNAMMSG_*
    std::string ownerAddr;    //!< derived vin[0] owner, empty for ownerless/drop
    uint8_t targetType;
    std::string targetValue;
    std::string textKey;
    std::string textValue;
    bool applied;             //!< false when record parsed but was ignored/no-op

    CZNAMHistory() { SetNull(); }

    void SetNull()
    {
        name.clear();
        txid.SetNull();
        blockHash.SetNull();
        blockHeight = 0;
        txIndex = 0;
        command = ZNAMMSG_INVALID;
        ownerAddr.clear();
        targetType = 0;
        targetValue.clear();
        textKey.clear();
        textValue.clear();
        applied = false;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(name);
        READWRITE(txid);
        READWRITE(blockHash);
        READWRITE(blockHeight);
        READWRITE(txIndex);
        READWRITE(command);
        READWRITE(ownerAddr);
        READWRITE(targetType);
        READWRITE(targetValue);
        READWRITE(textKey);
        READWRITE(textValue);
        READWRITE(applied);
    }
};

/** Resolved active name snapshot for RPC/market identity lookups. */
class CZNAMResolvedName
{
public:
    CZNAMName name;
    std::vector<CZNAMRecord> records;
    std::vector<CZNAMTextRecord> textRecords;
};

/**
 * LevelDB name store.
 *
 * Planned key schema:
 *   'n' + name                         -> CZNAMName
 *   'r' + name + targetType            -> value
 *   'x' + name + textKey               -> textValue
 *   'h' + name + BE(height) + txid     -> CZNAMHistory
 *   'o' + ownerAddr + name             -> empty reverse-index row
 *   'u' + blockHash + BE(seq)          -> CZNAMUndoOp
 *   'T'                                -> (height, blockHash)
 *   'V'                                -> uint32 index format version
 */
class CZNAMStore
{
private:
    CDBWrapper db;
    uint32_t nUndoSeq;
    uint256 hashConnecting;

public:
    enum UndoKind : uint8_t {
        UNDO_NAME_PUT = 1,
        UNDO_NAME_UPDATE = 2,
        UNDO_NAME_ERASE = 3,
        UNDO_RECORD_SET = 4,
        UNDO_RECORD_ERASE = 5,
        UNDO_TEXT_SET = 6,
        UNDO_TEXT_ERASE = 7,
        UNDO_OWNER_INDEX_PUT = 8,
        UNDO_OWNER_INDEX_ERASE = 9,
        UNDO_HISTORY_PUT = 10,
    };

    struct CZNAMUndoOp {
        uint8_t kind;
        std::string name;
        std::string ownerAddr;
        uint8_t targetType;
        std::string textKey;
        CZNAMName prevName;
        std::string prevValue;
        bool hadPrev;
        uint256 txid;
        int64_t blockHeight;

        CZNAMUndoOp()
            : kind(0), targetType(0), hadPrev(false), blockHeight(0)
        {
            txid.SetNull();
        }

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action)
        {
            READWRITE(kind);
            READWRITE(name);
            READWRITE(ownerAddr);
            READWRITE(targetType);
            READWRITE(textKey);
            READWRITE(prevName);
            READWRITE(prevValue);
            READWRITE(hadPrev);
            READWRITE(txid);
            READWRITE(blockHeight);
        }
    };

    CZNAMStore(const boost::filesystem::path& path, size_t nCacheSize,
               bool fMemory = false, bool fWipe = false);

    // Tip marker and format stamp.
    bool WriteTip(int64_t height, const uint256& blockHash);
    bool ReadTip(int64_t& height, uint256& blockHash) const;
    bool ReadIndexVersion(uint32_t& out) const;
    bool WriteIndexVersion(uint32_t version);

    // Connect/disconnect API. ApplyRecord returns true on DB commit success;
    // invalid owner/message/precondition cases are deterministic overlay no-ops.
    void ConnectBlockBegin(const uint256& blockHash);
    bool ApplyRecord(const ZNAMMessage& msg, const std::string& ownerAddr,
                     const uint256& txid, int64_t height, int32_t txIndex,
                     const uint256& blockHash);
    bool ConnectBlockEnd(int64_t height, const uint256& blockHash);
    bool DisconnectBlock(const uint256& blockHash, int64_t prevHeight,
                         const uint256& prevHash);

    // Read API.
    bool GetName(const std::string& name, CZNAMName& out) const;
    bool ResolveName(const std::string& name, int64_t currentHeight,
                     CZNAMResolvedName& out) const;
    bool GetRecord(const std::string& name, uint8_t targetType,
                   std::string& value) const;
    bool GetTextRecord(const std::string& name, const std::string& key,
                       std::string& value) const;
    int ListNames(int from, int count, std::vector<CZNAMName>& out) const;
    int ListOwnerNames(const std::string& ownerAddr, int from, int count,
                       std::vector<CZNAMName>& out) const;
    int ListHistory(const std::string& name, int from, int count,
                    std::vector<CZNAMHistory>& out) const;

    static bool IsActive(const CZNAMName& rec, int64_t height);
    static bool IsInGrace(const CZNAMName& rec, int64_t height);
    static bool IsFreeOrExpired(const CZNAMName& rec, int64_t height);

    // D3 — the ONE owner-authorization predicate shared by every mutating
    // command (UPDATE/TRANSFER/RENEW/SET_RECORD/SET_TEXT): the name exists with
    // a non-empty signer that equals the current owner of record, and is active
    // (or in grace IFF allowGrace, which only RENEW passes). Pure function of
    // its inputs; behavior is identical to the prior inline checks. The RPC
    // layer mirrors `allowGrace` via ZNAMCurrentOwnerOrThrow so model + caller
    // agree on "may this owner act now".
    static bool CheckOwnerAuth(const CZNAMName& cur, const std::string& ownerAddr,
                               int64_t height, bool allowGrace);

private:
    bool readName(const std::string& name, CZNAMName& out) const;
    void appendUndo(CDBBatch& batch, const CZNAMUndoOp& op);
};

#endif // BITCOIN_ZNAM_ZNAMSTORE_H
