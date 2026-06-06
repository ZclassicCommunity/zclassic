// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP token store — a LevelDB-backed, read-only-observation store for the
// Simple Ledger Protocol (SLP) token data carried in OP_RETURN outputs.
//
// NON-consensus: this store records what the indexer observes. It never
// participates in block/transaction validation, PoW, or wallet spends.
//
// Re-implements the data model from the zclassic-c reference
// (app/models/src/zslp.c + adapters/.../zslp_store_sqlite.c) over LevelDB
// (CDBWrapper) instead of sqlite. The on-chain semantics are identical:
//   - token genesis records (metadata + total_minted + baton state)
//   - transfer records (one per token-bearing vout)
//   - per-(token,address) balances (ZSLP rides transparent dust)
// Records are tagged by block hash + height + txid so a reorg can delete
// exactly the records a given block added, and a tip marker enables
// crash-resume.

#ifndef BITCOIN_ZSLP_ZSLPSTORE_H
#define BITCOIN_ZSLP_ZSLPSTORE_H

#include "dbwrapper.h"
#include "serialize.h"
#include "uint256.h"

#include <stdint.h>
#include <string>
#include <vector>

#include <boost/filesystem/path.hpp>

/** SLP transaction type tags as persisted (mirror enum slp_tx_type). */
static const uint8_t ZSLP_TX_GENESIS = 1;
static const uint8_t ZSLP_TX_MINT    = 2;
static const uint8_t ZSLP_TX_SEND    = 3;

/** Default upper bound for the count argument of the list RPCs. */
static const int ZSLP_LIST_MAX = 1000;

/** Persisted token genesis / metadata record. */
class CZSLPToken
{
public:
    uint256 tokenId;          //!< genesis txid (the canonical token id)
    std::string ticker;
    std::string name;
    std::string documentUrl;
    uint256 documentHash;     //!< 0 when absent
    bool hasDocumentHash;
    uint8_t decimals;
    uint8_t mintBatonVout;    //!< 0 = no/spent baton
    int64_t genesisHeight;
    int64_t totalMinted;      //!< running sum of genesis + mint quantities

    CZSLPToken() { SetNull(); }

    void SetNull()
    {
        tokenId.SetNull();
        ticker.clear();
        name.clear();
        documentUrl.clear();
        documentHash.SetNull();
        hasDocumentHash = false;
        decimals = 0;
        mintBatonVout = 0;
        genesisHeight = 0;
        totalMinted = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenId);
        READWRITE(ticker);
        READWRITE(name);
        READWRITE(documentUrl);
        READWRITE(documentHash);
        READWRITE(hasDocumentHash);
        READWRITE(decimals);
        READWRITE(mintBatonVout);
        READWRITE(genesisHeight);
        READWRITE(totalMinted);
    }
};

/** Persisted transfer record — one per token-bearing event/vout. */
class CZSLPTransfer
{
public:
    uint256 tokenId;
    uint256 txid;
    uint256 blockHash;
    int64_t blockHeight;
    uint8_t txType;           //!< ZSLP_TX_GENESIS / MINT / SEND
    int64_t amount;
    int32_t vout;
    std::string address;      //!< recipient t-address, "" if undecodable

    CZSLPTransfer() { SetNull(); }

    void SetNull()
    {
        tokenId.SetNull();
        txid.SetNull();
        blockHash.SetNull();
        blockHeight = 0;
        txType = 0;
        amount = 0;
        vout = 0;
        address.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenId);
        READWRITE(txid);
        READWRITE(blockHash);
        READWRITE(blockHeight);
        READWRITE(txType);
        READWRITE(amount);
        READWRITE(vout);
        READWRITE(address);
    }
};

/**
 * LevelDB token store.
 *
 * Key schema (first byte is a record-type discriminator):
 *   't' + tokenId                          -> CZSLPToken          (token by id)
 *   'x' + tokenId + height + txid + vout    -> CZSLPTransfer       (ordered transfers)
 *   'b' + tokenId + address                -> int64 balance       (balances)
 *   'r' + blockHash + seq                  -> CZSLPUndoOp          (reorg undo log)
 *   'T'                                    -> (height, blockHash)  (tip marker)
 *
 * The undo log records, per block, exactly which puts/credits were applied so
 * that DisconnectBlock can reverse them precisely (genesis/transfer deletion +
 * balance decrement + total_minted decrement), restoring the store to its
 * pre-connect state.
 */
class CZSLPStore
{
private:
    CDBWrapper db;

    // The reorg undo log appends ops under 'r'+blockHash+seq while a block is
    // being connected; ConnectBlockBegin resets the running sequence.
    uint32_t nUndoSeq;
    uint256 hashConnecting; //!< block currently being connected (for undo keys)

public:
    /** Undo-op kinds appended while connecting a block. */
    enum UndoKind : uint8_t {
        UNDO_TOKEN_PUT    = 1, //!< a genesis token record was created
        UNDO_TRANSFER_PUT = 2, //!< a transfer record was created
        UNDO_BALANCE_ADD  = 3, //!< balance(token,address) was credited by amount
        UNDO_MINTED_ADD   = 4, //!< token.totalMinted was increased by amount
        UNDO_BATON_SET    = 5, //!< token.mintBatonVout changed (old value stored)
    };

    struct CZSLPUndoOp {
        uint8_t kind;
        uint256 tokenId;
        uint256 txid;       //!< for UNDO_TRANSFER_PUT key reconstruction
        int64_t blockHeight;
        int32_t vout;
        std::string address; //!< for UNDO_BALANCE_ADD
        int64_t amount;      //!< for UNDO_BALANCE_ADD / UNDO_MINTED_ADD
        uint8_t prevBaton;   //!< for UNDO_BATON_SET

        CZSLPUndoOp() : kind(0), blockHeight(0), vout(0), amount(0), prevBaton(0)
        {
            tokenId.SetNull();
            txid.SetNull();
        }

        ADD_SERIALIZE_METHODS;
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action)
        {
            READWRITE(kind);
            READWRITE(tokenId);
            READWRITE(txid);
            READWRITE(blockHeight);
            READWRITE(vout);
            READWRITE(address);
            READWRITE(amount);
            READWRITE(prevBaton);
        }
    };

    /**
     * @param[in] path        leveldb directory (e.g. GetDataDir()/blocks/zslp)
     * @param[in] nCacheSize  leveldb cache size
     * @param[in] fMemory     in-memory env (used by tests)
     * @param[in] fWipe       wipe existing data
     */
    CZSLPStore(const boost::filesystem::path& path, size_t nCacheSize,
               bool fMemory = false, bool fWipe = false);

    // ── Tip marker (crash-resume) ──────────────────────────────────
    bool WriteTip(int64_t height, const uint256& blockHash);
    bool ReadTip(int64_t& height, uint256& blockHash) const;

    // ── Connect-side mutation (called by the indexer per block) ────
    //
    // ConnectBlockBegin() starts a fresh undo log for blockHash; the Apply*
    // calls append both the data record and a matching undo op; ConnectBlockEnd
    // advances the tip marker. The whole block is staged in one CDBBatch by the
    // caller-less helpers below for crash-atomicity.
    void ConnectBlockBegin(const uint256& blockHash);

    /** Create (or no-op if exists) a token genesis record + seed its
     *  total_minted with the initial quantity and the recipient balance. */
    bool ApplyGenesis(const CZSLPToken& token, const std::string& recipient,
                      const uint256& txid, int32_t vout, int64_t initialQty);

    /** Increase total_minted (and credit recipient) for an existing token. */
    bool ApplyMint(const uint256& tokenId, const std::string& recipient,
                   const uint256& txid, int64_t blockHeight, int32_t vout,
                   int64_t addQty, bool batonMoved, uint8_t newBatonVout);

    /** Record a SEND output: credit the recipient + transfer record. */
    bool ApplySend(const uint256& tokenId, const std::string& recipient,
                   const uint256& txid, int64_t blockHeight, int32_t vout,
                   int64_t amount);

    bool ConnectBlockEnd(int64_t height, const uint256& blockHash);

    // ── Disconnect-side (reorg) ────────────────────────────────────
    //
    // Replays the block's undo log in reverse, deleting exactly the records
    // ConnectBlock* added and decrementing balances / total_minted, then sets
    // the tip marker back to (prevHeight, prevHash). Idempotent: a block with
    // no undo log is a no-op.
    bool DisconnectBlock(const uint256& blockHash, int64_t prevHeight,
                         const uint256& prevHash);

    // ── Read API (used by the RPCs and tests) ─────────────────────
    bool GetToken(const uint256& tokenId, CZSLPToken& out) const;
    /** Bounded, deterministic token list (skip `from`, take up to `count`). */
    int ListTokens(int from, int count, std::vector<CZSLPToken>& out) const;
    /** Bounded transfer list for one token, newest height first. */
    int ListTransfers(const uint256& tokenId, int from, int count,
                      std::vector<CZSLPTransfer>& out) const;
    /** Balance of (token, address); 0 if absent. */
    int64_t GetBalance(const uint256& tokenId, const std::string& address) const;
    /** All (token, balance) pairs with balance>0 for `address`. */
    void GetTokensForAddress(const std::string& address,
                             std::vector<std::pair<uint256, int64_t> >& out) const;

    int64_t TokenCount() const;

private:
    // Internal helpers (single-record writes; the batch variants are used by
    // the Apply* path so a block connects/disconnects atomically).
    bool readToken(const uint256& tokenId, CZSLPToken& out) const;
    void writeTokenBatch(CDBBatch& batch, const CZSLPToken& token);
    int64_t readBalance(const uint256& tokenId, const std::string& address) const;
    void appendUndo(CDBBatch& batch, const CZSLPUndoOp& op);
};

#endif // BITCOIN_ZSLP_ZSLPSTORE_H
