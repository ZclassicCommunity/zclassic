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
// (CDBWrapper) instead of sqlite. The on-chain semantics are the *real* SLP
// Token-Type-1 UTXO-bound rules:
//   - token genesis records (metadata + total_minted + baton display mirror)
//   - token-carrying UTXOs keyed by (txid, vout) — THE SOURCE OF TRUTH
//   - per-(token,address) balances — a DERIVED view, kept conservation-correct
//     by signed +/- deltas as token UTXOs are created/consumed
//   - transfer records (one per VALID token-bearing vout) — a human audit log
// A SEND can only move tokens that exist on spent inputs; a MINT requires the
// mint baton on a spent input; an unfunded/over-budget SEND or baton-less MINT
// creates NOTHING (and burns any consumed inputs). Forgery is impossible.
//
// Records are tagged by block hash + height + txid so a reorg can delete
// exactly the records a given block added (and restore the UTXOs it consumed),
// and a tip marker enables crash-resume.

#ifndef BITCOIN_ZSLP_ZSLPSTORE_H
#define BITCOIN_ZSLP_ZSLPSTORE_H

#include "dbwrapper.h"
#include "primitives/transaction.h"  // COutPoint
#include "serialize.h"
#include "uint256.h"

#include <stdint.h>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <boost/filesystem/path.hpp>

/** SLP transaction type tags as persisted (mirror enum slp_tx_type). */
static const uint8_t ZSLP_TX_GENESIS = 1;
static const uint8_t ZSLP_TX_MINT    = 2;
static const uint8_t ZSLP_TX_SEND    = 3;

/** Default upper bound for the count argument of the list RPCs. */
static const int ZSLP_LIST_MAX = 1000;

/** Canonical SEND output-quantity cap (R-SEND-1 / R-12). MUST equal the C
 *  parser's ZSLP_SEND_MAX_OUTPUTS and the bridge's ZSLP_MAX_SEND_OUTPUTS; the
 *  indexer asserts this at the bridge boundary. A SEND with more than this many
 *  quantities is rejected by the parser (whole message INVALID), so the store
 *  never sees a larger count — this is both the array bound and the loop cap. */
static const int ZSLP_SEND_MAX_OUTPUTS_STORE = 19;

/** On-disk index format version. Bump when the schema/semantics change so the
 *  indexer wipes + rebuilds (the index is fully derivable and behind -zslpindex).
 *  v1 = legacy credit-only (absent stamp). v2 = UTXO-bound conservation. */
static const uint32_t ZSLP_INDEX_VERSION = 2;

/** Parsed SLP message kind, matching ZSLPMsgType, but usable by the store
 *  without pulling in the message bridge header. */
enum ZSLPStoreMsgType : uint8_t {
    ZSLP_MSG_GENESIS = 1,
    ZSLP_MSG_MINT    = 2,
    ZSLP_MSG_SEND    = 3,
};

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
    uint8_t mintBatonVout;    //!< 0 = no/spent baton (DISPLAY mirror of the live baton UTXO)
    int64_t genesisHeight;
    int64_t totalMinted;      //!< running sum of genesis + mint quantities (issued supply)

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

/**
 * Persisted token-carrying UTXO record — THE SOURCE OF TRUTH for ownership.
 * Keyed by (txid, vout). A token quantity (or a mint baton) lives at exactly
 * one UTXO; SEND/MINT consume inputs and create new UTXOs conservatively.
 *
 * Invariant: isMintBaton == true  =>  amount == 0  (a baton bears no quantity;
 * it is never counted in a SEND's availIn).
 */
class CZSLPTokenUtxo
{
public:
    uint256 tokenId;
    int64_t amount;        //!< 0 for a baton
    bool isMintBaton;
    std::string address;   //!< owner t-address, "" if undecodable
    int64_t height;        //!< block height the UTXO was created at

    CZSLPTokenUtxo() { SetNull(); }

    void SetNull()
    {
        tokenId.SetNull();
        amount = 0;
        isMintBaton = false;
        address.clear();
        height = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenId);
        READWRITE(amount);
        READWRITE(isMintBaton);
        READWRITE(address);
        READWRITE(height);
    }
};

/** Persisted transfer record — one per VALID token-bearing output. */
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

/** Minimal parsed-message view the store needs to apply a transaction. The
 *  indexer fills this from the ZSLPMessage it parsed; the store needs no
 *  script knowledge (consumed-input addresses come from stored UTXOs). */
struct CZSLPParsedMsg {
    ZSLPStoreMsgType type;
    uint256 tokenId;                 //!< MINT/SEND: target token. GENESIS: ignored (txid is id).
    int64_t initialQuantity;         //!< GENESIS
    int64_t additionalQuantity;      //!< MINT
    int32_t mintBatonVout;           //!< GENESIS/MINT: >=2 to (re)issue a baton, else 0/end
    int numOutputs;                  //!< SEND
    int64_t outputQuantities[ZSLP_SEND_MAX_OUTPUTS_STORE]; //!< SEND: outputQuantities[j] -> vout[1+j]

    CZSLPParsedMsg()
        : type(ZSLP_MSG_SEND), initialQuantity(0), additionalQuantity(0),
          mintBatonVout(0), numOutputs(0)
    {
        tokenId.SetNull();
        for (int i = 0; i < ZSLP_SEND_MAX_OUTPUTS_STORE; ++i)
            outputQuantities[i] = 0;
    }
};

/**
 * LevelDB token store.
 *
 * Key schema (first byte is a record-type discriminator):
 *   't' + tokenId                            -> CZSLPToken         (token by id)
 *   'u' + txid + BE(vout)                    -> CZSLPTokenUtxo     (token UTXO — TRUTH)
 *   'x' + tokenId + BE(height) + txid + BE(vout) -> CZSLPTransfer  (ordered transfers)
 *   'b' + tokenId + address                  -> int64 balance      (DERIVED view)
 *   'r' + blockHash + BE(seq)                -> CZSLPUndoOp         (reorg undo log)
 *   'T'                                      -> (height, blockHash) (tip marker)
 *   'M' + 0                                  -> uint32 version      (format stamp)
 *
 * The undo log records, per block, exactly which UTXO creates/consumes and
 * derived-balance deltas were applied so that DisconnectBlock can reverse them
 * precisely (restore consumed UTXOs, erase created ones, reverse balance/total_
 * minted/baton changes), restoring the store byte-for-byte to its pre-connect
 * state.
 */
class CZSLPStore
{
private:
    CDBWrapper db;

    // The reorg undo log appends ops under 'r'+blockHash+seq while a block is
    // being connected; ConnectBlockBegin resets the running sequence. The seq
    // runs across ALL txs in the block (not per-tx).
    uint32_t nUndoSeq;
    uint256 hashConnecting; //!< block currently being connected (for undo keys)

public:
    /** Undo-op kinds appended while connecting a block. */
    enum UndoKind : uint8_t {
        UNDO_TOKEN_PUT     = 1, //!< a genesis token record was created
        UNDO_TRANSFER_PUT  = 2, //!< a transfer record was created
        UNDO_BALANCE_ADD   = 3, //!< balance(token,address) changed by SIGNED amount
        UNDO_MINTED_ADD    = 4, //!< token.totalMinted was increased by amount
        UNDO_BATON_SET     = 5, //!< token.mintBatonVout changed (old value stored)
        UNDO_UTXO_CREATE   = 6, //!< a token UTXO was created (disconnect: erase it)
        UNDO_UTXO_CONSUME  = 7, //!< a token UTXO was consumed (disconnect: re-write it)
    };

    struct CZSLPUndoOp {
        uint8_t kind;
        uint256 tokenId;
        uint256 txid;       //!< UNDO_TRANSFER_PUT / UNDO_UTXO_* key reconstruction
        int64_t blockHeight;
        int32_t vout;       //!< UNDO_TRANSFER_PUT key (transfer vout)
        std::string address; //!< UNDO_BALANCE_ADD / UNDO_UTXO_CONSUME (restore)
        int64_t amount;      //!< UNDO_BALANCE_ADD (SIGNED delta) / UNDO_MINTED_ADD / UTXO amount
        uint8_t prevBaton;   //!< UNDO_BATON_SET
        int32_t utxoVout;    //!< UNDO_UTXO_CREATE / UNDO_UTXO_CONSUME: the 'u' key vout
        bool isMintBaton;    //!< UNDO_UTXO_CONSUME: restore baton flag

        CZSLPUndoOp()
            : kind(0), blockHeight(0), vout(0), amount(0), prevBaton(0),
              utxoVout(0), isMintBaton(false)
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
            READWRITE(utxoVout);
            READWRITE(isMintBaton);
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

    // ── Format version stamp (migration) ───────────────────────────
    bool ReadIndexVersion(uint32_t& out) const;
    bool WriteIndexVersion(uint32_t version);

    // ── Connect-side mutation (called by the indexer per block) ────
    //
    // ConnectBlockBegin() starts a fresh undo log for blockHash; ApplyTransaction
    // (called per tx, in block order) commits its own batch so a later tx in the
    // same block can spend a UTXO an earlier tx created; ConnectBlockEnd advances
    // the tip marker. The undo seq runs across the whole block.
    void ConnectBlockBegin(const uint256& blockHash);

    /**
     * Apply one transaction to the store under the real SLP UTXO-bound rules.
     * Runs for EVERY tx (SLP or not): first consume/burn the token UTXOs the
     * tx spends, then (if msg != NULL) create new UTXOs only as far as the
     * consumed inputs (or, for GENESIS, the genesis itself) permit.
     *
     * @param vin         tx.vin prevouts (token inputs are looked up by these)
     * @param msg         parsed SLP message, or NULL for a non-SLP tx
     * @param txid        this transaction's id
     * @param height      block height
     * @param genesisMeta GENESIS only: prebuilt token metadata (else NULL)
     * @param addrOfVout  maps an output index to its t-address ("" if none)
     * @param voutCount   tx.vout.size() (for output-index bounds checks)
     * @returns true on a successful commit
     */
    bool ApplyTransaction(const std::vector<COutPoint>& vin,
                          const CZSLPParsedMsg* msg,
                          const uint256& txid, int64_t height,
                          const CZSLPToken* genesisMeta,
                          const std::function<std::string(int32_t)>& addrOfVout,
                          int32_t voutCount);

    bool ConnectBlockEnd(int64_t height, const uint256& blockHash);

    /**
     * READ-ONLY dry-run validator for a built (but not yet broadcast) tx.
     *
     * Mirrors ApplyTransaction's conservation/baton/layout checks EXACTLY using
     * only point reads (GetUtxo/GetToken) — it NEVER writes leveldb. The wallet
     * write path (R-WALLET-9, doc/nft/MINT_TRANSFER_SPEC.md §4.3) calls this on
     * the final signed tx and REFUSES to broadcast unless it returns true, so a
     * builder bug can never publish a tx the live indexer would burn/mis-credit.
     *
     * The `msg` is the SAME CZSLPParsedMsg the indexer would produce from the
     * tx's vout[0] (callers pass what CZSLPIndexer::ParseTx returned); `vin`,
     * `genesisMeta`, `voutCount` mirror ApplyTransaction's arguments. The
     * non-burn caller intent (no input may be a token of a DIFFERENT token, no
     * baton may be spent unintentionally) is enforced by the wallet builder, not
     * here — this predicate answers strictly "does the overlay ledger accept and
     * fully credit this tx as the message intends?".
     *
     * @param reason  human-readable failure cause (set only when returning false)
     * @returns true iff the overlay would create EXACTLY the intended outputs
     *          (GENESIS/MINT mint output + baton present; SEND fully conserved,
     *          every quantity landing on an existing output; no implicit burn of
     *          the message's own declared quantities).
     */
    bool WouldBeValid(const std::vector<COutPoint>& vin,
                      const CZSLPParsedMsg* msg,
                      const uint256& txid,
                      const CZSLPToken* genesisMeta,
                      int32_t voutCount,
                      std::string& reason) const;

    // ── Disconnect-side (reorg) ────────────────────────────────────
    //
    // Replays the block's undo log in reverse, restoring consumed UTXOs,
    // erasing created ones, reversing balance/total_minted/baton changes and
    // deleting the transfer/token records the block added, then sets the tip
    // marker back to (prevHeight, prevHash). Yields byte-identical pre-state.
    bool DisconnectBlock(const uint256& blockHash, int64_t prevHeight,
                         const uint256& prevHash);

    // ── Read API (used by the RPCs and tests) ─────────────────────
    bool GetToken(const uint256& tokenId, CZSLPToken& out) const;
    /** Look up a token UTXO by (txid, vout). */
    bool GetUtxo(const uint256& txid, int32_t vout, CZSLPTokenUtxo& out) const;
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
    /** Count of live token UTXOs (test/diagnostic helper). */
    int64_t UtxoCount() const;

private:
    // Internal helpers.
    bool readToken(const uint256& tokenId, CZSLPToken& out) const;
    bool readUtxo(const uint256& txid, int32_t vout, CZSLPTokenUtxo& out) const;
    void writeTokenBatch(CDBBatch& batch, const CZSLPToken& token);
    int64_t readBalance(const uint256& tokenId, const std::string& address) const;
    void appendUndo(CDBBatch& batch, const CZSLPUndoOp& op);

    // Per-(token,address) balance delta accumulator. CDBBatch is write-only and
    // readBalance() sees only committed data, so several deltas to one address in
    // a single tx (e.g. consume the input then credit the change back to it)
    // must net in memory before a single committed read + write at flush time.
    typedef std::map<std::pair<uint256, std::string>, int64_t> BalDeltaMap;

    // The ONLY mutation sites for 'u', 'b', and 'x' (kept DRY). createUtxo /
    // consumeUtxo stage 'u'/'x' writes and the signed UNDO_BALANCE_ADD undo op
    // into the batch immediately, but route the derived-balance change through
    // the in-memory accumulator; flushBalances() commits it once per address.
    void createUtxo(CDBBatch& batch, BalDeltaMap& bal, const uint256& txid,
                    int32_t vout, const uint256& tokenId, int64_t amount,
                    bool isMintBaton, const std::string& address,
                    int64_t height, uint8_t txType);
    void consumeUtxo(CDBBatch& batch, BalDeltaMap& bal, const uint256& txid,
                     int32_t vout, const CZSLPTokenUtxo& rec);
    void recordBalanceDelta(CDBBatch& batch, BalDeltaMap& bal,
                            const uint256& tokenId, const std::string& address,
                            int64_t delta);
    void flushBalances(CDBBatch& batch, const BalDeltaMap& bal);
};

#endif // BITCOIN_ZSLP_ZSLPSTORE_H
