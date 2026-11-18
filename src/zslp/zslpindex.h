// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ZSLP token index (read-only token awareness, stage 1).
//
// Indexes SLP Token Type 1 (GENESIS / MINT / SEND) for every connected block,
// applying the validity rules of Z23's zslp_validity.c (src/c23/services). It
// never touches consensus, the coins view or wallet.dat: it only READS blocks
// and keeps its own LevelDB store under <datadir>/zslpindex. Every block is
// applied as ONE atomic batch together with an undo record and the new best
// block, so a crash leaves the store at an exact block boundary and a
// disconnect restores the exact prior state.
//
// OFF by default (-zslpindex=1 turns it on). See doc/zslp.md.

#ifndef BITCOIN_ZSLP_ZSLPINDEX_H
#define BITCOIN_ZSLP_ZSLPINDEX_H

#include "primitives/block.h"
#include "sync.h"
#include "uint256.h"

#include <functional>
#include <map>
#include <stdint.h>
#include <string>
#include <vector>

class CDBWrapper;

namespace zslp {

static const int STATUS_UNKNOWN = 0;
static const int STATUS_VALID = 1;
static const int STATUS_INVALID = 2;

static const int ROLE_TOKEN = 1;
static const int ROLE_BATON = 2;

/** Byte-string key/value store the index runs on. One WriteBatch is atomic. */
class KV
{
public:
    struct Op {
        std::string key;
        bool erase;
        std::string value;
    };
    virtual ~KV() {}
    virtual bool Get(const std::string& key, std::string& value) const = 0;
    virtual bool WriteBatch(const std::vector<Op>& ops, bool fSync) = 0;
    /** Calls fn for every key that starts with prefix, in key order, until fn returns false. */
    virtual void Scan(const std::string& prefix,
                      const std::function<bool(const std::string&, const std::string&)>& fn) const = 0;
};

/** In-memory store, for tests. */
class MemKV : public KV
{
public:
    std::map<std::string, std::string> m;
    size_t nBatches;
    MemKV() : nBatches(0) {}
    bool Get(const std::string& key, std::string& value) const;
    bool WriteBatch(const std::vector<Op>& ops, bool fSync);
    void Scan(const std::string& prefix,
              const std::function<bool(const std::string&, const std::string&)>& fn) const;
};

/** LevelDB store (the same library the block tree uses). */
class LevelKV : public KV
{
public:
    LevelKV(const std::string& path, size_t nCacheBytes, bool fMemory, bool fWipe);
    ~LevelKV();
    bool Get(const std::string& key, std::string& value) const;
    bool WriteBatch(const std::vector<Op>& ops, bool fSync);
    void Scan(const std::string& prefix,
              const std::function<bool(const std::string&, const std::string&)>& fn) const;
private:
    CDBWrapper* db;
};

/** 21 bytes: a type byte then 20 bytes. */
static const char ADDR_NONE = 0;   // all zero
static const char ADDR_P2PKH = 1;  // hash160 of the public key (P2PK is folded in)
static const char ADDR_P2SH = 2;   // hash160 of the redeem script
static const char ADDR_SCRIPT = 3; // hash160 of the whole scriptPubKey

struct TokenInfo {
    uint256 id; //! the GENESIS txid
    std::string ticker, name, documentUrl;
    bool hasDocumentHash;
    uint256 documentHash;
    unsigned int decimals;
    int genesisHeight;
    uint64_t minted;       //! sum of VALID GENESIS and MINT quantities
    uint64_t sendBurned;   //! sum of (inputs - outputs) of VALID SENDs (Z23's burned_units)
    uint64_t spentBurned;  //! token units spent by a transaction that does not carry them
    bool supplyOverflow;   //! a sum above 2^64-1: minted/burned are saturated
    bool hasBaton;
    uint256 batonTx;
    unsigned int batonVout;
    uint32_t nTx;          //! VALID token transactions
    TokenInfo() : hasDocumentHash(false), decimals(0), genesisHeight(0), minted(0), sendBurned(0),
                  spentBurned(0), supplyOverflow(false), hasBaton(false), batonVout(0), nTx(0) {}
};

struct OutInfo {
    uint256 token;
    uint64_t amount; //! base units, zero for a baton
    int role;
    std::string addr; //! 21-byte holder key
    int height;
    OutInfo() : amount(0), role(0), height(0) {}
};

struct TxInput {
    uint256 txid;
    unsigned int vout;
    uint256 token;
    uint64_t amount;
    int role;
    TxInput() : vout(0), amount(0), role(0) {}
};

struct TxOutput {
    unsigned int vout;
    uint256 token;
    uint64_t amount;
    int role;
    std::string addr;
    TxOutput() : vout(0), amount(0), role(0) {}
};

struct TxInfo {
    int type;     //! 1 GENESIS, 2 MINT, 3 SEND, 0 = not an SLP message: an ordinary transaction that spent token outputs
    int status;   //! STATUS_*
    std::string reason;
    uint256 token; //! null when type is 0
    int height;
    uint64_t inputUnits, outputUnits, mintedUnits, burnedUnits;
    std::vector<TxInput> inputs;   //! token and baton outputs this transaction spent
    std::vector<TxOutput> outputs; //! token and baton outputs this transaction created
    TxInfo() : type(0), status(0), height(0), inputUnits(0), outputUnits(0), mintedUnits(0), burnedUnits(0) {}
};

struct IndexStats {
    uint64_t tokens, txValid, txInvalid, txUnknown, txBurn, unspentOutputs;
    // every parsed SLP message, whatever its validity, by type
    uint64_t nGenesis, nMint, nSend;
    // messages whose quantities do not fit: unknown (a quantity or sum above 2^63-1) / invalid (a sum above 2^64-1)
    uint64_t nUnrepresentable, nOverflow;
    IndexStats() : tokens(0), txValid(0), txInvalid(0), txUnknown(0), txBurn(0), unspentOutputs(0),
                   nGenesis(0), nMint(0), nSend(0), nUnrepresentable(0), nOverflow(0) {}
};

/** One SLP transaction of a token, in chain order. */
struct TxRef {
    uint256 txid;
    int height;
    int type;   //! 1 GENESIS, 2 MINT, 3 SEND
    int status; //! STATUS_*
    TxRef() : height(0), type(0), status(0) {}
};

struct HolderBalance {
    std::string addr;
    uint256 token;
    uint64_t amount;
};

/** What the rules say about a transaction that is NOT in the index yet (a candidate the wallet has built):
 *  the answer ApplyBlock would give if it were the next transaction of the chain, computed from the current
 *  store without changing it. */
struct Evaluation {
    bool isSlp;              //! the first OP_RETURN output parses as an SLP message
    int type;                //! 1 GENESIS, 2 MINT, 3 SEND, 0 = not an SLP message
    int status;              //! STATUS_* (meaningful when isSlp)
    std::string reason;      //! Z23's reason code
    uint256 token;           //! the token the message names (the candidate's own txid for a GENESIS)
    uint64_t inputUnits, outputUnits, mintedUnits, burnedUnits; //! as for a VALID message; burnedUnits also counts
                                                                 //! units a non-carrying transaction would destroy
    std::vector<TxInput> spent;     //! token and baton outputs the indexed store holds among its inputs
    std::vector<TxOutput> created;  //! token and baton outputs it would create (empty unless VALID)
    Evaluation() : isSlp(false), type(0), status(0), inputUnits(0), outputUnits(0), mintedUnits(0), burnedUnits(0) {}
};

/** Holder key of a scriptPubKey. */
std::string AddrKeyForScript(const std::vector<unsigned char>& scriptPubKey);
/** "1abc..." for P2PKH/P2SH under the active chain params, "script:<hash160>" otherwise, "" for none. */
std::string AddrKeyToString(const std::string& addrKey);
/** The holder key of an address string; false if it is not a P2PKH/P2SH address or a "script:" form. */
bool AddrKeyFromString(const std::string& s, std::string& keyOut);

/** Base units as a decimal string with `decimals` fractional digits. Never floating point. */
std::string FormatAmount(uint64_t amount, unsigned int decimals);

class ZslpIndex
{
public:
    explicit ZslpIndex(KV* kv);

    /** Read the metadata. False (with err) on a store this code cannot read. */
    bool Load(std::string& err);

    /** Index a connected block. Atomic: the store moves from the previous best block to this one, or not at all. */
    bool ApplyBlock(const CBlock& block, const uint256& hash, int height, bool fSync, std::string& err);

    /** Undo the best block. `hash` must be the best block; the new best is prevHash/prevHeight. */
    bool DisconnectBlock(const uint256& hash, const uint256& prevHash, int prevHeight, std::string& err);

    bool GetBest(uint256& hash, int& height) const;
    IndexStats GetStats() const;

    bool GetToken(const uint256& id, TokenInfo& out) const;
    std::vector<TokenInfo> ListTokens(size_t skip, size_t count) const;
    bool GetTx(const uint256& txid, TxInfo& out) const;
    /** The SLP transactions that name this token (valid or not), oldest first. */
    std::vector<TxRef> ListTokenTransactions(const uint256& token, size_t skip, size_t count) const;
    bool GetOutput(const uint256& txid, unsigned int vout, OutInfo& out) const;
    /** Unspent token balances of one holder, one entry per token. */
    std::vector<HolderBalance> GetBalances(const std::string& addrKey) const;
    /** Holders of one token with a nonzero balance. */
    std::vector<HolderBalance> GetHolders(const uint256& token, size_t skip, size_t count) const;
    /** Sum of the unspent TOKEN amounts of one token (for consistency checks). */
    bool SumUnspent(const uint256& token, uint64_t& out) const;

    /** Dry run: judge `tx` by the rules of the validity code (src/c23/services) against the CURRENT store, as
     *  if it were the next transaction after the indexed tip. Read-only. False (with err) on a corrupt store. */
    bool EvaluateTx(const CTransaction& tx, Evaluation& out, std::string& err) const;

private:
    KV* kv;
    mutable CCriticalSection cs;
};

} // namespace zslp

#endif // BITCOIN_ZSLP_ZSLPINDEX_H
