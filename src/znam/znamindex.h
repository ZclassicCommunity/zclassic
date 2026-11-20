// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ZNAM name index (read-only name resolution, stage 1).
//
// Indexes ZNAM (Z23's on-chain name protocol) for every connected block,
// applying the rule set of Z23's apply_znam (src/c23/services, doc/znam.md).
// It never touches consensus, the coins view or wallet.dat: it only READS
// blocks (and the undo data of the blocks that carry a ZNAM message) and keeps
// its own LevelDB store under <datadir>/znamindex. Every block is applied as
// ONE atomic batch together with an undo record and the new best block, so a
// crash leaves the store at an exact block boundary and a disconnect restores
// the exact prior state. This is the part Z23's own tables do not do: they are
// not unwound when a block leaves the chain.
//
// OFF by default (-znamindex=1 turns it on). See doc/znam.md.

#ifndef BITCOIN_ZNAM_ZNAMINDEX_H
#define BITCOIN_ZNAM_ZNAMINDEX_H

#include "primitives/block.h"
#include "sync.h"
#include "uint256.h"
#include "zslp/zslpindex.h" // the byte store the ZSLP index runs on

#include <functional>
#include <stdint.h>
#include <string>
#include <vector>

namespace znam {

using zslp::KV;
using zslp::MemKV;
using zslp::LevelKV;

/** ZNAM_CMD_* of Z23's znam.h. */
static const int CMD_REGISTER = 1;
static const int CMD_UPDATE = 2;
static const int CMD_TRANSFER = 3;
static const int CMD_RENEW = 4;
static const int CMD_SET_RECORD = 5;
static const int CMD_SET_TEXT = 6;

/** ZNAM_TYPE_* of Z23's znam.h. */
static const unsigned int TYPE_ONION = 1;
static const unsigned int TYPE_ZADDR = 2;
static const unsigned int TYPE_TADDR = 3;
static const unsigned int TYPE_BTC = 4;
static const unsigned int TYPE_LTC = 5;
static const unsigned int TYPE_DOGE = 6;
static const unsigned int TYPE_CONTENT = 7;

/** "t-address" for TYPE_TADDR and so on, as Z23's znam_type_name; "unknown" otherwise. */
const char* TypeName(unsigned int type);
/** The type for a Z23 token ("taddr" or "t-address" ...); 0 when unknown. */
unsigned int TypeFromName(const std::string& s);
const char* CommandName(int cmd);

/** The current state of one name: Z23's znam_names row, plus where this index saw it change. */
struct Entry {
    std::string name;
    std::string owner;       //! address text. Z23 stores the first input's address as a P2PKH string, or a TRANSFER string verbatim
    unsigned int type;       //! TYPE_*: the primary target
    std::string value;       //! the primary target, unvalidated text
    int regHeight;
    uint256 regTxid;
    uint256 lastUpdateTxid;  //! Z23's last_update_txid: REGISTER, UPDATE, TRANSFER and RENEW set it
    int expiryHeight;        //! bookkeeping only, nothing reaps a name
    // What a payer relies on: set by REGISTER, UPDATE and TRANSFER (not by RENEW, SET_RECORD or SET_TEXT).
    int changeHeight;
    uint256 changeTxid;
    int changeCommand;
    Entry() : type(0), regHeight(0), expiryHeight(0), changeHeight(0), changeCommand(0) {}
};

/** A SET_RECORD address record: one per (name, type). */
struct AddrRecord {
    unsigned int type;
    std::string value;
    int height;
    uint256 txid;
    AddrRecord() : type(0), height(0) {}
};

/** A SET_TEXT record: one per (name, key). An empty value is kept, as Z23 does. */
struct TextRecord {
    std::string key, value;
    int height;
    uint256 txid;
    TextRecord() : height(0) {}
};

/** One message that changed a name, in chain order. */
struct Event {
    int height;
    uint32_t txIndex; //! position in the block
    uint256 txid;
    int command;      //! CMD_*
    std::string owner;       //! REGISTER: the owner; TRANSFER: the new owner
    unsigned int type;       //! REGISTER, UPDATE, SET_RECORD
    std::string value;       //! REGISTER, UPDATE, SET_RECORD target; SET_TEXT value
    std::string key;         //! SET_TEXT
    int expiryHeight;        //! REGISTER, RENEW: the new expiry
    std::string actor;       //! the address that signed it (the first input), "" when none
    Event() : height(0), txIndex(0), command(0), type(0), expiryHeight(0) {}
};

struct IndexStats {
    uint64_t names;       //! registered names
    uint64_t messages;    //! parsed ZNAM messages, whatever happened to them
    uint64_t applied;     //! messages that changed a name
    uint64_t ignored;     //! parsed messages that changed nothing
    uint64_t byCommand[7]; //! applied, by CMD_* (index 0 unused)
    IndexStats() : names(0), messages(0), applied(0), ignored(0) { for (int i = 0; i < 7; i++) byCommand[i] = 0; }
};

/** The P2PKH address text of a 20-byte key hash. */
std::string OwnerFromHash160(const unsigned char hash160[20]);

/** The P2SH address text of a 20-byte script hash. */
std::string OwnerFromScriptHash160(const unsigned char hash160[20]);

/** Owner rule ZNAM-OWNER-2 (token-name-rules): the owner of a transaction is the address of the output its first
 *  input spends, rendered by the TYPE of that output: an exact P2PKH script is the P2PKH address, an exact P2SH script
 *  is the P2SH address (a key hash and a script hash of the same 20 bytes are two owners). Returns 1 and sets `owner`,
 *  or 0 for any other script (no owner: the message is ignored). Before this rule both forms were a P2PKH address. */
int OwnerFromScript(const unsigned char* script, size_t len, std::string& owner);

/** Where ApplyBlock learns the owner of transaction `txIndex`: the address of the output its first input spends.
 *  Returns 1 and sets `owner`, 0 when there is none (coinbase, or an output that is neither P2PKH nor P2SH), or -1
 *  when the data needed to know cannot be read (the block is not applied and the index retries). */
typedef std::function<int(size_t txIndex, std::string& owner)> OwnerFn;

class ZnamIndex
{
public:
    explicit ZnamIndex(KV* kv);

    /** Read the metadata. False (with err) on a store this code cannot read. */
    bool Load(std::string& err);

    /** Forget everything indexed (the format version stays): the next block applied is the first of a new index.
     *  For an index whose tip is on no chain this node knows; the index is derived data and is rebuilt. */
    bool Reset(std::string& err);

    /** Index a connected block. Atomic: the store moves from the previous best block to this one, or not at all. */
    bool ApplyBlock(const CBlock& block, const OwnerFn& ownerOf, const uint256& hash, int height, bool fSync, std::string& err);

    /** Undo the best block. `hash` must be the best block; the new best is prevHash/prevHeight. */
    bool DisconnectBlock(const uint256& hash, const uint256& prevHash, int prevHeight, std::string& err);

    bool GetBest(uint256& hash, int& height) const;
    IndexStats GetStats() const;

    bool GetName(const std::string& name, Entry& out) const;
    std::vector<AddrRecord> GetAddrRecords(const std::string& name) const;
    bool GetAddrRecord(const std::string& name, unsigned int type, AddrRecord& out) const;
    std::vector<TextRecord> GetTextRecords(const std::string& name) const;
    /** Every message that changed the name, oldest first. */
    std::vector<Event> GetHistory(const std::string& name) const;
    /** Names owned by this exact address text, in name order. */
    std::vector<Entry> ListByOwner(const std::string& owner, size_t skip, size_t count) const;
    /** All names in name order. */
    std::vector<Entry> ListNames(size_t skip, size_t count) const;

private:
    KV* kv;
    mutable CCriticalSection cs;
};

} // namespace znam

#endif // BITCOIN_ZNAM_ZNAMINDEX_H
