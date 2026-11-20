// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCASH_WALLET_SENDJOURNAL_H
#define ZCASH_WALLET_SENDJOURNAL_H

#include "amount.h"
#include "serialize.h"
#include "uint256.h"
#include "univalue.h"

#include <stdint.h>
#include <string>
#include <vector>

class CTransaction;
class CWallet;

/**
 * The send journal: "send once" for z_sendmany.
 *
 * z_sendmany takes an optional idempotency_key. With a key, the wallet keeps one record in
 * wallet.dat ("sendonce" + SHA-256 of the key) that follows the send through its steps, so a
 * client that did not see the answer (a timeout, a crash, a restart of the daemon or of the
 * client) can ask again with the same key and the same request and never gets a second
 * transaction. Without a key nothing here runs.
 *
 * The record holds hashes, states, the operation id, the txid and times. It never holds the key,
 * an address, an amount or a memo. wallet.dat readers that do not know the record type skip it.
 *
 * State machine (see DecideSendOnce / ResolveSendOnce for the exact rules):
 *
 *   (none) --z_sendmany(key)--> STARTED --Build() done, before broadcast--> BUILT
 *   BUILT --broadcast accepted / tx seen in mempool or chain--> COMMITTED
 *   STARTED --failure before Build(), or no live operation--> (record erased: key released)
 *   BUILT or COMMITTED --tip beyond expiry height + margin, tx neither mined nor in the mempool--> EXPIRED (key released)
 */

//! Key: 1..128 characters of [A-Za-z0-9._:-]
static const size_t SENDONCE_MAX_KEY_LENGTH = 128;
static const uint32_t SENDONCE_RECORD_VERSION = 1;
//! Blocks past a built transaction's expiry height before its key is released. It must exceed MAX_REORG_LENGTH
//! (checked in sendjournal.cpp): a block at or below the expiry height is then too deep to be replaced, so a
//! transaction that is not in the active chain by then can never be mined, and a retry cannot pay a second time.
static const int SENDONCE_EXPIRY_MARGIN = 100;
//! A built transaction without an expiry height (pre-Overwinter) is never released: nothing bounds when it could
//! still be mined.
//! Finished records (COMMITTED, EXPIRED) older than this are pruned
static const int64_t SENDONCE_PRUNE_AGE = 90 * 24 * 3600;
//! Finished records beyond this count are pruned, oldest first
static const size_t SENDONCE_MAX_RECORDS = 10000;
static const size_t SENDONCE_MAX_ERROR_LENGTH = 200;

enum SendOnceState : uint8_t {
    SENDONCE_STARTED = 1,
    SENDONCE_BUILT = 2,
    SENDONCE_COMMITTED = 3,
    SENDONCE_EXPIRED = 4,
};

/** The wallet.dat value of a "sendonce" record. Fields are only ever appended; nRecordVersion tells readers how many. */
class CSendOnceRecord
{
public:
    uint32_t nRecordVersion = SENDONCE_RECORD_VERSION;
    uint256 requestDigest;     //!< SHA-256 of the canonical request (SendOnceRequestDigest)
    uint8_t state = SENDONCE_STARTED;
    std::string opid;          //!< the async operation id returned to the caller
    uint256 txid;              //!< set from BUILT on
    uint32_t nExpiryHeight = 0;//!< of the built transaction (0: none)
    int64_t nTimeStarted = 0;
    int64_t nTimeBuilt = 0;
    int64_t nTimeUpdated = 0;  //!< last state change
    int32_t nErrorCode = 0;    //!< broadcast failure after BUILT (0: none)
    std::string strError;      //!< its message, at most SENDONCE_MAX_ERROR_LENGTH characters

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nRecordVersion);
        READWRITE(requestDigest);
        READWRITE(state);
        READWRITE(opid);
        READWRITE(txid);
        READWRITE(nExpiryHeight);
        READWRITE(nTimeStarted);
        READWRITE(nTimeBuilt);
        READWRITE(nTimeUpdated);
        READWRITE(nErrorCode);
        READWRITE(strError);
    }
};

bool IsValidSendOnceKey(const std::string& key);
//! SHA-256 of the key bytes: the record key in wallet.dat
uint256 SendOnceKeyHash(const std::string& key);

struct SendOnceRecipient {
    std::string address;
    CAmount amount;
    std::string memoHex; //!< as given, "" if none; lower-cased by the digest
};

/**
 * The canonical request: SHA-256 over the serialization (compact-size prefixed strings, little
 * endian integers) of
 *   "z23-sendonce-request-v1", from address, int32 minconf, int64 fee in zatoshis,
 *   uint32 number of recipients, then per recipient in the order given:
 *   address, int64 amount in zatoshis, memo hex lower-cased ("" if none).
 * minconf and fee are the values the call resolved (a default is hashed as its value, so an
 * omitted fee and an explicit default fee are the same request). The order of recipients is
 * part of the request.
 */
uint256 SendOnceRequestDigest(const std::string& from, const std::vector<SendOnceRecipient>& recipients, int minconf, CAmount fee);

/** What is known about the send when a record is looked at. */
struct SendOnceFacts {
    bool opLive = false;      //!< the operation is queued or running in this process
    bool txMined = false;     //!< the built transaction is in the active chain
    bool txInMempool = false; //!< ... or in the mempool
    int tipHeight = 0;
    int64_t now = 0;
};

enum class SendOnceLabel { STARTED, COMMITTED, OUTCOME_UNKNOWN, EXPIRED, RELEASED };
const char* SendOnceLabelName(SendOnceLabel l);

struct SendOnceResolution {
    SendOnceLabel label;
    int newState = 0;    //!< a state to store (SendOnceState), 0: none
    bool fErase = false; //!< the record is to be erased (the key is released)
};

/** Where a record stands now. Pure: no I/O. */
SendOnceResolution ResolveSendOnce(const CSendOnceRecord& rec, const SendOnceFacts& facts);

enum class SendOnceAction {
    PROCEED,          //!< build a new transaction under this key
    RETURN_STORED,    //!< answer with the stored outcome (its opid)
    REJECT_DIFFERENT, //!< same key, different request: error
};

/** What z_sendmany does with this key and request. rec is NULL if the key has no record. Pure. */
SendOnceAction DecideSendOnce(const CSendOnceRecord* rec, const uint256& requestDigest, const SendOnceFacts& facts, SendOnceResolution* pResolution = NULL);

// ---- wallet side: cs_main and cs_wallet must be held, except where noted ----

/**
 * z_sendmany with a key, before the operation is created. PROCEED: the caller builds the
 * operation, then calls SendOnceStart. STORED: opid is the stored outcome's operation id (a
 * pending, unconfirmed built transaction was offered to the mempool again). Throws an RPC
 * error if the key was used with another request.
 */
enum class SendOnceBeginResult { PROCEED, STORED };
SendOnceBeginResult SendOnceBegin(CWallet* pwallet, const uint256& keyHash, const uint256& requestDigest, std::string& opid);
//! Writes STARTED durably. Throws an RPC error if it could not be written.
void SendOnceStart(CWallet* pwallet, const uint256& keyHash, const uint256& requestDigest, const std::string& opid);
//! Releases a key whose operation could not be queued
void SendOnceRelease(CWallet* pwallet, const uint256& keyHash);
//! BUILT, durably, then the transaction goes into the wallet (so a restart can offer it to the mempool again)
bool SendOnceBuilt(CWallet* pwallet, const uint256& keyHash, const CTransaction& tx);
//! COMMITTED, durably
void SendOnceCommitted(CWallet* pwallet, const uint256& keyHash);
//! The operation failed: STARTED is erased, BUILT keeps its state and stores the error
void SendOnceFailed(CWallet* pwallet, const uint256& keyHash, int code, const std::string& message);
//! Start-up: resolve every record that is not final, erase STARTED records without an operation, prune
void SendOnceResolveAtStart(CWallet* pwallet);
void SendOncePrune(CWallet* pwallet);
//! The stored result of the operation with this id, or a null value. Read-only.
UniValue SendOnceOperationStatus(CWallet* pwallet, const std::string& opid);
//! z_listsendjournal. Read-only.
UniValue SendOnceList(CWallet* pwallet);

#endif // ZCASH_WALLET_SENDJOURNAL_H
