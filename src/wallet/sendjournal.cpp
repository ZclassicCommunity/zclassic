// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/sendjournal.h"

#include "asyncrpcqueue.h"
#include "rpc/server.h"
#include "crypto/sha256.h"
#include "main.h"
#include "rpc/protocol.h"
#include "streams.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <algorithm>

static_assert(SENDONCE_EXPIRY_MARGIN > (int)MAX_REORG_LENGTH,
              "a released key's transaction must be beyond any reorg: the margin must exceed MAX_REORG_LENGTH");

bool IsValidSendOnceKey(const std::string& key)
{
    if (key.empty() || key.size() > SENDONCE_MAX_KEY_LENGTH) return false;
    for (char c : key) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '.' || c == '_' || c == ':' || c == '-';
        if (!ok) return false;
    }
    return true;
}

uint256 SendOnceKeyHash(const std::string& key)
{
    uint256 h;
    CSHA256().Write((const unsigned char*)key.data(), key.size()).Finalize(h.begin());
    return h;
}

uint256 SendOnceRequestDigest(const std::string& from, const std::vector<SendOnceRecipient>& recipients, int minconf, CAmount fee)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << std::string("z23-sendonce-request-v1");
    ss << from;
    ss << (int32_t)minconf;
    ss << (int64_t)fee;
    ss << (uint32_t)recipients.size();
    for (const SendOnceRecipient& r : recipients) {
        std::string memo = r.memoHex;
        std::transform(memo.begin(), memo.end(), memo.begin(), [](unsigned char c) { return (char)((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c); });
        ss << r.address;
        ss << (int64_t)r.amount;
        ss << memo;
    }
    uint256 h;
    CSHA256().Write((const unsigned char*)ss.data(), ss.size()).Finalize(h.begin());
    return h;
}

const char* SendOnceLabelName(SendOnceLabel l)
{
    switch (l) {
    case SendOnceLabel::STARTED: return "started";
    case SendOnceLabel::COMMITTED: return "committed";
    case SendOnceLabel::OUTCOME_UNKNOWN: return "outcome_unknown";
    case SendOnceLabel::EXPIRED: return "expired";
    case SendOnceLabel::RELEASED: return "released";
    }
    return "unknown";
}

SendOnceResolution ResolveSendOnce(const CSendOnceRecord& rec, const SendOnceFacts& f)
{
    SendOnceResolution r;
    switch (rec.state) {
    case SENDONCE_STARTED:
        if (f.opLive) {
            r.label = SendOnceLabel::STARTED;
        } else {
            // The operation is gone (restart, cancelled, died before it built anything): nothing was sent.
            r.label = SendOnceLabel::RELEASED;
            r.fErase = true;
        }
        return r;
    case SENDONCE_BUILT:
    case SENDONCE_COMMITTED: {
        if (f.txMined || f.txInMempool) {
            r.label = SendOnceLabel::COMMITTED;
            if (rec.state == SENDONCE_BUILT) r.newState = SENDONCE_COMMITTED;
            return r;
        }
        // Neither in a block nor in the mempool. A built transaction cannot be mined once the tip is
        // past its expiry height (plus a margin for a reorg); a committed one that never made it
        // into a block is then as dead, and its key is released so that a retry can send.
        // Without an expiry height nothing bounds when the transaction could still be mined: never released.
        const bool expired = rec.nExpiryHeight != 0 &&
            (int64_t)f.tipHeight > (int64_t)rec.nExpiryHeight + SENDONCE_EXPIRY_MARGIN;
        if (expired) {
            r.label = SendOnceLabel::EXPIRED;
            r.newState = SENDONCE_EXPIRED;
        } else if (rec.nExpiryHeight != 0 && (int64_t)f.tipHeight >= (int64_t)rec.nExpiryHeight) {
            // Past its expiry height: the active chain can no longer take it, only a reorg could. Neither sent
            // nor released: never reported as committed.
            r.label = SendOnceLabel::OUTCOME_UNKNOWN;
        } else {
            r.label = rec.state == SENDONCE_BUILT ? SendOnceLabel::OUTCOME_UNKNOWN : SendOnceLabel::COMMITTED;
        }
        return r;
    }
    case SENDONCE_EXPIRED:
        r.label = SendOnceLabel::EXPIRED;
        return r;
    default:
        // A state written by a newer version: keep it, treat it as unresolved, never release it.
        r.label = SendOnceLabel::OUTCOME_UNKNOWN;
        return r;
    }
}

SendOnceAction DecideSendOnce(const CSendOnceRecord* rec, const uint256& requestDigest, const SendOnceFacts& facts, SendOnceResolution* pResolution)
{
    if (!rec) {
        if (pResolution) {
            SendOnceResolution none;
            none.label = SendOnceLabel::RELEASED;
            *pResolution = none;
        }
        return SendOnceAction::PROCEED;
    }
    SendOnceResolution r = ResolveSendOnce(*rec, facts);
    if (pResolution) *pResolution = r;
    if (r.label == SendOnceLabel::RELEASED || r.label == SendOnceLabel::EXPIRED)
        return SendOnceAction::PROCEED;
    if (rec->requestDigest != requestDigest)
        return SendOnceAction::REJECT_DIFFERENT;
    return SendOnceAction::RETURN_STORED;
}

// ---- wallet side ----

namespace {

/** Writes (or erases, with r == NULL) one record, then forces the log to disk: the wallet
 *  environment runs with DB_TXN_WRITE_NOSYNC, so a plain commit survives a crash of this process
 *  but not necessarily of the machine. Memory is updated only after the write succeeded. */
bool PersistRecord(CWallet* w, const uint256& h, const CSendOnceRecord* r)
{
    AssertLockHeld(w->cs_wallet);
    if (w->fFileBacked) {
        CWalletDB db(w->strWalletFile, "r+", false);
        const bool ok = r ? db.WriteSendOnce(h, *r) : db.EraseSendOnce(h);
        if (!ok) {
            LogPrintf("send journal: could not %s the record %s\n", r ? "write" : "erase", HexStr(h.begin(), h.begin() + 8));
            return false;
        }
        if (!bitdb.FlushLog()) {
            // Not durable: fail closed. A caller that goes on (broadcasting after BUILT) must not.
            LogPrintf("send journal: log flush failed after writing %s\n", HexStr(h.begin(), h.begin() + 8));
            return false;
        }
    }
    if (r)
        w->mapSendOnce[h] = *r;
    else
        w->mapSendOnce.erase(h);
    return true;
}

SendOnceFacts Gather(CWallet* w, const CSendOnceRecord& rec)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(w->cs_wallet);
    SendOnceFacts f;
    f.now = GetTime();
    f.tipHeight = chainActive.Height();
    if (!rec.opid.empty()) {
        std::shared_ptr<AsyncRPCQueue> q = getAsyncRPCQueue();
        std::shared_ptr<AsyncRPCOperation> op = q->getOperationForId(rec.opid);
        f.opLive = op && (op->isReady() || op->isExecuting());
    }
    if (!rec.txid.IsNull()) {
        std::map<uint256, CWalletTx>::const_iterator it = w->mapWallet.find(rec.txid);
        if (it != w->mapWallet.end())
            f.txMined = it->second.IsInMainChain();
        f.txInMempool = mempool.exists(rec.txid);
    }
    return f;
}

/** Applies a resolution to the stored record. False if the write failed. */
bool Apply(CWallet* w, const uint256& h, CSendOnceRecord rec, const SendOnceResolution& res)
{
    if (res.fErase)
        return PersistRecord(w, h, NULL);
    if (res.newState != 0 && res.newState != rec.state) {
        rec.state = (uint8_t)res.newState;
        rec.nTimeUpdated = GetTime();
        return PersistRecord(w, h, &rec);
    }
    return true;
}

/** Offers a built transaction that is in the wallet but neither in a block nor in the mempool to the mempool again. */
bool Reoffer(CWallet* w, const uint256& txid)
{
    if (!w->GetBroadcastTransactions()) return false;
    std::map<uint256, CWalletTx>::iterator it = w->mapWallet.find(txid);
    if (it == w->mapWallet.end()) return false;
    CWalletTx& wtx = it->second;
    if (wtx.GetDepthInMainChain() >= 0) return false; // mined or in the mempool already
    bool ok;
    {
        LOCK(mempool.cs);
        ok = wtx.AcceptToMemoryPool(false);
    }
    if (ok) wtx.RelayWalletTransaction();
    return ok;
}

std::string TrimError(const std::string& msg)
{
    std::string s;
    for (char c : msg) s += (c == '\n' || c == '\r') ? ' ' : c;
    if (s.size() > SENDONCE_MAX_ERROR_LENGTH) s.resize(SENDONCE_MAX_ERROR_LENGTH);
    return s;
}

} // namespace

SendOnceBeginResult SendOnceBegin(CWallet* w, const uint256& keyHash, const uint256& requestDigest, std::string& opid)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(w->cs_wallet);
    std::map<uint256, CSendOnceRecord>::iterator it = w->mapSendOnce.find(keyHash);
    if (it == w->mapSendOnce.end())
        return SendOnceBeginResult::PROCEED;
    const CSendOnceRecord rec = it->second;
    SendOnceResolution res;
    SendOnceAction action = DecideSendOnce(&rec, requestDigest, Gather(w, rec), &res);
    if (action == SendOnceAction::REJECT_DIFFERENT)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "idempotency key reused with different parameters");
    if (!Apply(w, keyHash, rec, res))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: the send journal could not be written");
    if (action == SendOnceAction::PROCEED)
        return SendOnceBeginResult::PROCEED;
    // The stored outcome. A built transaction that nothing has taken yet is offered again.
    if (res.label == SendOnceLabel::OUTCOME_UNKNOWN && Reoffer(w, rec.txid)) {
        CSendOnceRecord upd = rec;
        upd.state = SENDONCE_COMMITTED;
        upd.nTimeUpdated = GetTime();
        PersistRecord(w, keyHash, &upd);
    }
    opid = rec.opid;
    return SendOnceBeginResult::STORED;
}

void SendOnceStart(CWallet* w, const uint256& keyHash, const uint256& requestDigest, const std::string& opid)
{
    AssertLockHeld(w->cs_wallet);
    CSendOnceRecord rec;
    rec.requestDigest = requestDigest;
    rec.state = SENDONCE_STARTED;
    rec.opid = opid;
    rec.nTimeStarted = rec.nTimeUpdated = GetTime();
    SendOncePrune(w);
    if (!PersistRecord(w, keyHash, &rec))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: the send journal could not be written; nothing was started");
    TestCrashPoint("sendonce-after-started");
}

void SendOnceRelease(CWallet* w, const uint256& keyHash)
{
    LOCK(w->cs_wallet);
    PersistRecord(w, keyHash, NULL);
}

bool SendOnceBuilt(CWallet* w, const uint256& keyHash, const CTransaction& tx)
{
    LOCK2(cs_main, w->cs_wallet);
    std::map<uint256, CSendOnceRecord>::iterator it = w->mapSendOnce.find(keyHash);
    if (it == w->mapSendOnce.end() || it->second.state != SENDONCE_STARTED) {
        LogPrintf("send journal: BUILT without a STARTED record for %s\n", HexStr(keyHash.begin(), keyHash.begin() + 8)); // log-ok: the 8-byte SHA-256 prefix that z_listsendjournal returns as "keyhash"; the key itself never reaches a log
        return false;
    }
    CSendOnceRecord rec = it->second;
    rec.state = SENDONCE_BUILT;
    rec.txid = tx.GetHash();
    rec.nExpiryHeight = tx.nExpiryHeight;
    rec.nTimeBuilt = rec.nTimeUpdated = GetTime();
    if (!PersistRecord(w, keyHash, &rec))
        return false;
    TestCrashPoint("sendonce-after-built-record");
    // The built transaction goes into the wallet by the path every transaction takes, so that the
    // wallet's own re-offer logic (start-up, tips after an unwind) can submit it if the broadcast
    // below never happens. Until it is in the mempool or a block it is neither spent nor counted:
    // wallet balances and the spent state of its inputs do not change.
    if (!w->AddToWalletIfInvolvingMe(tx, NULL, true))
        LogPrintf("send journal: the built transaction %s was not added to the wallet\n", rec.txid.ToString());
    TestCrashPoint("sendonce-after-built");
    return true;
}

void SendOnceCommitted(CWallet* w, const uint256& keyHash)
{
    LOCK2(cs_main, w->cs_wallet);
    std::map<uint256, CSendOnceRecord>::iterator it = w->mapSendOnce.find(keyHash);
    if (it == w->mapSendOnce.end() || it->second.state != SENDONCE_BUILT)
        return;
    CSendOnceRecord rec = it->second;
    rec.state = SENDONCE_COMMITTED;
    rec.nTimeUpdated = GetTime();
    rec.nErrorCode = 0;
    rec.strError.clear();
    // If this write fails the record stays BUILT and resolves to committed on the next look
    // (the transaction is in the mempool or a block).
    PersistRecord(w, keyHash, &rec);
}

void SendOnceFailed(CWallet* w, const uint256& keyHash, int code, const std::string& message)
{
    LOCK2(cs_main, w->cs_wallet);
    std::map<uint256, CSendOnceRecord>::iterator it = w->mapSendOnce.find(keyHash);
    if (it == w->mapSendOnce.end())
        return;
    CSendOnceRecord rec = it->second;
    if (rec.state == SENDONCE_STARTED) {
        // Nothing was built or sent: the key is free again.
        PersistRecord(w, keyHash, NULL);
    } else if (rec.state == SENDONCE_BUILT) {
        rec.nErrorCode = code;
        rec.strError = TrimError(message);
        rec.nTimeUpdated = GetTime();
        PersistRecord(w, keyHash, &rec);
    }
}

void SendOncePrune(CWallet* w)
{
    AssertLockHeld(w->cs_wallet);
    const int64_t now = GetTime();
    std::vector<std::pair<int64_t, uint256>> finished;
    std::vector<uint256> drop;
    for (const auto& item : w->mapSendOnce) {
        const CSendOnceRecord& r = item.second;
        if (r.state != SENDONCE_COMMITTED && r.state != SENDONCE_EXPIRED) continue;
        if (r.nTimeUpdated < now - SENDONCE_PRUNE_AGE)
            drop.push_back(item.first);
        else
            finished.push_back(std::make_pair(r.nTimeUpdated, item.first));
    }
    size_t total = w->mapSendOnce.size() - drop.size();
    if (total > SENDONCE_MAX_RECORDS) {
        std::sort(finished.begin(), finished.end());
        for (size_t i = 0; i < finished.size() && total > SENDONCE_MAX_RECORDS; i++, total--)
            drop.push_back(finished[i].second);
    }
    for (const uint256& h : drop)
        PersistRecord(w, h, NULL);
}

void SendOnceResolveAtStart(CWallet* w)
{
    LOCK2(cs_main, w->cs_wallet);
    std::vector<uint256> keys;
    for (const auto& item : w->mapSendOnce) keys.push_back(item.first);
    size_t nReleased = 0, nChanged = 0;
    for (const uint256& h : keys) {
        std::map<uint256, CSendOnceRecord>::iterator it = w->mapSendOnce.find(h);
        if (it == w->mapSendOnce.end()) continue;
        const CSendOnceRecord rec = it->second;
        SendOnceResolution res = ResolveSendOnce(rec, Gather(w, rec));
        if (res.fErase) nReleased++;
        else if (res.newState != 0) nChanged++;
        Apply(w, h, rec, res);
    }
    SendOncePrune(w);
    if (!keys.empty())
        LogPrintf("send journal: %u records, %u released, %u resolved at start\n", (unsigned)keys.size(), (unsigned)nReleased, (unsigned)nChanged);
}

UniValue SendOnceOperationStatus(CWallet* w, const std::string& opid)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(w->cs_wallet);
    for (const auto& item : w->mapSendOnce) {
        const CSendOnceRecord& rec = item.second;
        if (rec.opid != opid) continue;
        const SendOnceResolution res = ResolveSendOnce(rec, Gather(w, rec));
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("id", rec.opid));
        obj.push_back(Pair("method", "z_sendmany"));
        obj.push_back(Pair("creation_time", rec.nTimeStarted));
        obj.push_back(Pair("journal", SendOnceLabelName(res.label)));
        auto err = [&](const std::string& m) {
            UniValue e(UniValue::VOBJ);
            e.push_back(Pair("code", RPC_WALLET_ERROR));
            e.push_back(Pair("message", m));
            return e;
        };
        switch (res.label) {
        case SendOnceLabel::COMMITTED: {
            obj.push_back(Pair("status", "success"));
            UniValue r(UniValue::VOBJ);
            r.push_back(Pair("txid", rec.txid.GetHex()));
            obj.push_back(Pair("result", r));
            break;
        }
        case SendOnceLabel::OUTCOME_UNKNOWN:
        case SendOnceLabel::STARTED:
            obj.push_back(Pair("status", "executing"));
            if (!rec.txid.IsNull()) {
                obj.push_back(Pair("txid", rec.txid.GetHex()));
                obj.push_back(Pair("expiryheight", (int64_t)rec.nExpiryHeight));
            }
            if (rec.nErrorCode != 0)
                obj.push_back(Pair("last_error", err(rec.strError)));
            break;
        case SendOnceLabel::EXPIRED:
            obj.push_back(Pair("status", "failed"));
            obj.push_back(Pair("error", err("the transaction expired before it was mined; the idempotency key is released")));
            break;
        case SendOnceLabel::RELEASED:
            obj.push_back(Pair("status", "failed"));
            obj.push_back(Pair("error", err("the send was interrupted before its transaction was built; the idempotency key is released")));
            break;
        }
        return obj;
    }
    return NullUniValue;
}

UniValue SendOnceList(CWallet* w)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(w->cs_wallet);
    std::vector<std::pair<std::pair<int64_t, uint256>, const std::pair<const uint256, CSendOnceRecord>*>> order;
    for (const auto& item : w->mapSendOnce)
        order.push_back(std::make_pair(std::make_pair(item.second.nTimeStarted, item.first), &item));
    std::sort(order.begin(), order.end());
    UniValue ret(UniValue::VARR);
    for (const auto& o : order) {
        const uint256& h = o.second->first;
        const CSendOnceRecord& rec = o.second->second;
        const SendOnceResolution res = ResolveSendOnce(rec, Gather(w, rec));
        UniValue e(UniValue::VOBJ);
        e.push_back(Pair("keyhash", HexStr(h.begin(), h.begin() + 8)));
        e.push_back(Pair("state", SendOnceLabelName(res.label)));
        e.push_back(Pair("stored_state", rec.state == SENDONCE_STARTED ? "started" : rec.state == SENDONCE_BUILT ? "built" :
                                         rec.state == SENDONCE_COMMITTED ? "committed" : rec.state == SENDONCE_EXPIRED ? "expired" : "unknown"));
        e.push_back(Pair("opid", rec.opid));
        if (!rec.txid.IsNull())
            e.push_back(Pair("txid", rec.txid.GetHex()));
        e.push_back(Pair("expiryheight", (int64_t)rec.nExpiryHeight));
        e.push_back(Pair("started", rec.nTimeStarted));
        e.push_back(Pair("built", rec.nTimeBuilt));
        e.push_back(Pair("updated", rec.nTimeUpdated));
        if (rec.nErrorCode != 0) {
            e.push_back(Pair("error_code", (int64_t)rec.nErrorCode));
            e.push_back(Pair("error", rec.strError));
        }
        ret.push_back(e);
    }
    return ret;
}
