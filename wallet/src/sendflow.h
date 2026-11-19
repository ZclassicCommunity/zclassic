// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The send flow, as pure logic (QtCore + json only, so tst_logic links the same body the wallet runs).
//
// One user confirmation gets ONE idempotency key. A z_sendmany whose reply is lost (timeout, dropped
// connection, anything that is not a JSON-RPC answer) is repeated with the SAME key: the node answers with the
// stored operation id and never builds a second transaction. The user never has to press Send again.
//
// What the node reports about an operation comes from two places and this file decides what they mean together:
//   * the operation queue (z_getoperationstatus), which lives in memory and is empty after a node restart;
//   * the send journal (z_listsendjournal), which is in wallet.dat. Its states: started, committed,
//     outcome_unknown (built, but in neither mempool nor block), expired, released.
// A queue entry that says "failed" is NOT final for a keyed send: the failure may have happened after the
// transaction was built (broadcast refused), in which case the journal still holds it as outcome_unknown and the
// wallet must not tell the user "failed" and let them pay again.
#ifndef ZCL_SENDFLOW_H
#define ZCL_SENDFLOW_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QtGlobal>
#include <algorithm>
#include <string>

#include "securerandom.h"
#include "3rdparty/json/json.hpp"

namespace sendflow {

using json = nlohmann::json;

// 3 + 32 characters of [A-Za-z0-9-], about 190 bits from the system CSPRNG; the node accepts 1..128 of [A-Za-z0-9._:-].
inline QString newKey() {
    return QStringLiteral("zq-") + secureRandomBase62(32);
}

// --- classifying the answer to the z_sendmany call itself -------------------------------------------------------

enum class CallClass {
    Definitive,      // the node answered with a JSON-RPC error: nothing was queued
    KeyUnsupported,  // an older node that does not take the 5th parameter: it rejected the call, nothing was queued
    Ambiguous        // no usable answer: the request may or may not have reached the node
};

inline bool jsonErrorMessage(const json& parsed, QString* msg) {
    if (parsed.is_discarded() || !parsed.is_object()) return false;
    auto e = parsed.find("error");
    if (e == parsed.end() || !e->is_object()) return false;
    auto m = e->find("message");
    if (m == e->end() || !m->is_string()) return false;
    if (msg) *msg = QString::fromStdString(m->get<std::string>());
    return true;
}

// httpStatus is 0 when no HTTP answer was received at all.
inline CallClass classifyCall(const json& parsed, int httpStatus, bool keySent, QString* message) {
    QString m;
    if (jsonErrorMessage(parsed, &m)) {
        if (message) *message = m;
        // An older zclassicd throws its usage text (RPC_MISC_ERROR) when it gets more parameters than it knows. The
        // text names the call and, of course, not the key parameter.
        if (keySent && m.startsWith(QLatin1String("z_sendmany")) && !m.contains(QLatin1String("idempotency_key")))
            return CallClass::KeyUnsupported;
        return CallClass::Definitive;
    }
    // The node refused to even look at the request: wrong credentials. Nothing was queued.
    if (httpStatus == 401 || httpStatus == 403) {
        if (message) *message = QObject::tr("The node refused the wallet's credentials (HTTP %1).").arg(httpStatus);
        return CallClass::Definitive;
    }
    return CallClass::Ambiguous;
}

// Pause before the n-th (1-based) repeat of an unanswered keyed call: 1 s, 2 s, 4 s, 8 s, then every 15 s.
inline int retryDelayMs(int attempt, int baseMs = 1000) {
    if (attempt < 1) attempt = 1;
    const int shift = std::min(attempt - 1, 4);
    const qint64 d = (qint64)baseMs << shift;
    return (int)std::min<qint64>(d, (qint64)baseMs * 15);
}

// After this many unanswered repeats the wallet stops asking (about 10 minutes at the default pace) and says so.
constexpr int kMaxSendAttempts = 40;

// --- what the node says about a started operation ---------------------------------------------------------------

struct QueueEntry {
    bool    present = false;
    QString status;      // queued | executing | success | failed | cancelled
    QString txid;        // result.txid on success; "txid" on a journal answer for a built-but-unresolved send
    QString error;       // error.message on failure
    bool    hasLastError = false;
};

struct JournalEntry {
    bool    present = false;
    QString state;       // started | committed | outcome_unknown | expired | released
    QString txid;
};

inline QueueEntry parseQueueEntry(const json& it) {
    QueueEntry q;
    if (!it.is_object()) return q;
    q.present = true;
    auto str = [&](const char* k) {
        auto f = it.find(k);
        return (f != it.end() && f->is_string()) ? QString::fromStdString(f->get<std::string>()) : QString();
    };
    q.status = str("status");
    auto r = it.find("result");
    if (r != it.end() && r->is_object()) {
        auto t = r->find("txid");
        if (t != r->end() && t->is_string()) q.txid = QString::fromStdString(t->get<std::string>());
    }
    if (q.txid.isEmpty()) q.txid = str("txid");
    auto e = it.find("error");
    if (e != it.end() && e->is_object()) {
        auto m = e->find("message");
        if (m != e->end() && m->is_string()) q.error = QString::fromStdString(m->get<std::string>());
    }
    q.hasLastError = it.find("last_error") != it.end();
    return q;
}

inline JournalEntry parseJournalEntry(const json& it) {
    JournalEntry j;
    if (!it.is_object()) return j;
    j.present = true;
    auto f = it.find("state");
    if (f != it.end() && f->is_string()) j.state = QString::fromStdString(f->get<std::string>());
    auto t = it.find("txid");
    if (t != it.end() && t->is_string()) j.txid = QString::fromStdString(t->get<std::string>());
    return j;
}

enum class State {
    Sending,    // the node is working on it
    Sent,       // in the mempool or a block: txid known
    Unknown,    // built, but neither in a block nor in the mempool yet: the node holds it, nothing will be sent again
    Expired,    // never mined and can no longer be: nothing left the wallet
    Failed,     // refused before anything was built or sent
    Lost        // an older node no longer knows the operation (it restarted): the wallet cannot tell
};

struct Verdict {
    State   state = State::Sending;
    QString txid;
    QString text;    // what the user is told
};

inline QString sendingText() {
    return QObject::tr("Sending... your wallet is building the transaction (private sends can take up to a minute).");
}
inline QString unknownText() {
    return QObject::tr("Outcome unknown: the wallet will not send again; checking");
}
inline QString expiredText() {
    return QObject::tr("This payment expired before it was mined, so it was not sent. Funds are available again.");
}
inline QString lostText() {
    return QObject::tr("The node no longer has a record of this send (it may have restarted), so its outcome is unknown. "
                       "Check your transactions before sending again.");
}
inline QString interruptedText() {
    return QObject::tr("The send was interrupted before the transaction was built. Nothing was sent.");
}
inline QString gaveUpText() {
    return QObject::tr("The wallet could not reach the node to confirm this payment. It may or may not have been queued. "
                       "This wallet will not send it again: check your transactions before sending again.");
}
inline QString oldNodeAmbiguousText() {
    return QObject::tr("The connection was lost while sending, and this node is too old to tell whether the payment was queued. "
                       "Check your transactions before sending again.");
}

// True for the wallet's own wording above: it already says what to do, so it is shown as it is.
inline bool isFlowText(const QString& s) {
    return s == unknownText() || s == expiredText() || s == lostText() || s == interruptedText() || s == gaveUpText()
        || s == oldNodeAmbiguousText();
}

// Does deciding this operation need the journal? Only for a keyed send whose queue entry says failed or is gone, or
// that is already in the unknown state (then the journal is the only thing that can change its mind).
inline bool needsJournal(bool keyed, const QueueEntry& q, bool alreadyUnknown) {
    if (!keyed) return false;
    if (alreadyUnknown) return true;
    return !q.present || q.status == QLatin1String("failed");
}

// keyed: the send carried an idempotency key. journalKnown: the journal was fetched (new node, call succeeded);
// when it was not needed or not available, pass journalKnown=false and an empty JournalEntry.
inline Verdict resolve(bool keyed, const QueueEntry& q, bool journalKnown, const JournalEntry& j) {
    Verdict v;
    if (keyed && journalKnown && j.present) {
        if (j.state == QLatin1String("committed")) {
            v.state = State::Sent;
            v.txid = j.txid.isEmpty() ? q.txid : j.txid;
            return v;
        }
        if (j.state == QLatin1String("expired")) {
            v.state = State::Expired;
            v.text = expiredText();
            return v;
        }
        if (j.state == QLatin1String("outcome_unknown")) {
            v.state = State::Unknown;
            v.txid = j.txid;
            v.text = unknownText();
            return v;
        }
        if (j.state == QLatin1String("released")) {
            v.state = State::Failed;
            v.text = q.error.isEmpty() ? interruptedText() : q.error;
            return v;
        }
        // started: the operation is live
        v.state = State::Sending;
        v.text = sendingText();
        return v;
    }
    if (q.present) {
        if (q.status == QLatin1String("success")) {
            v.state = State::Sent;
            v.txid = q.txid;
            return v;
        }
        if (q.status == QLatin1String("failed") || q.status == QLatin1String("cancelled")) {
            v.state = State::Failed;
            v.text = q.error.isEmpty() ? QObject::tr("The send failed.") : q.error;
            return v;
        }
        // queued / executing. A journal answer for a built send that is not in a block or the mempool carries its txid.
        if (!q.txid.isEmpty() || q.hasLastError) {
            v.state = State::Unknown;
            v.txid = q.txid;
            v.text = unknownText();
            return v;
        }
        v.state = State::Sending;
        v.text = sendingText();
        return v;
    }
    if (keyed && journalKnown) {
        // Gone from the queue and no journal record: the record is erased when the operation was lost before the
        // transaction was built, so nothing was sent and the key is free.
        v.state = State::Failed;
        v.text = interruptedText();
        return v;
    }
    v.state = State::Lost;
    v.text = lostText();
    return v;
}

}  // namespace sendflow

#endif  // ZCL_SENDFLOW_H
