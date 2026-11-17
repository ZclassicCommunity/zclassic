// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Pure logic of the read-only "Tokens" view: turns the daemon's zslp_getindexinfo
// and zslp_listunspent replies into rows and plain-language text. No widgets, no
// network: tests/tst_tokens.cpp links this file alone.
//
// Token amounts are decimal STRINGS (the daemon formats them from integers with
// the token's decimals). They are shown exactly as received and never converted
// to a floating point number.
#ifndef ZCL_TOKENSMODEL_H
#define ZCL_TOKENSMODEL_H

#include <QString>
#include <QVector>

#include "3rdparty/json/json.hpp"

namespace tokens {

struct IndexStatus {
    bool enabled = false;      // the daemon runs with -zslpindex=1
    bool synced = false;       // the index has reached the chain tip
    double progress = 0.0;     // 0..1
    int indexedHeight = -1;
    int chainHeight = -1;
    QString error;             // a problem the daemon is retrying, or empty
};

struct Balance {
    QString tokenId;
    QString ticker;
    QString amount;            // decimal string, as received
    int decimals = 0;
};

struct Output {
    QString txid;
    int vout = 0;
    QString address;
    QString tokenId;
    QString ticker;
    QString role;              // "token" or "mintbaton"
    QString amount;            // decimal string, as received
    int confirmations = 0;
    bool isProtected = true;   // never spent as ordinary funds
};

struct Snapshot {
    bool synced = false;
    QVector<Balance> balances;
    QVector<Output> outputs;
};

// `result` is the "result" member of a zslp_getindexinfo reply. A reply that is not
// an object, or has no `enabled` flag, yields enabled == false.
IndexStatus parseIndexInfo(const nlohmann::json& result);

// `result` is the "result" member of a zslp_listunspent reply. False (and *out
// cleared) if it is not the expected object; malformed rows are skipped.
bool parseSnapshot(const nlohmann::json& result, Snapshot* out);

// "Token index is up to date (block 123,456)." / "Token index is building: 42%..."
QString statusLine(const IndexStatus& s);

// The wording that tells the user why these coins are not spendable as ordinary funds.
QString protectedNotice();

// What the user sees for an output's kind.
QString roleText(const QString& role);

// The ticker, or a short form of the token id when the creator left it empty.
QString displayTicker(const QString& ticker, const QString& tokenId);

// "ab12cd34...ef56:1"
QString shortOutpoint(const QString& txid, int vout);

} // namespace tokens

#endif // ZCL_TOKENSMODEL_H
