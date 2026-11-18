// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Pure logic of sending and creating ZSLP tokens from the Tokens window: exact amount
// parsing, input checks, the RPC parameters, the daemon's replies and the words the user reads
// before and after. No widgets, no network: tests/tst_tokenssend.cpp links this file alone.
//
// Token amounts are DECIMAL STRINGS end to end. They are parsed into 64-bit integers of base
// units and printed back from integers; no floating point touches a token amount. (The ZCL fee
// the daemon reports is converted to whole zatoshi first, and printed from the integer.) The
// daemon checks everything again; these checks exist so that the user hears about a mistake
// before the review step rather than after.
#ifndef ZCL_TOKENSSENDMODEL_H
#define ZCL_TOKENSSENDMODEL_H

#include <QString>
#include <QtGlobal>

#include "3rdparty/json/json.hpp"
#include "tokensmodel.h"

namespace tokens {

// The token a send is drawn from: one row of the wallet's balances.
struct TokenChoice {
    QString tokenId;
    QString ticker;
    int decimals = 0;
    QString balance;   // decimal string, as received from the daemon
};

// Token rows for the picker, from a Snapshot (only tokens the wallet holds).
QVector<TokenChoice> choicesFromSnapshot(const Snapshot& snap);

// ---- amounts ----------------------------------------------------------------------------------

struct AmountResult {
    bool ok = false;
    QString error;       // plain language, empty when ok
    quint64 units = 0;   // base units
    QString normalized;  // what is sent to the daemon: no sign, no leading zeros, no trailing point
};

// Exact: digits and at most one decimal point; at most `decimals` fractional digits (nothing is ever
// rounded); greater than zero; at most 2^63-1 base units (the token rules treat more as unknown).
AmountResult parseAmount(const QString& text, int decimals);

// Base units as a decimal string with `decimals` fractional digits, from integers only.
QString formatUnits(quint64 units, int decimals);

// ---- sending ----------------------------------------------------------------------------------

// Empty when the address can be a recipient; else the reason in plain language.
QString checkRecipient(const QString& address);

struct SendCheck {
    bool ok = false;
    QString error;
    quint64 units = 0;
    QString amount;  // normalized
    QString address; // trimmed
};

SendCheck checkSend(const TokenChoice& token, const QString& address, const QString& amountText);

// zslp_send parameters. The review step runs with dryRun = true: the daemon builds and checks the
// transaction and answers with the exact fee, but broadcasts nothing.
nlohmann::json sendParams(const TokenChoice& token, const SendCheck& check, bool dryRun);

struct TxPlan {
    bool ok = false;
    QString error;
    QString kind;         // send, genesis, mint, burn
    QString txid;
    QString tokenId;
    bool broadcast = false;
    QString amount;       // decimal string
    QString tokenChange;  // decimal string, "" when none
    QString changeAddress;
    int tokenInputs = 0;
    qint64 feeZat = 0;
};

// The reply of zslp_send / zslp_genesis (the "result" member).
TxPlan parseTxPlan(const nlohmann::json& result);

// "0.00000481" from whole zatoshi.
QString formatZcl(qint64 zat);

// What the user reads on the review page of a send.
QString sendReviewText(const TokenChoice& token, const SendCheck& check, const TxPlan& plan);
// What the user reads after the daemon accepted it.
QString sendResultText(const TokenChoice& token, const SendCheck& check, const TxPlan& plan);

// ---- creating a token -------------------------------------------------------------------------

struct GenesisDraft {
    QString ticker;
    QString name;
    QString decimals;   // text of a number, 0..8
    QString quantity;   // decimal string
    QString url;        // optional
    QString hash;       // optional, 64 hex
    bool baton = true;  // keep a mint baton
};

struct GenesisCheck {
    bool ok = false;
    QString error;
    int decimals = 0;
    quint64 units = 0;
    QString quantity;   // normalized
};

// Z23's creation rules: ticker 1-10 letters or digits, name 1-64 letters, digits and space - _ . /,
// decimals 0-8, a positive quantity of at most 2100000000000000 base units.
GenesisCheck checkGenesis(const GenesisDraft& d);

// zslp_genesis parameters (one object). With no baton the supply is fixed for good.
nlohmann::json genesisParams(const GenesisDraft& d, const GenesisCheck& check, bool dryRun);

QString createExplanation();
QString genesisReviewText(const GenesisDraft& d, const GenesisCheck& check, const TxPlan& plan);
QString genesisResultText(const GenesisDraft& d, const GenesisCheck& check, const TxPlan& plan);

// ---- errors -----------------------------------------------------------------------------------

// The daemon's message, with a plain-language lead in front when it is one the user can act on.
QString friendlyError(const QString& daemonMessage);

} // namespace tokens

#endif // ZCL_TOKENSSENDMODEL_H
