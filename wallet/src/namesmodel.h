// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Pure logic of "pay to a name": how a Pay-to entry is recognised as a name, how the daemon's
// znam_resolve / znam_listmine / znam_getindexinfo replies are read, and what the user is told about an answer.
// No widgets, no network: tests/tst_names.cpp links this file alone.
//
// A name is never sent. It is resolved (locally, through the daemon's index) to an ADDRESS that the user checks,
// and the transaction is built with that address exactly as if it had been pasted. Nothing name-related reaches the
// transaction or the z_sendmany parameters.
//
// Syntax. An entry is a name only when it starts with '@'. '@' cannot occur in any ZClassic address, so a name can
// never be mistaken for one, and an address can never be mistaken for a name. After the '@' the name must be exactly
// what the registry allows: 1-63 characters a-z 0-9 and '-', no leading or trailing '-'. Upper case ASCII is folded
// to lower case (the registry has no upper case names, so "@Alice" can only mean "@alice"). Everything else is
// refused, in particular every non-ASCII character: look-alike letters of other scripts, full-width forms, and
// zero-width characters are not "normalised into" a name, they are rejected with a message.
#ifndef ZCL_NAMESMODEL_H
#define ZCL_NAMESMODEL_H

#include <QString>
#include <QStringList>
#include <QVector>

#include "3rdparty/json/json.hpp"

namespace names {

// ---- the Pay-to entry ---------------------------------------------------------------------------------------------

enum class InputKind {
    NotAName,  // does not start with '@': the field behaves exactly as it always did
    Name,      // a well-formed name, in `name` (lower case, without '@')
    Rejected   // starts with '@' but is not a well-formed name: `problem` says why
};

struct Parsed {
    InputKind kind = InputKind::NotAName;
    QString name;       // Name only
    bool folded = false; // upper case letters were folded to lower case
    QString problem;    // Rejected only
};

Parsed parsePayTo(const QString& fieldText);

// 1-63 of a-z 0-9 '-', no leading or trailing '-'. No folding.
bool isValidName(const QString& name);

// ---- the daemon's answers -----------------------------------------------------------------------------------------

struct IndexStatus {
    bool enabled = false;   // the daemon runs with -znamindex=1
    bool synced = false;
    double progress = 0.0;
    int indexedHeight = -1;
    int chainHeight = -1;
    QString error;
};

// `result` is the "result" member of a znam_getindexinfo reply. Anything but an object with enabled == true is "not enabled".
IndexStatus parseIndexInfo(const nlohmann::json& result);

struct Record {
    QString type;
    QString value;
    bool primary = false;
    bool payable = false;
    QString kind;
    int height = 0;
    QString txid;
};

struct Resolution {
    bool resolved = false;
    QString errorCode;      // NAME_ABSENT, NAME_MALFORMED, NAME_NO_SUCH_TARGET, ... when not resolved
    QString error;
    QString name;
    QString address;        // only when payable
    QString value;
    QString type;
    QString kind;           // transparent | sapling | sprout | none
    bool payable = false;
    int setHeight = 0;      // the block that set the address (or the owner)
    QString setTxid;
    bool setByRecord = false;
    int blocksSinceChange = 0;
    bool changedRecently = false;
    int recentBlocks = 0;
    QString owner;
    int registeredHeight = 0;
    QString registeredTxid;
    int expiryHeight = 0;
    bool expired = false;
    QStringList warnings;   // the daemon's own wording
    QVector<Record> records;
    bool indexSynced = false;
    int tipHeight() const { return setHeight + blocksSinceChange; }
    int registrationAgeBlocks() const { return tipHeight() - registeredHeight; }
};

// `result` is the "result" member of a znam_resolve reply. False (and *out cleared) when it is not a reply this code
// understands. A well-formed "not resolved" reply returns true with resolved == false.
bool parseResolution(const nlohmann::json& result, Resolution* out);

struct OwnedName {
    QString name;
    QString owner;
    QString type;
    QString value;
    int registeredHeight = 0;
    bool spendable = false;
};

// `result` is the "result" member of a znam_listmine reply.
bool parseOwnedNames(const nlohmann::json& result, QVector<OwnedName>* out);

// ---- what the user is told ----------------------------------------------------------------------------------------

struct Assessment {
    bool usable = false;          // an address the user may be asked to confirm
    bool strongWarning = false;   // changed recently, or registered recently, or the registration lapsed
    QString headline;             // one line
    QStringList warnings;         // plain language, most important first
    QString info;                 // registration facts, plain language
};

// `recentBlocks` is the window the daemon used (Resolution::recentBlocks); a name REGISTERED inside it is flagged
// too: a brand new name is the usual shape of a look-alike.
Assessment assess(const Resolution& r);

// The text under "Pay to" for a name that does not resolve.
QString failureText(const Resolution& r);

// The two answers name the same address, set by the same transaction: the check made again just before sending.
bool sameAnswer(const Resolution& a, const Resolution& b);

// "ab12cd34...ef56"
QString shortTxid(const QString& txid);

} // namespace names

#endif // ZCL_NAMESMODEL_H
