// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokensmodel.h"

#include <QObject>

namespace tokens {

using json = nlohmann::json;

static QString str(const json& o, const char* key)
{
    auto it = o.find(key);
    if (it == o.end() || !it->is_string())
        return QString();
    return QString::fromStdString(it->get<std::string>());
}

static int num(const json& o, const char* key, int dflt)
{
    auto it = o.find(key);
    if (it == o.end() || !it->is_number())
        return dflt;
    return it->get<int>();
}

IndexStatus parseIndexInfo(const json& result)
{
    IndexStatus s;
    if (!result.is_object())
        return s;
    auto en = result.find("enabled");
    if (en == result.end() || !en->is_boolean() || !en->get<bool>())
        return s;
    s.enabled = true;
    auto sy = result.find("synced");
    s.synced = sy != result.end() && sy->is_boolean() && sy->get<bool>();
    auto pr = result.find("progress");
    if (pr != result.end() && pr->is_number()) {
        double p = pr->get<double>();
        s.progress = p < 0.0 ? 0.0 : p > 1.0 ? 1.0 : p;
    }
    s.indexedHeight = num(result, "indexedheight", -1);
    s.chainHeight = num(result, "chainheight", -1);
    s.error = str(result, "error");
    return s;
}

bool parseSnapshot(const json& result, Snapshot* out)
{
    if (!out)
        return false;
    *out = Snapshot();
    if (!result.is_object())
        return false;
    auto outs = result.find("outputs");
    auto bals = result.find("balances");
    if (outs == result.end() || !outs->is_array() || bals == result.end() || !bals->is_array())
        return false;
    auto sy = result.find("synced");
    out->synced = sy != result.end() && sy->is_boolean() && sy->get<bool>();
    for (const json& o : *outs) {
        if (!o.is_object())
            continue;
        Output r;
        r.txid = str(o, "txid");
        r.address = str(o, "address");
        r.tokenId = str(o, "tokenid");
        r.ticker = str(o, "ticker");
        r.role = str(o, "role");
        r.amount = str(o, "amount");
        if (r.txid.isEmpty() || r.tokenId.isEmpty() || r.amount.isEmpty() || o.find("vout") == o.end())
            continue; // an incomplete row is not shown rather than shown wrong
        r.vout = num(o, "vout", 0);
        r.confirmations = num(o, "confirmations", 0);
        auto p = o.find("protected");
        // the daemon says "protected" for every output the wallet will not spend as ordinary funds;
        // an absent field is treated as protected, never the other way round
        r.isProtected = p == o.end() || !p->is_boolean() || p->get<bool>();
        out->outputs.push_back(r);
    }
    for (const json& b : *bals) {
        if (!b.is_object())
            continue;
        Balance r;
        r.tokenId = str(b, "tokenid");
        r.ticker = str(b, "ticker");
        r.amount = str(b, "amount");
        r.decimals = num(b, "decimals", 0);
        if (r.tokenId.isEmpty() || r.amount.isEmpty())
            continue;
        out->balances.push_back(r);
    }
    return true;
}

QString statusLine(const IndexStatus& s)
{
    if (!s.enabled)
        return QObject::tr("The token index is switched off.");
    if (!s.error.isEmpty())
        return QObject::tr("The token index has a problem and will retry: %1").arg(s.error);
    if (s.synced) {
        if (s.indexedHeight >= 0)
            return QObject::tr("Token index is up to date (block %1).").arg(s.indexedHeight);
        return QObject::tr("Token index is up to date.");
    }
    const int pct = static_cast<int>(s.progress * 100.0);
    if (s.indexedHeight >= 0 && s.chainHeight >= 0)
        return QObject::tr("Token index is still building: %1% (block %2 of %3). Balances may be incomplete.")
            .arg(pct).arg(s.indexedHeight).arg(s.chainHeight);
    return QObject::tr("Token index is still building: %1%. Balances may be incomplete.").arg(pct);
}

QString protectedNotice()
{
    return QObject::tr(
        "These are ZSLP tokens your wallet holds. Each token sits on a small ZCL output. Those outputs are "
        "protected: your wallet never spends them as ordinary funds, because that would destroy the tokens. "
        "To move them on purpose use Send tokens below; ordinary ZCL sends never touch them.");
}

QString roleText(const QString& role)
{
    if (role == QLatin1String("mintbaton"))
        return QObject::tr("Mint baton (right to create more)");
    return QObject::tr("Tokens");
}

QString displayTicker(const QString& ticker, const QString& tokenId)
{
    // A ticker is chain text. Format and control characters (the right-to-left override U+202E and its kin) would
    // visually reorder what is shown after it, such as the balance in a picker row: drop them.
    QString clean;
    clean.reserve(ticker.size());
    for (QChar ch : ticker) {
        const QChar::Category cat = ch.category();
        if (cat == QChar::Other_Format || cat == QChar::Other_Control || cat == QChar::Separator_Line ||
            cat == QChar::Separator_Paragraph)
            continue;
        clean.append(ch);
    }
    if (!clean.trimmed().isEmpty())
        return clean;
    return tokenId.left(8) + QStringLiteral("...");
}

QString shortTokenId(const QString& tokenId)
{
    return tokenId.length() > 16 ? tokenId.left(8) + QStringLiteral("...") + tokenId.right(8) : tokenId;
}

QString tokenLabel(const QString& ticker, const QString& tokenId)
{
    // Anyone can create a token with any ticker: only the id tells two of them apart.
    return displayTicker(ticker, tokenId) + QStringLiteral(" [") + shortTokenId(tokenId) + QLatin1Char(']');
}

QString shortOutpoint(const QString& txid, int vout)
{
    QString t = txid.length() > 16 ? txid.left(8) + QStringLiteral("...") + txid.right(8) : txid;
    return t + QLatin1Char(':') + QString::number(vout);
}

} // namespace tokens
