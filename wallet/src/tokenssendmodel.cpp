// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokenssendmodel.h"

#include <QObject>
#include <QStringList>

#include <cmath>
#include <limits>

namespace tokens {

using json = nlohmann::json;

namespace {

const quint64 kMaxQuantity = 9223372036854775807ULL;   // 2^63-1: more is "unknown" to the token rules
const quint64 kMaxSupply = 2100000000000000ULL;        // the largest first supply (Z23's creation rule)
const qint64 kTokenDustZat = 546;

bool isDigit(QChar c) { return c.unicode() >= '0' && c.unicode() <= '9'; }
bool isAlnum(QChar c)
{
    const ushort u = c.unicode();
    return isDigit(c) || (u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z');
}

QString str(const json& o, const char* key)
{
    auto it = o.find(key);
    if (it == o.end() || !it->is_string())
        return QString();
    return QString::fromStdString(it->get<std::string>());
}

// digits -> quint64, false on overflow
bool digitsToU64(const QString& digits, quint64* out)
{
    quint64 v = 0;
    for (QChar c : digits) {
        const unsigned d = static_cast<unsigned>(c.unicode() - '0');
        if (v > (std::numeric_limits<quint64>::max() - d) / 10)
            return false;
        v = v * 10 + d;
    }
    *out = v;
    return true;
}

// a balance string from the daemon ("899.50") -> base units; false when it does not parse
bool balanceUnits(const QString& s, int decimals, quint64* out)
{
    const int dot = s.indexOf(QLatin1Char('.'));
    const QString whole = dot < 0 ? s : s.left(dot);
    QString frac = dot < 0 ? QString() : s.mid(dot + 1);
    if (whole.isEmpty() || frac.size() > decimals)
        return false;
    for (QChar c : whole + frac)
        if (!isDigit(c))
            return false;
    frac += QString(decimals - frac.size(), QLatin1Char('0'));
    return digitsToU64(whole + frac, out);
}

} // namespace

QVector<TokenChoice> choicesFromSnapshot(const Snapshot& snap)
{
    QVector<TokenChoice> v;
    for (const Balance& b : snap.balances) {
        quint64 units = 0;
        if (!balanceUnits(b.amount, b.decimals, &units) || units == 0)
            continue; // nothing to send
        TokenChoice c;
        c.tokenId = b.tokenId;
        c.ticker = b.ticker;
        c.decimals = b.decimals;
        c.balance = b.amount;
        v.push_back(c);
    }
    return v;
}

AmountResult parseAmount(const QString& textIn, int decimals)
{
    AmountResult r;
    const QString text = textIn.trimmed();
    if (text.isEmpty()) {
        r.error = QObject::tr("Enter an amount.");
        return r;
    }
    int dot = -1;
    for (int i = 0; i < text.size(); i++) {
        const QChar c = text[i];
        if (isDigit(c))
            continue;
        if (c == QLatin1Char('.') && dot < 0) {
            dot = i;
            continue;
        }
        r.error = c == QLatin1Char(',')
            ? QObject::tr("Use a decimal point (.), not a comma.")
            : QObject::tr("The amount may contain only digits and one decimal point.");
        return r;
    }
    QString whole = dot < 0 ? text : text.left(dot);
    const QString frac = dot < 0 ? QString() : text.mid(dot + 1);
    if (whole.isEmpty() && frac.isEmpty()) {
        r.error = QObject::tr("Enter an amount.");
        return r;
    }
    if (whole.isEmpty())
        whole = QStringLiteral("0");
    if (decimals < 0 || decimals > 18) {
        r.error = QObject::tr("This token has an unusable number of decimal places.");
        return r;
    }
    if (frac.size() > decimals) {
        r.error = decimals == 0
            ? QObject::tr("This token has no decimal places. Enter a whole number.")
            : QObject::tr("This token has %1 decimal places, and %2 has more. Nothing is rounded: shorten the amount.")
                  .arg(decimals).arg(text);
        return r;
    }
    quint64 v = 0;
    if (!digitsToU64(whole + frac + QString(decimals - frac.size(), QLatin1Char('0')), &v) || v > kMaxQuantity) {
        r.error = QObject::tr("That amount is too large.");
        return r;
    }
    if (v == 0) {
        r.error = QObject::tr("The amount must be greater than zero.");
        return r;
    }
    int lead = 0;
    while (lead < whole.size() - 1 && whole[lead] == QLatin1Char('0'))
        lead++;
    r.ok = true;
    r.units = v;
    r.normalized = whole.mid(lead) + (frac.isEmpty() ? QString() : QStringLiteral(".") + frac);
    return r;
}

QString formatUnits(quint64 units, int decimals)
{
    if (decimals <= 0 || decimals > 18)
        return QString::number(units);
    quint64 scale = 1;
    for (int i = 0; i < decimals; i++)
        scale *= 10;
    const QString frac = QString::number(units % scale).rightJustified(decimals, QLatin1Char('0'));
    return QString::number(units / scale) + QLatin1Char('.') + frac;
}

QString checkRecipient(const QString& addressIn)
{
    const QString a = addressIn.trimmed();
    if (a.isEmpty())
        return QObject::tr("Enter the recipient's address.");
    if (a[0] == QLatin1Char('z'))
        return QObject::tr("Tokens can only be sent to a transparent address (it starts with t). Shielded (z) addresses cannot hold tokens.");
    static const QString base58 = QStringLiteral("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    bool ok = a[0] == QLatin1Char('t') && a.size() == 35;
    for (QChar c : a)
        ok = ok && base58.contains(c);
    if (!ok)
        return QObject::tr("That does not look like a ZClassic transparent address (it starts with t and is 35 characters long).");
    return QString();
}

SendCheck checkSend(const TokenChoice& token, const QString& address, const QString& amountText)
{
    SendCheck c;
    if (token.tokenId.isEmpty()) {
        c.error = QObject::tr("Choose a token to send.");
        return c;
    }
    const QString addrProblem = checkRecipient(address);
    if (!addrProblem.isEmpty()) {
        c.error = addrProblem;
        return c;
    }
    const AmountResult a = parseAmount(amountText, token.decimals);
    if (!a.ok) {
        c.error = a.error;
        return c;
    }
    quint64 have = 0;
    if (balanceUnits(token.balance, token.decimals, &have) && a.units > have) {
        c.error = QObject::tr("You hold %1 %2 in confirmed outputs; %3 is more than that.")
                      .arg(token.balance, displayTicker(token.ticker, token.tokenId), a.normalized);
        return c;
    }
    c.ok = true;
    c.units = a.units;
    c.amount = a.normalized;
    c.address = address.trimmed();
    return c;
}

json sendParams(const TokenChoice& token, const SendCheck& check, bool dryRun)
{
    json recipient = {{"address", check.address.toStdString()}, {"amount", check.amount.toStdString()}};
    return json::array({token.tokenId.toStdString(), json::array({recipient}), 1, nullptr, dryRun});
}

QString formatZcl(qint64 zat)
{
    const bool neg = zat < 0;
    const quint64 a = neg ? static_cast<quint64>(-(zat + 1)) + 1 : static_cast<quint64>(zat);
    return QString(neg ? "-" : "") + QString::number(a / 100000000ULL) + QLatin1Char('.') +
           QString::number(a % 100000000ULL).rightJustified(8, QLatin1Char('0'));
}

TxPlan parseTxPlan(const json& result)
{
    TxPlan p;
    if (!result.is_object() || str(result, "txid").isEmpty()) {
        p.error = QObject::tr("The wallet answered with something this window does not understand.");
        return p;
    }
    p.kind = str(result, "type");
    p.txid = str(result, "txid");
    p.tokenId = str(result, "tokenid");
    p.amount = str(result, "amount");
    p.tokenChange = str(result, "tokenchange");
    p.changeAddress = str(result, "changeaddress");
    auto b = result.find("broadcast");
    p.broadcast = b != result.end() && b->is_boolean() && b->get<bool>();
    auto ti = result.find("tokeninputs");
    p.tokenInputs = (ti != result.end() && ti->is_number_integer()) ? ti->get<int>() : 0;
    auto fee = result.find("fee");
    if (fee != result.end() && fee->is_number()) {
        const double f = fee->get<double>();
        if (f >= 0 && f < 1000)
            p.feeZat = static_cast<qint64>(std::llround(f * 100000000.0)); // a ZCL fee, to whole zatoshi
    }
    p.ok = true;
    return p;
}

QString sendReviewText(const TokenChoice& token, const SendCheck& check, const TxPlan& plan)
{
    const QString t = displayTicker(token.ticker, token.tokenId);
    QStringList lines;
    lines << QObject::tr("You are about to send %1 %2").arg(check.amount, t);
    lines << QObject::tr("to %1").arg(check.address);
    lines << QString();
    bool change = false;
    for (QChar ch : plan.tokenChange)
        change = change || (ch.unicode() >= '1' && ch.unicode() <= '9');
    if (change) {
        lines << QObject::tr("Token change: the remaining %1 %2 returns to you, at %3. Nothing is burned.")
                     .arg(plan.tokenChange, t, plan.changeAddress.isEmpty() ? QObject::tr("your address") : plan.changeAddress);
    } else {
        lines << QObject::tr("This sends everything those outputs held, so there is no token change.");
    }
    lines << QObject::tr("Network fee: %1 ZCL. It is paid from your ordinary ZCL, never from tokens.")
                 .arg(formatZcl(plan.feeZat));
    lines << QObject::tr("The recipient's tokens ride on a small output of %1 ZCL that comes out of your ZCL.")
                 .arg(formatZcl(kTokenDustZat));
    lines << QObject::tr("It uses %1 of your token output(s).").arg(plan.tokenInputs);
    lines << QString();
    lines << QObject::tr("Sending cannot be undone. Check the address: tokens sent to a wrong address are gone.");
    return lines.join(QLatin1Char('\n'));
}

QString sendResultText(const TokenChoice& token, const SendCheck& check, const TxPlan& plan)
{
    const QString t = displayTicker(token.ticker, token.tokenId);
    return QObject::tr("Sent %1 %2 to %3.\n\nTransaction: %4\nFee: %5 ZCL\n\n"
                       "It is on its way to the network. The tokens count as received after the transaction is "
                       "confirmed in a block; until then your change is not spendable either.")
        .arg(check.amount, t, check.address, plan.txid, formatZcl(plan.feeZat));
}

// ---- creating a token --------------------------------------------------------------------------

GenesisCheck checkGenesis(const GenesisDraft& d)
{
    GenesisCheck c;
    const QString ticker = d.ticker.trimmed();
    if (ticker.isEmpty() || ticker.size() > 10) {
        c.error = QObject::tr("The ticker must be 1 to 10 letters or digits.");
        return c;
    }
    for (QChar ch : ticker)
        if (!isAlnum(ch)) {
            c.error = QObject::tr("The ticker may only contain the letters A-Z and the digits 0-9.");
            return c;
        }
    const QString name = d.name.trimmed();
    if (name.isEmpty() || name.size() > 64) {
        c.error = QObject::tr("The name must be 1 to 64 characters.");
        return c;
    }
    for (QChar ch : name)
        if (!isAlnum(ch) && ch != QLatin1Char(' ') && ch != QLatin1Char('-') && ch != QLatin1Char('_') &&
            ch != QLatin1Char('.') && ch != QLatin1Char('/')) {
            c.error = QObject::tr("The name may only contain letters, digits, spaces and - _ . /");
            return c;
        }
    bool decOk = !d.decimals.trimmed().isEmpty();
    for (QChar ch : d.decimals.trimmed())
        decOk = decOk && isDigit(ch);
    const int dec = decOk ? d.decimals.trimmed().toInt(&decOk) : 0;
    if (!decOk || dec < 0 || dec > 8) {
        c.error = QObject::tr("Decimal places must be a number from 0 to 8.");
        return c;
    }
    const AmountResult q = parseAmount(d.quantity, dec);
    if (!q.ok) {
        c.error = QObject::tr("First supply: %1").arg(q.error);
        return c;
    }
    if (q.units > kMaxSupply) {
        c.error = QObject::tr("The first supply is too large: the most allowed is %1 (that is 2,100,000,000,000,000 smallest units).")
                      .arg(formatUnits(kMaxSupply, dec));
        return c;
    }
    const QString url = d.url.trimmed();
    if (url.size() > 255) {
        c.error = QObject::tr("The document link is longer than 255 characters.");
        return c;
    }
    for (QChar ch : url)
        if (ch.unicode() < 0x21 || ch.unicode() > 0x7e) {
            c.error = QObject::tr("The document link may only contain visible ASCII characters, without spaces.");
            return c;
        }
    const QString hash = d.hash.trimmed();
    if (!hash.isEmpty()) {
        bool hex = hash.size() == 64;
        for (QChar ch : hash)
            hex = hex && (isDigit(ch) || (ch.unicode() >= 'a' && ch.unicode() <= 'f') || (ch.unicode() >= 'A' && ch.unicode() <= 'F'));
        if (!hex) {
            c.error = QObject::tr("The document hash must be 64 hexadecimal characters, or empty.");
            return c;
        }
    }
    c.ok = true;
    c.decimals = dec;
    c.units = q.units;
    c.quantity = q.normalized;
    return c;
}

json genesisParams(const GenesisDraft& d, const GenesisCheck& check, bool dryRun)
{
    json o = {{"ticker", d.ticker.trimmed().toStdString()},
              {"name", d.name.trimmed().toStdString()},
              {"decimals", check.decimals},
              {"initialquantity", check.quantity.toStdString()}};
    if (!d.url.trimmed().isEmpty())
        o["documenturl"] = d.url.trimmed().toStdString();
    if (!d.hash.trimmed().isEmpty())
        o["documenthash"] = d.hash.trimmed().toLower().toStdString();
    if (!d.baton)
        o["batonaddress"] = nullptr; // no baton: the supply is fixed for good
    if (dryRun)
        o["dryrun"] = true;
    return json::array({o});
}

QString createExplanation()
{
    return QObject::tr(
        "Advanced. A ZSLP token is a record on the ZClassic chain: you choose a ticker, a name, how many "
        "decimal places it has and how many exist at the start. The first supply, and optionally a \"mint baton\", "
        "are placed on small ZCL outputs at new addresses of this wallet.\n\n"
        "Whoever holds the mint baton can create more tokens later. If you do not keep a baton, the supply is "
        "fixed for good and nobody, you included, can ever create more.\n\n"
        "A token is identified by its id (the creating transaction), not by its ticker: anyone can make another "
        "token with the same ticker. Creating a token costs a small ZCL fee and cannot be undone.");
}

QString genesisReviewText(const GenesisDraft& d, const GenesisCheck& check, const TxPlan& plan)
{
    QStringList lines;
    lines << QObject::tr("You are about to create the token %1 (%2).").arg(d.ticker.trimmed(), d.name.trimmed());
    lines << QObject::tr("First supply: %1 %2 (%3 decimal places). All of it goes to a new address of this wallet.")
                 .arg(check.quantity, d.ticker.trimmed()).arg(check.decimals);
    lines << (d.baton ? QObject::tr("You keep the mint baton: you can create more of this token later. Keep this wallet backed up; "
                                    "losing the baton means nobody can ever create more.")
                      : QObject::tr("No mint baton is created: the supply is fixed for good at the amount above."));
    lines << QObject::tr("Network fee: %1 ZCL, paid from your ordinary ZCL. The token outputs hold %2 ZCL each, also yours.")
                 .arg(formatZcl(plan.feeZat), formatZcl(kTokenDustZat));
    lines << QString();
    lines << QObject::tr("Creating a token cannot be undone.");
    return lines.join(QLatin1Char('\n'));
}

QString genesisResultText(const GenesisDraft& d, const GenesisCheck& check, const TxPlan& plan)
{
    return QObject::tr("Created the token %1 with a first supply of %2.\n\nToken id: %3\nFee: %4 ZCL\n\n"
                       "The token exists once the transaction is confirmed in a block; it then shows up in your balances.")
        .arg(d.ticker.trimmed(), check.quantity, plan.tokenId.isEmpty() ? plan.txid : plan.tokenId, formatZcl(plan.feeZat));
}

// ---- errors ------------------------------------------------------------------------------------

QString friendlyError(const QString& m)
{
    QString lead;
    if (m.contains(QLatin1String("walletpassphrase")) || m.contains(QLatin1String("wallet passphrase")))
        lead = QObject::tr("Your wallet is locked. Unlock it, then try again.");
    else if (m.contains(QLatin1String("not enough ordinary ZCL")))
        lead = QObject::tr("You do not have enough ordinary ZCL to pay the fee. Your token outputs are never used for the fee; "
                           "add some ZCL to this wallet and try again.");
    else if (m.contains(QLatin1String("insufficient confirmed token balance")))
        lead = QObject::tr("You do not hold enough of this token in confirmed outputs. Tokens that have just arrived, or that you "
                           "just sent as change, can be sent again after one confirmation.");
    else if (m.contains(QLatin1String("not synced yet")))
        lead = QObject::tr("The token index is still catching up with the chain. Wait a moment and try again.");
    else if (m.contains(QLatin1String("does not hold the confirmed mint baton")))
        lead = QObject::tr("This wallet does not hold the mint baton of that token.");
    else if (m.contains(QLatin1String("token index is disabled")))
        lead = QObject::tr("The token index is switched off in this node.");
    if (lead.isEmpty())
        return m;
    return lead + QStringLiteral("\n\n") + QObject::tr("Details: %1").arg(m);
}

} // namespace tokens
