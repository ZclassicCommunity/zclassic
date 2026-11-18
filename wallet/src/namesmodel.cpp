// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "namesmodel.h"

#include <QObject>

namespace names {

using json = nlohmann::json;

namespace {

QString str(const json& o, const char* key)
{
    auto it = o.find(key);
    if (it == o.end() || !it->is_string())
        return QString();
    return QString::fromStdString(it->get<std::string>());
}

int num(const json& o, const char* key, int dflt)
{
    auto it = o.find(key);
    if (it == o.end() || !it->is_number())
        return dflt;
    return it->get<int>();
}

bool flag(const json& o, const char* key)
{
    auto it = o.find(key);
    return it != o.end() && it->is_boolean() && it->get<bool>();
}

// Only ASCII white space around the entry is ignored. QString::trimmed() would also drop a no-break space and the
// other Unicode spaces, which are exactly the characters a look-alike entry is made of.
QString trimAscii(const QString& s)
{
    int b = 0, e = s.size();
    auto sp = [](QChar c) { return c == QLatin1Char(' ') || c == QLatin1Char('\t') || c == QLatin1Char('\n') || c == QLatin1Char('\r'); };
    while (b < e && sp(s.at(b)))
        b++;
    while (e > b && sp(s.at(e - 1)))
        e--;
    return s.mid(b, e - b);
}

QString tr(const char* s) { return QObject::tr(s); }

} // namespace

bool isValidName(const QString& name)
{
    const int n = name.size();
    if (n < 1 || n > 63)
        return false;
    if (name.at(0) == QLatin1Char('-') || name.at(n - 1) == QLatin1Char('-'))
        return false;
    for (int i = 0; i < n; i++) {
        const ushort c = name.at(i).unicode();
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

Parsed parsePayTo(const QString& fieldText)
{
    Parsed p;
    const QString t = trimAscii(fieldText);
    if (t.isEmpty() || t.at(0) != QLatin1Char('@'))
        return p; // NotAName: the field is an address field, as before
    p.kind = InputKind::Rejected;
    const QString body = t.mid(1);
    if (body.isEmpty()) {
        p.problem = tr("Type a name after the @.");
        return p;
    }
    QString out;
    out.reserve(body.size());
    for (int i = 0; i < body.size(); i++) {
        const ushort c = body.at(i).unicode();
        if (c > 0x7f) {
            p.problem = tr("A name uses only the plain letters a-z, digits and hyphens. This one contains a character from "
                           "outside that set (look-alike letters of other alphabets are not accepted).");
            return p;
        }
        if (c >= 'A' && c <= 'Z') {
            out.append(QChar(c + ('a' - 'A')));
            p.folded = true;
        } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
            out.append(QChar(c));
        } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            p.problem = tr("A name has no spaces.");
            return p;
        } else {
            p.problem = tr("A name uses only the letters a-z, digits and hyphens.");
            return p;
        }
    }
    if (out.size() > 63) {
        p.problem = tr("A name is at most 63 characters.");
        return p;
    }
    if (out.startsWith(QLatin1Char('-')) || out.endsWith(QLatin1Char('-'))) {
        p.problem = tr("A name does not start or end with a hyphen.");
        return p;
    }
    p.kind = InputKind::Name;
    p.name = out;
    return p;
}

IndexStatus parseIndexInfo(const json& result)
{
    IndexStatus s;
    if (!result.is_object() || !flag(result, "enabled"))
        return s;
    s.enabled = true;
    s.synced = flag(result, "synced");
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

bool parseResolution(const json& result, Resolution* out)
{
    if (!out)
        return false;
    *out = Resolution();
    if (!result.is_object())
        return false;
    auto rs = result.find("resolved");
    if (rs == result.end() || !rs->is_boolean())
        return false;
    out->name = str(result, "name");
    out->resolved = rs->get<bool>();
    if (!out->resolved) {
        out->errorCode = str(result, "error_code");
        out->error = str(result, "error");
        return !out->errorCode.isEmpty();
    }
    out->value = str(result, "value");
    out->type = str(result, "type");
    out->kind = str(result, "kind");
    out->payable = flag(result, "payable");
    out->address = out->payable ? str(result, "address") : QString();
    out->setHeight = num(result, "set_height", 0);
    out->setTxid = str(result, "set_txid");
    out->setByRecord = flag(result, "set_by_record");
    out->blocksSinceChange = num(result, "blocks_since_change", 0);
    out->changedRecently = flag(result, "changed_recently");
    out->recentBlocks = num(result, "recent_change_blocks", 0);
    out->owner = str(result, "owner");
    out->registeredHeight = num(result, "registered_height", 0);
    out->registeredTxid = str(result, "registered_txid");
    out->expiryHeight = num(result, "expiry_height", 0);
    out->expired = flag(result, "expired");
    auto w = result.find("warnings");
    if (w != result.end() && w->is_array())
        for (const auto& e : *w)
            if (e.is_string())
                out->warnings << QString::fromStdString(e.get<std::string>());
    auto recs = result.find("records");
    if (recs != result.end() && recs->is_array())
        for (const auto& e : *recs) {
            if (!e.is_object())
                continue;
            Record r;
            r.type = str(e, "type");
            r.value = str(e, "value");
            r.primary = flag(e, "primary");
            r.payable = flag(e, "payable");
            r.kind = str(e, "kind");
            r.height = num(e, "height", 0);
            r.txid = str(e, "txid");
            out->records.push_back(r);
        }
    auto ix = result.find("index");
    if (ix != result.end() && ix->is_object())
        out->indexSynced = flag(*ix, "synced");
    // A resolution that claims to be payable must carry an address; one that does not is treated as not payable.
    if (out->payable && out->address.isEmpty())
        out->payable = false;
    return true;
}

bool parseOwnedNames(const json& result, QVector<OwnedName>* out)
{
    if (!out)
        return false;
    out->clear();
    if (!result.is_array())
        return false;
    for (const auto& e : result) {
        if (!e.is_object())
            continue;
        OwnedName n;
        n.name = str(e, "name");
        if (!isValidName(n.name))
            continue;
        n.owner = str(e, "owner");
        n.type = str(e, "type");
        n.value = str(e, "value");
        n.registeredHeight = num(e, "registeredheight", 0);
        n.spendable = flag(e, "spendable");
        out->push_back(n);
    }
    return true;
}

QString shortTxid(const QString& txid)
{
    if (txid.size() <= 16)
        return txid;
    return txid.left(8) + QStringLiteral("...") + txid.right(8);
}

Assessment assess(const Resolution& r)
{
    Assessment a;
    if (!r.resolved) {
        a.headline = failureText(r);
        return a;
    }
    if (!r.payable) {
        a.headline = tr("@%1 has no address this wallet can pay.").arg(r.name);
        a.warnings << (r.value.isEmpty()
                           ? tr("The name carries no usable address record.")
                           : tr("Its record (%1) is not a valid ZClassic address, so it is not offered for payment.").arg(r.type));
        return a;
    }
    a.usable = true;
    a.headline = tr("@%1 resolves to this address. Check it before you pay.").arg(r.name);

    if (r.changedRecently) {
        a.strongWarning = true;
        a.warnings << tr("WARNING: the %2 of @%1 changed %3 block(s) ago (block %4, transaction %5). If you did not expect a "
                         "change, the owner's key may have been taken over. Confirm this address with the recipient through "
                         "another channel before you pay.")
                          .arg(r.name, r.setByRecord ? tr("address record") : tr("address or owner"))
                          .arg(r.blocksSinceChange)
                          .arg(r.setHeight)
                          .arg(shortTxid(r.setTxid));
    }
    const int age = r.registrationAgeBlocks();
    if (r.recentBlocks > 0 && age >= 0 && age < r.recentBlocks && !r.changedRecently) {
        a.strongWarning = true;
        a.warnings << tr("WARNING: @%1 was registered only %2 block(s) ago. A brand-new name is the usual shape of a look-alike: "
                         "check the spelling letter by letter and confirm the address with the recipient.")
                          .arg(r.name)
                          .arg(age);
    }
    if (r.expired) {
        a.strongWarning = true;
        a.warnings << tr("The registration term of this name has lapsed. The name still resolves, and anyone may renew it.");
    }
    for (const QString& w : r.warnings) {
        // the daemon's wording of the two above is already covered; keep any other warning it adds
        if (w.contains(QLatin1String("changed")) || w.contains(QLatin1String("lapsed")))
            continue;
        a.warnings << w;
    }
    a.info = tr("Registered at block %1 (%2 blocks ago) by %3. This address was set at block %4 (transaction %5).")
                 .arg(QString::number(r.registeredHeight), QString::number(age < 0 ? 0 : age),
                      r.owner.isEmpty() ? tr("an unknown owner") : r.owner, // chain text: substituted in one pass so a "%4" in it stays literal
                      QString::number(r.setHeight), shortTxid(r.setTxid));
    return a;
}

QString failureText(const Resolution& r)
{
    if (r.resolved)
        return QString();
    if (r.errorCode == QLatin1String("NAME_ABSENT"))
        return tr("No one has registered @%1 (as far as this node's name index has seen).").arg(r.name);
    if (r.errorCode == QLatin1String("NAME_MALFORMED"))
        return tr("That is not a valid name.");
    if (r.errorCode == QLatin1String("NAME_NO_SUCH_TARGET"))
        return tr("@%1 is registered but has no address that can be paid.").arg(r.name);
    if (!r.error.isEmpty())
        return r.error;
    return tr("The name could not be looked up.");
}

bool sameAnswer(const Resolution& a, const Resolution& b)
{
    return a.resolved && b.resolved && a.payable && b.payable && a.address == b.address && a.setTxid == b.setTxid &&
           a.owner == b.owner;
}

} // namespace names
