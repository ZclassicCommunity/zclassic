// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Logic and widget tests of "pay to a name": the Pay-to entry grammar (normalisation, look-alikes), the reading of
// the daemon's replies, the "changed recently" and "registered recently" warnings, and the NamePayBox that turns a
// confirmed answer into an address. No daemon: the lookup is a fake.
//
//   cd wallet/tests && qmake names.pro && make && QT_QPA_PLATFORM=offscreen ./tst_names

#include <QtTest>
#include <QCheckBox>
#include <QLabel>
#include <QWidget>

#include <functional>

#include "namepaybox.h"
#include "namesmodel.h"

using json = nlohmann::json;
using namespace names;

namespace {

const char* kAddrT = "t1cEFAvXjAZ1JpCCCPrUrcYQr5Kj9FRSXYa"; // text only: the model never decodes addresses

json resolvedReply(const char* name = "alice", const char* addr = kAddrT, int setHeight = 1000, int sinceChange = 500,
                   bool recent = false, int regHeight = 900, const char* txid = "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44")
{
    return json{{"name", name},
                {"resolved", true},
                {"value", addr},
                {"type", "t-address"},
                {"kind", "transparent"},
                {"payable", true},
                {"address", addr},
                {"set_height", setHeight},
                {"set_txid", txid},
                {"set_by_record", false},
                {"blocks_since_change", sinceChange},
                {"changed_recently", recent},
                {"recent_change_blocks", 100},
                {"owner", "t1OwnerOwnerOwnerOwnerOwnerOwner12"},
                {"registered_height", regHeight},
                {"registered_txid", "00"},
                {"expiry_height", 900000},
                {"expired", false},
                {"warnings", json::array()},
                {"records", json::array()},
                {"index", {{"synced", true}}}};
}

json absentReply(const char* name = "ghost")
{
    return json{{"name", name}, {"resolved", false}, {"error_code", "NAME_ABSENT"}, {"error", "not registered"}, {"registered", false}};
}

// A lookup the test answers by hand.
struct FakeLookup {
    QVector<QString> asked;
    QVector<NamePayBox::Reply> pending;
    NamePayBox::ResolveFn fn()
    {
        return [this](const QString& name, const NamePayBox::Reply& done) {
            asked.push_back(name);
            pending.push_back(done);
        };
    }
    void answer(bool ok, const json& reply)
    {
        Q_ASSERT(!pending.isEmpty());
        NamePayBox::Reply cb = pending.takeFirst();
        cb(ok, reply);
    }
};

QString uni(std::initializer_list<ushort> cps)
{
    QString s;
    for (ushort c : cps)
        s.append(QChar(c));
    return s;
}

} // namespace

class TstNames : public QObject {
    Q_OBJECT
private slots:
    // ---- the Pay-to entry ----
    void addressesAreNotNames();
    void wellFormedNames();
    void upperCaseIsFolded();
    void malformedNamesAreRejected();
    void lookalikesAreRejectedNotNormalised();
    void fullWidthAtIsNotAPrefix();
    void nameLengthLimits();

    // ---- the daemon's replies ----
    void indexInfo();
    void resolutionParsing();
    void ownedNamesParsing();

    // ---- what the user is told ----
    void recentChangeIsAStrongWarning();
    void freshRegistrationIsAStrongWarning();
    void quietNameHasNoWarning();
    void unpayableAnswerIsNotUsable();
    void failureTexts();
    void sameAnswerCompares();

    // ---- the widget ----
    void boxIsHiddenForAddresses();
    void boxShowsFullAddressAndNeedsConfirmation();
    void boxShowsRecentChangeWarningProminently();
    void staleReplyIsIgnored();
    void unavailableDoesNotChangeTheField();
    void absentNameDoesNotChangeTheField();
    void editingClearsTheConfirmation();
    void recheckKeepsAnUnchangedAnswer();
    void recheckRefusesAChangedAnswer();
    void recheckFailsClosed();
    void unpayableRecordOffersNoAddress();
    void effectiveAddressOnlyForTheNameTyped();
    void ownerMarkupIsShownAsPlainText();
    void ownerPercentSequencesStayLiteral();
    void replyAfterTheBoxIsGoneIsIgnored();
    void recheckReplyAfterTheBoxIsGoneFailsClosed();
};

// ---------------------------------------------------------------------------------------------------------------

void TstNames::addressesAreNotNames()
{
    const QString samples[] = {QString(kAddrT), QStringLiteral("zs1abcdefghijklmnopqrstuvwxyz0123456789"), QString(), QStringLiteral("   "),
                               QStringLiteral("alice"), QStringLiteral("Alice (t1abc)"), QStringLiteral("name@host")};
    for (const QString& s : samples)
        QCOMPARE((int)parsePayTo(s).kind, (int)InputKind::NotAName);
}

void TstNames::wellFormedNames()
{
    const QString good[] = {"alice", "a", "0", "a-b", "a--b", "xn--80ak6aa92e", "a1-b2-c3", "z9"};
    for (const QString& g : good) {
        const Parsed p = parsePayTo(QStringLiteral("@") + g);
        QCOMPARE((int)p.kind, (int)InputKind::Name);
        QCOMPARE(p.name, g);
        QVERIFY(!p.folded);
    }
    // surrounding white space is not part of the entry
    const Parsed t = parsePayTo(QStringLiteral("  @alice \n"));
    QCOMPARE((int)t.kind, (int)InputKind::Name);
    QCOMPARE(t.name, QStringLiteral("alice"));
}

void TstNames::upperCaseIsFolded()
{
    const Parsed p = parsePayTo(QStringLiteral("@AliCE-7"));
    QCOMPARE((int)p.kind, (int)InputKind::Name);
    QCOMPARE(p.name, QStringLiteral("alice-7"));
    QVERIFY(p.folded);
}

void TstNames::malformedNamesAreRejected()
{
    const QString bad[] = {"@", "@-", "@-a", "@a-", "@a b", "@a\tb", "@a.b", "@a_b", "@a@b", "@@a", "@a/b", "@a:b", "@a,b", "@a!", "@\\u0000"};
    for (const QString& b : bad) {
        const Parsed p = parsePayTo(b);
        QCOMPARE((int)p.kind, (int)InputKind::Rejected);
        QVERIFY2(!p.problem.isEmpty(), qPrintable(b));
        QVERIFY(p.name.isEmpty());
    }
}

void TstNames::lookalikesAreRejectedNotNormalised()
{
    // Each of these looks like "@alice" (or part of it) and is NOT it. None may be turned into a name.
    const QString cases[] = {
        QStringLiteral("@") + uni({0x0430}) + QStringLiteral("lice"),                // Cyrillic a
        QStringLiteral("@alic") + uni({0x0435}),                                      // Cyrillic e
        QStringLiteral("@") + uni({0xFF41}) + QStringLiteral("lice"),                // fullwidth a
        QStringLiteral("@alice") + uni({0x200B}),                                     // zero width space
        QStringLiteral("@al") + uni({0x200D}) + QStringLiteral("ice"),               // zero width joiner
        QStringLiteral("@alice") + uni({0x202E}),                                     // right-to-left override
        QStringLiteral("@a") + uni({0x0301}) + QStringLiteral("lice"),               // combining accent
        QStringLiteral("@") + uni({0x0131}) + QStringLiteral("lice"),                // dotless i
        QStringLiteral("@al") + uni({0x00ED}) + QStringLiteral("ce"),                // i with acute
        QStringLiteral("@") + uni({0xFB01}) + QStringLiteral("sh"),                  // fi ligature
        QStringLiteral("@alice") + uni({0x2010}),                                     // Unicode hyphen
        QStringLiteral("@alice") + uni({0x00A0}),                                     // no-break space
        QStringLiteral("@") + QString::fromUcs4(U"\U0001D4D0"),                       // surrogate pair (math script A)
    };
    for (const QString& c : cases) {
        const Parsed p = parsePayTo(c);
        QCOMPARE((int)p.kind, (int)InputKind::Rejected);
        QVERIFY(p.name.isEmpty());
        QVERIFY2(p.problem.contains(QLatin1String("look-alike")) || p.problem.contains(QLatin1String("plain")), qPrintable(p.problem));
    }
    // the plain ASCII look-alikes ARE names (different names); the model does not guess at them
    QCOMPARE(parsePayTo(QStringLiteral("@a1ice")).name, QStringLiteral("a1ice"));
    QCOMPARE(parsePayTo(QStringLiteral("@rnartin")).name, QStringLiteral("rnartin"));
}

void TstNames::fullWidthAtIsNotAPrefix()
{
    // a full-width '@' is not the prefix: the field stays an address field, where it is simply an invalid address
    QCOMPARE((int)parsePayTo(uni({0xFF20}) + QStringLiteral("alice")).kind, (int)InputKind::NotAName);
    QCOMPARE((int)parsePayTo(uni({0x200B}) + QStringLiteral("@alice")).kind, (int)InputKind::NotAName);
}

void TstNames::nameLengthLimits()
{
    QCOMPARE((int)parsePayTo(QStringLiteral("@") + QString(63, QLatin1Char('a'))).kind, (int)InputKind::Name);
    QCOMPARE((int)parsePayTo(QStringLiteral("@") + QString(64, QLatin1Char('a'))).kind, (int)InputKind::Rejected);
    QVERIFY(isValidName(QString(63, QLatin1Char('a'))));
    QVERIFY(!isValidName(QString(64, QLatin1Char('a'))));
    QVERIFY(!isValidName(QString()));
    QVERIFY(!isValidName(QStringLiteral("Alice")));
    QVERIFY(!isValidName(QStringLiteral("a-")));
}

// ---------------------------------------------------------------------------------------------------------------

void TstNames::indexInfo()
{
    QVERIFY(!parseIndexInfo(json{{"enabled", false}, {"error", "disabled"}}).enabled);
    QVERIFY(!parseIndexInfo(json("a string")).enabled);
    QVERIFY(!parseIndexInfo(json{{"synced", true}}).enabled);
    const IndexStatus s = parseIndexInfo(json{{"enabled", true}, {"synced", false}, {"progress", 1.7}, {"indexedheight", 10}, {"chainheight", 99}});
    QVERIFY(s.enabled);
    QVERIFY(!s.synced);
    QCOMPARE(s.progress, 1.0);
    QCOMPARE(s.indexedHeight, 10);
    QCOMPARE(s.chainHeight, 99);
}

void TstNames::resolutionParsing()
{
    Resolution r;
    QVERIFY(parseResolution(resolvedReply(), &r));
    QVERIFY(r.resolved);
    QVERIFY(r.payable);
    QCOMPARE(r.address, QString(kAddrT));
    QCOMPARE(r.setHeight, 1000);
    QCOMPARE(r.tipHeight(), 1500);
    QCOMPARE(r.registrationAgeBlocks(), 600);

    QVERIFY(parseResolution(absentReply(), &r));
    QVERIFY(!r.resolved);
    QCOMPARE(r.errorCode, QStringLiteral("NAME_ABSENT"));

    // not a reply: refused, and nothing is left behind
    QVERIFY(!parseResolution(json("x"), &r));
    QVERIFY(!r.resolved);
    QVERIFY(!parseResolution(json{{"name", "x"}}, &r));
    QVERIFY(!parseResolution(json{{"resolved", false}}, &r)); // a "no" without a code
    // "payable" without an address is not payable
    json bad = resolvedReply();
    bad.erase("address");
    QVERIFY(parseResolution(bad, &r));
    QVERIFY(!r.payable);
    QVERIFY(r.address.isEmpty());
    // a non-payable record never exposes its value as an address
    json np = resolvedReply();
    np["payable"] = false;
    QVERIFY(parseResolution(np, &r));
    QVERIFY(r.address.isEmpty());
}

void TstNames::ownedNamesParsing()
{
    QVector<OwnedName> v;
    json a = json::array({json{{"name", "alice"}, {"owner", "t1o"}, {"type", "t-address"}, {"value", "t1v"}, {"registeredheight", 5}, {"spendable", true}},
                          json{{"name", "Bad Name"}, {"owner", "t1o"}},
                          json("junk")});
    QVERIFY(parseOwnedNames(a, &v));
    QCOMPARE(v.size(), 1);
    QCOMPARE(v[0].name, QStringLiteral("alice"));
    QVERIFY(v[0].spendable);
    QVERIFY(!parseOwnedNames(json{{"a", 1}}, &v));
}

// ---------------------------------------------------------------------------------------------------------------

void TstNames::recentChangeIsAStrongWarning()
{
    Resolution r;
    QVERIFY(parseResolution(resolvedReply("alice", kAddrT, 1000, 12, true, 100), &r));
    const Assessment a = assess(r);
    QVERIFY(a.usable);
    QVERIFY(a.strongWarning);
    QVERIFY(!a.warnings.isEmpty());
    QVERIFY(a.warnings[0].startsWith(QLatin1String("WARNING")));
    QVERIFY(a.warnings[0].contains(QLatin1String("12 block")));
    QVERIFY(a.warnings[0].contains(QLatin1String("1000")));
    QVERIFY(a.warnings[0].contains(shortTxid(r.setTxid)));
}

void TstNames::freshRegistrationIsAStrongWarning()
{
    Resolution r;
    // registered 5 blocks ago, address never changed since: still flagged (a brand-new name)
    QVERIFY(parseResolution(resolvedReply("newname", kAddrT, 995, 5, false, 995), &r));
    QVERIFY(assess(r).strongWarning);
    // registered exactly the window ago: not flagged
    QVERIFY(parseResolution(resolvedReply("oldname", kAddrT, 900, 100, false, 900), &r));
    QCOMPARE(r.registrationAgeBlocks(), 100);
    QVERIFY(!assess(r).strongWarning);
    // 99 blocks old: flagged
    QVERIFY(parseResolution(resolvedReply("oldname", kAddrT, 901, 99, false, 901), &r));
    QCOMPARE(r.registrationAgeBlocks(), 99);
    QVERIFY(assess(r).strongWarning);
    // a window of 0 (the caller turned the check off) flags nothing
    json off = resolvedReply("newname", kAddrT, 995, 5, false, 995);
    off["recent_change_blocks"] = 0;
    QVERIFY(parseResolution(off, &r));
    QVERIFY(!assess(r).strongWarning);
}

void TstNames::quietNameHasNoWarning()
{
    Resolution r;
    QVERIFY(parseResolution(resolvedReply(), &r));
    const Assessment a = assess(r);
    QVERIFY(a.usable);
    QVERIFY(!a.strongWarning);
    QVERIFY(a.warnings.isEmpty());
    QVERIFY(a.info.contains(QLatin1String("Registered at block 900")));
}

void TstNames::unpayableAnswerIsNotUsable()
{
    Resolution r;
    json np = resolvedReply();
    np["payable"] = false;
    np["kind"] = "none";
    QVERIFY(parseResolution(np, &r));
    const Assessment a = assess(r);
    QVERIFY(!a.usable);
    QVERIFY(!a.headline.isEmpty());
}

void TstNames::failureTexts()
{
    Resolution r;
    QVERIFY(parseResolution(absentReply("ghost"), &r));
    QVERIFY(failureText(r).contains(QLatin1String("@ghost")));
    QVERIFY(parseResolution(json{{"name", "x"}, {"resolved", false}, {"error_code", "NAME_NO_SUCH_TARGET"}, {"error", "e"}}, &r));
    QVERIFY(failureText(r).contains(QLatin1String("no address")));
    QVERIFY(parseResolution(json{{"name", "x"}, {"resolved", false}, {"error_code", "WEIRD"}, {"error", "the node says no"}}, &r));
    QCOMPARE(failureText(r), QStringLiteral("the node says no"));
}

void TstNames::sameAnswerCompares()
{
    Resolution a, b;
    QVERIFY(parseResolution(resolvedReply(), &a));
    QVERIFY(parseResolution(resolvedReply("alice", kAddrT, 1000, 700), &b)); // later, nothing changed
    QVERIFY(sameAnswer(a, b));
    QVERIFY(parseResolution(resolvedReply("alice", "t1SomeoneElsesAddressAAAAAAAAAAAAAAAA"), &b));
    QVERIFY(!sameAnswer(a, b));
    QVERIFY(parseResolution(resolvedReply("alice", kAddrT, 1000, 500, false, 900, "ff"), &b)); // same address, a new setting transaction
    QVERIFY(!sameAnswer(a, b));
    QVERIFY(parseResolution(absentReply(), &b));
    QVERIFY(!sameAnswer(a, b));
}

// ---------------------------------------------------------------------------------------------------------------

void TstNames::boxIsHiddenForAddresses()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QString(kAddrT));
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Hidden);
    QVERIFY(!box.isVisibleTo(&top));
    QCOMPARE(box.effectiveAddress(QString(kAddrT)), QString(kAddrT));
    QString why;
    QVERIFY(!box.blocksSending(QString(kAddrT), &why));
    QVERIFY(f.asked.isEmpty());
    // nothing is looked up for an address, ever
    box.resolveNow();
    QVERIFY(f.asked.isEmpty());
}

void TstNames::boxShowsFullAddressAndNeedsConfirmation()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@alice"));
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Waiting);
    QVERIFY(box.isVisibleTo(&top));
    QString why;
    QVERIFY(box.blocksSending(QStringLiteral("@alice"), &why)); // still looking up
    QVERIFY(why.contains(QLatin1String("@alice")));
    box.resolveNow();
    QCOMPARE(f.asked.size(), 1);
    QCOMPARE(f.asked[0], QStringLiteral("alice"));
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Resolving);
    f.answer(true, resolvedReply());
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Resolved);
    QVERIFY(box.usable());
    // the address is shown in FULL, not shortened
    QCOMPARE(box.addressLabel()->text(), QString(kAddrT));
    QVERIFY(box.addressLabel()->isVisibleTo(&top));
    QVERIFY(box.infoLabel()->text().contains(QLatin1String("Registered at block 900")));
    QVERIFY(box.warningLabel()->isHidden()); // nothing to warn about
    // not confirmed yet: the entry stays "@alice" (and sending is blocked with a reason)
    QVERIFY(!box.confirmed());
    QCOMPARE(box.effectiveAddress(QStringLiteral("@alice")), QStringLiteral("@alice"));
    QVERIFY(box.blocksSending(QStringLiteral("@alice"), &why));
    QVERIFY(why.contains(QLatin1String("confirm")));
    // the user confirms the ADDRESS: now the entry stands for exactly that address
    QSignalSpy spy(&box, &NamePayBox::changed);
    box.confirmCheck()->setChecked(true);
    QVERIFY(spy.count() >= 1);
    QVERIFY(box.confirmed());
    QCOMPARE(box.effectiveAddress(QStringLiteral("@alice")), QString(kAddrT));
    QCOMPARE(box.effectiveAddress(QStringLiteral("  @ALICE ")), QString(kAddrT)); // same name, other spelling of the entry
    QVERIFY(!box.blocksSending(QStringLiteral("@alice"), &why));
}

void TstNames::boxShowsRecentChangeWarningProminently()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@shop"));
    box.resolveNow();
    f.answer(true, resolvedReply("shop", kAddrT, 2000, 3, true, 100));
    QVERIFY(box.warningLabel()->isVisibleTo(&top));
    QVERIFY(box.warningLabel()->text().startsWith(QLatin1String("WARNING")));
    QVERIFY(box.warningLabel()->text().contains(QLatin1String("3 block")));
    QVERIFY(box.confirmCheck()->text().contains(QLatin1String("confirmed this address with the recipient")));
    // the warning is styled to stand out
    QVERIFY(box.warningLabel()->styleSheet().contains(QLatin1String("#ffe3e0")));
    QVERIFY(box.warningLabel()->styleSheet().contains(QLatin1String("bold")));
    // and a quiet name's checkbox is the plain one
    box.setFieldText(QStringLiteral("@quiet"));
    box.resolveNow();
    f.answer(true, resolvedReply("quiet"));
    QVERIFY(box.confirmCheck()->text().contains(QLatin1String("address I mean to pay")));
}

void TstNames::staleReplyIsIgnored()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@alice"));
    box.resolveNow();
    box.setFieldText(QStringLiteral("@bob")); // the user kept typing
    f.answer(true, resolvedReply("alice")); // alice's answer arrives late
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Waiting);
    QVERIFY(box.addressLabel()->text().isEmpty());
    QCOMPARE(box.effectiveAddress(QStringLiteral("@bob")), QStringLiteral("@bob"));
    // deleting the whole entry hides the box, and a late answer does not bring it back
    box.setFieldText(QStringLiteral("@bo"));
    box.resolveNow();
    box.setFieldText(QString());
    f.answer(true, resolvedReply("bo"));
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Hidden);
    QVERIFY(!box.isVisibleTo(&top));
}

void TstNames::unavailableDoesNotChangeTheField()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@alice"));
    box.resolveNow();
    f.answer(false, json{{"error", {{"code", -1}, {"message", "The ZNAM name index is disabled."}}}});
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Unavailable);
    QVERIFY(box.statusLabel()->text().contains(QLatin1String("disabled")));
    // the entry is exactly what it was; nothing new blocks sending beyond the field's own validation
    QCOMPARE(box.effectiveAddress(QStringLiteral("@alice")), QStringLiteral("@alice"));
    QString why;
    QVERIFY(!box.blocksSending(QStringLiteral("@alice"), &why));
    QVERIFY(box.addressLabel()->isHidden());
    QVERIFY(box.confirmCheck()->isHidden());
    // garbage from the daemon is also "unavailable", not a crash and not an address
    box.setFieldText(QStringLiteral("@alice2"));
    box.resolveNow();
    f.answer(true, json("not an object"));
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Unavailable);
}

void TstNames::absentNameDoesNotChangeTheField()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@ghost"));
    box.resolveNow();
    f.answer(true, absentReply("ghost"));
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Failed);
    QVERIFY(box.statusLabel()->text().contains(QLatin1String("@ghost")));
    QCOMPARE(box.effectiveAddress(QStringLiteral("@ghost")), QStringLiteral("@ghost"));
    QString why;
    QVERIFY(!box.blocksSending(QStringLiteral("@ghost"), &why));
    // a rejected spelling shows why and looks nothing up
    box.setFieldText(QStringLiteral("@al") + uni({0x0456}) + QStringLiteral("ce"));
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Rejected);
    QVERIFY(box.statusLabel()->text().contains(QLatin1String("look-alike")));
    box.resolveNow();
    QCOMPARE(f.asked.size(), 1); // only the earlier "ghost"
}

void TstNames::editingClearsTheConfirmation()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@alice"));
    box.resolveNow();
    f.answer(true, resolvedReply());
    box.confirmCheck()->setChecked(true);
    QVERIFY(box.confirmed());
    // the same name with a trailing space keeps the answer and the confirmation
    box.setFieldText(QStringLiteral("@alice "));
    QVERIFY(box.confirmed());
    // a different name does not inherit it
    box.setFieldText(QStringLiteral("@alicf"));
    QVERIFY(!box.confirmed());
    QCOMPARE(box.effectiveAddress(QStringLiteral("@alicf")), QStringLiteral("@alicf"));
    // back to the first name: it must be looked up and confirmed again
    box.setFieldText(QStringLiteral("@alice"));
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Waiting);
    QVERIFY(!box.confirmed());
}

void TstNames::recheckKeepsAnUnchangedAnswer()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@alice"));
    box.resolveNow();
    f.answer(true, resolvedReply());
    box.confirmCheck()->setChecked(true);
    bool called = false, result = false;
    box.recheck([&](bool ok) { called = true; result = ok; });
    QCOMPARE(f.asked.size(), 2);
    f.answer(true, resolvedReply("alice", kAddrT, 1000, 501)); // one block later, nothing else changed
    QVERIFY(called);
    QVERIFY(result);
    QVERIFY(box.confirmed()); // the confirmation stands
    QCOMPARE(box.effectiveAddress(QStringLiteral("@alice")), QString(kAddrT));
    // and with nothing to check (not a name answer) it passes at once
    FakeLookup g;
    NamePayBox plain(g.fn(), &top);
    plain.setFieldText(QString(kAddrT));
    bool pass = false;
    plain.recheck([&](bool ok) { pass = ok; });
    QVERIFY(pass);
    QVERIFY(g.asked.isEmpty());
}

void TstNames::recheckRefusesAChangedAnswer()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@alice"));
    box.resolveNow();
    f.answer(true, resolvedReply());
    box.confirmCheck()->setChecked(true);
    bool called = false, result = true;
    box.recheck([&](bool ok) { called = true; result = ok; });
    // the owner moved the name to another address in the meantime
    f.answer(true, resolvedReply("alice", "t1SomeoneElsesAddressAAAAAAAAAAAAAAAA", 1501, 0, true, 900, "bb"));
    QVERIFY(called);
    QVERIFY(!result);
    QVERIFY(!box.confirmed());
    QCOMPARE(box.effectiveAddress(QStringLiteral("@alice")), QStringLiteral("@alice")); // nothing is sent to either address
    QCOMPARE(box.addressLabel()->text(), QStringLiteral("t1SomeoneElsesAddressAAAAAAAAAAAAAAAA"));
    QVERIFY(box.statusLabel()->text().contains(QLatin1String("CHANGED")));
    QVERIFY(box.warningLabel()->isVisibleTo(&top));
}

void TstNames::recheckFailsClosed()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@alice"));
    box.resolveNow();
    f.answer(true, resolvedReply());
    box.confirmCheck()->setChecked(true);
    bool called = false, result = true;
    box.recheck([&](bool ok) { called = true; result = ok; });
    f.answer(false, json()); // the node cannot answer right now
    QVERIFY(called);
    QVERIFY(!result);
    QVERIFY(!box.confirmed());
    QCOMPARE(box.effectiveAddress(QStringLiteral("@alice")), QStringLiteral("@alice"));
    // an answer that arrives after the entry was edited does not count either
    box.confirmCheck()->setChecked(true);
    called = false; result = true;
    box.recheck([&](bool ok) { called = true; result = ok; });
    box.setFieldText(QStringLiteral("@alicf"));
    f.answer(true, resolvedReply());
    QVERIFY(called);
    QVERIFY(!result);
}

void TstNames::unpayableRecordOffersNoAddress()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@onion"));
    box.resolveNow();
    json np = resolvedReply("onion", "abcdefgh.onion");
    np["payable"] = false;
    np["kind"] = "none";
    np["type"] = "onion";
    np.erase("address");
    f.answer(true, np);
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Resolved);
    QVERIFY(!box.usable());
    QVERIFY(box.addressLabel()->isHidden());
    QVERIFY(box.confirmCheck()->isHidden());
    QCOMPARE(box.effectiveAddress(QStringLiteral("@onion")), QStringLiteral("@onion"));
    QVERIFY(!box.confirmed());
}

void TstNames::effectiveAddressOnlyForTheNameTyped()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@alice"));
    box.resolveNow();
    f.answer(true, resolvedReply());
    box.confirmCheck()->setChecked(true);
    // an address typed into the same field, or another name, never picks up alice's answer
    QCOMPARE(box.effectiveAddress(QString(kAddrT)), QString(kAddrT));
    QCOMPARE(box.effectiveAddress(QStringLiteral("t1SomeoneElse")), QStringLiteral("t1SomeoneElse"));
    QCOMPARE(box.effectiveAddress(QStringLiteral("@alic")), QStringLiteral("@alic"));
    QCOMPARE(box.effectiveAddress(QStringLiteral("@alice2")), QStringLiteral("@alice2"));
    QCOMPARE(box.effectiveAddress(QString()), QString());
}

// The owner of a name is whatever 1-63 bytes its last TRANSFER carried. Qt would render a label that looks like
// markup as HTML (an <img src="file://host/x"> then fetches the host), so every label here is plain text.
void TstNames::ownerMarkupIsShownAsPlainText()
{
    FakeLookup f;
    QWidget top;
    NamePayBox box(f.fn(), &top);
    top.show();
    box.setFieldText(QStringLiteral("@alice"));
    box.resolveNow();
    json r = resolvedReply();
    r["owner"] = "<img src=\"file://203.0.113.5/x\"><b>trusted</b>";
    f.answer(true, r);
    QCOMPARE((int)box.state(), (int)NamePayBox::State::Resolved);
    QCOMPARE((int)box.infoLabel()->textFormat(), (int)Qt::PlainText);
    QCOMPARE((int)box.statusLabel()->textFormat(), (int)Qt::PlainText);
    QCOMPARE((int)box.addressLabel()->textFormat(), (int)Qt::PlainText);
    QCOMPARE((int)box.warningLabel()->textFormat(), (int)Qt::PlainText);
    QVERIFY(box.infoLabel()->text().contains(QLatin1String("<img src=\"file://203.0.113.5/x\"><b>trusted</b>")));
}

void TstNames::ownerPercentSequencesStayLiteral()
{
    Resolution res;
    json r = resolvedReply("alice", kAddrT, 1000, 500, false, 900);
    r["owner"] = "<b>trusted</b> %4 %5";
    QVERIFY(parseResolution(r, &res));
    const Assessment a = assess(res);
    QVERIFY(a.info.contains(QLatin1String("<b>trusted</b> %4 %5")));   // not replaced by the later facts
    QCOMPARE(a.info.count(QLatin1String("1000")), 1);                    // the set height appears once, where it belongs
    QVERIFY(a.info.contains(QLatin1String("aa11bb22")));
}

// The Send tab deletes a recipient row at once; the node can answer a lookup much later.
void TstNames::replyAfterTheBoxIsGoneIsIgnored()
{
    FakeLookup f;
    QWidget top;
    auto* box = new NamePayBox(f.fn(), &top);
    top.show();
    box->setFieldText(QStringLiteral("@alice"));
    box->resolveNow();
    QCOMPARE(f.pending.size(), 1);
    delete box;
    f.answer(true, resolvedReply());   // must be a no-op (ASan: no heap-use-after-free)
    QVERIFY(true);
}

void TstNames::recheckReplyAfterTheBoxIsGoneFailsClosed()
{
    FakeLookup f;
    QWidget top;
    auto* box = new NamePayBox(f.fn(), &top);
    top.show();
    box->setFieldText(QStringLiteral("@alice"));
    box->resolveNow();
    f.answer(true, resolvedReply());
    box->confirmCheck()->setChecked(true);
    int calls = 0;
    bool result = true;
    box->recheck([&](bool ok) { ++calls; result = ok; });
    QCOMPARE(f.pending.size(), 1);
    delete box;
    f.answer(true, resolvedReply());
    QCOMPARE(calls, 1);   // the send path is still told
    QVERIFY(!result);     // and nothing is sent on the strength of a row that no longer exists
}

QTEST_MAIN(TstNames)
#include "tst_names.moc"
