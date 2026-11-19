// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests of sending and creating tokens from the Tokens window: the pure logic (exact amounts,
// checks, RPC parameters, replies, wording) and the two dialogs driven offscreen against a fake daemon.
// No real daemon, no MainWindow.

#include <QtTest>

#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalSpy>

#include "tokenssend.h"
#include "tokenssendmodel.h"

using json = nlohmann::json;
using namespace tokens;

namespace {

const char* kTok = "40f47139acb5c3088aa282a48c58324a43177ec2704d5aa748f03c3d09828568";
const char* kAddr = "tmCasruXew9jQ1q2cSXMo2yaEsjaySSLTFT";   // 35 characters
const char* kChange = "tmGJKVmfFzFRKXUXnDkN8XdQPvmxPT4x8gv";

TokenChoice aaa()
{
    TokenChoice c;
    c.tokenId = kTok;
    c.ticker = "AAA";
    c.decimals = 2;
    c.balance = "899.50";
    return c;
}

TokenChoice bbb()
{
    TokenChoice c;
    c.tokenId = "f8b5c5237f85d2c9e1c8a60fba8f0c5b6a8de5fc9c28c7e1a2b3c4d5e6f70811";
    c.ticker = "BBB";
    c.decimals = 0;
    c.balance = "5000";
    return c;
}

// a daemon that answers when the test says so
class FakeRpc : public TokensRpc {
public:
    struct Call {
        QString method;
        json params;
        std::function<void(const json&)> ok;
        std::function<void(const QString&)> fail;
    };
    QVector<Call> calls;
    void call(const QString& method, const json& params, std::function<void(const json&)> ok,
              std::function<void(const QString&)> fail) override
    {
        calls.push_back({method, params, ok, fail});
    }
    void answer(int i, const json& r) { calls[i].ok(r); }
    void answerError(int i, const QString& m) { calls[i].fail(m); }
};

json sendReply(bool broadcast)
{
    return {{"txid", "0e543b8cc4a11d8180d67d4baf46f3faf42cddf8f8ee41de312ce18310552f55"},
            {"tokenid", kTok}, {"type", "send"}, {"broadcast", broadcast}, {"amount", "12.34"},
            {"tokenchange", "887.16"}, {"changeaddress", kChange}, {"tokeninputs", 1}, {"fee", 0.00000481}};
}

} // namespace

class TstTokensSend : public QObject {
    Q_OBJECT
private slots:
    // ---- amounts ---------------------------------------------------------------------------

    void amount_valid_data()
    {
        QTest::addColumn<QString>("text");
        QTest::addColumn<int>("decimals");
        QTest::addColumn<QString>("units");
        QTest::addColumn<QString>("normalized");
        QTest::newRow("whole") << "7" << 0 << "7" << "7";
        QTest::newRow("two places") << "1.5" << 2 << "150" << "1.5";
        QTest::newRow("padded") << "1.50" << 2 << "150" << "1.50";
        QTest::newRow("smallest") << "0.00000001" << 8 << "1" << "0.00000001";
        QTest::newRow("leading zeros") << "00012.5" << 1 << "125" << "12.5";
        QTest::newRow("no leading digit") << ".5" << 1 << "5" << "0.5";
        QTest::newRow("trailing point") << "5." << 2 << "500" << "5";
        QTest::newRow("spaces") << "  3.25 " << 2 << "325" << "3.25";
        QTest::newRow("0.1 is exact at 8") << "0.1" << 8 << "10000000" << "0.1";
        QTest::newRow("largest") << "92233720368547758.07" << 2 << "9223372036854775807" << "92233720368547758.07";
        QTest::newRow("largest whole") << "9223372036854775807" << 0 << "9223372036854775807" << "9223372036854775807";
    }
    void amount_valid()
    {
        QFETCH(QString, text);
        QFETCH(int, decimals);
        QFETCH(QString, units);
        QFETCH(QString, normalized);
        const AmountResult r = parseAmount(text, decimals);
        QVERIFY2(r.ok, qPrintable(r.error));
        QCOMPARE(QString::number(r.units), units);
        QCOMPARE(r.normalized, normalized);
    }

    void amount_invalid_data()
    {
        QTest::addColumn<QString>("text");
        QTest::addColumn<int>("decimals");
        QTest::addColumn<QString>("fragment");
        QTest::newRow("empty") << "" << 2 << "Enter an amount";
        QTest::newRow("blank") << "   " << 2 << "Enter an amount";
        QTest::newRow("point only") << "." << 2 << "Enter an amount";
        QTest::newRow("comma") << "1,5" << 2 << "comma";
        QTest::newRow("sign") << "-1" << 2 << "only digits";
        QTest::newRow("plus") << "+1" << 2 << "only digits";
        QTest::newRow("exponent") << "1e3" << 2 << "only digits";
        QTest::newRow("hex") << "0x10" << 0 << "only digits";
        QTest::newRow("two points") << "1.2.3" << 2 << "only digits";
        QTest::newRow("words") << "ten" << 2 << "only digits";
        QTest::newRow("over precision") << "1.234" << 2 << "2 decimal places";
        QTest::newRow("fraction on whole token") << "1.5" << 0 << "no decimal places";
        QTest::newRow("zero") << "0" << 2 << "greater than zero";
        QTest::newRow("zero fraction") << "0.00" << 2 << "greater than zero";
        QTest::newRow("2^63") << "92233720368547758.08" << 2 << "too large";
        QTest::newRow("2^64") << "184467440737095516.16" << 2 << "too large";
        QTest::newRow("huge") << "99999999999999999999999999" << 0 << "too large";
        QTest::newRow("unicode digit") << QString::fromUtf8("\xd9\xa3") << 0 << "only digits";
    }
    void amount_invalid()
    {
        QFETCH(QString, text);
        QFETCH(int, decimals);
        QFETCH(QString, fragment);
        const AmountResult r = parseAmount(text, decimals);
        QVERIFY2(!r.ok, qPrintable(text));
        QVERIFY2(r.error.contains(fragment), qPrintable(r.error));
    }

    void amount_roundTripsThroughFormat()
    {
        quint64 s = 88172645463325252ULL;
        for (int i = 0; i < 3000; i++) {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17; // xorshift: the same run everywhere
            const int dec = static_cast<int>(s % 9);
            const quint64 v = (s >> (s % 60)) % 9223372036854775807ULL;
            if (v == 0)
                continue;
            const QString text = formatUnits(v, dec);
            const AmountResult r = parseAmount(text, dec);
            QVERIFY2(r.ok, qPrintable(text));
            QCOMPARE(r.units, v);
        }
        QCOMPARE(formatUnits(5, 3), QString("0.005"));
        QCOMPARE(formatUnits(12345, 2), QString("123.45"));
        QCOMPARE(formatUnits(100, 2), QString("1.00"));
        QCOMPARE(formatUnits(7, 0), QString("7"));
    }

    // ---- recipients and the send check -------------------------------------------------------

    void recipient()
    {
        QVERIFY(checkRecipient(kAddr).isEmpty());
        QVERIFY(checkRecipient(QString(" ") + kAddr + " ").isEmpty());
        QVERIFY(checkRecipient("").contains("Enter"));
        QVERIFY(checkRecipient("zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly").contains("Shielded"));
        QVERIFY(checkRecipient("zcWsmqT4X2V4jgxbgiCzyrAfRT1vi1F4sksTiUMVAHtFPrRDvaPLm7UK1o5UXBHFF4ZZSdnkYWTN1hSrfx5ufzcT12ukP9L").contains("Shielded"));
        QVERIFY(!checkRecipient("tmCasruXew9jQ1q2cSXMo2yaEsjaySSLTF").isEmpty());          // 34
        QVERIFY(!checkRecipient("tmCasruXew9jQ1q2cSXMo2yaEsjaySSLTFTT").isEmpty());        // 36
        QVERIFY(!checkRecipient("tmCasruXew9jQ1q2cSXMo2yaEsjaySSLTF0").isEmpty());         // 0 is not base58
        QVERIFY(!checkRecipient("1BoatSLRHtKNngkdXEeobR76b53LETtpyT").isEmpty());          // not transparent ZClassic
        QVERIFY(!checkRecipient("hello world").isEmpty());
    }

    void send_check()
    {
        SendCheck c = checkSend(aaa(), kAddr, "12.34");
        QVERIFY2(c.ok, qPrintable(c.error));
        QCOMPARE(c.units, 1234u);
        QCOMPARE(c.amount, QString("12.34"));
        QCOMPARE(c.address, QString(kAddr));
        QVERIFY(checkSend(aaa(), kAddr, "899.50").ok);                          // exactly the balance
        c = checkSend(aaa(), kAddr, "899.51");
        QVERIFY(!c.ok);
        QVERIFY(c.error.contains("899.50"));
        QVERIFY(!checkSend(aaa(), kAddr, "1.234").ok);
        QVERIFY(!checkSend(aaa(), "", "1").ok);
        QVERIFY(!checkSend(TokenChoice(), kAddr, "1").ok);
        QVERIFY(!checkSend(bbb(), kAddr, "1.5").ok);
        QVERIFY(checkSend(bbb(), kAddr, "5000").ok);
        QVERIFY(!checkSend(bbb(), kAddr, "5001").ok);
    }

    void send_params()
    {
        const SendCheck c = checkSend(aaa(), kAddr, "12.34");
        const json dry = sendParams(aaa(), c, true);
        QCOMPARE(dry.size(), size_t(5));
        QCOMPARE(QString::fromStdString(dry[0].get<std::string>()), QString(kTok));
        QVERIFY(dry[1].is_array() && dry[1].size() == 1);
        QCOMPARE(QString::fromStdString(dry[1][0]["address"].get<std::string>()), QString(kAddr));
        QVERIFY(dry[1][0]["amount"].is_string());                               // never a JSON number
        QCOMPARE(QString::fromStdString(dry[1][0]["amount"].get<std::string>()), QString("12.34"));
        QCOMPARE(dry[2].get<int>(), 1);
        QVERIFY(dry[3].is_null());
        QVERIFY(dry[4].is_boolean() && dry[4].get<bool>());
        QVERIFY(!sendParams(aaa(), c, false)[4].get<bool>());
    }

    void plan_parse()
    {
        const TxPlan p = parseTxPlan(sendReply(false));
        QVERIFY(p.ok);
        QVERIFY(!p.broadcast);
        QCOMPARE(p.tokenChange, QString("887.16"));
        QCOMPARE(p.changeAddress, QString(kChange));
        QCOMPARE(p.tokenInputs, 1);
        QCOMPARE(p.feeZat, qint64(481));
        QVERIFY(parseTxPlan(sendReply(true)).broadcast);
        QCOMPARE(parseTxPlan(json{{"txid", "ab"}, {"fee", 0.00000312}}).feeZat, qint64(312));
        QCOMPARE(parseTxPlan(json{{"txid", "ab"}, {"fee", 0.0001}}).feeZat, qint64(10000));
        QCOMPARE(parseTxPlan(json{{"txid", "ab"}, {"fee", 0.00000001}}).feeZat, qint64(1));
        QVERIFY(!parseTxPlan(json::object()).ok);
        QVERIFY(!parseTxPlan(json("x")).ok);
        QVERIFY(!parseTxPlan(json(nullptr)).ok);
    }

    void zcl_formatting()
    {
        QCOMPARE(formatZcl(481), QString("0.00000481"));
        QCOMPARE(formatZcl(546), QString("0.00000546"));
        QCOMPARE(formatZcl(100000000), QString("1.00000000"));
        QCOMPARE(formatZcl(0), QString("0.00000000"));
        QCOMPARE(formatZcl(1250000001), QString("12.50000001"));
        QCOMPARE(formatZcl(-5), QString("-0.00000005"));
    }

    // ---- the words ----------------------------------------------------------------------------

    void review_text()
    {
        const SendCheck c = checkSend(aaa(), kAddr, "12.34");
        const QString t = sendReviewText(aaa(), c, parseTxPlan(sendReply(false)));
        QVERIFY(t.contains("send 12.34 AAA"));
        QVERIFY(t.contains(kAddr));
        QVERIFY(t.contains("remaining 887.16 AAA returns to you"));
        QVERIFY(t.contains(kChange));
        QVERIFY(t.contains("Nothing is burned"));
        QVERIFY(t.contains("Network fee: 0.00000481 ZCL"));
        QVERIFY(t.contains("never from tokens"));
        QVERIFY(t.contains("0.00000546 ZCL"));                                  // the dust the recipient's output carries
        QVERIFY(t.contains("cannot be undone"));
        // no change
        json r = sendReply(false);
        r["tokenchange"] = "0.00";
        r["changeaddress"] = nullptr;
        const QString nc = sendReviewText(aaa(), c, parseTxPlan(r));
        QVERIFY(nc.contains("no token change"));
        QVERIFY(!nc.contains("returns to you"));
        // an unnamed token shows its id prefix, not an empty name
        TokenChoice u = aaa();
        u.ticker = "";
        QVERIFY(sendReviewText(u, checkSend(u, kAddr, "1"), parseTxPlan(sendReply(false))).contains("40f47139..."));
    }

    // Anyone can create a token with any ticker (and any ticker can hide a right-to-left override), so two
    // different tokens can look the same; the id is what tells them apart.
    void lookalike_tickers_are_distinguishable()
    {
        TokenChoice a = aaa();
        TokenChoice b = aaa();
        b.tokenId = "11f47139acb5c3088aa282a48c58324a43177ec2704d5aa748f03c3d098285ff";
        QVERIFY(tokenLabel(a.ticker, a.tokenId) != tokenLabel(b.ticker, b.tokenId));
        QVERIFY(tokenLabel(a.ticker, a.tokenId).contains("40f47139...09828568"));
        const SendCheck c = checkSend(b, kAddr, "1");
        const QString review = sendReviewText(b, c, parseTxPlan(sendReply(false)));
        QVERIFY(review.contains(b.tokenId));
        QVERIFY(review.contains("11f47139...098285ff"));
        QVERIFY(sendResultText(b, c, parseTxPlan(sendReply(true))).contains("11f47139...098285ff"));
        // bidi and format controls are not shown
        QCOMPARE(displayTicker(QString("AB") + QChar(0x202E) + "00", kTok), QString("AB00"));
        QCOMPARE(displayTicker(QString(QChar(0x202E)), kTok), QString("40f47139..."));
    }

    void picker_rows_show_the_token_id()
    {
        FakeRpc rpc;
        TokenChoice a = aaa();
        TokenChoice b = aaa();
        b.tokenId = "11f47139acb5c3088aa282a48c58324a43177ec2704d5aa748f03c3d098285ff";
        TokenSendDialog d(&rpc, {a, b});
        auto* box = d.findChild<QComboBox*>("tokenBox");
        QVERIFY(box);
        QVERIFY(box->itemText(0) != box->itemText(1));
        QVERIFY(box->itemText(0).contains("40f47139...09828568"));
        QVERIFY(box->itemText(1).contains("11f47139...098285ff"));
        QVERIFY(box->itemText(0).contains("another token has this ticker"));
        QVERIFY(d.findChild<QLabel*>("availableLabel")->text().contains("40f47139...09828568"));
    }

    void result_text()
    {
        const SendCheck c = checkSend(aaa(), kAddr, "12.34");
        const QString t = sendResultText(aaa(), c, parseTxPlan(sendReply(true)));
        QVERIFY(t.contains("Sent 12.34 AAA"));
        QVERIFY(t.contains("0e543b8cc4a11d8180d67d4baf46f3faf42cddf8f8ee41de312ce18310552f55"));
        QVERIFY(t.contains("0.00000481"));
        QVERIFY(t.contains("confirmed in a block"));
    }

    void friendly_errors()
    {
        QVERIFY(friendlyError("Error: Please enter the wallet passphrase with walletpassphrase first.").contains("locked"));
        QVERIFY(friendlyError("not enough ordinary ZCL for the fee and the token dust outputs (...)").contains("never used for the fee"));
        QVERIFY(friendlyError("insufficient confirmed token balance: this wallet holds 0 AAA").contains("confirmed outputs"));
        QVERIFY(friendlyError("the ZSLP token index is not synced yet (indexed height 3, chain height 9)").contains("catching up"));
        QVERIFY(friendlyError("this wallet does not hold the confirmed mint baton of this token").contains("mint baton"));
        // the daemon's own words are always kept
        QVERIFY(friendlyError("not enough ordinary ZCL for the fee").contains("Details: not enough ordinary ZCL for the fee"));
        QCOMPARE(friendlyError("something unforeseen"), QString("something unforeseen"));
    }

    // ---- creating ------------------------------------------------------------------------------

    void genesis_check()
    {
        GenesisDraft d;
        d.ticker = "TST"; d.name = "Test token"; d.decimals = "2"; d.quantity = "1000.00";
        GenesisCheck c = checkGenesis(d);
        QVERIFY2(c.ok, qPrintable(c.error));
        QCOMPARE(c.decimals, 2);
        QCOMPARE(c.units, 100000u);
        QCOMPARE(c.quantity, QString("1000.00"));
        auto bad = [&](GenesisDraft x, const char* fragment) {
            const GenesisCheck r = checkGenesis(x);
            QVERIFY2(!r.ok, fragment);
            QVERIFY2(r.error.contains(fragment), qPrintable(r.error));
        };
        { GenesisDraft x = d; x.ticker = ""; bad(x, "ticker"); }
        { GenesisDraft x = d; x.ticker = "ABCDEFGHIJK"; bad(x, "ticker"); }
        { GenesisDraft x = d; x.ticker = "A B"; bad(x, "ticker"); }
        { GenesisDraft x = d; x.name = ""; bad(x, "name"); }
        { GenesisDraft x = d; x.name = QString(65, 'a'); bad(x, "name"); }
        { GenesisDraft x = d; x.name = "no <tags>"; bad(x, "name"); }
        { GenesisDraft x = d; x.decimals = "9"; bad(x, "Decimal places"); }
        { GenesisDraft x = d; x.decimals = "-1"; bad(x, "Decimal places"); }
        { GenesisDraft x = d; x.decimals = "2.5"; bad(x, "Decimal places"); }
        { GenesisDraft x = d; x.decimals = ""; bad(x, "Decimal places"); }
        { GenesisDraft x = d; x.quantity = "0"; bad(x, "First supply"); }
        { GenesisDraft x = d; x.quantity = "1.234"; bad(x, "First supply"); }
        { GenesisDraft x = d; x.quantity = "21000000000000.01"; bad(x, "too large"); }
        { GenesisDraft x = d; x.url = "has space"; bad(x, "document link"); }
        { GenesisDraft x = d; x.hash = "abcd"; bad(x, "hash"); }
        { GenesisDraft x = d; x.quantity = "21000000000000.00"; QVERIFY(checkGenesis(x).ok); }   // the exact maximum
        { GenesisDraft x = d; x.hash = QString(64, 'a'); x.url = "https://example.org/a.json"; QVERIFY(checkGenesis(x).ok); }
    }

    void genesis_params()
    {
        GenesisDraft d;
        d.ticker = " TST "; d.name = "Test token"; d.decimals = "2"; d.quantity = "1000.00";
        GenesisCheck c = checkGenesis(d);
        json p = genesisParams(d, c, true);
        QCOMPARE(p.size(), size_t(1));
        const json o = p[0];
        QCOMPARE(QString::fromStdString(o["ticker"].get<std::string>()), QString("TST"));
        QVERIFY(o["decimals"].is_number_integer());
        QVERIFY(o["initialquantity"].is_string());
        QVERIFY(o["dryrun"].get<bool>());
        QVERIFY(o.find("batonaddress") == o.end());                              // default: a baton at a fresh wallet address
        QVERIFY(o.find("documenturl") == o.end());
        const json real = genesisParams(d, c, false);
        QVERIFY(real[0].find("dryrun") == real[0].end());
        d.baton = false;
        d.url = "https://example.org/a.json";
        d.hash = QString(64, 'A');
        const json o2 = genesisParams(d, c, false)[0];
        QVERIFY(o2.find("batonaddress") != o2.end() && o2["batonaddress"].is_null());   // null: no baton, fixed supply
        QCOMPARE(QString::fromStdString(o2["documenturl"].get<std::string>()), QString("https://example.org/a.json"));
        QCOMPARE(QString::fromStdString(o2["documenthash"].get<std::string>()), QString(64, 'a'));
    }

    void genesis_texts()
    {
        QVERIFY(createExplanation().contains("Advanced"));
        QVERIFY(createExplanation().contains("mint baton"));
        QVERIFY(createExplanation().contains("cannot be undone"));
        QVERIFY(createExplanation().contains("not by its ticker"));
        GenesisDraft d;
        d.ticker = "TST"; d.name = "Test token"; d.decimals = "2"; d.quantity = "1000.00";
        const GenesisCheck c = checkGenesis(d);
        const TxPlan p = parseTxPlan(json{{"txid", "ab12"}, {"tokenid", "ab12"}, {"fee", 0.00000312}, {"broadcast", false}});
        QVERIFY(genesisReviewText(d, c, p).contains("keep the mint baton"));
        QVERIFY(genesisReviewText(d, c, p).contains("0.00000312 ZCL"));
        d.baton = false;
        QVERIFY(genesisReviewText(d, c, p).contains("fixed for good"));
        QVERIFY(genesisResultText(d, c, p).contains("Token id: ab12"));
    }

    // ---- the send dialog, against a fake daemon --------------------------------------------------

    void sendDialog_fullFlow()
    {
        FakeRpc rpc;
        TokenSendDialog d(&rpc, {aaa(), bbb()});
        QSignalSpy sent(&d, &StepDialog::sent);
        auto* to = d.findChild<QLineEdit*>("toEdit");
        auto* amt = d.findChild<QLineEdit*>("amountEdit");
        auto* review = d.findChild<QPushButton*>("reviewButton");
        auto* send = d.findChild<QPushButton*>("sendButton");
        QVERIFY(to && amt && review && send);
        QCOMPARE(d.page(), int(StepDialog::FormPage));
        QVERIFY(d.findChild<QLabel*>("availableLabel")->text().contains("899.50"));
        to->setText(kAddr);
        amt->setText("12.34");
        review->click();
        QCOMPARE(rpc.calls.size(), 1);                                           // the dry run, nothing else
        QCOMPARE(rpc.calls[0].method, QString("zslp_send"));
        QVERIFY(rpc.calls[0].params[4].get<bool>());
        QCOMPARE(d.page(), int(StepDialog::FormPage));                          // not until the daemon has answered
        QVERIFY(!review->isEnabled());                                           // busy
        rpc.answer(0, sendReply(false));
        QCOMPARE(d.page(), int(StepDialog::ReviewPage));
        auto* rl = d.findChild<QLabel*>("reviewLabel");
        QVERIFY(rl->text().contains("Network fee: 0.00000481 ZCL"));
        QVERIFY(rl->text().contains("887.16"));
        QCOMPARE(rl->textFormat(), Qt::PlainText);                               // chain text is never rendered as HTML
        QCOMPARE(sent.count(), 0);
        send->click();
        QCOMPARE(rpc.calls.size(), 2);
        QVERIFY(!rpc.calls[1].params[4].get<bool>());                           // the real thing
        QCOMPARE(rpc.calls[1].params[1][0]["amount"].get<std::string>(), std::string("12.34"));
        send->click();                                                           // a second click while busy does nothing
        QCOMPARE(rpc.calls.size(), 2);
        rpc.answer(1, sendReply(true));
        QCOMPARE(d.page(), int(StepDialog::ResultPage));
        QVERIFY(d.findChild<QLabel*>("resultLabel")->text().contains("Sent 12.34 AAA"));
        QCOMPARE(sent.count(), 1);
        QVERIFY(!send->isEnabled());                                             // no second send from one review
    }

    void sendDialog_cannotCloseWhileTheNodeWorks()
    {
        // the reply callbacks hold the dialog (deleted on close in the wallet): it must stay while busy
        FakeRpc rpc;
        TokenSendDialog d(&rpc, {aaa()});
        d.show();
        d.findChild<QLineEdit*>("toEdit")->setText(kAddr);
        d.findChild<QLineEdit*>("amountEdit")->setText("12.34");
        d.findChild<QPushButton*>("reviewButton")->click();
        QCOMPARE(rpc.calls.size(), 1);
        QTest::keyClick(&d, Qt::Key_Escape);
        QVERIFY(d.isVisible());
        d.reject();
        QVERIFY(d.isVisible());
        QVERIFY(!d.close());
        QVERIFY(d.isVisible());
        rpc.answer(0, sendReply(false));
        QCOMPARE(d.page(), int(StepDialog::ReviewPage));
        d.findChild<QPushButton*>("sendButton")->click();
        QCOMPARE(rpc.calls.size(), 2);
        QTest::keyClick(&d, Qt::Key_Escape);
        QVERIFY(d.isVisible());                                                  // the send is in flight
        rpc.answer(1, sendReply(true));
        QCOMPARE(d.page(), int(StepDialog::ResultPage));
        QTest::keyClick(&d, Qt::Key_Escape);
        QVERIFY(!d.isVisible());                                                 // idle again: closes as usual
    }

    void sendDialog_badInputNeverReachesTheDaemon()
    {
        FakeRpc rpc;
        TokenSendDialog d(&rpc, {aaa()});
        auto* to = d.findChild<QLineEdit*>("toEdit");
        auto* amt = d.findChild<QLineEdit*>("amountEdit");
        auto* review = d.findChild<QPushButton*>("reviewButton");
        auto* err = d.findChild<QLabel*>("errorLabel");
        d.show();
        to->setText(kAddr);
        amt->setText("1.234");
        review->click();
        QCOMPARE(rpc.calls.size(), 0);
        QVERIFY(err->isVisible());
        QVERIFY(err->text().contains("2 decimal places"));
        amt->setText("900");
        review->click();
        QVERIFY(err->text().contains("899.50"));
        to->setText("zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly");
        amt->setText("1");
        review->click();
        QVERIFY(err->text().contains("Shielded"));
        QCOMPARE(rpc.calls.size(), 0);
        QCOMPARE(d.page(), int(StepDialog::FormPage));
    }

    void sendDialog_daemonRefusesTheReview()
    {
        FakeRpc rpc;
        TokenSendDialog d(&rpc, {aaa()});
        d.show();
        d.findChild<QLineEdit*>("toEdit")->setText(kAddr);
        d.findChild<QLineEdit*>("amountEdit")->setText("1");
        d.findChild<QPushButton*>("reviewButton")->click();
        rpc.answerError(0, "not enough ordinary ZCL for the fee and the token dust outputs");
        QCOMPARE(d.page(), int(StepDialog::FormPage));
        auto* err = d.findChild<QLabel*>("errorLabel");
        QVERIFY(err->isVisible());
        QVERIFY(err->text().contains("never used for the fee"));
        QVERIFY(d.findChild<QPushButton*>("reviewButton")->isEnabled());        // the user can fix it and try again
    }

    void sendDialog_aDryRunThatBroadcastIsNotTrusted()
    {
        FakeRpc rpc;
        TokenSendDialog d(&rpc, {aaa()});
        d.show();
        d.findChild<QLineEdit*>("toEdit")->setText(kAddr);
        d.findChild<QLineEdit*>("amountEdit")->setText("1");
        d.findChild<QPushButton*>("reviewButton")->click();
        rpc.answer(0, sendReply(true));                                          // an answer that says it was broadcast
        QCOMPARE(d.page(), int(StepDialog::FormPage));
        QVERIFY(d.findChild<QLabel*>("errorLabel")->text().contains("not a dry run"));
    }

    void sendDialog_failureOnSend()
    {
        FakeRpc rpc;
        TokenSendDialog d(&rpc, {aaa()});
        QSignalSpy sent(&d, &StepDialog::sent);
        d.findChild<QLineEdit*>("toEdit")->setText(kAddr);
        d.findChild<QLineEdit*>("amountEdit")->setText("1");
        d.findChild<QPushButton*>("reviewButton")->click();
        rpc.answer(0, sendReply(false));
        d.findChild<QPushButton*>("sendButton")->click();
        rpc.answerError(1, "the transaction was built and checked, but this node rejected it");
        QCOMPARE(d.page(), int(StepDialog::ResultPage));
        const QString t = d.findChild<QLabel*>("resultLabel")->text();
        QVERIFY(t.contains("was not sent"));
        QVERIFY(t.contains("rejected it"));
        QCOMPARE(sent.count(), 0);
    }

    // The node never answered the real send (the dialog's 120 s timeout): it may have broadcast it, so the result
    // page must say the outcome is unknown and must not say "not sent", which invites a second send.
    void sendDialog_noAnswerIsNotCalledNotSent()
    {
        FakeRpc rpc;
        TokenSendDialog d(&rpc, {aaa()});
        d.findChild<QLineEdit*>("toEdit")->setText(kAddr);
        d.findChild<QLineEdit*>("amountEdit")->setText("1");
        d.findChild<QPushButton*>("reviewButton")->click();
        rpc.answer(0, sendReply(false));
        d.findChild<QPushButton*>("sendButton")->click();
        rpc.answerError(1, tokens::outcomeUnknownText());
        QCOMPARE(d.page(), int(StepDialog::ResultPage));
        const QString t = d.findChild<QLabel*>("resultLabel")->text();
        QVERIFY2(!t.contains("not sent"), qPrintable(t));
        QVERIFY(t.contains("outcome is unknown"));

        FakeRpc rpc2;
        TokenCreateDialog c(&rpc2);
        c.findChild<QLineEdit*>("tickerEdit")->setText("TST");
        c.findChild<QLineEdit*>("nameEdit")->setText("Test token");
        c.findChild<QLineEdit*>("quantityEdit")->setText("1000");
        c.findChild<QPushButton*>("reviewButton")->click();
        QCOMPARE(rpc2.calls.size(), 1);
        rpc2.answer(0, json{{"txid", "0e543b8cc4a11d8180d67d4baf46f3faf42cddf8f8ee41de312ce18310552f55"},
                            {"tokenid", kTok}, {"type", "genesis"}, {"broadcast", false}, {"amount", "1000"},
                            {"tokeninputs", 0}, {"fee", 0.00000481}});
        QCOMPARE(c.page(), int(StepDialog::ReviewPage));
        c.findChild<QPushButton*>("sendButton")->click();
        rpc2.answerError(1, tokens::outcomeUnknownText());
        QCOMPARE(c.page(), int(StepDialog::ResultPage));
        const QString ct = c.findChild<QLabel*>("resultLabel")->text();
        QVERIFY2(!ct.contains("not created"), qPrintable(ct));
        QVERIFY(ct.contains("outcome is unknown"));
    }

    void sendDialog_maxAndTokenSwitch()
    {
        FakeRpc rpc;
        TokenSendDialog d(&rpc, {aaa(), bbb()});
        auto* amt = d.findChild<QLineEdit*>("amountEdit");
        auto* box = d.findChild<QComboBox*>("tokenBox");
        d.findChild<QPushButton*>("maxButton")->click();
        QCOMPARE(amt->text(), QString("899.50"));                               // the balance string as the daemon wrote it
        box->setCurrentIndex(1);
        QVERIFY(d.findChild<QLabel*>("availableLabel")->text().contains("5000 BBB"));
        d.findChild<QPushButton*>("maxButton")->click();
        QCOMPARE(amt->text(), QString("5000"));
    }

    void sendDialog_noTokens()
    {
        FakeRpc rpc;
        TokenSendDialog d(&rpc, QVector<TokenChoice>());
        QVERIFY(!d.findChild<QPushButton*>("reviewButton")->isEnabled());
        QVERIFY(d.findChild<QLabel*>("availableLabel")->text().contains("no confirmed tokens"));
    }

    void sendDialog_backReturnsToTheForm()
    {
        FakeRpc rpc;
        TokenSendDialog d(&rpc, {aaa()});
        d.findChild<QLineEdit*>("toEdit")->setText(kAddr);
        d.findChild<QLineEdit*>("amountEdit")->setText("1");
        d.findChild<QPushButton*>("reviewButton")->click();
        rpc.answer(0, sendReply(false));
        QCOMPARE(d.page(), int(StepDialog::ReviewPage));
        d.findChild<QPushButton*>("backButton")->click();
        QCOMPARE(d.page(), int(StepDialog::FormPage));
        QCOMPARE(rpc.calls.size(), 1);                                           // going back sends nothing
    }

    // ---- the create dialog -------------------------------------------------------------------------

    void createDialog_fullFlow()
    {
        FakeRpc rpc;
        TokenCreateDialog d(&rpc);
        QSignalSpy sent(&d, &StepDialog::sent);
        QVERIFY(d.findChild<QLabel*>("explainLabel")->text().contains("Advanced"));
        QCOMPARE(d.findChild<QLabel*>("explainLabel")->textFormat(), Qt::PlainText);
        QVERIFY(d.findChild<QCheckBox*>("batonBox")->isChecked());
        d.findChild<QLineEdit*>("tickerEdit")->setText("TST");
        d.findChild<QLineEdit*>("nameEdit")->setText("Test token");
        d.findChild<QLineEdit*>("decimalsEdit")->setText("2");
        d.findChild<QLineEdit*>("quantityEdit")->setText("1000.00");
        d.findChild<QPushButton*>("reviewButton")->click();
        QCOMPARE(rpc.calls.size(), 1);
        QCOMPARE(rpc.calls[0].method, QString("zslp_genesis"));
        QVERIFY(rpc.calls[0].params[0]["dryrun"].get<bool>());
        QVERIFY(rpc.calls[0].params[0].find("batonaddress") == rpc.calls[0].params[0].end());
        rpc.answer(0, json{{"txid", "ab12"}, {"tokenid", "ab12"}, {"type", "genesis"}, {"broadcast", false},
                           {"amount", "1000.00"}, {"tokeninputs", 0}, {"fee", 0.00000312}});
        QCOMPARE(d.page(), int(StepDialog::ReviewPage));
        QVERIFY(d.findChild<QLabel*>("reviewLabel")->text().contains("create the token TST"));
        d.findChild<QPushButton*>("sendButton")->click();
        QCOMPARE(rpc.calls.size(), 2);
        QVERIFY(rpc.calls[1].params[0].find("dryrun") == rpc.calls[1].params[0].end());
        rpc.answer(1, json{{"txid", "cd34"}, {"tokenid", "cd34"}, {"type", "genesis"}, {"broadcast", true},
                           {"amount", "1000.00"}, {"tokeninputs", 0}, {"fee", 0.00000312}});
        QCOMPARE(d.page(), int(StepDialog::ResultPage));
        QVERIFY(d.findChild<QLabel*>("resultLabel")->text().contains("Token id: cd34"));
        QCOMPARE(sent.count(), 1);
    }

    void createDialog_noBatonAndBadInput()
    {
        FakeRpc rpc;
        TokenCreateDialog d(&rpc);
        d.show();
        d.findChild<QLineEdit*>("tickerEdit")->setText("TST");
        d.findChild<QLineEdit*>("nameEdit")->setText("Test token");
        d.findChild<QLineEdit*>("quantityEdit")->setText("0");
        d.findChild<QPushButton*>("reviewButton")->click();
        QCOMPARE(rpc.calls.size(), 0);
        QVERIFY(d.findChild<QLabel*>("errorLabel")->text().contains("greater than zero"));
        d.findChild<QLineEdit*>("quantityEdit")->setText("1000");
        d.findChild<QCheckBox*>("batonBox")->setChecked(false);
        d.findChild<QPushButton*>("reviewButton")->click();
        QCOMPARE(rpc.calls.size(), 1);
        const json& o = rpc.calls[0].params[0];
        QVERIFY(o.find("batonaddress") != o.end() && o["batonaddress"].is_null());
    }

    void createDialog_daemonErrors()
    {
        FakeRpc rpc;
        TokenCreateDialog d(&rpc);
        d.show();
        d.findChild<QLineEdit*>("tickerEdit")->setText("TST");
        d.findChild<QLineEdit*>("nameEdit")->setText("Test token");
        d.findChild<QLineEdit*>("quantityEdit")->setText("1000");
        d.findChild<QPushButton*>("reviewButton")->click();
        rpc.answerError(0, "Error: Please enter the wallet passphrase with walletpassphrase first.");
        QCOMPARE(d.page(), int(StepDialog::FormPage));
        QVERIFY(d.findChild<QLabel*>("errorLabel")->text().contains("locked"));
    }
};

QTEST_MAIN(TstTokensSend)
#include "tst_tokenssend.moc"
