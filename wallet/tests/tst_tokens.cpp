// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// L0 logic tests of the read-only Tokens view (tokensmodel.cpp): reply parsing, exact
// amount strings, protection wording. No daemon, no widgets.

#include <QtTest>

#include "pollguard.h"
#include "tokensmodel.h"

using json = nlohmann::json;

class TstTokens : public QObject {
    Q_OBJECT
private slots:
    void indexInfo_enabledAndSynced()
    {
        json r = {{"enabled", true}, {"running", true}, {"synced", true}, {"progress", 1.0},
                  {"indexedheight", 3300000}, {"chainheight", 3300000}, {"error", nullptr}};
        tokens::IndexStatus s = tokens::parseIndexInfo(r);
        QVERIFY(s.enabled);
        QVERIFY(s.synced);
        QCOMPARE(s.indexedHeight, 3300000);
        QVERIFY(s.error.isEmpty());
        QVERIFY(tokens::statusLine(s).contains("up to date"));
    }

    void indexInfo_building()
    {
        json r = {{"enabled", true}, {"synced", false}, {"progress", 0.425}, {"indexedheight", 1400000},
                  {"chainheight", 3300000}, {"error", nullptr}};
        tokens::IndexStatus s = tokens::parseIndexInfo(r);
        QVERIFY(s.enabled);
        QVERIFY(!s.synced);
        QCOMPARE(s.progress, 0.425);
        const QString line = tokens::statusLine(s);
        QVERIFY(line.contains("42%"));
        QVERIFY(line.contains("incomplete"));
    }

    void indexInfo_errorIsShown()
    {
        json r = {{"enabled", true}, {"synced", false}, {"progress", 0.1}, {"error", "cannot read block"}};
        tokens::IndexStatus s = tokens::parseIndexInfo(r);
        QVERIFY(tokens::statusLine(s).contains("cannot read block"));
    }

    void indexInfo_notEnabledOrMalformed()
    {
        QVERIFY(!tokens::parseIndexInfo(json::object()).enabled);
        QVERIFY(!tokens::parseIndexInfo(json(nullptr)).enabled);
        QVERIFY(!tokens::parseIndexInfo(json("x")).enabled);
        QVERIFY(!tokens::parseIndexInfo(json{{"enabled", false}}).enabled);
        QVERIFY(!tokens::parseIndexInfo(json{{"enabled", "yes"}}).enabled);
        // progress outside 0..1 is clamped
        QCOMPARE(tokens::parseIndexInfo(json{{"enabled", true}, {"progress", 7}}).progress, 1.0);
        QCOMPARE(tokens::parseIndexInfo(json{{"enabled", true}, {"progress", -3}}).progress, 0.0);
    }

    void snapshot_rowsAndExactAmounts()
    {
        json r = {
            {"synced", true},
            {"outputs", json::array({
                {{"txid", "aa"}, {"vout", 1}, {"address", "t1abc"}, {"tokenid", "t1"}, {"ticker", "TOK"},
                 {"decimals", 2}, {"role", "token"}, {"amount", "400.00"}, {"confirmations", 12}, {"protected", true}},
                {{"txid", "bb"}, {"vout", 2}, {"address", "t1def"}, {"tokenid", "t1"}, {"ticker", "TOK"},
                 {"decimals", 2}, {"role", "mintbaton"}, {"amount", "0.00"}, {"confirmations", 3}, {"protected", true}},
                {{"txid", "cc"}, {"vout", 1}, {"address", "t1ghi"}, {"tokenid", "t2"}, {"ticker", "BIG"},
                 {"decimals", 0}, {"role", "token"}, {"amount", "9223372036854775807"}, {"confirmations", 1}, {"protected", true}},
            })},
            {"balances", json::array({
                {{"tokenid", "t1"}, {"ticker", "TOK"}, {"decimals", 2}, {"amount", "400.00"}},
                {{"tokenid", "t2"}, {"ticker", "BIG"}, {"decimals", 0}, {"amount", "9223372036854775807"}},
            })}};
        tokens::Snapshot s;
        QVERIFY(tokens::parseSnapshot(r, &s));
        QVERIFY(s.synced);
        QCOMPARE(s.outputs.size(), 3);
        QCOMPARE(s.balances.size(), 2);
        QCOMPARE(s.outputs[0].amount, QString("400.00"));
        QCOMPARE(s.outputs[0].confirmations, 12);
        QCOMPARE(s.outputs[1].role, QString("mintbaton"));
        // 2^63-1 survives untouched: amounts are strings, never a double
        QCOMPARE(s.balances[1].amount, QString("9223372036854775807"));
        QCOMPARE(s.outputs[2].amount, QString("9223372036854775807"));
        for (const tokens::Output& o : s.outputs)
            QVERIFY(o.isProtected);
    }

    void snapshot_missingProtectedFieldMeansProtected()
    {
        json r = {{"outputs", json::array({{{"txid", "aa"}, {"vout", 0}, {"tokenid", "t"}, {"amount", "1"}, {"role", "token"}}})},
                  {"balances", json::array()}};
        tokens::Snapshot s;
        QVERIFY(tokens::parseSnapshot(r, &s));
        QCOMPARE(s.outputs.size(), 1);
        QVERIFY(s.outputs[0].isProtected);
        QVERIFY(!s.synced);
    }

    void snapshot_incompleteRowsAreDropped()
    {
        json r = {{"outputs", json::array({
                      {{"txid", "aa"}, {"vout", 1}, {"tokenid", "t"}, {"role", "token"}},          // no amount
                      {{"vout", 1}, {"tokenid", "t"}, {"amount", "5"}, {"role", "token"}},         // no txid
                      {{"txid", "dd"}, {"tokenid", "t"}, {"amount", "5"}, {"role", "token"}},      // no vout
                      "garbage",
                      {{"txid", "ee"}, {"vout", 0}, {"tokenid", "t"}, {"amount", "5"}, {"role", "token"}},
                  })},
                  {"balances", json::array({{{"tokenid", "t"}}, 7, {{"tokenid", "t"}, {"amount", "5"}}})}};
        tokens::Snapshot s;
        QVERIFY(tokens::parseSnapshot(r, &s));
        QCOMPARE(s.outputs.size(), 1);
        QCOMPARE(s.outputs[0].txid, QString("ee"));
        QCOMPARE(s.balances.size(), 1);
    }

    void snapshot_malformedReply()
    {
        tokens::Snapshot s;
        QVERIFY(!tokens::parseSnapshot(json(nullptr), &s));
        QVERIFY(!tokens::parseSnapshot(json::array(), &s));
        QVERIFY(!tokens::parseSnapshot(json{{"outputs", 3}, {"balances", json::array()}}, &s));
        QVERIFY(!tokens::parseSnapshot(json{{"outputs", json::array()}}, &s));
        QVERIFY(s.outputs.isEmpty());
        QVERIFY(!tokens::parseSnapshot(json::object(), nullptr));
    }

    void wording_saysProtectedAndPointsToSend()
    {
        const QString n = tokens::protectedNotice();
        QVERIFY(n.contains("protected"));
        QVERIFY(n.contains("never spends"));
        QVERIFY(n.contains("Send tokens"));            // sending is now a deliberate action of its own
        QVERIFY(n.contains("ordinary ZCL sends never touch them"));
        QVERIFY(tokens::roleText("mintbaton").contains("Mint baton"));
        QCOMPARE(tokens::roleText("token"), QString("Tokens"));
    }

    // A poll must not stay blocked after a node restart: the old connection never answers (doRPC drops the call and
    // its reply during a shutdown) and the new one is a different object.
    void pollGuardNeverGetsStuck()
    {
        int connA = 0, connB = 0;
        PollGuard g;
        const PollGuard::Ticket t1 = g.begin(&connA, false, 1000);
        QVERIFY(t1 != 0);
        QCOMPARE(g.begin(&connA, false, 2000), PollGuard::Ticket(0));   // one at a time
        QCOMPARE(g.begin(&connA, true, 2000), PollGuard::Ticket(0));    // shutting down: nothing is sent
        QCOMPARE(g.begin(nullptr, false, 2000), PollGuard::Ticket(0));
        // the restart replaced the connection: the request that will never be answered no longer blocks
        const PollGuard::Ticket t2 = g.begin(&connB, false, 3000);
        QVERIFY(t2 != 0 && t2 != t1);
        g.end(t1);                                                       // a late answer to the abandoned request
        QVERIFY(g.inFlight());
        g.end(t2);
        QVERIFY(!g.inFlight());
        // the same connection, but the reply was dropped: give up after the stale limit
        const PollGuard::Ticket t3 = g.begin(&connB, false, 4000);
        QVERIFY(t3 != 0);
        QCOMPARE(g.begin(&connB, false, 4000 + 59999), PollGuard::Ticket(0));
        QVERIFY(g.begin(&connB, false, 4000 + 60000) != 0);
    }

    void helpers()
    {
        QCOMPARE(tokens::displayTicker("TOK", "0123456789abcdef"), QString("TOK"));
        QCOMPARE(tokens::displayTicker("  ", "0123456789abcdef"), QString("01234567..."));
        QCOMPARE(tokens::displayTicker("", "ab"), QString("ab..."));
        QCOMPARE(tokens::shortOutpoint("0123456789abcdef0123456789abcdef", 3), QString("01234567...89abcdef:3"));
        QCOMPARE(tokens::shortOutpoint("abcd", 0), QString("abcd:0"));
    }
};

QTEST_APPLESS_MAIN(TstTokens)
#include "tst_tokens.moc"
