// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "torwatch.h"
#include "test/test_bitcoin.h"
#include "util.h"

#include <limits.h>
#include <stdio.h>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(torwatch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(torwatch_retry_schedule)
{
    BOOST_CHECK_EQUAL(TorRetryDelayMs(0), 5000);
    BOOST_CHECK_EQUAL(TorRetryDelayMs(1), 15000);
    BOOST_CHECK_EQUAL(TorRetryDelayMs(2), 45000);
    BOOST_CHECK_EQUAL(TorRetryDelayMs(3), 135000);
    BOOST_CHECK_EQUAL(TorRetryDelayMs(4), 300000);
    BOOST_CHECK_EQUAL(TorRetryDelayMs(5), 300000);
    // No overflow, no negative delay, whatever the count.
    BOOST_CHECK_EQUAL(TorRetryDelayMs(100), 300000);
    BOOST_CHECK_EQUAL(TorRetryDelayMs(INT_MAX), 300000);
    BOOST_CHECK_EQUAL(TorRetryDelayMs(-1), 5000);
    BOOST_CHECK_EQUAL(TorRetryDelayMs(INT_MIN), 5000);
}

BOOST_AUTO_TEST_CASE(torwatch_fault_tokens)
{
    BOOST_CHECK_EQUAL(std::string(TorFaultToken(TorFault::NONE)), "none");
    BOOST_CHECK_EQUAL(std::string(TorFaultToken(TorFault::EXITED)), "exited");
    BOOST_CHECK_EQUAL(std::string(TorFaultToken(TorFault::START_LIMIT)), "start_limit");
    BOOST_CHECK_EQUAL(std::string(TorFaultToken(TorFault::CONFIG_INVALID)), "config_invalid");
    BOOST_CHECK_EQUAL(std::string(TorFaultToken(TorFault::DATADIR)), "datadir");
    BOOST_CHECK_EQUAL(std::string(TorFaultToken(TorFault::PORT_IN_USE)), "port_in_use");
    // Ordered by specificity.
    BOOST_CHECK(TorFault::PORT_IN_USE > TorFault::DATADIR);
    BOOST_CHECK(TorFault::DATADIR > TorFault::CONFIG_INVALID);
    BOOST_CHECK(TorFault::CONFIG_INVALID > TorFault::START_LIMIT);
    BOOST_CHECK(TorFault::START_LIMIT > TorFault::EXITED);
    BOOST_CHECK(TorFault::EXITED > TorFault::NONE);
}

static const char* const LINE_BIND =
    "Nov 19 10:00:00.000 [warn] Could not bind to 127.0.0.1:9050: Address already in use. Is Tor already running?";
static const char* const LINE_CONFIG =
    "Nov 19 10:00:00.000 [err] Failed to parse/validate config: Unknown option 'Foo'.  Failing.";
static const char* const LINE_DATADIR =
    "Nov 19 10:00:00.000 [warn] Couldn't access private data directory \"/x/tor\": Permission denied";

BOOST_AUTO_TEST_CASE(torwatch_classify_line)
{
    BOOST_CHECK(TorClassifyLogLine(LINE_BIND) == TorFault::PORT_IN_USE);
    BOOST_CHECK(TorClassifyLogLine(LINE_CONFIG) == TorFault::CONFIG_INVALID);
    BOOST_CHECK(TorClassifyLogLine(LINE_DATADIR) == TorFault::DATADIR);
    BOOST_CHECK(TorClassifyLogLine("Reading config failed--see warnings above.") == TorFault::CONFIG_INVALID);
    BOOST_CHECK(TorClassifyLogLine("DataDirectory /x is not owned by this user") == TorFault::DATADIR);
    BOOST_CHECK(TorClassifyLogLine("Bootstrapped 100% (done): Done") == TorFault::NONE);
    BOOST_CHECK(TorClassifyLogLine("") == TorFault::NONE);
}

static std::string TempLog(const std::string& tag)
{
    return (boost::filesystem::temp_directory_path() / UniquePath("zcl-torwatch-" + tag + "-%%%%-%%%%")).string();
}

static void WriteFile(const std::string& path, const std::string& body)
{
    FILE* f = fopen(path.c_str(), "wb");
    BOOST_REQUIRE(f);
    BOOST_REQUIRE_EQUAL(fwrite(body.data(), 1, body.size(), f), body.size());
    fclose(f);
}

BOOST_AUTO_TEST_CASE(torwatch_scan_log_tail)
{
    uint64_t next = 7;
    // A missing log is no fault, and never throws.
    BOOST_CHECK(TorScanLogTail("/nonexistent/zcl-torwatch/tor.log", 0, &next) == TorFault::NONE);

    // All three faults: the most specific wins, and the next offset is the size.
    const std::string path = TempLog("all");
    const std::string body = std::string("[notice] Tor starting\n") + LINE_CONFIG + "\n" + LINE_BIND + "\n" +
                             LINE_DATADIR + "\n";
    WriteFile(path, body);
    BOOST_CHECK(TorScanLogTail(path, 0, &next) == TorFault::PORT_IN_USE);
    BOOST_CHECK_EQUAL(next, body.size());
    // Nothing new after the offset: no fault.
    BOOST_CHECK(TorScanLogTail(path, next, &next) == TorFault::NONE);
    // An offset past the end (log truncated) starts over.
    BOOST_CHECK(TorScanLogTail(path, body.size() + 100, &next) == TorFault::PORT_IN_USE);
    boost::filesystem::remove(path);

    // Only the last 8 KiB are read: a match just before them is not seen ...
    const std::string capped = TempLog("cap");
    const std::string filler(TOR_LOG_TAIL_BYTES, 'x');
    WriteFile(capped, std::string(LINE_BIND) + "\n" + filler);
    BOOST_CHECK(TorScanLogTail(capped, 0, &next) == TorFault::NONE);
    BOOST_CHECK_EQUAL(next, std::string(LINE_BIND).size() + 1 + filler.size());
    // ... and one inside them is.
    WriteFile(capped, filler + "\n" + LINE_DATADIR + "\n");
    BOOST_CHECK(TorScanLogTail(capped, 0, NULL) == TorFault::DATADIR);
    boost::filesystem::remove(capped);
}

BOOST_AUTO_TEST_CASE(torwatch_redact_onion)
{
    const std::string v3 = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd"; // 56 chars
    BOOST_REQUIRE_EQUAL(v3.size(), 56U);
    BOOST_CHECK_EQUAL(TorRedactOnion("Got service ID " + v3 + ", advertising " + v3 + ".onion:8033 now"),
                      "Got service ID " + v3 + ", advertising <onion>:8033 now");
    BOOST_CHECK_EQUAL(TorRedactOnion("a " + v3 + ".onion b " + v3 + ".onion"), "a <onion> b <onion>");
    // A 55-character run is not a v3 name and is left alone.
    const std::string short55 = v3.substr(1);
    BOOST_CHECK_EQUAL(TorRedactOnion("x " + short55 + ".onion y"), "x " + short55 + ".onion y");
    // Upper case is not base32 as Tor prints it; nothing else is touched.
    BOOST_CHECK_EQUAL(TorRedactOnion("Tor exited: Address already in use"), "Tor exited: Address already in use");
    BOOST_CHECK_EQUAL(TorRedactOnion(""), "");
}

static TorRestartPolicy NewPolicy(bool inProcess)
{
    TorRestartPolicy p = TorRestartPolicy();
    p.inProcess = inProcess;
    return p;
}

/** Tor dies at `now`: the stop, then the start once its delay passed. Returns the start time. */
static int64_t DieAndRestart(TorRestartPolicy& p, int64_t now, bool ok)
{
    BOOST_CHECK(TorRestartStep(p, false, now) == TorRestartDecision::STOP_AND_SCHEDULE);
    const int64_t due = p.nextAttemptMs;
    BOOST_CHECK(TorRestartStep(p, false, due - 1) == TorRestartDecision::NOTHING);
    BOOST_CHECK(TorRestartStep(p, false, due) == TorRestartDecision::START_NOW);
    // Held until the start reports back.
    BOOST_CHECK(TorRestartStep(p, false, due + 60000) == TorRestartDecision::NOTHING);
    TorRestartStarted(p, ok, due);
    return due;
}

BOOST_AUTO_TEST_CASE(torwatch_policy_backoff_and_settle)
{
    TorRestartPolicy p = NewPolicy(false);
    BOOST_CHECK(TorRestartStep(p, true, 1000) == TorRestartDecision::NOTHING);

    // First death: 5 s, then the restart dies quickly: 15 s.
    int64_t up = DieAndRestart(p, 10000, true);
    BOOST_CHECK_EQUAL(up, 15000);
    BOOST_CHECK_EQUAL(p.attempts, 1);
    up = DieAndRestart(p, up + 1000, true);
    BOOST_CHECK_EQUAL(up, 16000 + 15000);
    BOOST_CHECK_EQUAL(p.attempts, 2);

    // Up 29.999 s: not settled, the backoff stays.
    BOOST_CHECK(TorRestartStep(p, true, up + TOR_UP_SETTLE_MS - 1) == TorRestartDecision::NOTHING);
    BOOST_CHECK_EQUAL(p.attempts, 2);
    // Up 30 s: settled, the next death waits 5 s again.
    BOOST_CHECK(TorRestartStep(p, true, up + TOR_UP_SETTLE_MS) == TorRestartDecision::NOTHING);
    BOOST_CHECK_EQUAL(p.attempts, 0);
    const int64_t died = up + 100000;
    BOOST_CHECK(TorRestartStep(p, false, died) == TorRestartDecision::STOP_AND_SCHEDULE);
    BOOST_CHECK_EQUAL(p.nextAttemptMs, died + 5000);

    // A failed start schedules the next one with the grown delay.
    BOOST_CHECK(TorRestartStep(p, false, died + 5000) == TorRestartDecision::START_NOW);
    TorRestartStarted(p, false, died + 6000);
    BOOST_CHECK_EQUAL(p.nextAttemptMs, died + 6000 + 15000);
    BOOST_CHECK(TorRestartStep(p, false, died + 6000 + 15000) == TorRestartDecision::START_NOW);
}

BOOST_AUTO_TEST_CASE(torwatch_policy_inprocess_cap)
{
    TorRestartPolicy p = NewPolicy(true);
    int64_t now = 1000;
    for (int i = 0; i < TOR_MAX_RESTARTS_IN_PROCESS; i++)
        now = DieAndRestart(p, now + 1000, true);
    BOOST_CHECK_EQUAL(p.restartsThisProcess, TOR_MAX_RESTARTS_IN_PROCESS);

    // The fourth death: stopped, then given up exactly once.
    BOOST_CHECK(TorRestartStep(p, false, now + 1000) == TorRestartDecision::STOP_AND_SCHEDULE);
    BOOST_CHECK(TorRestartStep(p, false, p.nextAttemptMs) == TorRestartDecision::GIVE_UP);
    BOOST_CHECK(p.gaveUp);
    for (int i = 0; i < 5; i++) {
        BOOST_CHECK(TorRestartStep(p, false, now + 1000000 * (i + 1)) == TorRestartDecision::NOTHING);
        BOOST_CHECK(TorRestartStep(p, true, now + 1000000 * (i + 1)) == TorRestartDecision::NOTHING);
    }
    BOOST_CHECK(p.gaveUp);
}

BOOST_AUTO_TEST_CASE(torwatch_policy_child_unlimited)
{
    TorRestartPolicy p = NewPolicy(false);
    int64_t now = 1000;
    for (int i = 0; i < 50; i++)
        now = DieAndRestart(p, now + 1000, true);
    BOOST_CHECK_EQUAL(p.restartsThisProcess, 50);
    BOOST_CHECK(!p.gaveUp);
    // The delay stays at the cap however many restarts there were.
    BOOST_CHECK(TorRestartStep(p, false, now + 1000) == TorRestartDecision::STOP_AND_SCHEDULE);
    BOOST_CHECK_EQUAL(p.nextAttemptMs, now + 1000 + TOR_RETRY_CAP_MS);
}

BOOST_AUTO_TEST_SUITE_END()
