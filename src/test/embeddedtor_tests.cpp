// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "embeddedtor.h"
#include "c23/tor/keyfile.h"
#include "net.h"
#include "netbase.h"
#include "test/test_bitcoin.h"
#include "utiltime.h"
#include "util.h"

#include <string>

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

#ifndef WIN32
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

BOOST_FIXTURE_TEST_SUITE(embeddedtor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(embeddedtor_mode_parsing)
{
    EmbeddedTorMode mode = EMBEDDED_TOR_CHILD;
    BOOST_CHECK(ParseEmbeddedTorMode("inprocess", mode));
    BOOST_CHECK_EQUAL(mode, EMBEDDED_TOR_INPROCESS);
    BOOST_CHECK(ParseEmbeddedTorMode("child", mode));
    BOOST_CHECK_EQUAL(mode, EMBEDDED_TOR_CHILD);

    // The default must parse; it is the child process on Linux, in-process elsewhere.
    BOOST_CHECK(ParseEmbeddedTorMode(DEFAULT_EMBEDDED_TOR_MODE, mode));
#if defined(__linux__)
    BOOST_CHECK_EQUAL(mode, EMBEDDED_TOR_CHILD);
#else
    BOOST_CHECK_EQUAL(mode, EMBEDDED_TOR_INPROCESS);
#endif

    // Anything else is refused and leaves the output alone.
    mode = EMBEDDED_TOR_CHILD;
    BOOST_CHECK(!ParseEmbeddedTorMode("", mode));
    BOOST_CHECK(!ParseEmbeddedTorMode("1", mode));
    BOOST_CHECK(!ParseEmbeddedTorMode("InProcess", mode));
    BOOST_CHECK(!ParseEmbeddedTorMode("in-process", mode));
    BOOST_CHECK(!ParseEmbeddedTorMode("child ", mode));
    BOOST_CHECK(!ParseEmbeddedTorMode("thread", mode));
    BOOST_CHECK_EQUAL(mode, EMBEDDED_TOR_CHILD);
}

BOOST_AUTO_TEST_CASE(embeddedtor_options)
{
    // Off unless asked for, in every build.
    BOOST_CHECK_EQUAL(DEFAULT_EMBEDDED_TOR, false);
    mapArgs.erase("-embeddedtor");
    BOOST_CHECK(!GetBoolArg("-embeddedtor", DEFAULT_EMBEDDED_TOR));
    mapArgs["-embeddedtor"] = "1";
    BOOST_CHECK(GetBoolArg("-embeddedtor", DEFAULT_EMBEDDED_TOR));
    mapArgs["-embeddedtor"] = "0";
    BOOST_CHECK(!GetBoolArg("-embeddedtor", DEFAULT_EMBEDDED_TOR));
    mapArgs.erase("-embeddedtor");

    // Nothing is running in a unit test, and stopping nothing is harmless.
    BOOST_CHECK(!EmbeddedTorRunning());
    BOOST_CHECK_EQUAL(EmbeddedTorSocksPort(), 0);
    BOOST_CHECK_EQUAL(EmbeddedTorControlPort(), 0);
    StopEmbeddedTor();
    BOOST_CHECK(!EmbeddedTorRunning());

    // Only the private child argument selects the Tor child role.
    char arg0[] = "zclassicd";
    char arg1[] = "-regtest";
    char* argv[] = {arg0, arg1, NULL};
    BOOST_CHECK_EQUAL(EmbeddedTorDispatch(2, argv), -1);
    BOOST_CHECK_EQUAL(EmbeddedTorDispatch(1, argv), -1);

#ifndef ENABLE_EMBEDDED_TOR
    BOOST_CHECK(!EmbeddedTorAvailable());
    std::string err;
    BOOST_CHECK(!StartEmbeddedTor("/nonexistent", EMBEDDED_TOR_INPROCESS, err));
    BOOST_CHECK(!err.empty());
#else
    BOOST_CHECK(EmbeddedTorAvailable());
    // A datadir that does not exist is refused before anything is launched.
    std::string err;
    BOOST_CHECK(!StartEmbeddedTor("/nonexistent-zcl-embeddedtor-test", EMBEDDED_TOR_CHILD, err));
    BOOST_CHECK(!err.empty());
    BOOST_CHECK(!EmbeddedTorRunning());
#endif
}

BOOST_AUTO_TEST_CASE(embeddedtor_not_running_state)
{
    // Nothing started: no cookie path to trust, and not alive. The watchdog
    // and the control client key off these.
    BOOST_CHECK(EmbeddedTorCookiePath().empty());
    BOOST_CHECK(!EmbeddedTorAlive());
    StopEmbeddedTor();
    BOOST_CHECK(EmbeddedTorCookiePath().empty());
    BOOST_CHECK(!EmbeddedTorAlive());
}

BOOST_AUTO_TEST_CASE(proxy_only_refuses_direct_dial)
{
    // Off by default: nothing changes for a node without onion-only Tor.
    BOOST_CHECK(!IsProxyOnly());

    // On: an address with no proxy for its network is not dialled at all
    // (TEST-NET-1 is unroutable, so it never has a proxy), and the call
    // returns at once instead of after a connect timeout.
    SetProxyOnly(true);
    SOCKET s = INVALID_SOCKET;
    bool fProxyFailed = true;
    int64_t nStart = GetTimeMillis();
    BOOST_CHECK(!ConnectSocket(CService("192.0.2.1", 8033), s, 5000, &fProxyFailed));
    BOOST_CHECK(s == INVALID_SOCKET);
    BOOST_CHECK(!fProxyFailed);
    BOOST_CHECK(GetTimeMillis() - nStart < 1000);
    BOOST_CHECK(!ConnectSocket(CService("10.1.2.3", 8033), s, 5000));
    BOOST_CHECK(s == INVALID_SOCKET);
    SetProxyOnly(false);
    BOOST_CHECK(!IsProxyOnly());
}

BOOST_AUTO_TEST_CASE(embeddedtor_onion_only_requested)
{
    std::map<std::string, std::string> savedArgs = mapArgs;
    std::map<std::string, std::vector<std::string> > savedMulti = mapMultiArgs;
    mapArgs.erase("-embeddedtor");
    mapArgs.erase("-onlynet");
    mapMultiArgs.erase("-onlynet");

    // No -embeddedtor: never, whatever -onlynet says.
    mapArgs["-onlynet"] = "onion";
    mapMultiArgs["-onlynet"] = std::vector<std::string>(1, "onion");
    BOOST_CHECK(!EmbeddedTorOnionOnlyRequested());
    mapArgs["-embeddedtor"] = "0";
    BOOST_CHECK(!EmbeddedTorOnionOnlyRequested());

    // -embeddedtor with onion only (any spelling ParseNetwork accepts).
    mapArgs["-embeddedtor"] = "1";
    BOOST_CHECK(EmbeddedTorOnionOnlyRequested());
    mapMultiArgs["-onlynet"] = std::vector<std::string>(1, "tor");
    BOOST_CHECK(EmbeddedTorOnionOnlyRequested());
    mapMultiArgs["-onlynet"] = std::vector<std::string>(1, "ONION");
    BOOST_CHECK(EmbeddedTorOnionOnlyRequested());

    // Any clearnet network in the list: not onion-only.
    mapMultiArgs["-onlynet"].push_back("ipv4");
    BOOST_CHECK(!EmbeddedTorOnionOnlyRequested());
    mapMultiArgs["-onlynet"] = std::vector<std::string>(1, "ipv6");
    BOOST_CHECK(!EmbeddedTorOnionOnlyRequested());

    // -embeddedtor without -onlynet: a clearnet node that also uses Tor.
    mapArgs.erase("-onlynet");
    mapMultiArgs.erase("-onlynet");
    BOOST_CHECK(!EmbeddedTorOnionOnlyRequested());

    mapArgs = savedArgs;
    mapMultiArgs = savedMulti;
}

BOOST_AUTO_TEST_CASE(dnsseed_oneshots_only_off_in_onion_only_embedded_tor)
{
    std::map<std::string, std::string> savedArgs = mapArgs;
    std::map<std::string, std::vector<std::string> > savedMulti = mapMultiArgs;
    mapArgs.erase("-embeddedtor");
    mapArgs.erase("-onlynet");
    mapMultiArgs.erase("-onlynet");

    // Default and -embeddedtor=0 (with or without -onlynet=onion): unchanged.
    BOOST_CHECK(DnsSeedOneShotsAllowed());
    mapArgs["-onlynet"] = "onion";
    mapMultiArgs["-onlynet"] = std::vector<std::string>(1, "onion");
    BOOST_CHECK(DnsSeedOneShotsAllowed());
    mapArgs["-embeddedtor"] = "0";
    BOOST_CHECK(DnsSeedOneShotsAllowed());

    // Embedded Tor, onion only: seeds are not queued.
    mapArgs["-embeddedtor"] = "1";
    BOOST_CHECK(!DnsSeedOneShotsAllowed());

    // Embedded Tor that also allows clearnet: unchanged.
    mapMultiArgs["-onlynet"].push_back("ipv4");
    BOOST_CHECK(DnsSeedOneShotsAllowed());

    mapArgs = savedArgs;
    mapMultiArgs = savedMulti;
}
#ifndef WIN32
static mode_t FileMode(const std::string& path)
{
    struct stat st;
    BOOST_REQUIRE(lstat(path.c_str(), &st) == 0);
    return st.st_mode & 07777;
}

BOOST_AUTO_TEST_CASE(onion_keyfile_owner_only)
{
    boost::filesystem::path dir = boost::filesystem::temp_directory_path() /
                                  UniquePath("zcl-keyfile-%%%%-%%%%-%%%%");
    BOOST_REQUIRE(boost::filesystem::create_directories(dir));
    const std::string path = (dir / "onion_v3_private_key").string();
    const std::string key = "ED25519-V3:test-key-material-not-a-real-key";
    char err[256] = "";
    mode_t old = umask(022); // the daemon's usual umask must not matter

    // A new key file is 0600 whatever the umask is.
    BOOST_CHECK_EQUAL(zcl_keyfile_write(path.c_str(), key.data(), key.size(), err, sizeof(err)), 0);
    BOOST_CHECK_EQUAL(FileMode(path), 0600);
    char buf[256];
    size_t len = 0;
    BOOST_CHECK_EQUAL(zcl_keyfile_read(path.c_str(), buf, sizeof(buf), &len, err, sizeof(err)), 0);
    BOOST_CHECK_EQUAL(std::string(buf, len), key);

    // A key file left world-readable by an older version is tightened.
    BOOST_REQUIRE(chmod(path.c_str(), 0644) == 0);
    BOOST_CHECK_EQUAL(zcl_keyfile_tighten(path.c_str(), err, sizeof(err)), 0);
    BOOST_CHECK_EQUAL(FileMode(path), 0600);

    // Replacing a loose file leaves an owner-only file with the new contents
    // and no temporary file behind.
    BOOST_REQUIRE(chmod(path.c_str(), 0666) == 0);
    const std::string key2 = "ED25519-V3:second-test-key";
    BOOST_CHECK_EQUAL(zcl_keyfile_write(path.c_str(), key2.data(), key2.size(), err, sizeof(err)), 0);
    BOOST_CHECK_EQUAL(FileMode(path), 0600);
    BOOST_CHECK_EQUAL(zcl_keyfile_read(path.c_str(), buf, sizeof(buf), &len, err, sizeof(err)), 0);
    BOOST_CHECK_EQUAL(std::string(buf, len), key2);
    int entries = 0;
    for (boost::filesystem::directory_iterator it(dir); it != boost::filesystem::directory_iterator(); ++it)
        entries++;
    BOOST_CHECK_EQUAL(entries, 1);

    // A missing key file is reported as absent, not as an error.
    const std::string missing = (dir / "missing").string();
    BOOST_CHECK_EQUAL(zcl_keyfile_tighten(missing.c_str(), err, sizeof(err)), 1);

    // A symlink in place of the key file is refused for reading and
    // tightening, and its target is never touched.
    const std::string target = (dir / "victim").string();
    const std::string link = (dir / "link_key").string();
    BOOST_CHECK_EQUAL(zcl_keyfile_write(target.c_str(), "victim", 6, err, sizeof(err)), 0);
    BOOST_REQUIRE(chmod(target.c_str(), 0644) == 0);
    BOOST_REQUIRE(symlink(target.c_str(), link.c_str()) == 0);
    BOOST_CHECK(zcl_keyfile_tighten(link.c_str(), err, sizeof(err)) < 0);
    BOOST_CHECK(zcl_keyfile_read(link.c_str(), buf, sizeof(buf), &len, err, sizeof(err)) < 0);
    BOOST_CHECK_EQUAL(FileMode(target), 0644);
    // Writing replaces the link itself with a regular owner-only file.
    BOOST_CHECK_EQUAL(zcl_keyfile_write(link.c_str(), key.data(), key.size(), err, sizeof(err)), 0);
    struct stat st;
    BOOST_REQUIRE(lstat(link.c_str(), &st) == 0);
    BOOST_CHECK(S_ISREG(st.st_mode));
    BOOST_CHECK_EQUAL(FileMode(link), 0600);
    BOOST_CHECK_EQUAL(zcl_keyfile_read(target.c_str(), buf, sizeof(buf), &len, err, sizeof(err)), 0);
    BOOST_CHECK_EQUAL(std::string(buf, len), "victim");

    umask(old);
    boost::filesystem::remove_all(dir);
}
#endif // !WIN32

#if defined(ENABLE_EMBEDDED_TOR) && !defined(WIN32)
/** zclassicd to run as the Tor child: $ZCL_TEST_ZCLASSICD, else ../zclassicd beside test_bitcoin. */
static std::string ZclassicdForTest()
{
    const char* env = getenv("ZCL_TEST_ZCLASSICD");
    boost::filesystem::path exe;
    if (env && *env) {
        exe = env;
    } else {
        const boost::unit_test::master_test_suite_t& suite = boost::unit_test::framework::master_test_suite();
        if (suite.argc < 1)
            return std::string();
        exe = boost::filesystem::absolute(suite.argv[0]).parent_path().parent_path() / "zclassicd";
    }
    return access(exe.string().c_str(), X_OK) == 0 ? boost::filesystem::absolute(exe).string() : std::string();
}

/** Send PROTOCOLINFO to the control port; true when Tor answers 250. */
static bool ControlPortAnswers(uint16_t port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return false;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct timeval tv = {5, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    bool ok = false;
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
        const char cmd[] = "PROTOCOLINFO 1\r\n";
        char buf[64] = "";
        if (send(s, cmd, sizeof(cmd) - 1, 0) == (ssize_t)(sizeof(cmd) - 1)) {
            ssize_t n = recv(s, buf, sizeof(buf) - 1, 0);
            ok = n >= 3 && strncmp(buf, "250", 3) == 0;
        }
    }
    CloseSocket(s);
    return ok;
}

BOOST_AUTO_TEST_CASE(embeddedtor_child_killed_then_restarted)
{
    const std::string exe = ZclassicdForTest();
    if (exe.empty()) {
        BOOST_TEST_MESSAGE("skipped: no zclassicd to run as the Tor child (set ZCL_TEST_ZCLASSICD)");
        return;
    }
    boost::filesystem::path dir = boost::filesystem::temp_directory_path() /
                                  UniquePath("zcl-torrestart-%%%%-%%%%-%%%%");
    BOOST_REQUIRE(boost::filesystem::create_directories(dir));
    SetEmbeddedTorTestOptions(exe, true); // DisableNetwork: nothing leaves loopback
    std::string err;
    BOOST_REQUIRE_MESSAGE(StartEmbeddedTor(dir.string(), EMBEDDED_TOR_CHILD, err), err);
    BOOST_CHECK(EmbeddedTorAlive());
    const long pid = EmbeddedTorChildPid();
    BOOST_REQUIRE(pid > 0);
    BOOST_CHECK(ControlPortAnswers(EmbeddedTorControlPort()));

    // The child is killed: no longer alive within 5 s, still published until stopped.
    BOOST_REQUIRE_EQUAL(kill((pid_t)pid, SIGKILL), 0);
    const int64_t nKilled = GetTimeMillis();
    while (EmbeddedTorAlive() && GetTimeMillis() - nKilled < 5000)
        MilliSleep(50);
    BOOST_CHECK(!EmbeddedTorAlive());
    BOOST_CHECK(EmbeddedTorRunning());

    // Stopping is idempotent and leaves nothing running.
    StopEmbeddedTor();
    BOOST_CHECK(!EmbeddedTorRunning());
    BOOST_CHECK_EQUAL(EmbeddedTorControlPort(), 0);
    BOOST_CHECK_EQUAL(EmbeddedTorChildPid(), 0);
    StopEmbeddedTor();
    BOOST_CHECK(!EmbeddedTorRunning());

    // A fresh start on the same state directory works and answers on its control port.
    BOOST_REQUIRE_MESSAGE(StartEmbeddedTor(dir.string(), EMBEDDED_TOR_CHILD, err), err);
    BOOST_CHECK(EmbeddedTorAlive());
    BOOST_CHECK(EmbeddedTorChildPid() > 0 && EmbeddedTorChildPid() != pid);
    BOOST_CHECK(!EmbeddedTorCookiePath().empty());
    BOOST_CHECK(ControlPortAnswers(EmbeddedTorControlPort()));
    StopEmbeddedTor();
    BOOST_CHECK(!EmbeddedTorRunning());
    SetEmbeddedTorTestOptions("", false);
    boost::filesystem::remove_all(dir);
}
#endif // ENABLE_EMBEDDED_TOR && !WIN32

BOOST_AUTO_TEST_SUITE_END()
