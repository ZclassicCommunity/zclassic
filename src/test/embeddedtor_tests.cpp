// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "embeddedtor.h"
#include "c23/tor/keyfile.h"
#include "netbase.h"
#include "test/test_bitcoin.h"
#include "utiltime.h"
#include "util.h"

#include <string>

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

#ifndef WIN32
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

    // The default must parse, and is the in-process mode.
    BOOST_CHECK(ParseEmbeddedTorMode(DEFAULT_EMBEDDED_TOR_MODE, mode));
    BOOST_CHECK_EQUAL(mode, EMBEDDED_TOR_INPROCESS);

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
                                  boost::filesystem::unique_path("zcl-keyfile-%%%%-%%%%-%%%%");
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

BOOST_AUTO_TEST_SUITE_END()
