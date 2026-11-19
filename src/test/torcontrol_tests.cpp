// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include "test/test_bitcoin.h"
#include "torcontrol.cpp"

#include <boost/test/unit_test.hpp>


BOOST_FIXTURE_TEST_SUITE(torcontrol_tests, BasicTestingSetup)

void CheckSplitTorReplyLine(std::string input, std::string command, std::string args)
{
    BOOST_TEST_MESSAGE(std::string("CheckSplitTorReplyLine(") + input + ")");
    auto ret = SplitTorReplyLine(input);
    BOOST_CHECK_EQUAL(ret.first, command);
    BOOST_CHECK_EQUAL(ret.second, args);
}

BOOST_AUTO_TEST_CASE(util_SplitTorReplyLine)
{
    // Data we should receive during normal usage
    CheckSplitTorReplyLine(
        "PROTOCOLINFO PIVERSION",
        "PROTOCOLINFO", "PIVERSION");
    CheckSplitTorReplyLine(
        "AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/home/x/.tor/control_auth_cookie\"",
        "AUTH", "METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/home/x/.tor/control_auth_cookie\"");
    CheckSplitTorReplyLine(
        "AUTH METHODS=NULL",
        "AUTH", "METHODS=NULL");
    CheckSplitTorReplyLine(
        "AUTH METHODS=HASHEDPASSWORD",
        "AUTH", "METHODS=HASHEDPASSWORD");
    CheckSplitTorReplyLine(
        "VERSION Tor=\"0.2.9.8 (git-a0df013ea241b026)\"",
        "VERSION", "Tor=\"0.2.9.8 (git-a0df013ea241b026)\"");
    CheckSplitTorReplyLine(
        "AUTHCHALLENGE SERVERHASH=aaaa SERVERNONCE=bbbb",
        "AUTHCHALLENGE", "SERVERHASH=aaaa SERVERNONCE=bbbb");

    // Other valid inputs
    CheckSplitTorReplyLine("COMMAND", "COMMAND", "");
    CheckSplitTorReplyLine("COMMAND SOME  ARGS", "COMMAND", "SOME  ARGS");

    // These inputs are valid because PROTOCOLINFO accepts an OtherLine that is
    // just an OptArguments, which enables multiple spaces to be present
    // between the command and arguments.
    CheckSplitTorReplyLine("COMMAND  ARGS", "COMMAND", " ARGS");
    CheckSplitTorReplyLine("COMMAND   EVEN+more  ARGS", "COMMAND", "  EVEN+more  ARGS");
}

void CheckParseTorReplyMapping(std::string input, std::map<std::string,std::string> expected)
{
    BOOST_TEST_MESSAGE(std::string("CheckParseTorReplyMapping(") + input + ")");
    auto ret = ParseTorReplyMapping(input);
    BOOST_CHECK_EQUAL(ret.size(), expected.size());
    auto r_it = ret.begin();
    auto e_it = expected.begin();
    while (r_it != ret.end() && e_it != expected.end()) {
        BOOST_CHECK_EQUAL(r_it->first, e_it->first);
        BOOST_CHECK_EQUAL(r_it->second, e_it->second);
        r_it++;
        e_it++;
    }
}

BOOST_AUTO_TEST_CASE(util_ParseTorReplyMapping)
{
    // Data we should receive during normal usage
    CheckParseTorReplyMapping(
        "METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/home/x/.tor/control_auth_cookie\"", {
            {"METHODS", "COOKIE,SAFECOOKIE"},
            {"COOKIEFILE", "/home/x/.tor/control_auth_cookie"},
        });
    CheckParseTorReplyMapping(
        "METHODS=NULL", {
            {"METHODS", "NULL"},
        });
    CheckParseTorReplyMapping(
        "METHODS=HASHEDPASSWORD", {
            {"METHODS", "HASHEDPASSWORD"},
        });
    CheckParseTorReplyMapping(
        "Tor=\"0.2.9.8 (git-a0df013ea241b026)\"", {
            {"Tor", "0.2.9.8 (git-a0df013ea241b026)"},
        });
    CheckParseTorReplyMapping(
        "SERVERHASH=aaaa SERVERNONCE=bbbb", {
            {"SERVERHASH", "aaaa"},
            {"SERVERNONCE", "bbbb"},
        });
    CheckParseTorReplyMapping(
        "ServiceID=exampleonion1234", {
            {"ServiceID", "exampleonion1234"},
        });
    CheckParseTorReplyMapping(
        "PrivateKey=RSA1024:BLOB", {
            {"PrivateKey", "RSA1024:BLOB"},
        });
    CheckParseTorReplyMapping(
        "ClientAuth=bob:BLOB", {
            {"ClientAuth", "bob:BLOB"},
        });

    // Other valid inputs
    CheckParseTorReplyMapping(
        "Foo=Bar=Baz Spam=Eggs", {
            {"Foo", "Bar=Baz"},
            {"Spam", "Eggs"},
        });
    CheckParseTorReplyMapping(
        "Foo=\"Bar=Baz\"", {
            {"Foo", "Bar=Baz"},
        });
    CheckParseTorReplyMapping(
        "Foo=\"Bar Baz\"", {
            {"Foo", "Bar Baz"},
        });

    // Escapes
    CheckParseTorReplyMapping(
        "Foo=\"Bar\\ Baz\"", {
            {"Foo", "Bar Baz"},
        });
    CheckParseTorReplyMapping(
        "Foo=\"Bar\\Baz\"", {
            {"Foo", "BarBaz"},
        });
    CheckParseTorReplyMapping(
        "Foo=\"Bar\\@Baz\"", {
            {"Foo", "Bar@Baz"},
        });
    CheckParseTorReplyMapping(
        "Foo=\"Bar\\\"Baz\" Spam=\"\\\"Eggs\\\"\"", {
            {"Foo", "Bar\"Baz"},
            {"Spam", "\"Eggs\""},
        });
    CheckParseTorReplyMapping(
        "Foo=\"Bar\\\\Baz\"", {
            {"Foo", "Bar\\Baz"},
        });

    // C escapes
    CheckParseTorReplyMapping(
        "Foo=\"Bar\\nBaz\\t\" Spam=\"\\rEggs\" Octals=\"\\1a\\11\\17\\18\\81\\377\\378\\400\\2222\" Final=Check", {
            {"Foo", "Bar\nBaz\t"},
            {"Spam", "\rEggs"},
            {"Octals", "\1a\11\17\1" "881\377\37" "8\40" "0\222" "2"},
            {"Final", "Check"},
        });
    CheckParseTorReplyMapping(
        "Valid=Mapping Escaped=\"Escape\\\\\"", {
            {"Valid", "Mapping"},
            {"Escaped", "Escape\\"},
        });
    CheckParseTorReplyMapping(
        "Valid=Mapping Bare=\"Escape\\\"", {});
    CheckParseTorReplyMapping(
        "OneOctal=\"OneEnd\\1\" TwoOctal=\"TwoEnd\\11\"", {
            {"OneOctal", "OneEnd\1"},
            {"TwoOctal", "TwoEnd\11"},
        });

    // Special handling for null case
    // (needed because string comparison reads the null as end-of-string)
    BOOST_TEST_MESSAGE(std::string("CheckParseTorReplyMapping(Null=\"\\0\")"));
    auto ret = ParseTorReplyMapping("Null=\"\\0\"");
    BOOST_CHECK_EQUAL(ret.size(), 1);
    auto r_it = ret.begin();
    BOOST_CHECK_EQUAL(r_it->first, "Null");
    BOOST_CHECK_EQUAL(r_it->second.size(), 1);
    BOOST_CHECK_EQUAL(r_it->second[0], '\0');

    // A more complex valid grammar. PROTOCOLINFO accepts a VersionLine that
    // takes a key=value pair followed by an OptArguments, making this valid.
    // Because an OptArguments contains no semantic data, there is no point in
    // parsing it.
    CheckParseTorReplyMapping(
        "SOME=args,here MORE optional=arguments  here", {
            {"SOME", "args,here"},
        });

    // Inputs that are effectively invalid under the target grammar.
    // PROTOCOLINFO accepts an OtherLine that is just an OptArguments, which
    // would make these inputs valid. However,
    // - This parser is never used in that situation, because the
    //   SplitTorReplyLine parser enables OtherLine to be skipped.
    // - Even if these were valid, an OptArguments contains no semantic data,
    //   so there is no point in parsing it.
    CheckParseTorReplyMapping("ARGS", {});
    CheckParseTorReplyMapping("MORE ARGS", {});
    CheckParseTorReplyMapping("MORE  ARGS", {});
    CheckParseTorReplyMapping("EVEN more=ARGS", {});
    CheckParseTorReplyMapping("EVEN+more ARGS", {});
}

BOOST_AUTO_TEST_CASE(util_ParseTorSocksListeners)
{
    CService addr;

    // The usual single listener
    BOOST_CHECK(ParseTorSocksListeners("net/listeners/socks=\"127.0.0.1:9050\"", addr));
    BOOST_CHECK_EQUAL(addr.ToString(), "127.0.0.1:9050");

    // A listener on another port (embedded or non-default Tor)
    BOOST_CHECK(ParseTorSocksListeners("net/listeners/socks=\"127.0.0.1:39211\"", addr));
    BOOST_CHECK_EQUAL(addr.ToString(), "127.0.0.1:39211");

    // Unix sockets are skipped, the first TCP listener wins
    BOOST_CHECK(ParseTorSocksListeners(
        "net/listeners/socks=\"unix:/run/tor/socks\" \"127.0.0.1:9150\" \"127.0.0.1:9050\"", addr));
    BOOST_CHECK_EQUAL(addr.ToString(), "127.0.0.1:9150");

    // IPv6 loopback
    BOOST_CHECK(ParseTorSocksListeners("net/listeners/socks=\"[::1]:9050\"", addr));
    BOOST_CHECK_EQUAL(addr.ToString(), "[::1]:9050");

    // Nothing usable: no listener, only a unix socket, a wildcard bind, a
    // missing port, a host name (never resolved), another key, bad quoting.
    CService unchanged("10.1.2.3", 1234);
    addr = unchanged;
    BOOST_CHECK(!ParseTorSocksListeners("net/listeners/socks=", addr));
    BOOST_CHECK(!ParseTorSocksListeners("net/listeners/socks=\"unix:/run/tor/socks\"", addr));
    BOOST_CHECK(!ParseTorSocksListeners("net/listeners/socks=\"0.0.0.0:9050\"", addr));
    BOOST_CHECK(!ParseTorSocksListeners("net/listeners/socks=\"127.0.0.1\"", addr));
    BOOST_CHECK(!ParseTorSocksListeners("net/listeners/socks=\"localhost:9050\"", addr));
    BOOST_CHECK(!ParseTorSocksListeners("net/listeners/control=\"127.0.0.1:9051\"", addr));
    BOOST_CHECK(!ParseTorSocksListeners("net/listeners/socks=\"127.0.0.1:9050", addr));
    BOOST_CHECK(!ParseTorSocksListeners("net/listeners/socks=127.0.0.1:9050", addr));
    BOOST_CHECK(!ParseTorSocksListeners("OK", addr));
    BOOST_CHECK(!ParseTorSocksListeners("", addr));
    BOOST_CHECK(addr == unchanged);
}

BOOST_AUTO_TEST_CASE(util_DefaultTorSocksProxy)
{
    // With the default control port this is the address that used to be
    // hard-coded.
    BOOST_CHECK_EQUAL(DefaultTorSocksProxy(DEFAULT_TOR_CONTROL).ToString(), "127.0.0.1:9050");
    // The control port's host is kept, the port is Tor's default SOCKS port.
    BOOST_CHECK_EQUAL(DefaultTorSocksProxy("10.0.0.5:9151").ToString(), "10.0.0.5:9050");
    BOOST_CHECK_EQUAL(DefaultTorSocksProxy("10.0.0.5").ToString(), "10.0.0.5:9050");
    // A control target that is not a literal address is not resolved.
    BOOST_CHECK_EQUAL(DefaultTorSocksProxy("tor.invalid:9051").ToString(), "127.0.0.1:9050");
}

BOOST_AUTO_TEST_CASE(util_GetTorControlTarget)
{
    // No embedded Tor runs in a unit test: the option or its default is used.
    std::string saved = mapArgs.count("-torcontrol") ? mapArgs["-torcontrol"] : "";
    bool had = mapArgs.count("-torcontrol") != 0;
    mapArgs.erase("-torcontrol");
    BOOST_CHECK_EQUAL(GetTorControlTarget(), DEFAULT_TOR_CONTROL);
    mapArgs["-torcontrol"] = "127.0.0.1:19051";
    BOOST_CHECK_EQUAL(GetTorControlTarget(), "127.0.0.1:19051");
    if (had)
        mapArgs["-torcontrol"] = saved;
    else
        mapArgs.erase("-torcontrol");
}

// The dedicated onion listener (port+1 on our loopback) only helps a Tor that
// shares our loopback: a control address elsewhere keeps the P2P port as target.
BOOST_AUTO_TEST_CASE(util_TorControlAddressIsLocal)
{
    BOOST_CHECK(TorControlAddressIsLocal("127.0.0.1:9051"));
    BOOST_CHECK(TorControlAddressIsLocal("127.0.0.1"));
    BOOST_CHECK(TorControlAddressIsLocal("127.1.2.3:9051"));
    BOOST_CHECK(TorControlAddressIsLocal("[::1]:9051"));
    BOOST_CHECK(TorControlAddressIsLocal("localhost:9051"));
    BOOST_CHECK(!TorControlAddressIsLocal("172.17.0.1:9051"));
    BOOST_CHECK(!TorControlAddressIsLocal("192.168.1.5:9051"));
    BOOST_CHECK(!TorControlAddressIsLocal("93.184.216.34:9051"));
    BOOST_CHECK(!TorControlAddressIsLocal("tor.example.org:9051"));
    BOOST_CHECK(!TorControlAddressIsLocal(""));
}

BOOST_AUTO_TEST_SUITE_END()
