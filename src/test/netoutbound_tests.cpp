// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Outbound candidate selection (SelectOutboundCandidate in net.cpp). Each case
// uses a table of one address, so every draw returns that address and the
// result depends only on the selection rules, not on addrman's randomness.

#include "addrman.h"
#include "chainparams.h"
#include "net.h"
#include "netbase.h"
#include "test/test_bitcoin.h"

#include <set>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

const int64_t NOW = 1700000000;

/** IPv4 and IPv6 reachable for the life of one test case. */
struct ReachableSetup : public BasicTestingSetup {
    bool fLimited4, fLimited6;
    ReachableSetup() : fLimited4(IsLimited(NET_IPV4)), fLimited6(IsLimited(NET_IPV6))
    {
        SetLimited(NET_IPV4, false);
        SetLimited(NET_IPV6, false);
    }
    ~ReachableSetup()
    {
        SetLimited(NET_IPV4, fLimited4);
        SetLimited(NET_IPV6, fLimited6);
    }
};

CAddress Addr(const char* ip, unsigned short port, int64_t nTime)
{
    CAddress a(CService(ip, port), NODE_NETWORK);
    a.nTime = (unsigned int)nTime;
    return a;
}

unsigned short DefaultPort()
{
    return Params().GetDefaultPort();
}

/** The one-address table's answer: the address, or an invalid one. nLastTry
 *  (0: never) is set through Attempt, which also counts one failed attempt. */
CAddrInfo SelectFromOne(const CAddress& addr, int64_t nLastTry = 0,
                        const std::set<std::vector<unsigned char> >& setConnected = std::set<std::vector<unsigned char> >(),
                        const COutboundSkip& skip = COutboundSkip())
{
    CAddrMan man;
    BOOST_REQUIRE(man.Add(addr, CNetAddr("93.184.216.1")));
    if (nLastTry != 0)
        man.Attempt(addr, nLastTry);
    return SelectOutboundCandidate(man, setConnected, NOW, skip);
}

bool Picks(const CAddress& addr, int64_t nLastTry = 0,
           const std::set<std::vector<unsigned char> >& setConnected = std::set<std::vector<unsigned char> >(),
           const COutboundSkip& skip = COutboundSkip())
{
    CAddrInfo pick = SelectFromOne(addr, nLastTry, setConnected, skip);
    if (!pick.IsValid())
        return false;
    BOOST_CHECK(CService(pick) == CService(addr));
    return true;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(netoutbound_tests, ReachableSetup)

BOOST_AUTO_TEST_CASE(empty_table_gives_nothing)
{
    CAddrMan man;
    BOOST_CHECK(!SelectOutboundCandidate(man, std::set<std::vector<unsigned char> >(), NOW).IsValid());
}

BOOST_AUTO_TEST_CASE(fresh_default_port_address_is_picked)
{
    BOOST_CHECK(Picks(Addr("94.185.1.2", DefaultPort(), NOW - 3600)));
}

BOOST_AUTO_TEST_CASE(recency_rules)
{
    const CAddress a = Addr("94.185.1.2", DefaultPort(), NOW - 3600);
    // tried within the minute: never, however many draws
    BOOST_CHECK(!Picks(a, NOW - 1));
    BOOST_CHECK(!Picks(a, NOW - 59));
    // at a minute and past it: only after the 10 minute rule relaxes, which a
    // one-address table reaches within the round
    BOOST_CHECK(Picks(a, NOW - 60));
    BOOST_CHECK(Picks(a, NOW - 90));
    BOOST_CHECK(Picks(a, NOW - 599));
    BOOST_CHECK(Picks(a, NOW - 600));
    BOOST_CHECK(Picks(a, NOW - 86400));
}

BOOST_AUTO_TEST_CASE(terrible_and_other_port_are_picked_late)
{
    // not seen for 40 days: terrible, picked once 30 tries have passed
    const CAddress ancient = Addr("94.185.1.2", DefaultPort(), NOW - 40 * 24 * 60 * 60);
    BOOST_REQUIRE(CAddrInfo(ancient, CNetAddr("93.184.216.1")).IsTerrible(NOW));
    BOOST_CHECK(Picks(ancient));
    // a non-default port: picked once 50 tries have passed
    BOOST_CHECK(Picks(Addr("95.186.3.4", DefaultPort() + 1, NOW - 3600)));
    BOOST_CHECK(Picks(Addr("95.186.3.4", 1, NOW - 3600)));
}

BOOST_AUTO_TEST_CASE(free_skips_never_pick)
{
    const CAddress a = Addr("94.185.1.2", DefaultPort(), NOW - 3600);
    // its network group already has an outbound peer
    std::set<std::vector<unsigned char> > setConnected;
    setConnected.insert(a.GetGroup());
    BOOST_CHECK(!Picks(a, 0, setConnected));
    // another group connected does not matter
    std::set<std::vector<unsigned char> > other;
    other.insert(Addr("8.8.8.8", DefaultPort(), NOW).GetGroup());
    BOOST_CHECK(Picks(a, 0, other));

    // a skipped host, on any port
    COutboundSkip skip;
    skip.hosts.insert(CNetAddr("94.185.1.2"));
    BOOST_CHECK(!Picks(a, 0, std::set<std::vector<unsigned char> >(), skip));
    BOOST_CHECK(!Picks(Addr("94.185.1.2", DefaultPort() + 7, NOW - 3600), 0, std::set<std::vector<unsigned char> >(), skip));

    // IPv6 without an IPv6 route; IPv4 is not affected by the flag
    const CAddress v6 = Addr("2001:4860:4860::8888", DefaultPort(), NOW - 3600);
    COutboundSkip noRoute;
    noRoute.fNoIPv6Route = true;
    BOOST_CHECK(!Picks(v6, 0, std::set<std::vector<unsigned char> >(), noRoute));
    BOOST_CHECK(Picks(v6));
    BOOST_CHECK(Picks(a, 0, std::set<std::vector<unsigned char> >(), noRoute));
}

BOOST_AUTO_TEST_CASE(limited_network_never_picked)
{
    const CAddress a = Addr("94.185.1.2", DefaultPort(), NOW - 3600);
    SetLimited(NET_IPV4, true);
    BOOST_CHECK(!Picks(a));
    SetLimited(NET_IPV4, false);
    BOOST_CHECK(Picks(a));
}

BOOST_AUTO_TEST_SUITE_END()
