// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Outbound candidate selection. The SelectOutboundCandidate cases (net.cpp) use
// a table of one address, so every draw returns that address and the result
// depends only on the selection rules, not on addrman's randomness. The
// SelectOutboundDraw cases (netoutbound.h) feed a fixed list of draws and pin
// the try counts at which each rule relaxes.

#include "addrman.h"
#include "chainparams.h"
#include "net.h"
#include "netbase.h"
#include "netoutbound.h"
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

/** A fixed list of draws; past its end the table is empty. */
class FixedDraws : public COutboundDrawSource
{
public:
    std::vector<COutboundDraw> draws;
    size_t nTaken = 0;
    COutboundDraw Draw() override
    {
        return nTaken < draws.size() ? draws[nTaken++] : COutboundDraw();
    }
    void Add(const COutboundDraw& d, size_t n = 1) { draws.insert(draws.end(), n, d); }
};

COutboundDraw Good()
{
    COutboundDraw d;
    d.fValid = true;
    return d;
}

COutboundDraw Free()
{
    COutboundDraw d = Good();
    d.fFree = true;
    return d;
}

COutboundDraw Limited()
{
    COutboundDraw d = Good();
    d.fLimited = true;
    return d;
}

COutboundDraw TriedAgo(int64_t nAgo)
{
    COutboundDraw d = Good();
    d.nLastTry = NOW - nAgo;
    return d;
}

/** The draw number a list of n copies of d is chosen at, or -1. */
int ChosenAt(const COutboundDraw& d, size_t n = OUTBOUND_MAX_DRAWS)
{
    FixedDraws src;
    src.Add(d, n);
    return SelectOutboundDraw(src, NOW);
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

BOOST_AUTO_TEST_CASE(draw_eligibility_rules)
{
    // never tried, default port, not terrible: the first try
    BOOST_CHECK(OutboundDrawEligible(Good(), NOW, 1));
    BOOST_CHECK(!OutboundDrawEligible(Limited(), NOW, 1));
    BOOST_CHECK(!OutboundDrawEligible(Limited(), NOW, 100));
    // the minute: never, at any try
    BOOST_CHECK(!OutboundDrawEligible(TriedAgo(0), NOW, 100));
    BOOST_CHECK(!OutboundDrawEligible(TriedAgo(OUTBOUND_MIN_REDIAL_SECONDS - 1), NOW, 100));
    // ten minutes: from the 30th try
    BOOST_CHECK(!OutboundDrawEligible(TriedAgo(OUTBOUND_MIN_REDIAL_SECONDS), NOW, 29));
    BOOST_CHECK(OutboundDrawEligible(TriedAgo(OUTBOUND_MIN_REDIAL_SECONDS), NOW, 30));
    BOOST_CHECK(!OutboundDrawEligible(TriedAgo(599), NOW, 29));
    BOOST_CHECK(OutboundDrawEligible(TriedAgo(600), NOW, 1));
    // a nLastTry in the future counts as within the minute
    BOOST_CHECK(!OutboundDrawEligible(TriedAgo(-3600), NOW, 100));
    // terrible: from the 30th try
    COutboundDraw terrible = Good();
    terrible.fTerrible = true;
    BOOST_CHECK(!OutboundDrawEligible(terrible, NOW, 29));
    BOOST_CHECK(OutboundDrawEligible(terrible, NOW, 30));
    // another port: from the 50th try, whatever else holds
    COutboundDraw port = Good();
    port.fDefaultPort = false;
    BOOST_CHECK(!OutboundDrawEligible(port, NOW, 49));
    BOOST_CHECK(OutboundDrawEligible(port, NOW, 50));
    port.fTerrible = true;
    port.nLastTry = NOW - 100;
    BOOST_CHECK(!OutboundDrawEligible(port, NOW, 49));
    BOOST_CHECK(OutboundDrawEligible(port, NOW, 50));
}

BOOST_AUTO_TEST_CASE(round_try_counts)
{
    BOOST_CHECK_EQUAL(ChosenAt(Good()), 0);
    BOOST_CHECK_EQUAL(ChosenAt(TriedAgo(600)), 0);
    BOOST_CHECK_EQUAL(ChosenAt(TriedAgo(OUTBOUND_MIN_REDIAL_SECONDS)), 29);
    BOOST_CHECK_EQUAL(ChosenAt(TriedAgo(OUTBOUND_MIN_REDIAL_SECONDS - 1)), -1);
    COutboundDraw terrible = Good();
    terrible.fTerrible = true;
    BOOST_CHECK_EQUAL(ChosenAt(terrible), 29);
    COutboundDraw port = Good();
    port.fDefaultPort = false;
    BOOST_CHECK_EQUAL(ChosenAt(port), 49);
    BOOST_CHECK_EQUAL(ChosenAt(Limited()), -1);
    // the round is short: fewer draws than the rule needs
    BOOST_CHECK_EQUAL(ChosenAt(port, 49), -1);
    BOOST_CHECK_EQUAL(ChosenAt(port, 50), 49);
    // an empty table
    BOOST_CHECK_EQUAL(ChosenAt(Good(), 0), -1);
}

BOOST_AUTO_TEST_CASE(round_limits)
{
    {
        // free draws are not tries: 299 of them, then a good one, is chosen
        FixedDraws src;
        src.Add(Free(), OUTBOUND_MAX_DRAWS - 1);
        src.Add(Good());
        BOOST_CHECK_EQUAL(SelectOutboundDraw(src, NOW), OUTBOUND_MAX_DRAWS - 1);
    }
    {
        // but they use up the round's draws
        FixedDraws src;
        src.Add(Free(), OUTBOUND_MAX_DRAWS);
        src.Add(Good());
        BOOST_CHECK_EQUAL(SelectOutboundDraw(src, NOW), -1);
        BOOST_CHECK_EQUAL(src.nTaken, (size_t)OUTBOUND_MAX_DRAWS);
    }
    {
        // 100 tries end the round, the 101st draw that is not free is still taken
        FixedDraws src;
        src.Add(Limited(), 100);
        src.Add(Good());
        BOOST_CHECK_EQUAL(SelectOutboundDraw(src, NOW), -1);
        BOOST_CHECK_EQUAL(src.nTaken, 101U);
    }
    {
        FixedDraws src;
        src.Add(Limited(), 99);
        src.Add(Good());
        BOOST_CHECK_EQUAL(SelectOutboundDraw(src, NOW), 99);
    }
    {
        // free draws in between do not move the 30-try relaxation
        FixedDraws src;
        for (int i = 0; i < 40; i++) {
            src.Add(Free());
            src.Add(TriedAgo(100));
        }
        BOOST_CHECK_EQUAL(SelectOutboundDraw(src, NOW), 59); // the 30th tried-recently draw
    }
    {
        // an empty draw ends the round at once
        FixedDraws src;
        src.Add(Limited(), 5);
        src.Add(COutboundDraw());
        src.Add(Good());
        BOOST_CHECK_EQUAL(SelectOutboundDraw(src, NOW), -1);
        BOOST_CHECK_EQUAL(src.nTaken, 6U);
    }
    {
        // a draw that becomes eligible later in the round is chosen when reached
        FixedDraws src;
        src.Add(TriedAgo(100), 10);
        src.Add(Good());
        BOOST_CHECK_EQUAL(SelectOutboundDraw(src, NOW), 10);
    }
}

BOOST_AUTO_TEST_SUITE_END()
