// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstrap.h"
#include "chainparams.h"
#include "netbase.h"
#include "test/test_bitcoin.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bootstrap_onion_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(onion_bootstrap_peers_parse_as_v3)
{
    const CChainParams& main = Params(CBaseChainParams::MAIN);
    BOOST_REQUIRE_EQUAL(main.OnionBootstrapPeers().size(), 2u);
    // One onion service per clearnet bootstrap node.
    BOOST_CHECK_EQUAL(main.OnionBootstrapPeers().size(), main.BootstrapPeers().size());
    for (const std::string& peer : main.OnionBootstrapPeers()) {
        CService svc;
        BOOST_CHECK_MESSAGE(Lookup(peer.c_str(), svc, 0, false), peer);
        BOOST_CHECK_MESSAGE(svc.IsValid(), peer);
        BOOST_CHECK_MESSAGE(svc.IsTor(), peer);
        BOOST_CHECK_EQUAL(svc.GetPort(), 8035);
        BOOST_CHECK_EQUAL(svc.ToStringIPPort(), peer);
        // 56 base32 characters + ".onion" = a v3 address.
        BOOST_CHECK_EQUAL(peer.find(".onion:8035"), 56u);
    }
    // Distinct services.
    BOOST_CHECK(main.OnionBootstrapPeers()[0] != main.OnionBootstrapPeers()[1]);
}

BOOST_AUTO_TEST_CASE(onion_bootstrap_peers_empty_off_mainnet)
{
    BOOST_CHECK(Params(CBaseChainParams::TESTNET).OnionBootstrapPeers().empty());
    BOOST_CHECK(Params(CBaseChainParams::REGTEST).OnionBootstrapPeers().empty());
}

BOOST_AUTO_TEST_CASE(select_bootstrap_peers_by_mode)
{
    const std::vector<std::string> clear = {"1.2.3.4:8035", "5.6.7.8:8035"};
    const std::vector<std::string> onion = {"a.onion:8035", "b.onion:8035"};

    // Tor off: no onion proxy, clearnet allowed.
    BOOST_CHECK(SelectBootstrapPeers(clear, onion, false, false, false) == clear);
    // Tor on, clearnet allowed (dual-stack): clearnet only, the onion
    // services are the same nodes.
    BOOST_CHECK(SelectBootstrapPeers(clear, onion, true, false, false) == clear);
    // Onion-only with a proxy: the onion peers.
    BOOST_CHECK(SelectBootstrapPeers(clear, onion, true, true, false) == onion);
    // Onion-only after the fallback: the clearnet peers again.
    BOOST_CHECK(SelectBootstrapPeers(clear, onion, true, true, true) == clear);
    // Onion-only but no proxy at all: nothing can reach .onion, unchanged.
    BOOST_CHECK(SelectBootstrapPeers(clear, onion, false, true, false) == clear);
    // No onion peers (testnet/regtest): always clearnet.
    BOOST_CHECK(SelectBootstrapPeers(clear, std::vector<std::string>(), true, true, false) == clear);
}

BOOST_AUTO_TEST_CASE(fallback_due_rules)
{
    // Only an onion-only node, only after the grace period.
    BOOST_CHECK(!BootstrapFallbackDue(false, 0, 0, 300, 300));
    BOOST_CHECK(!BootstrapFallbackDue(true, 0, 0, 299, 300));
    BOOST_CHECK(BootstrapFallbackDue(true, 0, 0, 300, 300));
    // An onion bootstrap peer is connected, or the node syncs from other
    // outbound peers: stay on Tor.
    BOOST_CHECK(!BootstrapFallbackDue(true, 1, 1, 600, 300));
    BOOST_CHECK(!BootstrapFallbackDue(true, 0, 3, 600, 300));
}

BOOST_AUTO_TEST_SUITE_END()
