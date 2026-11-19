// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstrap.h"
#include "chainparams.h"
#include "net.h"
#include "netbase.h"
#include "sync.h"
#include "util.h"
#include "test/test_bitcoin.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bootstrap_onion_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(onion_bootstrap_peers_parse_as_v3)
{
    const CChainParams& main = Params(CBaseChainParams::MAIN);
    BOOST_REQUIRE_EQUAL(main.OnionBootstrapPeers().size(), 4u);
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
    // Distinct services (pairwise).
    for (size_t i = 0; i < main.OnionBootstrapPeers().size(); ++i)
        for (size_t j = i + 1; j < main.OnionBootstrapPeers().size(); ++j)
            BOOST_CHECK(main.OnionBootstrapPeers()[i] != main.OnionBootstrapPeers()[j]);
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

namespace {
// Leaves the process-wide proxy and network-limit state as it found it.
struct NetworkStateGuard {
    ~NetworkStateGuard()
    {
        ClearProxies();
        SetLimited(NET_IPV4, false);
        SetLimited(NET_IPV6, false);
    }
};

bool ListsAnyClearnetBootstrapPeer(const std::vector<std::string>& peers)
{
    for (const std::string& clear : Params().BootstrapPeers())
        if (std::find(peers.begin(), peers.end(), clear) != peers.end())
            return true;
    return false;
}
} // namespace

// -onlynet=onion -onion=<tor> with no -proxy: nothing covers the clearnet
// addresses, so the snapshot peer list and the addnode fallback must stay on
// the onion peers instead of dialling the bootstrap servers from the node's IP.
BOOST_AUTO_TEST_CASE(onion_only_without_a_clearnet_proxy_never_uses_the_clearnet_peers)
{
    NetworkStateGuard guard;
    SetLimited(NET_IPV4);
    SetLimited(NET_IPV6);
    BOOST_REQUIRE(SetProxy(NET_ONION, proxyType(CService("127.0.0.1", 9050))));
    BOOST_REQUIRE(BootstrapOnionOnlyActive());
    BOOST_CHECK(!BootstrapClearnetProxied());

    const std::vector<std::string> peers = GetBootstrapSnapshotPeerList();
    BOOST_CHECK(peers == Params().OnionBootstrapPeers());
    BOOST_CHECK(!ListsAnyClearnetBootstrapPeer(peers));

    {
        LOCK(cs_vAddedNodes);
        vAddedNodes.clear();
    }
    BootstrapOnionFallbackCheck(); // no connections at all: the grace rule would fire
    LOCK(cs_vAddedNodes);
    BOOST_CHECK(!ListsAnyClearnetBootstrapPeer(vAddedNodes));
}

// -onlynet=onion with a system Tor found through its control port: no proxy
// at all yet when init builds the snapshot and addnode lists (Tor control sets
// the onion proxy later). The clearnet bootstrap peers must not be listed, and
// discovery must not dial the clearnet seeds.
BOOST_AUTO_TEST_CASE(onion_only_before_any_proxy_never_lists_the_clearnet_peers)
{
    NetworkStateGuard guard;
    SetLimited(NET_IPV4);
    SetLimited(NET_IPV6);
    BOOST_REQUIRE(!BootstrapOnionOnlyActive()); // no onion proxy yet
    BOOST_CHECK(!BootstrapClearnetProxied());

    BOOST_CHECK(!ListsAnyClearnetBootstrapPeer(GetBootstrapPeerList()));
    BOOST_CHECK(!ListsAnyClearnetBootstrapPeer(GetBootstrapSnapshotPeerList()));
    BOOST_CHECK(GetBootstrapPeerList() == Params().OnionBootstrapPeers());
    BOOST_CHECK(DiscoverBootstrapPeers().empty());
}

// The same node with a proxy for the clearnet addresses (-proxy): the
// clearnet peers stay available behind the onion ones.
BOOST_AUTO_TEST_CASE(onion_only_with_a_clearnet_proxy_keeps_the_clearnet_peers_as_a_later_choice)
{
    NetworkStateGuard guard;
    SetLimited(NET_IPV4);
    SetLimited(NET_IPV6);
    BOOST_REQUIRE(SetProxy(NET_ONION, proxyType(CService("127.0.0.1", 9050))));
    BOOST_REQUIRE(SetProxy(NET_IPV4, proxyType(CService("127.0.0.1", 9050))));
    BOOST_CHECK(BootstrapClearnetProxied());

    const std::vector<std::string> peers = GetBootstrapSnapshotPeerList();
    const std::vector<std::string>& onion = Params().OnionBootstrapPeers();
    BOOST_REQUIRE_EQUAL(peers.size(), onion.size() + Params().BootstrapPeers().size());
    BOOST_CHECK(std::equal(onion.begin(), onion.end(), peers.begin()));
    BOOST_CHECK(ListsAnyClearnetBootstrapPeer(peers));
}

// The Zcash parameter fetch of init runs before -proxy / -onlynet take effect:
// it is only allowed when nothing says that connections must not leave directly.
BOOST_AUTO_TEST_CASE(param_fetch_is_refused_when_it_would_bypass_the_proxy)
{
    const std::map<std::string, std::string> savedArgs = mapArgs;
    const std::map<std::string, std::vector<std::string> > savedMulti = mapMultiArgs;
    struct Restore {
        const std::map<std::string, std::string>& a;
        const std::map<std::string, std::vector<std::string> >& m;
        ~Restore() { mapArgs = a; mapMultiArgs = m; }
    } restore{savedArgs, savedMulti};

    mapArgs.clear();
    mapMultiArgs.clear();
    BOOST_CHECK(!ZcashParamFetchWouldBypassProxy()); // plain node

    mapArgs["-proxy"] = "127.0.0.1:9050";
    mapMultiArgs["-proxy"].push_back("127.0.0.1:9050");
    BOOST_CHECK(ZcashParamFetchWouldBypassProxy()); // -proxy, no -embeddedtor
    mapArgs["-proxy"] = "0";
    BOOST_CHECK(!ZcashParamFetchWouldBypassProxy()); // -proxy=0 means none
    mapArgs.erase("-proxy");

    mapMultiArgs["-onlynet"].push_back("onion");
    mapArgs["-onlynet"] = "onion";
    mapArgs["-onion"] = "127.0.0.1:9050";
    BOOST_CHECK(ZcashParamFetchWouldBypassProxy()); // onion-only with an external Tor

    mapMultiArgs["-onlynet"].push_back("ipv4");
    BOOST_CHECK(!ZcashParamFetchWouldBypassProxy()); // clearnet allowed again
}

BOOST_AUTO_TEST_SUITE_END()
