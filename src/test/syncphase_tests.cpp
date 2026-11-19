// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "rpc/nodestatus.h"
#include "syncphase.h"
#include "test/test_bitcoin.h"
#include "univalue.h"

#include <climits>
#include <string>

#include <boost/test/unit_test.hpp>

namespace {

SyncInputs After(int blocks, int64_t age, int conns, int peerHeight, int64_t connected)
{
    SyncInputs s;
    s.nBlocks = blocks;
    s.nHeaders = blocks;
    s.tipAgeSeconds = age;
    s.nConnections = conns;
    s.nOutboundConnected = conns;
    s.nBestPeerHeight = peerHeight;
    s.connectedForSeconds = connected;
    return s;
}

std::string Phase(const SyncInputs& s) { return ClassifySyncPhaseV2(s); }

std::string Str(const UniValue& o, const char* k) { return find_value(o, k).get_str(); }

bool HasReason(const UniValue& o, const std::string& needle)
{
    const UniValue& r = find_value(o, "reasons");
    for (size_t i = 0; i < r.size(); i++)
        if (r[i].get_str().find(needle) != std::string::npos) return true;
    return false;
}

NodeStatusInputs Status(const SyncInputs& s, int in, int out)
{
    NodeStatusInputs n;
    n.sync = s;
    n.nInbound = in;
    n.nOutbound = out;
    n.sync.nConnections = in + out;
    return n;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(syncphase_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(after_ibd_table)
{
    // Fresh snapshot: IBD latch false, tip 20 h old, peers 400 blocks ahead.
    BOOST_CHECK_EQUAL(Phase(After(1000, 20 * 3600, 8, 1400, 500)), "downloading_blocks");
    // Same, peer height unknown.
    BOOST_CHECK_EQUAL(Phase(After(1000, 20 * 3600, 8, -1, 500)), "downloading_headers");
    // Caught up.
    BOOST_CHECK_EQUAL(Phase(After(1000, 100, 8, 1001, 500)), "synced");
    // Slack boundary: two ahead is level, three is behind.
    BOOST_CHECK_EQUAL(Phase(After(1000, 100, 8, 1002, 500)), "synced");
    BOOST_CHECK_EQUAL(Phase(After(1000, 100, 8, 1003, 500)), "downloading_blocks");
    // Freshness boundary.
    BOOST_CHECK_EQUAL(Phase(After(1000, SYNC_TIP_FRESH_SECONDS, 8, 1000, 0)), "synced");
    BOOST_CHECK_EQUAL(Phase(After(1000, SYNC_TIP_FRESH_SECONDS + 1, 8, 1000, 0)), "downloading_blocks");
    // Quiet chain: old tip, peers at our height, connected long enough.
    BOOST_CHECK_EQUAL(Phase(After(1000, 2 * 3600, 8, 1000, 61)), "synced");
    BOOST_CHECK_EQUAL(Phase(After(1000, 2 * 3600, 8, 1000, 60)), "synced");
    BOOST_CHECK_EQUAL(Phase(After(1000, 2 * 3600, 8, 1000, 59)), "downloading_blocks");
    // Headers ahead of the tip beyond the slack: not synced, fresh tip or old.
    SyncInputs h = After(1000, 100, 8, 1000, 500);
    h.nHeaders = 1010;
    BOOST_CHECK_EQUAL(Phase(h), "downloading_blocks");
    h.tipAgeSeconds = 5 * 3600;
    BOOST_CHECK_EQUAL(Phase(h), "downloading_blocks");
    h.nHeaders = 1002;
    h.tipAgeSeconds = 100;
    BOOST_CHECK_EQUAL(Phase(h), "synced");
    // No connections.
    BOOST_CHECK_EQUAL(Phase(After(1000, 100, 0, 1000, 500)), "waiting_for_peers");
    BOOST_CHECK(IsSyncedV2(After(1000, 100, 8, 1000, 500)));
    BOOST_CHECK(!IsSyncedV2(After(1000, 20 * 3600, 8, 1400, 500)));
}

// The six cases of p2p_sync_tests sync_phase_classification: while IBD (and for reindex and
// import) the V2 answer equals ClassifySyncPhase.
BOOST_AUTO_TEST_CASE(precedence_matches_classic)
{
    struct Row { bool ibd, reindex, import; int conns, blocks, headers; };
    const Row rows[] = {
        {false, false, false, 8, 100, 100}, {true, false, false, 0, 100, 100}, {true, false, false, 2, 100, 5000},
        {true, false, false, 2, 100, 100},  {true, true, false, 0, 100, 100},  {true, false, true, 0, 100, 100},
    };
    for (const Row& r : rows) {
        SyncInputs s;
        s.ibd = r.ibd; s.reindexing = r.reindex; s.importing = r.import;
        s.nConnections = r.conns; s.nBlocks = r.blocks; s.nHeaders = r.headers;
        // peers, tip age and connection time must not matter while the classic answer is not "synced"
        s.nBestPeerHeight = r.blocks; s.tipAgeSeconds = 10; s.connectedForSeconds = 1000;
        const std::string classic = ClassifySyncPhase(r.ibd, r.reindex, r.import, r.conns, r.blocks, r.headers);
        if (classic == "synced") {
            BOOST_CHECK_EQUAL(Phase(s), "synced"); // not IBD, fresh tip, peer level
        } else {
            BOOST_CHECK_EQUAL(Phase(s), classic);
        }
    }
}

BOOST_AUTO_TEST_CASE(robust_peer_height)
{
    BOOST_CHECK_EQUAL(RobustPeerHeight({}, 100), -1);
    // One outlier among several peers is ignored.
    BOOST_CHECK_EQUAL(RobustPeerHeight({1000, INT_MAX, 1001}, 1000), 1001);
    BOOST_CHECK_EQUAL(Phase(After(1000, 100, 3, RobustPeerHeight({1000, INT_MAX, 1000}, 1000), 500)), "synced");
    // A lone peer is bounded by headers plus slack.
    BOOST_CHECK_EQUAL(RobustPeerHeight({INT_MAX}, 1000), 1000 + SYNC_PEER_SLACK_BLOCKS);
    BOOST_CHECK_EQUAL(RobustPeerHeight({900}, 1000), 900);
    // Empty chain and a huge claim: no signed overflow in blocks_behind.
    SyncInputs e = After(-1, 100, 1, INT_MAX, 500);
    e.nHeaders = -1;
    BOOST_CHECK_EQUAL(find_value(BuildNodeStatus(Status(e, 0, 1)), "blocks_behind").get_int(), INT_MAX);
}

BOOST_AUTO_TEST_CASE(nodestatus_states_and_reasons)
{
    // ok
    UniValue o = BuildNodeStatus(Status(After(1000, 100, 8, 1000, 500), 2, 6));
    BOOST_CHECK_EQUAL(Str(o, "state"), "ok");
    BOOST_CHECK(find_value(o, "synced").get_bool());
    BOOST_CHECK_EQUAL(find_value(o, "reasons").size(), (size_t)0);
    BOOST_CHECK_EQUAL(find_value(o, "blocks_behind").get_int(), 0);

    // syncing: the snapshot case
    o = BuildNodeStatus(Status(After(1000, 20 * 3600, 8, 1400, 500), 2, 6));
    BOOST_CHECK_EQUAL(Str(o, "state"), "syncing");
    BOOST_CHECK_EQUAL(Str(o, "syncphase"), "downloading_blocks");
    BOOST_CHECK(!find_value(o, "synced").get_bool());
    BOOST_CHECK_EQUAL(find_value(o, "blocks_behind").get_int(), 400);
    BOOST_CHECK(HasReason(o, "behind the best known chain"));

    // tip_stale: old tip, peers level, but not connected long enough to trust that
    o = BuildNodeStatus(Status(After(1000, 7200, 8, 1000, 10), 2, 6));
    BOOST_CHECK_EQUAL(Str(o, "state"), "tip_stale");
    BOOST_CHECK(HasReason(o, "tip is 7200 s old and no peer reports a higher block"));

    // no_peers
    o = BuildNodeStatus(Status(After(1000, 100, 0, -1, 0), 0, 0));
    BOOST_CHECK_EQUAL(Str(o, "state"), "no_peers");
    BOOST_CHECK_EQUAL(Str(o, "syncphase"), "waiting_for_peers");
    BOOST_CHECK(HasReason(o, "no peer connections"));

    // only inbound peers: reason names the outbound gap
    o = BuildNodeStatus(Status(After(1000, 100, 0, -1, 0), 3, 0));
    BOOST_CHECK(HasReason(o, "no handshaken outbound peer"));

    // initial_block_download
    SyncInputs ibd = After(100, 100, 4, 100, 100);
    ibd.ibd = true;
    ibd.nHeaders = 5000;
    o = BuildNodeStatus(Status(ibd, 0, 4));
    BOOST_CHECK_EQUAL(Str(o, "state"), "initial_block_download");
    BOOST_CHECK_EQUAL(Str(o, "syncphase"), "downloading_blocks");
    BOOST_CHECK(HasReason(o, "initial block download"));
    BOOST_CHECK_EQUAL(find_value(o, "blocks_behind").get_int(), 4900);

    // reindexing and importing win over everything
    SyncInputs re = ibd;
    re.reindexing = true;
    o = BuildNodeStatus(Status(re, 0, 4));
    BOOST_CHECK_EQUAL(Str(o, "state"), "reindexing");
    BOOST_CHECK(HasReason(o, "reindexed"));
    SyncInputs im = ibd;
    im.importing = true;
    o = BuildNodeStatus(Status(im, 0, 0));
    BOOST_CHECK_EQUAL(Str(o, "state"), "importing");
    BOOST_CHECK(HasReason(o, "imported"));

    // outbound peers connected but none reported a height
    SyncInputs unk = After(1000, 100, 4, -1, 100);
    o = BuildNodeStatus(Status(unk, 0, 4));
    BOOST_CHECK(HasReason(o, "no outbound peer has reported its height"));
}

BOOST_AUTO_TEST_CASE(nodestatus_fields)
{
    NodeStatusInputs n = Status(After(1000, 100, 8, 1000, 500), 2, 6);
    n.mempoolSize = 7;
    n.mempoolBytes = 1234;
    n.uptimeSeconds = 99;
    n.txindex = true;
    n.zslp.enabled = true;
    n.zslp.synced = true;
    n.zslp.indexedHeight = 1000;
    n.datadirFreeBytes = 5000;
    const UniValue o = BuildNodeStatus(n);
    BOOST_CHECK_EQUAL(find_value(find_value(o, "peers"), "in").get_int(), 2);
    BOOST_CHECK_EQUAL(find_value(find_value(o, "peers"), "out").get_int(), 6);
    BOOST_CHECK_EQUAL(find_value(find_value(o, "mempool"), "size").get_int(), 7);
    BOOST_CHECK_EQUAL(find_value(find_value(o, "mempool"), "bytes").get_int64(), 1234);
    BOOST_CHECK_EQUAL(find_value(o, "uptime_seconds").get_int64(), 99);
    BOOST_CHECK_EQUAL(find_value(o, "datadir_free_bytes").get_int64(), 5000);
    const UniValue& ix = find_value(o, "indexes");
    BOOST_CHECK(find_value(ix, "txindex").get_bool());
    BOOST_CHECK(find_value(find_value(ix, "zslpindex"), "enabled").get_bool());
    BOOST_CHECK_EQUAL(find_value(find_value(ix, "zslpindex"), "indexed_height").get_int(), 1000);
    BOOST_CHECK(!find_value(find_value(ix, "znamindex"), "enabled").get_bool());
    BOOST_CHECK(find_value(find_value(ix, "znamindex"), "synced").isNull());
}

BOOST_AUTO_TEST_SUITE_END()
