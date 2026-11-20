// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bootstrap resume tests, part 2 of 3: the multi-server scheduling logic of BootstrapPeerBoard (stream
// assignment, moves, stealing, blame and benching, holders, connection limits). Pure logic, no sockets.
// Each part is its own Boost suite.

#include "test/bootstrap_resume_testutil.h"

BOOST_FIXTURE_TEST_SUITE(bootstrap_peer_board_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Multi-server scheduling (pure logic)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(peer_board_spreads_streams_round_robin)
{
    BootstrapPeerBoard two(2, 4);
    BOOST_CHECK_EQUAL(two.Assign(0, 0), 0);
    BOOST_CHECK_EQUAL(two.Assign(1, 0), 1);
    BOOST_CHECK_EQUAL(two.Assign(2, 0), 0);
    BOOST_CHECK_EQUAL(two.Assign(3, 0), 1);
    // one peer: every stream goes to it, as before
    BootstrapPeerBoard one(1, 3);
    for (int s = 0; s < 3; ++s)
        BOOST_CHECK_EQUAL(one.Assign(s, 0), 0);
    BOOST_CHECK_EQUAL(one.UsablePeers(), 1U);
}

BOOST_AUTO_TEST_CASE(peer_board_never_assigns_an_ignored_or_failing_peer_first)
{
    BootstrapPeerBoard b(3, 3);
    b.ManifestMismatch(0);
    BOOST_CHECK_EQUAL(b.UsablePeers(), 2U);
    for (int s = 0; s < 3; ++s)
        BOOST_CHECK(b.Assign(s, 0) != 0);
    b.ManifestMismatch(1);
    b.ManifestMismatch(2);
    BOOST_CHECK_EQUAL(b.UsablePeers(), 0U);
    BOOST_CHECK_EQUAL(b.Assign(0, 0), -1);
    BOOST_CHECK(b.Peer(0, 0).ignored);

    // a peer that just failed to connect is avoided while another is usable, then tried again
    BootstrapPeerBoard c(2, 2);
    c.ConnectFailed(0, 0);
    BOOST_CHECK_EQUAL(c.Assign(0, 100), 1);
    BOOST_CHECK_EQUAL(c.Assign(1, 100), 1);
    BootstrapPeerBoard d(2, 2);
    d.ConnectFailed(0, 0);
    BOOST_CHECK_EQUAL(d.Assign(0, 70000), 0); // cooldown over
    d.ConnectFailed(0, 70000);
    d.ConnectFailed(0, 70001);
    d.ConnectFailed(1, 70002);
    BOOST_CHECK(d.Assign(1, 70003) >= 0); // all failing: still picks one, never -1
}

BOOST_AUTO_TEST_CASE(peer_board_moves_a_stream_the_server_defers)
{
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.stallMs = 2000;
    BootstrapPeerBoard b(2, 4, pol);
    for (int s = 0; s < 4; ++s)
        b.Attach(s, b.Assign(s, 0), 0);
    BOOST_CHECK_EQUAL(b.StreamPeer(1), 1);
    // streams 0 and 2 (peer 0) are served, streams 1 and 3 (peer 1, over its cap) get nothing
    for (int64_t t = 100; t <= 3000; t += 100) {
        b.NoteChunk(0, 10, 1000, t);
        b.NoteChunk(2, 11, 1000, t);
    }
    BOOST_CHECK(b.Rebalance(1500).empty()); // not yet stalled long enough
    const std::vector<BootstrapMove> mv = b.Rebalance(3000);
    BOOST_REQUIRE_EQUAL(mv.size(), 1U);
    for (size_t i = 0; i < mv.size(); ++i) {
        BOOST_CHECK(mv[i].stream == 1 || mv[i].stream == 3);
        BOOST_CHECK(mv[i].reason == BMR_STALLED);
    }
    BOOST_CHECK(b.Rebalance(3100).empty()); // a stream already asked to move is not asked again
    b.Detach(1);
    BOOST_CHECK_EQUAL(b.Assign(1, 3200), 0); // the server that deferred it is avoided for a while
    // its other stream is the last one on the quiet server: it stays to see the server recover, so the server is
    // never left with no stream to measure (and never compared away for good)
    b.Attach(1, 0, 3200);
    const std::vector<BootstrapMove> later = b.Rebalance(9000);
    for (size_t i = 0; i < later.size(); ++i)
        BOOST_CHECK(later[i].stream != 3);
    // with a single usable peer a quiet stream stays put (the receive timeout handles it)
    BootstrapPeerBoard solo(1, 1, pol);
    solo.Attach(0, solo.Assign(0, 0), 0);
    BOOST_CHECK(solo.Rebalance(60000).empty());
}

BOOST_AUTO_TEST_CASE(peer_board_moves_a_stream_off_a_much_slower_server_but_keeps_one)
{
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.moveCooldownMs = 1000;
    pol.stallMs = 1000000;
    BootstrapPeerBoard b(2, 4, pol);
    for (int s = 0; s < 4; ++s)
        b.Attach(s, b.Assign(s, 0), 0);
    for (int64_t t = 100; t <= 2000; t += 100) {
        b.NoteChunk(0, 10, 10000, t); // 100 kB/s on peer 0
        b.NoteChunk(2, 11, 10000, t);
        b.NoteChunk(1, 12, 100, t);   // 1 kB/s on peer 1
        b.NoteChunk(3, 13, 100, t);
    }
    std::vector<BootstrapMove> mv = b.Rebalance(2000);
    BOOST_REQUIRE_EQUAL(mv.size(), 1U);
    BOOST_CHECK(mv[0].reason == BMR_SLOW);
    BOOST_CHECK(mv[0].stream == 1 || mv[0].stream == 3);
    const int movedStream = mv[0].stream;
    const int stayed = movedStream == 1 ? 3 : 1;
    b.Detach(movedStream);
    BOOST_CHECK_EQUAL(b.Assign(movedStream, 2100), 0); // goes to the fast server
    // the last stream on the slow server is left alone: it keeps the rate measured
    for (int64_t t = 2100; t <= 4000; t += 100) {
        b.NoteChunk(0, 10, 10000, t);
        b.NoteChunk(2, 11, 10000, t);
        b.NoteChunk(stayed, 14, 100, t);
    }
    BOOST_CHECK(b.Rebalance(4000).empty());
    BOOST_CHECK(b.Peer(0, 4000).mibps > b.Peer(1, 4000).mibps);
}

BOOST_AUTO_TEST_CASE(peer_board_idle_stream_steals_from_a_much_slower_holder)
{
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.stallMs = 1000000;
    pol.stealMinSeconds = 15;
    pol.moveCooldownMs = 1000;
    BootstrapPeerBoard b(2, 3, pol);
    b.Attach(0, b.Assign(0, 0), 0);
    b.Attach(1, b.Assign(1, 0), 0);
    b.NoteClaim(0, 8, 100000, false);
    b.NoteClaim(1, 7, 1000000, false);
    b.SetIdle(2, true); // nothing queued for stream 2
    for (int64_t t = 100; t <= 2000; t += 100) {
        b.NoteChunk(0, 8, 100, t); // both servers equally slow
        b.NoteChunk(1, 7, 100, t);
    }
    BOOST_CHECK(b.Rebalance(2000).empty()); // no steal while the holder is not much slower
    for (int64_t t = 2100; t <= 4000; t += 100) {
        b.NoteChunk(0, 8, 10000, t); // peer 0 speeds up to 100 kB/s
        b.NoteChunk(1, 7, 10, t);
    }
    std::vector<BootstrapMove> mv = b.Rebalance(4000);
    BOOST_REQUIRE_EQUAL(mv.size(), 1U);
    BOOST_CHECK_EQUAL(mv[0].stream, 1);
    BOOST_CHECK(mv[0].reason == BMR_STEAL);

    // a nearly finished file is not worth taking over
    BootstrapPeerBoard c(2, 3, pol);
    c.Attach(0, c.Assign(0, 0), 0);
    c.Attach(1, c.Assign(1, 0), 0);
    c.NoteClaim(1, 7, 500, false);
    c.SetIdle(2, true);
    for (int64_t t = 100; t <= 2000; t += 100) {
        c.NoteChunk(0, 8, 10000, t);
        c.NoteChunk(1, 7, 10, t);
    }
    BOOST_CHECK(c.Rebalance(2000).empty());
    // and nothing is stolen when no stream is idle
    BootstrapPeerBoard d(2, 2, pol);
    d.Attach(0, d.Assign(0, 0), 0);
    d.Attach(1, d.Assign(1, 0), 0);
    d.NoteClaim(1, 7, 1000000, false);
    for (int64_t t = 100; t <= 2000; t += 100) {
        d.NoteChunk(0, 8, 10000, t);
        d.NoteChunk(1, 7, 10, t);
    }
    BOOST_CHECK(d.Rebalance(2000).empty());
}

BOOST_AUTO_TEST_CASE(peer_board_blames_the_peer_that_supplied_a_bad_file)
{
    // a file supplied by one peer only: that peer is benched as soon as another is usable
    BootstrapPeerBoard b(2, 2);
    b.Attach(0, b.Assign(0, 0), 0);
    b.Attach(1, b.Assign(1, 0), 0);
    b.NoteClaim(1, 5, 100, false);
    b.NoteChunk(1, 5, 100, 10);
    BOOST_CHECK(b.HashFailed(1, 5));
    BOOST_CHECK(b.Peer(1, 20).banned);
    BOOST_CHECK(!b.Peer(0, 20).banned);
    b.Detach(1);
    BOOST_CHECK_EQUAL(b.Assign(1, 30), 0);
    // streams still on the benched peer are told to leave
    BootstrapPeerBoard c(2, 2);
    c.SetPeerHas(1, std::vector<uint8_t>()); // the other server has answered: it is a holder
    c.Attach(0, c.Assign(0, 0), 0);
    c.Attach(1, c.Assign(1, 0), 0);
    c.NoteClaim(0, 6, 100, false);
    c.NoteChunk(0, 6, 100, 10);
    c.HashFailed(0, 6); // peer 0 benched, stream 0 is on it
    const std::vector<BootstrapMove> mv = c.Rebalance(100);
    BOOST_REQUIRE_EQUAL(mv.size(), 1U);
    BOOST_CHECK_EQUAL(mv[0].stream, 0);
    BOOST_CHECK(mv[0].reason == BMR_UNUSABLE);

    // the only usable peer is never benched: the plain strike limit decides
    BootstrapPeerBoard solo(1, 1);
    solo.Attach(0, solo.Assign(0, 0), 0);
    solo.NoteClaim(0, 5, 100, false);
    solo.NoteChunk(0, 5, 100, 10);
    BOOST_CHECK(!solo.HashFailed(0, 5));
    BOOST_CHECK(!solo.Peer(0, 20).banned);

    // bytes of unknown origin already on disk: the culprit is unknown, so nobody is benched, however often it fails
    BootstrapPeerBoard m(2, 2);
    m.Attach(0, m.Assign(0, 0), 0);
    m.Attach(1, m.Assign(1, 0), 0);
    m.NoteClaim(0, 9, 100, true); // resumed from disk
    m.NoteChunk(0, 9, 50, 10);
    BOOST_CHECK(m.HashFailed(0, 9));
    BOOST_CHECK(!m.Peer(0, 20).banned);
    m.NoteClaim(0, 9, 100, false);
    m.NoteChunk(0, 9, 50, 30);
    m.NoteChunk(1, 9, 50, 30); // two suppliers
    BOOST_CHECK(m.HashFailed(0, 9));
    BOOST_CHECK(!m.Peer(0, 40).banned);
    BOOST_CHECK(!m.Peer(1, 40).banned);
    BOOST_CHECK_EQUAL(m.UsablePeers(), 2U);
}
#ifndef WIN32

// ---- blame, pins, holders, connection limits (BootstrapPeerBoard) ----

BOOST_AUTO_TEST_CASE(peer_board_a_lying_secondary_does_not_get_the_honest_primary_banned)
{
    // The secondary writes a bad prefix of two files and drops before the last chunk; the primary continues each
    // .part and finishes it, so the failure names both. Nobody may be benched on that (the primary is honest and the
    // only server of other files), and each file goes back to ONE server, the primary.
    BootstrapPeerBoard b(2, 2);
    b.Attach(0, b.Assign(0, 0), 0);
    b.Attach(1, b.Assign(1, 0), 0);
    BOOST_CHECK_EQUAL(b.StreamPeer(0), 0);
    BOOST_CHECK_EQUAL(b.StreamPeer(1), 1);
    std::vector<uint8_t> unfinished(16, 0);
    for (uint32_t f = 10; f < 12; ++f) {
        unfinished[f] = 1;
        b.NoteClaim(1, f, 100, false);
        b.NoteChunk(1, f, 50, 10);
        b.NoteRelease(1, f);
        b.NoteClaim(0, f, 50, true);
        b.NoteChunk(0, f, 50, 20);
        BOOST_CHECK(b.HashFailed(0, f, &unfinished));
    }
    BOOST_CHECK(!b.Peer(0, 30).banned);
    BOOST_CHECK(!b.Peer(1, 30).banned);
    std::vector<uint8_t> mask(16, 1);
    b.MaskPinned(1, mask); // the stream of the secondary must leave both files alone
    BOOST_CHECK(!mask[10] && !mask[11] && mask[9]);
    mask.assign(16, 1);
    b.MaskPinned(0, mask); // the primary's stream may take them
    BOOST_CHECK(mask[10] && mask[11]);
    // the primary fetches file 10 again from byte 0 and it verifies: the pin is gone with the file
    b.NoteClaim(0, 10, 100, false);
    b.NoteChunk(0, 10, 100, 40);
    b.NoteComplete(0, 10);
    mask.assign(16, 1);
    b.MaskPinned(1, mask);
    BOOST_CHECK(mask[10] && !mask[11]);
    // a server that alone supplied a failing file is benched
    b.NoteClaim(1, 12, 100, false);
    b.NoteChunk(1, 12, 100, 50);
    unfinished[12] = 1;
    b.HashFailed(1, 12, &unfinished);
    BOOST_CHECK(b.Peer(1, 60).banned);
    BOOST_CHECK(!b.Peer(0, 60).banned);
}

BOOST_AUTO_TEST_CASE(peer_board_two_torn_parts_of_unknown_origin_bench_nobody)
{
    BootstrapPeerBoard b(2, 2);
    b.Attach(0, b.Assign(0, 0), 0);
    b.Attach(1, b.Assign(1, 0), 0);
    for (uint32_t f = 3; f < 5; ++f) {
        b.NoteClaim(0, f, 50, true); // resumed from a .part of unknown origin
        b.NoteChunk(0, f, 50, 10);
        BOOST_CHECK(b.HashFailed(0, f));
        b.NoteClaim(0, f, 100, true);
        b.NoteChunk(0, f, 50, 20);
        BOOST_CHECK(b.HashFailed(0, f));
    }
    BOOST_CHECK(!b.Peer(0, 30).banned);
    BOOST_CHECK(!b.Peer(1, 30).banned);
    BOOST_CHECK_EQUAL(b.UsablePeers(), 2U);
}

BOOST_AUTO_TEST_CASE(peer_board_never_benches_the_only_holder_of_a_pending_file)
{
    BootstrapPeerBoard b(2, 2);
    b.Attach(0, b.Assign(0, 0), 0);
    b.Attach(1, b.Assign(1, 0), 0);
    std::vector<uint8_t> has0(8, 1);
    has0[6] = 0; // file 6 is held by peer 1 only
    b.SetPeerHas(0, has0);
    b.SetPeerHas(1, std::vector<uint8_t>()); // peer 1 has answered: it holds everything
    std::vector<uint8_t> unfinished(8, 0);
    unfinished[5] = unfinished[6] = 1;
    b.NoteClaim(1, 5, 100, false);
    b.NoteChunk(1, 5, 100, 10);
    BOOST_CHECK(b.HashFailed(1, 5, &unfinished)); // peer 1 supplied file 5 alone but holds the only copy of 6
    BOOST_CHECK(!b.Peer(1, 20).banned);
    unfinished[6] = 0; // once nothing needs it any more it may be benched
    b.NoteClaim(1, 5, 100, false);
    b.NoteChunk(1, 5, 100, 30);
    b.HashFailed(1, 5, &unfinished);
    BOOST_CHECK(b.Peer(1, 40).banned);
    // the primary is not benched while it is the only source of a pending file either
    BootstrapPeerBoard c(2, 2);
    c.Attach(0, c.Assign(0, 0), 0);
    c.Attach(1, c.Assign(1, 0), 0);
    std::vector<uint8_t> has1(8, 1);
    has1[4] = 0; // file 4 is held by the primary only
    c.SetPeerHas(1, has1);
    std::vector<uint8_t> pend(8, 0);
    pend[4] = pend[2] = 1;
    c.NoteClaim(0, 2, 100, false);
    c.NoteChunk(0, 2, 100, 10);
    c.HashFailed(0, 2, &pend);
    BOOST_CHECK(!c.Peer(0, 20).banned);
}

BOOST_AUTO_TEST_CASE(peer_board_knows_when_a_pending_file_has_no_usable_holder)
{
    BootstrapPeerBoard b(2, 2);
    std::vector<uint8_t> has1(4, 0);
    has1[1] = 1;
    b.SetPeerHas(1, has1); // peer 1 holds file 1 only; peer 0 holds everything
    std::vector<uint8_t> need(4, 0);
    need[0] = need[1] = 1;
    BOOST_CHECK(b.EveryFileHasHolder(need));
    b.ManifestMismatch(0); // the holder of file 0 is gone
    BOOST_CHECK(!b.EveryFileHasHolder(need));
    need[0] = 0;
    BOOST_CHECK(b.EveryFileHasHolder(need)); // file 1 is still held by peer 1
}

BOOST_AUTO_TEST_CASE(peer_board_limits_connection_attempts_per_server_and_minute)
{
    BootstrapPeerPolicy pol;
    pol.maxConnectsPerMinute = 5;
    BootstrapPeerBoard b(2, 2, pol);
    for (int i = 0; i < 5; ++i)
        BOOST_CHECK(b.AllowConnect(0, 1000 + i));
    BOOST_CHECK(!b.AllowConnect(0, 2000));
    BOOST_CHECK(b.AllowConnect(1, 2000)); // another server has its own share
    BOOST_CHECK(b.AllowConnect(0, 62000)); // a minute later
}

BOOST_AUTO_TEST_CASE(peer_board_applies_each_move_under_its_own_lock_with_the_peer_it_was_decided_for)
{
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.stallMs = 2000;
    BootstrapPeerBoard b(2, 4, pol);
    for (int s = 0; s < 4; ++s)
        b.Attach(s, b.Assign(s, 0), 0);
    for (int64_t t = 100; t <= 3000; t += 100) {
        b.NoteChunk(0, 10, 1000, t);
        b.NoteChunk(2, 11, 1000, t);
    }
    std::vector<BootstrapMove> applied;
    const std::vector<BootstrapMove> mv = b.Rebalance(3000, [&applied](const BootstrapMove& m) { applied.push_back(m); });
    BOOST_REQUIRE_EQUAL(mv.size(), 1U);
    BOOST_REQUIRE_EQUAL(applied.size(), 1U);
    for (size_t i = 0; i < mv.size(); ++i) {
        BOOST_CHECK_EQUAL(applied[i].stream, mv[i].stream);
        BOOST_CHECK_EQUAL(mv[i].peer, 1); // the quiet server's streams, named while they were still attached to it
    }
}

BOOST_AUTO_TEST_CASE(peer_board_does_not_steal_from_a_stream_that_just_connected)
{
    BootstrapPeerPolicy pol; // production defaults
    BootstrapPeerBoard b(2, 3, pol);
    b.Attach(0, b.Assign(0, 0), 0);
    b.NoteClaim(0, 1, (uint64_t)1 << 30, false);
    for (int64_t t = 100; t <= 20000; t += 100)
        b.NoteChunk(0, 1, 104858, t); // peer 0: ~1 MiB/s on one mature stream
    b.Attach(1, 1, 20000);            // stream 1 just attached to peer 1
    b.NoteClaim(1, 2, (uint64_t)128 << 20, false);
    b.SetIdle(2, true);
    std::vector<BootstrapMove> mv = b.Rebalance(20200); // first manager tick, 200 ms later
    BOOST_CHECK_MESSAGE(mv.empty(), "stream stolen 200 ms after attach, nothing measured yet");
    BootstrapPeerBoard c(2, 3, pol);
    c.Attach(0, c.Assign(0, 0), 0);
    c.NoteClaim(0, 1, (uint64_t)1 << 30, false);
    for (int64_t t = 100; t <= 20000; t += 100)
        c.NoteChunk(0, 1, 1048576, t); // peer 0: 10 MiB/s
    c.Attach(1, 1, 20000);
    c.NoteClaim(1, 2, (uint64_t)128 << 20, false);
    c.NoteChunk(1, 2, 1048576, 20300);
    c.SetIdle(2, true);
    mv = c.Rebalance(20400);
    BOOST_CHECK_MESSAGE(mv.empty(), "stream stolen 400 ms after attach on one sample");
    // a stream with a full window but inside the move cooldown is left alone too, and a steal benches the server
    // of the victim for the next assignment
    BootstrapPeerPolicy p2;
    p2.windowMs = 1000;
    p2.stallMs = 1000000;
    p2.stealMinSeconds = 15;
    p2.moveCooldownMs = 3000;
    BootstrapPeerBoard d(2, 3, p2);
    d.Attach(0, d.Assign(0, 0), 0);
    d.Attach(1, d.Assign(1, 0), 0);
    d.NoteClaim(0, 8, 100000, false);
    d.NoteClaim(1, 7, 1000000, false);
    d.SetIdle(2, true);
    for (int64_t t = 100; t <= 2500; t += 100) {
        d.NoteChunk(0, 8, 10000, t);
        d.NoteChunk(1, 7, 10, t);
    }
    BOOST_CHECK(d.Rebalance(2500).empty()); // window full, cooldown (3 s from the attach) not over
    for (int64_t t = 2600; t <= 3200; t += 100) {
        d.NoteChunk(0, 8, 10000, t);
        d.NoteChunk(1, 7, 10, t);
    }
    mv = d.Rebalance(3200);
    BOOST_REQUIRE_EQUAL(mv.size(), 1U);
    BOOST_CHECK(mv[0].reason == BMR_STEAL);
    BOOST_CHECK_EQUAL(mv[0].peer, 1);
    d.Detach(1);
    BOOST_CHECK_EQUAL(d.Assign(1, 3300), 0); // the victim's server is avoided for a while
}

BOOST_AUTO_TEST_CASE(peer_board_does_not_move_streams_when_every_server_is_quiet)
{
    // all servers stop delivering at once: that is this side (a starved host), and a move would only throw away
    // the requests in flight
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.stallMs = 2000;
    BootstrapPeerBoard b(2, 4, pol);
    for (int s = 0; s < 4; ++s)
        b.Attach(s, b.Assign(s, 0), 0);
    for (int64_t t = 100; t <= 1000; t += 100)
        for (int s = 0; s < 4; ++s)
            b.NoteChunk(s, 10 + s, 1000, t);
    BOOST_CHECK(b.Rebalance(4000).empty());
}

BOOST_AUTO_TEST_CASE(peer_board_a_stream_is_not_taken_from_a_fast_server_to_a_slow_one)
{
    // A stream that gets a small share of a fast server's cap just now must not be "stolen" for a slow server
    // that gives its single stream more: judged by what each server delivers in all, the fast one wins.
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.stallMs = 1000000;
    pol.moveCooldownMs = 1000;
    pol.stealMinSeconds = 3;
    BootstrapPeerBoard b(2, 5, pol);
    b.SetPeerHas(1, std::vector<uint8_t>());
    for (int s = 0; s < 3; ++s)
        b.Attach(s, 0, 0);
    b.Attach(3, 1, 0);
    for (int s = 0; s < 4; ++s)
        b.NoteClaim(s, 1 + s, (uint64_t)1 << 30, false);
    for (int64_t t = 100; t <= 3000; t += 100) {
        b.NoteChunk(0, 1, 209715, t); // 2 MiB/s
        b.NoteChunk(1, 2, 209715, t); // 2 MiB/s
        b.NoteChunk(2, 3, 52428, t);  // 0.5 MiB/s
        b.NoteChunk(3, 4, 83886, t);  // the slow server: 0.8 MiB/s
    }
    b.SetIdle(4, true);
    // the only legitimate steal is from the slow server toward the fast one, never a stream of the fast server
    const std::vector<BootstrapMove> mv = b.Rebalance(3000);
    for (size_t i = 0; i < mv.size(); ++i)
        BOOST_CHECK_MESSAGE(mv[i].stream == 3, "stream " << mv[i].stream << " of the fast server was moved");
}

BOOST_AUTO_TEST_CASE(peer_board_an_idle_stream_takes_over_a_slow_holder_when_the_fast_server_has_no_stream_left)
{
    // The end of a download over a fast and a slow server: the fast server's streams ran out of files and are idle,
    // the slow server's stream still holds a big file. What the fast server gave a stream is remembered, so the
    // idle stream takes the rest of the file instead of everything waiting for the slow server.
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.stallMs = 1000000;
    pol.stealMinSeconds = 3;
    pol.moveCooldownMs = 1000;
    BootstrapPeerBoard b(2, 3, pol);
    b.Attach(0, b.Assign(0, 0), 0);
    b.Attach(1, b.Assign(1, 0), 0);
    BOOST_CHECK_EQUAL(b.StreamPeer(1), 1);
    b.NoteClaim(1, 7, (uint64_t)16 << 20, false);
    for (int64_t t = 100; t <= 3000; t += 100) {
        b.NoteChunk(0, 8, 100000, t); // ~1 MB/s from the fast server
        b.NoteChunk(1, 7, 10000, t);  // ~100 kB/s from the slow one
    }
    b.Detach(0);
    b.SetIdle(0, true);
    b.SetIdle(2, true);
    const std::vector<BootstrapMove> mv = b.Rebalance(3000);
    BOOST_REQUIRE_EQUAL(mv.size(), 1U);
    BOOST_CHECK_EQUAL(mv[0].stream, 1);
    BOOST_CHECK(mv[0].reason == BMR_STEAL);
}

// ---- second review: servers that hold nothing, dead servers, unanswered servers, liars ----

BOOST_AUTO_TEST_CASE(peer_board_a_server_without_pending_files_does_not_pull_streams)
{
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.stallMs = 1000000;
    pol.moveCooldownMs = 1000;
    pol.penaltyMs = 1000;
    BootstrapPeerBoard b(2, 4, pol);
    std::vector<uint8_t> has(10, 0);
    has[0] = 1; // peer 1 shares only file 0
    b.SetPeerHas(1, has);
    b.SetPartial(1, true);
    b.Attach(3, 1, 0);
    b.NoteClaim(3, 0, (uint64_t)20 << 20, false);
    for (int64_t t = 100; t <= 2000; t += 100)
        b.NoteChunk(3, 0, 1048576, t); // 10 MiB/s
    b.NoteComplete(3, 0);
    b.Detach(3); // it ran out of files
    for (int s = 0; s < 3; ++s) {
        b.Attach(s, 0, 2000);
        b.NoteClaim(s, 5 + s, (uint64_t)1 << 30, false);
    }
    for (int64_t t = 2100; t <= 6000; t += 100)
        for (int s = 0; s < 3; ++s)
            b.NoteChunk(s, 5 + s, 104858, t); // 1 MiB/s each
    b.SetIdle(3, true);
    const std::vector<BootstrapMove> mv = b.Rebalance(6000);
    std::string r;
    for (size_t i = 0; i < mv.size(); ++i)
        r += strprintf(" stream %d %s", mv[i].stream, mv[i].reason == BMR_SLOW ? "SLOW" : mv[i].reason == BMR_STEAL ? "STEAL" : "other");
    BOOST_CHECK_MESSAGE(mv.empty(), "streams moved off the only holder toward a server that has none of their files:" << r);
}

BOOST_AUTO_TEST_CASE(peer_board_a_remembered_rate_never_makes_a_slow_server_move_and_dies_with_the_connection)
{
    BootstrapPeerPolicy pol;
    pol.windowMs = 1000;
    pol.stallMs = 1000000;
    pol.moveCooldownMs = 1000;
    pol.penaltyMs = 1000;
    pol.stealMinSeconds = 3;
    // peer 1 holds everything and once ran at 10 MiB/s; peer 0 has three live streams at 1 MiB/s. Without an idle
    // stream nothing may move on the strength of the old rate (only live rates are compared for a slow server).
    BootstrapPeerBoard b(2, 4, pol);
    b.SetPeerHas(1, std::vector<uint8_t>());
    b.Attach(3, 1, 0);
    b.NoteClaim(3, 0, (uint64_t)20 << 20, false);
    for (int64_t t = 100; t <= 2000; t += 100)
        b.NoteChunk(3, 0, 1048576, t);
    b.NoteComplete(3, 0);
    b.Detach(3);
    for (int s = 0; s < 3; ++s) {
        b.Attach(s, 0, 2000);
        b.NoteClaim(s, 5 + s, (uint64_t)1 << 30, false);
    }
    for (int64_t t = 2100; t <= 6000; t += 100)
        for (int s = 0; s < 3; ++s)
            b.NoteChunk(s, 5 + s, 104858, t);
    BOOST_CHECK(b.Rebalance(6000).empty());
    // with an idle stream the old rate may steal ...
    BootstrapPeerBoard c(2, 4, pol);
    c.SetPeerHas(1, std::vector<uint8_t>());
    c.Attach(3, 1, 0);
    c.NoteClaim(3, 0, (uint64_t)20 << 20, false);
    for (int64_t t = 100; t <= 2000; t += 100)
        c.NoteChunk(3, 0, 1048576, t);
    c.NoteComplete(3, 0);
    c.Detach(3);
    for (int s = 0; s < 3; ++s) {
        c.Attach(s, 0, 2000);
        c.NoteClaim(s, 5 + s, (uint64_t)1 << 30, false);
    }
    for (int64_t t = 2100; t <= 6000; t += 100)
        for (int s = 0; s < 3; ++s)
            c.NoteChunk(s, 5 + s, 104858, t);
    c.SetIdle(3, true);
    BOOST_CHECK_EQUAL(c.Rebalance(6000).size(), 1U);
    // ... but not once a connection to that server failed: the rate it had says nothing about it now
    BootstrapPeerBoard d(2, 4, pol);
    d.SetPeerHas(1, std::vector<uint8_t>());
    d.Attach(3, 1, 0);
    d.NoteClaim(3, 0, (uint64_t)20 << 20, false);
    for (int64_t t = 100; t <= 2000; t += 100)
        d.NoteChunk(3, 0, 1048576, t);
    d.NoteComplete(3, 0);
    d.Detach(3);
    d.ConnectFailed(1, 2000);
    for (int s = 0; s < 3; ++s) {
        d.Attach(s, 0, 2000);
        d.NoteClaim(s, 5 + s, (uint64_t)1 << 30, false);
    }
    for (int64_t t = 2100; t <= 6000; t += 100)
        for (int s = 0; s < 3; ++s)
            d.NoteChunk(s, 5 + s, 104858, t);
    d.SetIdle(3, true);
    BOOST_CHECK(d.Rebalance(6000).empty());
}

BOOST_AUTO_TEST_CASE(peer_board_assigns_a_stream_to_a_server_that_has_something_for_it)
{
    BootstrapPeerBoard b(2, 4);
    std::vector<uint8_t> has(10, 0);
    has[0] = has[1] = 1; // peer 1 holds files 0 and 1 only
    b.SetPeerHas(1, has);
    std::vector<uint8_t> unfinished(10, 0);
    unfinished[5] = unfinished[6] = 1; // what is left is held by the primary only
    b.SetPendingSource([unfinished]() { return unfinished; });
    for (int s = 0; s < 4; ++s) {
        bool useful = false;
        BOOST_CHECK_EQUAL(b.Assign(s, 1000 + s, &useful), 0);
        BOOST_CHECK(useful);
        b.Attach(s, 0, 1000 + s);
    }
    // nothing at all for anyone (every pending file is pinned elsewhere or gone): the caller is told to wait
    BootstrapPeerBoard c(2, 2);
    std::vector<uint8_t> none(4, 0);
    c.SetPendingSource([none]() { return none; });
    c.SetPeerHas(1, std::vector<uint8_t>());
    bool useful = true;
    c.Assign(0, 0, &useful);
    BOOST_CHECK(!useful);
    // a server that has not answered yet is probed
    BootstrapPeerBoard d(2, 2);
    std::vector<uint8_t> some(4, 1);
    d.SetPendingSource([some]() { return some; });
    bool probe = false;
    d.Assign(0, 0, &probe);
    d.Attach(0, 0, 0);
    BOOST_CHECK_EQUAL(d.Assign(1, 1, &probe), 1);
    BOOST_CHECK(probe);
}

BOOST_AUTO_TEST_CASE(peer_board_a_server_that_never_answered_holds_nothing)
{
    // the primary alone supplied a failing file; the other server never sent its manifest, so it is no holder
    // and the primary must not be benched on its account
    BootstrapPeerBoard b(2, 2);
    b.Attach(0, b.Assign(0, 0), 0);
    b.NoteClaim(0, 5, 100, false);
    b.NoteChunk(0, 5, 100, 10);
    std::vector<uint8_t> unfinished(8, 0);
    unfinished[5] = 1;
    b.HashFailed(0, 5, &unfinished);
    BOOST_CHECK(!b.Peer(0, 20).banned);
    std::vector<uint8_t> need(8, 0);
    need[5] = 1;
    b.ManifestMismatch(0);
    BOOST_CHECK(!b.EveryFileHasHolder(need)); // nobody that has answered holds file 5
    b.SetPeerHas(1, std::vector<uint8_t>());
    BOOST_CHECK(b.EveryFileHasHolder(need));
    // once it has answered it is a holder and the sole supplier is benched
    BootstrapPeerBoard c(2, 2);
    c.Attach(0, c.Assign(0, 0), 0);
    c.SetPeerHas(1, std::vector<uint8_t>());
    c.NoteClaim(0, 5, 100, false);
    c.NoteChunk(0, 5, 100, 10);
    c.HashFailed(0, 5, &unfinished);
    BOOST_CHECK(c.Peer(0, 20).banned);
}

BOOST_AUTO_TEST_CASE(peer_board_a_lying_supplier_is_benched_after_two_files_one_server_then_got_right)
{
    BootstrapPeerBoard b(2, 2);
    b.Attach(0, b.Assign(0, 0), 0);
    b.Attach(1, b.Assign(1, 0), 0);
    b.SetPeerHas(1, std::vector<uint8_t>());
    std::vector<uint8_t> unfinished(16, 0);
    b.SetUnfinishedSource([&unfinished]() { return unfinished; });
    for (uint32_t f = 10; f < 12; ++f) {
        unfinished[f] = 1;
        // both suppliers touched the file and it failed; it is pinned to the primary, which fetches it again
        b.NoteClaim(1, f, 100, false);
        b.NoteChunk(1, f, 50, 10);
        b.NoteRelease(1, f);
        b.NoteClaim(0, f, 50, true);
        b.NoteChunk(0, f, 50, 20);
        b.HashFailed(0, f, &unfinished);
        b.NoteClaim(0, f, 100, false); // from byte 0
        b.NoteChunk(0, f, 100, 40);
        unfinished[f] = 0;
        b.NoteComplete(0, f);
        if (f == 10)
            BOOST_CHECK(!b.Peer(1, 45).banned);
    }
    BOOST_CHECK(!b.Peer(0, 50).banned);
    BOOST_CHECK(b.Peer(1, 50).banned); // two files its attempts failed and the primary alone got right
    // never while it is the only holder of a file still to come
    BootstrapPeerBoard c(2, 2);
    c.Attach(0, c.Assign(0, 0), 0);
    c.Attach(1, c.Assign(1, 0), 0);
    std::vector<uint8_t> has0(16, 1);
    has0[14] = 0; // file 14 is held by peer 1 only
    c.SetPeerHas(0, has0);
    c.SetPeerHas(1, std::vector<uint8_t>());
    std::vector<uint8_t> pend(16, 0);
    pend[14] = 1;
    c.SetUnfinishedSource([&pend]() { return pend; });
    for (uint32_t f = 10; f < 12; ++f) {
        c.NoteClaim(1, f, 100, false);
        c.NoteChunk(1, f, 50, 10);
        c.NoteRelease(1, f);
        c.NoteClaim(0, f, 50, true);
        c.NoteChunk(0, f, 50, 20);
        c.HashFailed(0, f, &pend);
        c.NoteClaim(0, f, 100, false);
        c.NoteChunk(0, f, 100, 40);
        c.NoteComplete(0, f);
    }
    BOOST_CHECK(!c.Peer(1, 50).banned);
}

#endif // !WIN32

BOOST_AUTO_TEST_SUITE_END()
