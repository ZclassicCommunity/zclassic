// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bootstrap.h"
#include "main.h"
#include "test/test_bitcoin.h"

#include <string>

#include <boost/filesystem.hpp>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(p2p_sync_tests, BasicTestingSetup)

// A getheaders request nobody answers must time out so the single-sync-peer slot
// can move to another peer (a peer that is itself in initial block download
// silently ignores getheaders).
BOOST_AUTO_TEST_CASE(headers_request_timeout)
{
    const int64_t sec = 1000000;
    // No request outstanding: never times out.
    BOOST_CHECK(!HeadersRequestTimedOut(1000 * sec, 0, HEADERS_RESPONSE_TIMEOUT));
    // Outstanding but within the timeout.
    BOOST_CHECK(!HeadersRequestTimedOut(1000 * sec, 1000 * sec, HEADERS_RESPONSE_TIMEOUT));
    BOOST_CHECK(!HeadersRequestTimedOut(1000 * sec + HEADERS_RESPONSE_TIMEOUT * sec, 1000 * sec, HEADERS_RESPONSE_TIMEOUT));
    // Outstanding past the timeout.
    BOOST_CHECK(HeadersRequestTimedOut(1000 * sec + (HEADERS_RESPONSE_TIMEOUT + 1) * sec, 1000 * sec, HEADERS_RESPONSE_TIMEOUT));
}

BOOST_AUTO_TEST_CASE(replay_progress_percent)
{
    // Measured from the height the replay started at, not from the current tip.
    BOOST_CHECK_EQUAL(ReplayProgressPercent(3126937, 3126938, 3326937), 1);
    BOOST_CHECK_EQUAL(ReplayProgressPercent(3126937, 3226937, 3326937), 50);
    BOOST_CHECK_EQUAL(ReplayProgressPercent(3126937, 3326937, 3326937), 99);
    BOOST_CHECK_EQUAL(ReplayProgressPercent(10, 10, 10), 99);
    BOOST_CHECK_EQUAL(ReplayProgressPercent(100, 90, 200), 1);
}

BOOST_AUTO_TEST_CASE(block_index_write_interval)
{
    // During initial block download the block index is written often enough that a crash costs minutes, not an hour.
    BOOST_CHECK_EQUAL(BlockIndexWriteInterval(true), (int64_t)DATABASE_WRITE_INTERVAL_IBD);
    BOOST_CHECK_EQUAL(BlockIndexWriteInterval(false), (int64_t)DATABASE_WRITE_INTERVAL);
    BOOST_CHECK(BlockIndexWriteInterval(true) <= 10 * 60);
    BOOST_CHECK(BlockIndexWriteInterval(true) < BlockIndexWriteInterval(false));
}

BOOST_AUTO_TEST_CASE(chainstate_flush_interval)
{
    // At the tip the coins are flushed every few minutes (a kill then costs minutes of blocks, not up to a
    // day of them); initial block download keeps the long interval so the big coins cache keeps its speed.
    mapArgs.erase("-dbflushinterval");
    BOOST_CHECK_EQUAL(ChainstateFlushInterval(true), (int64_t)DATABASE_FLUSH_INTERVAL);
    BOOST_CHECK_EQUAL(ChainstateFlushInterval(false), (int64_t)DATABASE_FLUSH_INTERVAL_TIP);
    BOOST_CHECK(ChainstateFlushInterval(false) <= 15 * 60);
    BOOST_CHECK(ChainstateFlushInterval(false) < ChainstateFlushInterval(true));
    mapArgs["-dbflushinterval"] = "30";
    BOOST_CHECK_EQUAL(ChainstateFlushInterval(false), 30);
    BOOST_CHECK_EQUAL(ChainstateFlushInterval(true), (int64_t)DATABASE_FLUSH_INTERVAL); // IBD ignores it
    // 0, negative and over-long values mean the legacy once-a-day interval, never longer
    mapArgs["-dbflushinterval"] = "0";
    BOOST_CHECK_EQUAL(ChainstateFlushInterval(false), (int64_t)DATABASE_FLUSH_INTERVAL);
    mapArgs["-dbflushinterval"] = "-5";
    BOOST_CHECK_EQUAL(ChainstateFlushInterval(false), (int64_t)DATABASE_FLUSH_INTERVAL);
    mapArgs["-dbflushinterval"] = "99999999";
    BOOST_CHECK_EQUAL(ChainstateFlushInterval(false), (int64_t)DATABASE_FLUSH_INTERVAL);
    mapArgs.erase("-dbflushinterval");
}

BOOST_AUTO_TEST_CASE(sync_phase_classification)
{
    // Not in IBD: synced regardless of anything else.
    BOOST_CHECK_EQUAL(std::string(ClassifySyncPhase(false, false, false, 8, 100, 100)), "synced");
    // IBD with no connections: waiting for peers.
    BOOST_CHECK_EQUAL(std::string(ClassifySyncPhase(true, false, false, 0, 100, 100)), "waiting_for_peers");
    // IBD, peers, headers ahead of blocks: downloading blocks.
    BOOST_CHECK_EQUAL(std::string(ClassifySyncPhase(true, false, false, 2, 100, 5000)), "downloading_blocks");
    // IBD, peers, no headers beyond tip yet: looking for headers.
    BOOST_CHECK_EQUAL(std::string(ClassifySyncPhase(true, false, false, 2, 100, 100)), "downloading_headers");
    // Reindex and import override.
    BOOST_CHECK_EQUAL(std::string(ClassifySyncPhase(true, true, false, 0, 100, 100)), "reindexing");
    BOOST_CHECK_EQUAL(std::string(ClassifySyncPhase(true, false, true, 0, 100, 100)), "importing");
}

// An interrupted snapshot download used to leave its staging directory (up to the full snapshot size)
// in the datadir forever.
BOOST_AUTO_TEST_CASE(stale_bootstrap_staging_removed)
{
    const boost::filesystem::path dir = boost::filesystem::temp_directory_path() / UniquePath("z23-staging-%%%%-%%%%");
    boost::filesystem::create_directories(dir / "bootstrap-peer-staging-100" / "blocks");
    boost::filesystem::create_directories(dir / "bootstrap-peer-staging-200" / "chainstate");
    boost::filesystem::create_directories(dir / "blocks");
    boost::filesystem::create_directories(dir / "bootstrap-import-300");
    BOOST_CHECK_EQUAL(RemoveStaleBootstrapStaging(dir), (size_t)2);
    BOOST_CHECK(!boost::filesystem::exists(dir / "bootstrap-peer-staging-100"));
    BOOST_CHECK(!boost::filesystem::exists(dir / "bootstrap-peer-staging-200"));
    BOOST_CHECK(boost::filesystem::exists(dir / "blocks"));
    BOOST_CHECK(boost::filesystem::exists(dir / "bootstrap-import-300"));
    BOOST_CHECK_EQUAL(RemoveStaleBootstrapStaging(dir), (size_t)0);
    boost::filesystem::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()
