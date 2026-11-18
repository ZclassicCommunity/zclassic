// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "rpc/server.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <univalue.h>

extern UniValue CallRPC(std::string args);

BOOST_FIXTURE_TEST_SUITE(blockchaininfo_tests, TestingSetup)

/*
 * After a snapshot import the best known header can lag the tip (the index was loaded
 * with headers above the anchor, then RewindBlockIndex used to pull the best header down
 * to the anchor-height tip while the bundled blocks were connected afterwards):
 * getblockchaininfo must never report fewer headers than blocks.
 */
BOOST_AUTO_TEST_CASE(headers_never_below_blocks)
{
    LOCK(cs_main);
    CBlockIndex* const saved = pindexBestHeader;
    const int blocks = chainActive.Height();

    pindexBestHeader = NULL; // no best header at all
    UniValue info = CallRPC("getblockchaininfo");
    BOOST_CHECK_EQUAL(find_value(info.get_obj(), "blocks").get_int(), blocks);
    BOOST_CHECK_EQUAL(find_value(info.get_obj(), "headers").get_int(), blocks);
    BOOST_CHECK_EQUAL(find_value(info.get_obj(), "estimatedheight").get_int(), blocks);

    // a best header strictly below the tip is not reported as such
    CBlockIndex stale;
    stale.nHeight = blocks - 1;
    pindexBestHeader = &stale;
    info = CallRPC("getblockchaininfo");
    BOOST_CHECK_EQUAL(find_value(info.get_obj(), "headers").get_int(), blocks);

    // headers ahead of the tip still show as such
    CBlockIndex ahead;
    ahead.nHeight = blocks + 50;
    pindexBestHeader = &ahead;
    info = CallRPC("getblockchaininfo");
    BOOST_CHECK_EQUAL(find_value(info.get_obj(), "headers").get_int(), blocks + 50);
    BOOST_CHECK_EQUAL(find_value(info.get_obj(), "estimatedheight").get_int(), blocks + 50);

    pindexBestHeader = saved;
}

BOOST_AUTO_TEST_SUITE_END()
