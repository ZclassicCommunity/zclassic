// Copyright (c) 2011-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Unit tests for block-chain checkpoints
//

#include "checkpoints.h"

#include "uint256.h"
#include "test/test_bitcoin.h"
#include "chainparams.h"

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(Checkpoints_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fast_sync_anchor_mainnet)
{
    std::string error;
    BOOST_CHECK(Checkpoints::ValidateFastSyncAnchor(Params(CBaseChainParams::MAIN), error));
    BOOST_CHECK(error.empty());
}

BOOST_AUTO_TEST_CASE(fast_sync_anchor_disabled_networks)
{
    std::string error;
    BOOST_CHECK(Checkpoints::ValidateFastSyncAnchor(Params(CBaseChainParams::TESTNET), error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(Checkpoints::ValidateFastSyncAnchor(Params(CBaseChainParams::REGTEST), error));
    BOOST_CHECK(error.empty());
}

BOOST_AUTO_TEST_SUITE_END()
