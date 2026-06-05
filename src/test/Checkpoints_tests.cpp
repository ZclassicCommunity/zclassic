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

// Test-only overload (external linkage; declared extern here, not in checkpoints.h)
// so the negative branches of the startup forgery guard can be driven with
// synthetic anchors the compiled singletons cannot express (TEST-N1). Declared at
// GLOBAL scope so it binds to ::Checkpoints::ValidateFastSyncAnchors, not a nested
// Checkpoints_tests::Checkpoints.
namespace Checkpoints {
bool ValidateFastSyncAnchors(const CChainParams& chainparams,
                             const std::vector<CFastSyncAnchorData>& anchors,
                             const MapCheckpoints& checkpoints,
                             std::string& strError);
}

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

BOOST_AUTO_TEST_CASE(fast_sync_anchor_negative_branches)
{
    const CChainParams& params = Params(CBaseChainParams::MAIN);
    const uint256 hashB  = uint256S("0x00000000000000000000000000000000000000000000000000000000000000bb");
    const uint256 commit = uint256S("0x0000000000000000000000000000000000000000000000000000000000c0ffee");

    CFastSyncAnchorData a;
    a.nHeight = 100;
    a.hashBlock = hashB;
    a.hashChainstateSerialized = commit;

    std::string error;

    // (1) A null UTXO-set commitment must hard-fail (SEC-1: a null commitment would
    // silently disable the only forged-chainstate check).
    {
        CFastSyncAnchorData nullCommit = a;
        nullCommit.hashChainstateSerialized.SetNull();
        std::vector<CFastSyncAnchorData> anchors(1, nullCommit);
        MapCheckpoints cps; cps[100] = hashB;
        error.clear();
        BOOST_CHECK(!Checkpoints::ValidateFastSyncAnchors(params, anchors, cps, error));
        BOOST_CHECK(error.find("commitment") != std::string::npos);
    }
    // (2) Anchor height absent from the checkpoint set must fail.
    {
        std::vector<CFastSyncAnchorData> anchors(1, a);
        MapCheckpoints cps; // height 100 not present
        error.clear();
        BOOST_CHECK(!Checkpoints::ValidateFastSyncAnchors(params, anchors, cps, error));
        BOOST_CHECK(error.find("checkpoint") != std::string::npos);
    }
    // (3) Checkpoint hash mismatch must fail.
    {
        std::vector<CFastSyncAnchorData> anchors(1, a);
        MapCheckpoints cps;
        cps[100] = uint256S("0x00000000000000000000000000000000000000000000000000000000deadbeef");
        error.clear();
        BOOST_CHECK(!Checkpoints::ValidateFastSyncAnchors(params, anchors, cps, error));
        BOOST_CHECK(error.find("mismatch") != std::string::npos);
    }
    // (4) An anchor with nHeight < 0 is skipped; an empty list is vacuously valid.
    {
        std::vector<CFastSyncAnchorData> anchors;
        MapCheckpoints cps;
        error.clear();
        BOOST_CHECK(Checkpoints::ValidateFastSyncAnchors(params, anchors, cps, error));
        BOOST_CHECK(error.empty());
    }
}

BOOST_AUTO_TEST_SUITE_END()
