// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "main.h"

#include "test/test_bitcoin.h"

#include <vector>

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>


BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

const CAmount INITIAL_SUBSIDY = 12.5 * COIN;

// Independently recompute the expected subsidy for a height, mirroring the
// consensus schedule (Consensus::Params::Halving + GetBlockSubsidy) but written
// separately here so the test is an oracle, not a tautology. ZClassic's Buttercup
// upgrade halves the block spacing AND applies a "triple halving" (+3), so at
// activation the reward drops by BUTTERCUP_POW_TARGET_SPACING_RATIO * 2^3 in one
// step -- not a single /2 as a naive upstream-Zcash schedule would assume.
static CAmount ExpectedSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    int shift = consensusParams.SubsidySlowStartShift();
    int buttercupHeight = consensusParams.vUpgrades[Consensus::UPGRADE_BUTTERCUP].nActivationHeight;
    bool buttercupActive =
        buttercupHeight != Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT &&
        nHeight >= buttercupHeight;
    int halvings = buttercupActive
        ? (nHeight - shift - buttercupHeight) / consensusParams.nPostButtercupSubsidyHalvingInterval + 3
        : (nHeight - shift) / consensusParams.nPreButtercupSubsidyHalvingInterval;
    if (halvings >= 64)
        return 0;
    CAmount nSubsidy = INITIAL_SUBSIDY;
    if (buttercupActive)
        return (nSubsidy / Consensus::BUTTERCUP_POW_TARGET_SPACING_RATIO) >> halvings;
    return nSubsidy >> halvings;
}

static void TestBlockSubsidyHalvings(const Consensus::Params& consensusParams)
{
    const int shift = consensusParams.SubsidySlowStartShift();
    const int buttercupHeight = consensusParams.vUpgrades[Consensus::UPGRADE_BUTTERCUP].nActivationHeight;
    const bool hasButtercup = buttercupHeight != Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

    // Full reward once the slow-start ramp completes.
    BOOST_CHECK_EQUAL(GetBlockSubsidy(consensusParams.nSubsidySlowStartInterval, consensusParams), INITIAL_SUBSIDY);

    // First height of each halving level ("boundaries"): the pre-Buttercup steps
    // that fall before activation, then the Buttercup activation height, then the
    // post-Buttercup steps.
    std::vector<int> boundaries;
    for (int k = 1; k < 64; k++) {
        int h = shift + k * consensusParams.nPreButtercupSubsidyHalvingInterval;
        if (hasButtercup && h >= buttercupHeight)
            break;
        boundaries.push_back(h);
    }
    if (hasButtercup) {
        // Level 3 begins exactly at activation. Subsequent post-Buttercup levels
        // begin at shift + activation + m*postInterval (the slow-start shift offset
        // matters here just as it does pre-Buttercup).
        boundaries.push_back(buttercupHeight);
        for (int j = 1; j < 64; j++)
            boundaries.push_back(shift + buttercupHeight + j * consensusParams.nPostButtercupSubsidyHalvingInterval);
    }

    CAmount nPreviousSubsidy = INITIAL_SUBSIDY;
    for (size_t i = 0; i < boundaries.size(); i++) {
        int nHeight = boundaries[i];
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        // GetBlockSubsidy matches the independently-computed schedule, at the
        // boundary and at the block just before it (still the previous level).
        BOOST_CHECK_EQUAL(nSubsidy, ExpectedSubsidy(nHeight, consensusParams));
        BOOST_CHECK_EQUAL(GetBlockSubsidy(nHeight - 1, consensusParams), nPreviousSubsidy);
        // Subsidy never exceeds the initial reward and never increases.
        BOOST_CHECK(nSubsidy <= INITIAL_SUBSIDY);
        BOOST_CHECK(nSubsidy <= nPreviousSubsidy);
        nPreviousSubsidy = nSubsidy;
        if (nSubsidy == 0)
            break;
    }
    // The schedule eventually reaches zero.
    BOOST_CHECK_EQUAL(GetBlockSubsidy(boundaries.back(), consensusParams), 0);
}

static void TestBlockSubsidyHalvings(int nSubsidySlowStartInterval, int nPreButtercupSubsidyHalvingInterval, int buttercupActivationHeight)
{
    Consensus::Params consensusParams;
    consensusParams.nSubsidySlowStartInterval = nSubsidySlowStartInterval;
    consensusParams.nPreButtercupSubsidyHalvingInterval = nPreButtercupSubsidyHalvingInterval;
    consensusParams.nPostButtercupSubsidyHalvingInterval = nPreButtercupSubsidyHalvingInterval * Consensus::BUTTERCUP_POW_TARGET_SPACING_RATIO;
    consensusParams.vUpgrades[Consensus::UPGRADE_BUTTERCUP].nActivationHeight = buttercupActivationHeight;
    TestBlockSubsidyHalvings(consensusParams);
}

BOOST_AUTO_TEST_CASE(block_subsidy_test)
{
    TestBlockSubsidyHalvings(Params(CBaseChainParams::MAIN).GetConsensus()); // As in main
    TestBlockSubsidyHalvings(20000, Consensus::PRE_BUTTERCUP_HALVING_INTERVAL, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT); // Pre-Buttercup
    TestBlockSubsidyHalvings(50, 150, 80); // As in regtest
    TestBlockSubsidyHalvings(500, 1000, 900); // Just another interval
    TestBlockSubsidyHalvings(500, 1000, 3000); // Multiple halvings before Buttercup activation
}

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const Consensus::Params& consensusParams = Params(CBaseChainParams::MAIN).GetConsensus();
    
    CAmount nSum = 0;
    int nHeight = 0;
    // Mining slow start
    for (; nHeight < consensusParams.nSubsidySlowStartInterval; nHeight++) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy <= INITIAL_SUBSIDY);
        nSum += nSubsidy;
        BOOST_CHECK(MoneyRange(nSum));
    }
    BOOST_CHECK_EQUAL(nSum, 1250000000);

    // Regular mining
    CAmount nSubsidy;
    do {
        nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy <= INITIAL_SUBSIDY);
        nSum += nSubsidy;
        BOOST_ASSERT(MoneyRange(nSum));
        ++nHeight;
    } while (nSubsidy > 0);

    // ZClassic's total money supply is lower than upstream Zcash's ~21M ZEC. The
    // Buttercup upgrade halves the block spacing (twice as many blocks) while
    // cutting the per-block reward by BUTTERCUP_POW_TARGET_SPACING_RATIO * 2^3
    // (the "triple halving"), so the net emission rate drops and the schedule
    // sums (deterministically, over every height until the subsidy reaches 0) to
    // ~11.46M ZEC. This assertion pins ZClassic's intended total emission; the
    // old ~21M value was an upstream-Zcash leftover.
    BOOST_CHECK_EQUAL(nSum, 1146248809645000ULL);
}

bool ReturnFalse() { return false; }
bool ReturnTrue() { return true; }

BOOST_AUTO_TEST_CASE(test_combiner_all)
{
    boost::signals2::signal<bool (), CombinerAll> Test;
    BOOST_CHECK(Test());
    Test.connect(&ReturnFalse);
    BOOST_CHECK(!Test());
    Test.connect(&ReturnTrue);
    BOOST_CHECK(!Test());
    Test.disconnect(&ReturnFalse);
    BOOST_CHECK(Test());
    Test.disconnect(&ReturnTrue);
    BOOST_CHECK(Test());
}

BOOST_AUTO_TEST_SUITE_END()
