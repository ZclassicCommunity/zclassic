// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Positive-only Sapling verdict cache (shieldedcache.h) and its single call
// site in ContextualCheckTransaction.

#include "chainparams.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "main.h"
#include "primitives/transaction.h"
#include "random.h"
#include "shieldedcache.h"
#include "test/test_bitcoin.h"
#include "util.h"

#include <boost/test/unit_test.hpp>

namespace {

bool NotInIBD() { return false; }

/** Restores -maxshieldedcachesize and empties the cache around a test. */
struct ShieldedCacheArgGuard {
    bool fHad;
    std::string strOld;
    ShieldedCacheArgGuard()
    {
        fHad = mapArgs.count("-maxshieldedcachesize") != 0;
        if (fHad) strOld = mapArgs["-maxshieldedcachesize"];
        ShieldedVerdictClearForTest();
    }
    ~ShieldedCacheArgGuard()
    {
        if (fHad)
            mapArgs["-maxshieldedcachesize"] = strOld;
        else
            mapArgs.erase("-maxshieldedcachesize");
        ShieldedVerdictClearForTest();
    }
    void Set(const std::string& v)
    {
        mapArgs["-maxshieldedcachesize"] = v;
        ShieldedVerdictClearForTest();
    }
};

/** A structurally valid Sapling transaction whose spend proof is garbage. */
CMutableTransaction GarbageSaplingTx()
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nExpiryHeight = 0;
    SpendDescription sd;
    sd.cv = GetRandHash();
    sd.anchor = GetRandHash();
    sd.nullifier = GetRandHash();
    sd.rk = GetRandHash();
    mtx.vShieldedSpend.push_back(sd);
    return mtx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shieldedcache_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(insert_then_contains_exact_key_only)
{
    ShieldedCacheArgGuard guard;
    BOOST_CHECK_EQUAL(ShieldedVerdictMaxEntriesForTest(),
                      (size_t)DEFAULT_MAX_SHIELDED_CACHE_SIZE * 1048576 / 64);
    const uint256 txid = GetRandHash();
    const uint32_t branch = 0x76b809bb; // Sapling
    BOOST_CHECK(!ShieldedVerdictContains(txid, branch));
    ShieldedVerdictInsert(txid, branch);
    BOOST_CHECK(ShieldedVerdictContains(txid, branch));
    BOOST_CHECK_EQUAL(ShieldedVerdictSizeForTest(), 1U);

    // A different branch id misses, in either byte order.
    BOOST_CHECK(!ShieldedVerdictContains(txid, 0x5ba81b19)); // Overwinter
    BOOST_CHECK(!ShieldedVerdictContains(txid, 0xbb09b876));
    BOOST_CHECK(!ShieldedVerdictContains(txid, 0));
    // A different txid misses, including a one-bit change.
    uint256 other = txid;
    *other.begin() ^= 0x01;
    BOOST_CHECK(!ShieldedVerdictContains(other, branch));
    for (int i = 0; i < 1000; i++)
        BOOST_CHECK(!ShieldedVerdictContains(GetRandHash(), branch));

    // Re-inserting does not grow the set.
    ShieldedVerdictInsert(txid, branch);
    BOOST_CHECK_EQUAL(ShieldedVerdictSizeForTest(), 1U);
    ShieldedVerdictClearForTest();
    BOOST_CHECK(!ShieldedVerdictContains(txid, branch));
}

BOOST_AUTO_TEST_CASE(bound_holds)
{
    ShieldedCacheArgGuard guard;
    guard.Set("1");
    const size_t nMax = ShieldedVerdictMaxEntriesForTest();
    BOOST_CHECK_EQUAL(nMax, 1048576U / 64);
    uint256 last;
    for (size_t i = 0; i < 3 * nMax; i++) {
        last = GetRandHash();
        ShieldedVerdictInsert(last, 1);
        // The entry just inserted is always present (it is never the victim).
        if (i % 997 == 0)
            BOOST_REQUIRE(ShieldedVerdictContains(last, 1));
        BOOST_REQUIRE(ShieldedVerdictSizeForTest() <= nMax);
    }
    BOOST_CHECK_EQUAL(ShieldedVerdictSizeForTest(), nMax);
    BOOST_CHECK(ShieldedVerdictContains(last, 1));
}

BOOST_AUTO_TEST_CASE(size_zero_disables)
{
    ShieldedCacheArgGuard guard;
    guard.Set("0");
    BOOST_CHECK_EQUAL(ShieldedVerdictMaxEntriesForTest(), 0U);
    const uint256 txid = GetRandHash();
    ShieldedVerdictInsert(txid, 7);
    BOOST_CHECK(!ShieldedVerdictContains(txid, 7));
    BOOST_CHECK_EQUAL(ShieldedVerdictSizeForTest(), 0U);
    guard.Set("-3");
    ShieldedVerdictInsert(txid, 7);
    BOOST_CHECK(!ShieldedVerdictContains(txid, 7));
}

BOOST_AUTO_TEST_CASE(contextual_check_failures_are_never_cached)
{
    ShieldedCacheArgGuard guard;
    const Consensus::Params& consensus = Params().GetConsensus();
    const int nHeight = consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight + 10;
    const uint32_t branch = CurrentEpochBranchId(nHeight, consensus);
    const CTransaction tx(GarbageSaplingTx());

    for (int round = 0; round < 3; round++) {
        CValidationState state;
        BOOST_CHECK(!ContextualCheckTransaction(tx, state, nHeight, 100, NotInIBD));
        int nDoS = 0;
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_EQUAL(nDoS, 100);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-sapling-spend-description-invalid");
        BOOST_CHECK(!ShieldedVerdictContains(tx.GetHash(), branch));
    }
    BOOST_CHECK_EQUAL(ShieldedVerdictSizeForTest(), 0U);

    // Output-only garbage fails in the output loop and is not cached either.
    CMutableTransaction mtx = GarbageSaplingTx();
    mtx.vShieldedSpend.clear();
    OutputDescription od;
    od.cv = GetRandHash();
    od.cm = GetRandHash();
    od.ephemeralKey = GetRandHash();
    mtx.vShieldedOutput.push_back(od);
    const CTransaction txOut(mtx);
    CValidationState state;
    BOOST_CHECK(!ContextualCheckTransaction(txOut, state, nHeight, 100, NotInIBD));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-sapling-output-description-invalid");
    BOOST_CHECK(!ShieldedVerdictContains(txOut.GetHash(), branch));
}

BOOST_AUTO_TEST_CASE(contextual_check_consults_exact_key)
{
    // White-box wiring check: an entry for (txid, branch id) is what lets
    // ContextualCheckTransaction skip the Sapling block. Only a successful
    // verification can create such an entry in a running node; inserting one
    // by hand here proves the lookup key is exactly (txid, height's branch id)
    // and that every other key still runs the full checks.
    ShieldedCacheArgGuard guard;
    const Consensus::Params& consensus = Params().GetConsensus();
    const int nHeight = consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight + 10;
    const uint32_t branch = CurrentEpochBranchId(nHeight, consensus);
    const CTransaction tx(GarbageSaplingTx());

    ShieldedVerdictInsert(tx.GetHash(), branch ^ 1);
    ShieldedVerdictInsert(GetRandHash(), branch);
    {
        CValidationState state;
        BOOST_CHECK(!ContextualCheckTransaction(tx, state, nHeight, 100, NotInIBD));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-sapling-spend-description-invalid");
    }
    ShieldedVerdictInsert(tx.GetHash(), branch);
    {
        CValidationState state;
        BOOST_CHECK(ContextualCheckTransaction(tx, state, nHeight, 100, NotInIBD));
        BOOST_CHECK(state.IsValid());
    }
    // A mutated copy (different txid) is verified again and rejected.
    CMutableTransaction mtx(tx);
    mtx.vShieldedSpend[0].zkproof[0] ^= 0x01;
    const CTransaction mutated(mtx);
    BOOST_REQUIRE(mutated.GetHash() != tx.GetHash());
    {
        CValidationState state;
        BOOST_CHECK(!ContextualCheckTransaction(mutated, state, nHeight, 100, NotInIBD));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-sapling-spend-description-invalid");
    }
    // Checks above the Sapling block are not affected by an entry: the same
    // transaction marked as expired still fails on expiry.
    CMutableTransaction expiring(tx);
    expiring.nExpiryHeight = nHeight - 5;
    const CTransaction expired(expiring);
    ShieldedVerdictInsert(expired.GetHash(), branch);
    {
        CValidationState state;
        BOOST_CHECK(!ContextualCheckTransaction(expired, state, nHeight, 100, NotInIBD));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "tx-overwinter-expired");
    }
}

BOOST_AUTO_TEST_SUITE_END()
