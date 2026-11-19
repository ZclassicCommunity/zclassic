// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Positive-result Equihash memo (equihashmemo.h) and its call sites in
// main.cpp: CheckBlockHeader, CheckBlock and ReadBlockFromDisk. Every reject
// must be identical with the memo cold, warm or disabled, and with either
// Equihash verifier.

#include "chainparams.h"
#include "consensus/validation.h"
#include "equihashmemo.h"
#include "main.h"
#include "pow.h"
#include "random.h"
#include "test/test_bitcoin.h"
#include "zcash/Proof.hpp"

#include <atomic>
#include <thread>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

struct EquihashSettingsGuard {
    EquihashImpl impl;
    bool memo;
    EquihashSettingsGuard() : impl(GetEquihashImplementation()), memo(GetEquihashMemoEnabled()) {}
    ~EquihashSettingsGuard()
    {
        SetEquihashImplementation(impl);
        SetEquihashMemoEnabled(memo);
        SetEquihashDifferential(false);
        GetEquihashMemo().Clear();
    }
};

uint256 RandomHash()
{
    uint256 h;
    GetRandBytes(h.begin(), h.size());
    return h;
}

enum Mutation { MUT_SOLUTION_BIT, MUT_NONCE, MUT_TIME, MUT_SOLUTION_SHORT, MUT_SOLUTION_SWAP };

CBlock Mutate(const CBlock& valid, Mutation m)
{
    CBlock b(valid);
    switch (m) {
    case MUT_SOLUTION_BIT:
        b.nSolution[b.nSolution.size() / 2] ^= 0x10;
        break;
    case MUT_NONCE:
        *(b.nNonce.begin()) ^= 0x01;
        break;
    case MUT_TIME:
        b.nTime += 1;
        break;
    case MUT_SOLUTION_SHORT:
        b.nSolution.pop_back();
        break;
    case MUT_SOLUTION_SWAP: {
        // Swap byte 0 of the minimal encoding with the first byte that
        // differs from it (moves index bits between indices).
        size_t j = 1;
        while (j < b.nSolution.size() && b.nSolution[j] == b.nSolution[0])
            j++;
        assert(j < b.nSolution.size());
        std::swap(b.nSolution[0], b.nSolution[j]);
        break;
    }
    }
    return b;
}

const Mutation ALL_MUTATIONS[] = {MUT_SOLUTION_BIT, MUT_NONCE, MUT_TIME, MUT_SOLUTION_SHORT, MUT_SOLUTION_SWAP};

void ExpectRejectedEverywhere(const CBlock& bad, int nFileForDisk)
{
    const uint256 badHash = bad.GetHash();

    BOOST_CHECK(!CheckEquihashSolutionMemo(&bad, Params()));
    BOOST_CHECK(!CheckEquihashSolution(&bad, Params()));

    {
        CValidationState state;
        BOOST_CHECK(!CheckBlockHeader(bad, state));
        int nDoS = 0;
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_EQUAL(nDoS, 100);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "invalid-solution");
    }
    {
        CValidationState state;
        auto verifier = libzcash::ProofVerifier::Disabled();
        BOOST_CHECK(!CheckBlock(bad, state, verifier, true, false, false));
        int nDoS = 0;
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_EQUAL(nDoS, 100);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "invalid-solution");
    }
    {
        CBlock copy(bad);
        CDiskBlockPos pos(nFileForDisk, 0);
        BOOST_REQUIRE(WriteBlockToDisk(copy, pos, Params().MessageStart()));
        CBlock readBack;
        BOOST_CHECK(!ReadBlockFromDisk(readBack, pos, true));
        // fCheckPOW=false skips the header check entirely, as before.
        BOOST_CHECK(ReadBlockFromDisk(readBack, pos, false));
        BOOST_CHECK(readBack.GetHash() == badHash);
    }
    // A false result is never memoised.
    BOOST_CHECK(!GetEquihashMemo().Contains(badHash));
}

void ExpectAcceptedEverywhere(const CBlock& good, int nFileForDisk)
{
    BOOST_CHECK(CheckEquihashSolutionMemo(&good, Params()));
    {
        CValidationState state;
        BOOST_CHECK(CheckBlockHeader(good, state));
        BOOST_CHECK(state.IsValid());
    }
    {
        CValidationState state;
        auto verifier = libzcash::ProofVerifier::Disabled();
        BOOST_CHECK(CheckBlock(good, state, verifier, true, true, false));
        BOOST_CHECK(state.IsValid());
    }
    {
        CBlock copy(good);
        CDiskBlockPos pos(nFileForDisk, 0);
        BOOST_REQUIRE(WriteBlockToDisk(copy, pos, Params().MessageStart()));
        CBlock readBack;
        BOOST_CHECK(ReadBlockFromDisk(readBack, pos, true));
        BOOST_CHECK(readBack.GetHash() == good.GetHash());
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(equihashmemo_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(memo_capacity_is_bounded)
{
    BOOST_CHECK_EQUAL(CEquihashMemo(1).Capacity(), 4U);
    BOOST_CHECK_EQUAL(CEquihashMemo(5).Capacity(), 8U);
    BOOST_CHECK_EQUAL(CEquihashMemo(64).Capacity(), 64U);
    BOOST_CHECK_EQUAL(GetEquihashMemo().Capacity(), DEFAULT_EQUIHASH_MEMO_ENTRIES);

    CEquihashMemo memo(64);
    std::vector<uint256> inserted;
    for (int i = 0; i < 5000; i++) {
        uint256 h = RandomHash();
        memo.Insert(h);
        inserted.push_back(h);
        BOOST_REQUIRE(memo.Size() <= memo.Capacity());
        // The entry just inserted is always present (it is never the victim).
        BOOST_REQUIRE(memo.Contains(h));
    }
    BOOST_CHECK_EQUAL(memo.Size(), memo.Capacity());
    CEquihashMemo::Stats s = memo.GetStats();
    BOOST_CHECK_EQUAL(s.inserts, 5000U);
    BOOST_CHECK_EQUAL(s.evictions, 5000U - memo.Capacity());

    // At most Capacity() of the inserted keys can still be present.
    size_t present = 0;
    for (const uint256& h : inserted)
        present += memo.Contains(h) ? 1 : 0;
    BOOST_CHECK(present <= memo.Capacity());

    // Re-inserting a present key does not grow or evict.
    memo.Insert(inserted.back());
    BOOST_CHECK_EQUAL(memo.GetStats().inserts, 5000U);

    // Keys never inserted are never reported.
    for (int i = 0; i < 1000; i++)
        BOOST_CHECK(!memo.Contains(RandomHash()));

    memo.Clear();
    BOOST_CHECK_EQUAL(memo.Size(), 0U);
    BOOST_CHECK(!memo.Contains(inserted.back()));
}

BOOST_AUTO_TEST_CASE(memo_concurrent_access)
{
    CEquihashMemo memo(256);
    const int nThreads = 8;
    const int nPerThread = 4000;
    std::vector<std::vector<uint256> > keys(nThreads);
    for (int t = 0; t < nThreads; t++)
        for (int i = 0; i < nPerThread; i++)
            keys[t].push_back(RandomHash());
    std::vector<uint256> never;
    for (int i = 0; i < 512; i++)
        never.push_back(RandomHash());

    std::atomic<int> falsePositives{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < nThreads; t++) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < nPerThread; i++) {
                memo.Insert(keys[t][i]);
                if (memo.Contains(never[i % never.size()]))
                    falsePositives++;
                (void)memo.Contains(keys[(t + 1) % nThreads][i]);
                (void)memo.Size();
            }
        });
    }
    for (auto& th : threads)
        th.join();

    BOOST_CHECK_EQUAL(falsePositives.load(), 0);
    BOOST_CHECK(memo.Size() <= memo.Capacity());
    CEquihashMemo::Stats s = memo.GetStats();
    BOOST_CHECK_EQUAL(s.inserts, (uint64_t)(nThreads * nPerThread));
    BOOST_CHECK_EQUAL(s.inserts - s.evictions, (uint64_t)memo.Size());
}

BOOST_AUTO_TEST_CASE(invalid_solution_rejected_at_every_call_site)
{
    EquihashSettingsGuard guard;
    const CBlock genesis = Params().GenesisBlock();
    BOOST_REQUIRE_EQUAL(genesis.nSolution.size(), 1344U);

    const EquihashImpl impls[] = {EquihashImpl::CPP, EquihashImpl::C23};
    for (EquihashImpl impl : impls) {
        SetEquihashImplementation(impl);
        for (int memoMode = 0; memoMode < 3; memoMode++) {
            // 0: memo disabled; 1: memo enabled and cold; 2: memo enabled and
            // warm (the valid header and unrelated hashes already memoised).
            SetEquihashMemoEnabled(memoMode != 0);
            GetEquihashMemo().Clear();
            if (memoMode == 2) {
                BOOST_REQUIRE(CheckEquihashSolutionMemo(&genesis, Params()));
                for (int i = 0; i < 100; i++)
                    GetEquihashMemo().Insert(RandomHash());
                BOOST_REQUIRE(GetEquihashMemo().Contains(genesis.GetHash()));
            }
            int nFile = 9000 + 100 * (int)impl + 10 * memoMode;
            for (Mutation m : ALL_MUTATIONS) {
                BOOST_TEST_MESSAGE("impl " << (int)impl << " memo " << memoMode << " mutation " << (int)m);
                CBlock bad = Mutate(genesis, m);
                BOOST_REQUIRE(bad.GetHash() != genesis.GetHash());
                ExpectRejectedEverywhere(bad, nFile++);
                // Asking twice gives the same answer (nothing cached).
                ExpectRejectedEverywhere(bad, nFile++);
            }
            ExpectAcceptedEverywhere(genesis, nFile++);
            BOOST_CHECK_EQUAL(GetEquihashMemo().Contains(genesis.GetHash()), memoMode != 0);
            // The valid header is still accepted, and the mutants still
            // rejected, after it has been memoised.
            for (Mutation m : ALL_MUTATIONS)
                ExpectRejectedEverywhere(Mutate(genesis, m), nFile++);
        }
    }
}

BOOST_AUTO_TEST_CASE(memo_skips_repeat_verification_only)
{
    EquihashSettingsGuard guard;
    const CBlock genesis = Params().GenesisBlock();
    const CBlock bad = Mutate(genesis, MUT_SOLUTION_BIT);

    SetEquihashMemoEnabled(true);
    GetEquihashMemo().Clear();
    EquihashVerifierStats before = GetEquihashVerifierStats();
    for (int i = 0; i < 5; i++) {
        BOOST_CHECK(CheckEquihashSolutionMemo(&genesis, Params()));
        BOOST_CHECK(!CheckEquihashSolutionMemo(&bad, Params()));
    }
    EquihashVerifierStats after = GetEquihashVerifierStats();
    // Valid header: 1 verification + 4 memo hits. Invalid: 5 verifications.
    BOOST_CHECK_EQUAL(after.nVerifications - before.nVerifications, 6U);
    BOOST_CHECK_EQUAL(after.nMemoHits - before.nMemoHits, 4U);

    SetEquihashMemoEnabled(false);
    before = GetEquihashVerifierStats();
    for (int i = 0; i < 5; i++)
        BOOST_CHECK(CheckEquihashSolutionMemo(&genesis, Params()));
    after = GetEquihashVerifierStats();
    BOOST_CHECK_EQUAL(after.nVerifications - before.nVerifications, 5U);
    BOOST_CHECK_EQUAL(after.nMemoHits - before.nMemoHits, 0U);

    // CheckEquihashSolution itself never consults the memo.
    SetEquihashMemoEnabled(true);
    BOOST_REQUIRE(CheckEquihashSolutionMemo(&genesis, Params()));
    before = GetEquihashVerifierStats();
    BOOST_CHECK(CheckEquihashSolution(&genesis, Params()));
    after = GetEquihashVerifierStats();
    BOOST_CHECK_EQUAL(after.nVerifications - before.nVerifications, 1U);
}

BOOST_AUTO_TEST_CASE(concurrent_header_checks)
{
    EquihashSettingsGuard guard;
    const CBlock genesis = Params().GenesisBlock();
    std::vector<CBlock> bad;
    for (Mutation m : ALL_MUTATIONS)
        bad.push_back(Mutate(genesis, m));

    const EquihashImpl impls[] = {EquihashImpl::CPP, EquihashImpl::C23};
    for (EquihashImpl impl : impls) {
        SetEquihashImplementation(impl);
        SetEquihashMemoEnabled(true);
        GetEquihashMemo().Clear();
        std::atomic<int> wrong{0};
        std::vector<std::thread> threads;
        for (int t = 0; t < 8; t++) {
            threads.emplace_back([&]() {
                for (int i = 0; i < 10; i++) {
                    if (!CheckEquihashSolutionMemo(&genesis, Params()))
                        wrong++;
                    for (const CBlock& b : bad)
                        if (CheckEquihashSolutionMemo(&b, Params()))
                            wrong++;
                    GetEquihashMemo().Insert(RandomHash());
                }
            });
        }
        for (auto& th : threads)
            th.join();
        BOOST_CHECK_EQUAL(wrong.load(), 0);
        for (const CBlock& b : bad)
            BOOST_CHECK(!GetEquihashMemo().Contains(b.GetHash()));
    }
}

BOOST_AUTO_TEST_CASE(differential_mode_returns_reference_verdict)
{
    EquihashSettingsGuard guard;
    const CBlock genesis = Params().GenesisBlock();
    SetEquihashDifferential(true);
    const uint64_t before = GetEquihashVerifierStats().nDisagreements;
    BOOST_CHECK(CheckEquihashSolution(&genesis, Params()));
    for (Mutation m : ALL_MUTATIONS) {
        CBlock bad = Mutate(genesis, m);
        BOOST_CHECK(!CheckEquihashSolution(&bad, Params()));
    }
    BOOST_CHECK_EQUAL(GetEquihashVerifierStats().nDisagreements, before);
}

BOOST_AUTO_TEST_SUITE_END()
