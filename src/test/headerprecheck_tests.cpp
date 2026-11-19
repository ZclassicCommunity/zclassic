// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Parallel Equihash pre-pass for "headers" messages (headerprecheck.h). It may
// only warm the positive-only memo; every reject stays a fresh evaluation.

#include "arith_uint256.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "crypto/equihash.h"
#include "equihashmemo.h"
#include "headerprecheck.h"
#include "main.h"
#include "pow.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "util.h"

#include <functional>
#include <set>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

struct PrecheckSettingsGuard {
    bool memo;
    PrecheckSettingsGuard() : memo(GetEquihashMemoEnabled())
    {
        SetEquihashMemoEnabled(true);
        GetEquihashMemo().Clear();
        mapArgs.erase("-headerprecheck");
    }
    ~PrecheckSettingsGuard()
    {
        SetEquihashMemoEnabled(memo);
        GetEquihashMemo().Clear();
        mapArgs.erase("-headerprecheck");
    }
};

/** Find an Equihash (48,5) solution for header (the regtest parameter set;
 *  CheckEquihashSolution derives (n,k) from the solution size, so these
 *  headers verify under any network's parameters and are cheap to mine). */
void SolveHeader(CBlockHeader& header)
{
    const unsigned int n = 48, k = 5;
    eh_HashState eh_state;
    EhInitialiseState(n, k, eh_state);
    CEquihashInput I{header};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    crypto_generichash_blake2b_update(&eh_state, (unsigned char*)&ss[0], ss.size());
    for (;;) {
        header.nNonce = ArithToUint256(UintToArith256(header.nNonce) + 1);
        eh_HashState curr_state = eh_state;
        crypto_generichash_blake2b_update(&curr_state, header.nNonce.begin(), header.nNonce.size());
        std::function<bool(std::vector<unsigned char>)> validBlock =
            [&header](std::vector<unsigned char> soln) {
                header.nSolution = soln;
                return true;
            };
        if (EhBasicSolveUncancellable(n, k, curr_state, validBlock))
            return;
    }
}

/** A continuous chain of nCount headers on top of prev. Headers at the
 *  indices in bad get one flipped solution byte after solving (so their
 *  successors are mined on top of the mutated hash and stay continuous). */
std::vector<CBlockHeader> MineChain(const uint256& prev, size_t nCount, const std::set<size_t>& bad = {})
{
    std::vector<CBlockHeader> v;
    uint256 hashPrev = prev;
    for (size_t i = 0; i < nCount; i++) {
        CBlockHeader h;
        h.nVersion = 4;
        h.hashPrevBlock = hashPrev;
        h.hashMerkleRoot = GetRandHash();
        h.nTime = 1600000000 + i * 150;
        h.nBits = 0x200f0f0f;
        SolveHeader(h);
        BOOST_REQUIRE(CheckEquihashSolution(&h, Params()));
        if (bad.count(i)) {
            h.nSolution[h.nSolution.size() / 2] ^= 0x10;
            BOOST_REQUIRE(!CheckEquihashSolution(&h, Params()));
        }
        hashPrev = h.GetHash();
        v.push_back(h);
    }
    return v;
}

const std::vector<CBlockHeader>& ValidChain()
{
    static std::vector<CBlockHeader> chain;
    if (chain.empty())
        chain = MineChain(Params().GenesisBlock().GetHash(), 40);
    return chain;
}

size_t CountMemoised(const std::vector<CBlockHeader>& v, size_t nBegin, size_t nEnd)
{
    size_t n = 0;
    for (size_t i = nBegin; i < nEnd; i++)
        n += GetEquihashMemo().Contains(v[i].GetHash()) ? 1 : 0;
    return n;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(headerprecheck_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(prepass_memoises_every_valid_header)
{
    PrecheckSettingsGuard guard;
    const std::vector<CBlockHeader>& chain = ValidChain();
    BOOST_REQUIRE_EQUAL(chain.size(), 40U);
    BOOST_REQUIRE(mapBlockIndex.count(Params().GenesisBlock().GetHash()));

    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(chain), 40U);
    BOOST_CHECK_EQUAL(CountMemoised(chain, 0, 40), 40U);

    // The serial pass is now answered entirely by the memo.
    const EquihashVerifierStats before = GetEquihashVerifierStats();
    for (const CBlockHeader& h : chain)
        BOOST_CHECK(CheckEquihashSolutionMemo(&h, Params()));
    const EquihashVerifierStats after = GetEquihashVerifierStats();
    BOOST_CHECK_EQUAL(after.nMemoHits - before.nMemoHits, 40U);
    BOOST_CHECK_EQUAL(after.nVerifications - before.nVerifications, 0U);
}

BOOST_AUTO_TEST_CASE(invalid_solutions_are_not_memoised)
{
    PrecheckSettingsGuard guard;
    const std::set<size_t> bad = {10, 20, 30};
    const std::vector<CBlockHeader> chain = MineChain(Params().GenesisBlock().GetHash(), 40, bad);

    const size_t nVerified = PreverifyHeadersEquihash(chain);
    // Every header before the first bad one was claimed before it, so it was
    // verified and memoised; workers stop soon after the first failure.
    // (How many more depends on scheduling: a worker can finish several
    // headers while another is still on the bad one.)
    BOOST_TEST_MESSAGE("pre-pass verified " << nVerified << " of 40 with bad headers at 10, 20, 30");
    BOOST_CHECK(nVerified >= 11);
    BOOST_CHECK(nVerified < 40);
    BOOST_CHECK_EQUAL(CountMemoised(chain, 0, 10), 10U);
    for (size_t i : bad)
        BOOST_CHECK(!GetEquihashMemo().Contains(chain[i].GetHash()));

    // The serial path still rejects them exactly as before.
    for (size_t i : bad) {
        CValidationState state;
        BOOST_CHECK(!CheckBlockHeader(chain[i], state));
        int nDoS = 0;
        BOOST_CHECK(state.IsInvalid(nDoS));
        BOOST_CHECK_EQUAL(nDoS, 100);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "invalid-solution");
        BOOST_CHECK(!GetEquihashMemo().Contains(chain[i].GetHash()));
    }
}

BOOST_AUTO_TEST_CASE(stops_at_continuity_break)
{
    PrecheckSettingsGuard guard;
    const std::vector<CBlockHeader>& chain = ValidChain();
    // Drop header 20: header 21 no longer connects to header 19.
    std::vector<CBlockHeader> v(chain.begin(), chain.begin() + 20);
    v.insert(v.end(), chain.begin() + 21, chain.end());
    BOOST_REQUIRE_EQUAL(v.size(), 39U);

    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(v), 20U);
    BOOST_CHECK_EQUAL(CountMemoised(v, 0, 20), 20U);
    BOOST_CHECK_EQUAL(CountMemoised(v, 20, 39), 0U);
}

BOOST_AUTO_TEST_CASE(skips_known_and_unconnected)
{
    PrecheckSettingsGuard guard;
    const std::vector<CBlockHeader>& chain = ValidChain();

    // A leading header already in mapBlockIndex (genesis) is skipped.
    std::vector<CBlockHeader> withGenesis;
    withGenesis.push_back(Params().GenesisBlock().GetBlockHeader());
    withGenesis.insert(withGenesis.end(), chain.begin(), chain.end());
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(withGenesis), 40U);
    GetEquihashMemo().Clear();

    // Headers whose first parent is unknown would be rejected by the serial
    // loop after one verification: the pre-pass does nothing.
    std::vector<CBlockHeader> orphan(chain.begin() + 1, chain.end());
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(orphan), 0U);
    BOOST_CHECK_EQUAL(CountMemoised(orphan, 0, orphan.size()), 0U);

    // All headers known: nothing to do.
    std::vector<CBlockHeader> onlyGenesis(MIN_HEADER_PRECHECK_CANDIDATES, Params().GenesisBlock().GetBlockHeader());
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(onlyGenesis), 0U);
}

BOOST_AUTO_TEST_CASE(small_or_disabled_is_noop)
{
    PrecheckSettingsGuard guard;
    const std::vector<CBlockHeader>& chain = ValidChain();

    std::vector<CBlockHeader> seven(chain.begin(), chain.begin() + 7);
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(seven), 0U);
    BOOST_CHECK_EQUAL(CountMemoised(seven, 0, 7), 0U);

    std::vector<CBlockHeader> eight(chain.begin(), chain.begin() + 8);
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(eight), 8U);
    GetEquihashMemo().Clear();

    mapArgs["-headerprecheck"] = "0";
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(chain), 0U);
    BOOST_CHECK_EQUAL(CountMemoised(chain, 0, chain.size()), 0U);
    mapArgs.erase("-headerprecheck");

    SetEquihashMemoEnabled(false);
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(chain), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
