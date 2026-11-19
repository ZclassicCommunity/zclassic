// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Parallel Equihash pre-pass for "headers" messages (headerprecheck.h). It may
// only warm the positive-only memo; every reject stays a fresh evaluation.
//
// The suite runs on a regtest block index (genesis only) with the regtest PoW
// limit relaxed to 7fff..., so headers that pass every AcceptBlockHeader check
// are cheap to mine: the (48,5) solution is the regtest one, and about one
// solved nonce in two meets the target.

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
#include "tinyformat.h"
#include "util.h"

#include <functional>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <utility>
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

const uint256 RELAXED_POW_LIMIT = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

/** Empty the block index and put the regtest genesis header back as its only entry. */
CBlockIndex* ResetRegtestIndex()
{
    UnloadBlockIndex();
    LOCK(cs_main);
    CValidationState state;
    CBlockIndex* pindex = NULL;
    BOOST_REQUIRE(AcceptBlockHeader(Params().GenesisBlock().GetBlockHeader(), state, &pindex));
    BOOST_REQUIRE(pindex != NULL);
    chainActive.SetTip(pindex);
    return pindex;
}

/** Regtest parameters with a relaxed PoW limit and a block index holding only
 *  the regtest genesis, for the life of one test case. */
struct RegtestHeaderIndex {
    uint256 savedPowLimit;
    RegtestHeaderIndex() : savedPowLimit(Params(CBaseChainParams::REGTEST).GetConsensus().powLimit)
    {
        SelectParams(CBaseChainParams::REGTEST);
        UpdateRegtestPow(0, 0, RELAXED_POW_LIMIT);
        ResetRegtestIndex();
    }
    ~RegtestHeaderIndex()
    {
        UnloadBlockIndex();
        UpdateRegtestPow(0, 0, savedPowLimit);
        SelectParams(CBaseChainParams::MAIN);
    }
};

struct HeaderPrecheckSetup : public TestingSetup {
    RegtestHeaderIndex regtest;
    PrecheckSettingsGuard settings;
};

/** Find the next nonce with an Equihash (48,5) solution for header.
 *  CheckEquihashSolution derives (n,k) from the solution size. */
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

bool MeetsTarget(const CBlockHeader& h)
{
    return CheckProofOfWork(h.GetHash(), h.nBits, Params().GetConsensus());
}

/** How a mined header is spoiled (its successors are mined on top of the
 *  spoiled hash, so the chain stays continuous). */
enum Spoil {
    SPOIL_NONE,
    SPOIL_SOLUTION, // one solution byte flipped: Equihash fails, PoW passes
    SPOIL_POW,      // a valid solution whose hash misses the target
    SPOIL_VERSION,  // nVersion 3, valid solution and PoW
    SPOIL_JUNK      // a (48,5)-sized solution of junk bytes, PoW passes
};

CBlockHeader MineHeader(const uint256& prev, size_t i, Spoil spoil)
{
    CBlockHeader h;
    h.nVersion = spoil == SPOIL_VERSION ? 3 : 4;
    h.hashPrevBlock = prev;
    h.hashMerkleRoot = GetRandHash();
    // 2000 s apart: past 12 target spacings, so GetNextWorkRequired gives the
    // limit at every height (the upgrade-window and min-difficulty rules)
    h.nTime = 1600000000 + i * 2000;
    h.nBits = UintToArith256(Params().GetConsensus().powLimit).GetCompact();
    for (;;) {
        SolveHeader(h);
        BOOST_REQUIRE(CheckEquihashSolution(&h, Params()));
        CBlockHeader out = h;
        if (spoil == SPOIL_SOLUTION)
            out.nSolution[out.nSolution.size() / 2] ^= 0x10;
        if (spoil == SPOIL_JUNK)
            for (size_t j = 0; j < out.nSolution.size(); j++)
                out.nSolution[j] = (unsigned char)(j * 37 + 11);
        if (MeetsTarget(out) == (spoil == SPOIL_POW))
            continue;
        if (spoil == SPOIL_SOLUTION || spoil == SPOIL_JUNK)
            BOOST_REQUIRE(!CheckEquihashSolution(&out, Params()));
        return out;
    }
}

/** A continuous chain of nCount headers on top of prev, spoiled where spoils says. */
std::vector<CBlockHeader> MineChain(const uint256& prev, size_t nCount, const std::map<size_t, Spoil>& spoils = {})
{
    std::vector<CBlockHeader> v;
    uint256 hashPrev = prev;
    for (size_t i = 0; i < nCount; i++) {
        std::map<size_t, Spoil>::const_iterator it = spoils.find(i);
        v.push_back(MineHeader(hashPrev, i, it == spoils.end() ? SPOIL_NONE : it->second));
        hashPrev = v.back().GetHash();
    }
    return v;
}

std::map<size_t, Spoil> SpoilAt(const std::set<size_t>& at, Spoil spoil)
{
    std::map<size_t, Spoil> m;
    for (size_t i : at)
        m[i] = spoil;
    return m;
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

/** Everything a "headers" message leaves behind that the pre-pass must not change. */
struct HeadersOutcome {
    std::vector<std::string> steps;                            // one per header the loop handled
    int nMisbehavior = 0;                                      // what Misbehaving() would add
    std::map<uint256, std::pair<int, unsigned int> > index;    // hash -> (height, nStatus)
    uint256 bestHeader;
    size_t nPreverified = 0;
};

/** Reset the index, let seed add known headers, then handle headers as
 *  ProcessMessage("headers") in main.cpp does: the pre-pass, then the serial
 *  AcceptBlockHeader loop with its continuity check and DoS scoring. */
HeadersOutcome RunHeadersMessage(const std::vector<CBlockHeader>& headers, bool fPrecheck,
                                 const std::function<void()>& seed)
{
    ResetRegtestIndex();
    seed();
    GetEquihashMemo().Clear();
    mapArgs["-headerprecheck"] = fPrecheck ? "1" : "0";
    HeadersOutcome out;
    out.nPreverified = PreverifyHeadersEquihash(headers);
    mapArgs.erase("-headerprecheck");

    LOCK(cs_main);
    CBlockIndex* pindexLast = NULL;
    for (const CBlockHeader& header : headers) {
        if (pindexLast != NULL && header.hashPrevBlock != pindexLast->GetBlockHash()) {
            out.steps.push_back("non-continuous");
            out.nMisbehavior += 20;
            break;
        }
        CValidationState state;
        if (AcceptBlockHeader(header, state, &pindexLast)) {
            out.steps.push_back("accept");
            continue;
        }
        int nDoS = 0;
        if (state.IsInvalid(nDoS)) {
            out.steps.push_back(strprintf("reject %s %d", state.GetRejectReason(), nDoS));
            out.nMisbehavior += nDoS > 0 ? nDoS : 0;
            break;
        }
        out.steps.push_back("error " + state.GetRejectReason());
    }
    for (const BlockMap::value_type& entry : mapBlockIndex)
        out.index[entry.first] = std::make_pair(entry.second->nHeight, (unsigned int)entry.second->nStatus);
    if (pindexBestHeader)
        out.bestHeader = pindexBestHeader->GetBlockHash();
    return out;
}

void SeedNothing() {}

/** Run headers with the pre-pass off and on and require identical results. */
HeadersOutcome CheckSameWithAndWithout(const std::string& name, const std::vector<CBlockHeader>& headers,
                                       const std::function<void()>& seed = SeedNothing)
{
    const HeadersOutcome off = RunHeadersMessage(headers, false, seed);
    const HeadersOutcome on = RunHeadersMessage(headers, true, seed);
    BOOST_TEST_MESSAGE(name << ": " << off.steps.size() << " headers handled, last \""
                            << (off.steps.empty() ? std::string() : off.steps.back()) << "\", pre-pass verified "
                            << on.nPreverified);
    BOOST_CHECK_EQUAL(off.nPreverified, 0U);
    BOOST_CHECK_MESSAGE(off.steps == on.steps, name << ": per-header results differ");
    BOOST_CHECK_EQUAL(off.nMisbehavior, on.nMisbehavior);
    BOOST_CHECK_MESSAGE(off.index == on.index, name << ": final block index differs");
    BOOST_CHECK(off.bestHeader == on.bestHeader);
    return on;
}

bool MultiCore()
{
    if (std::thread::hardware_concurrency() > 1)
        return true;
    BOOST_TEST_MESSAGE("single core: the pre-pass never runs, count expectations skipped");
    return false;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(headerprecheck_tests, HeaderPrecheckSetup)

BOOST_AUTO_TEST_CASE(prepass_memoises_every_valid_header)
{
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
    const std::set<size_t> bad = {10, 20, 30};
    const std::vector<CBlockHeader> chain = MineChain(Params().GenesisBlock().GetHash(), 40, SpoilAt(bad, SPOIL_SOLUTION));

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

    // The first new header's parent is known but marked failed: nothing to do.
    {
        LOCK(cs_main);
        CValidationState state;
        CBlockIndex* pindex = NULL;
        BOOST_REQUIRE(AcceptBlockHeader(chain[0], state, &pindex));
        pindex->nStatus |= BLOCK_FAILED_VALID;
    }
    std::vector<CBlockHeader> afterFailed(chain.begin() + 1, chain.end());
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(afterFailed), 0U);
}

BOOST_AUTO_TEST_CASE(small_or_disabled_is_noop)
{
    const std::vector<CBlockHeader>& chain = ValidChain();

    std::vector<CBlockHeader> seven(chain.begin(), chain.begin() + 7);
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(seven), 0U);
    BOOST_CHECK_EQUAL(CountMemoised(seven, 0, 7), 0U);

    std::vector<CBlockHeader> eight(chain.begin(), chain.begin() + 8);
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(eight), 8U);
    GetEquihashMemo().Clear();

    // Eight headers of which only seven are new: below the candidate floor.
    std::vector<CBlockHeader> sevenNew;
    sevenNew.push_back(Params().GenesisBlock().GetBlockHeader());
    sevenNew.insert(sevenNew.end(), chain.begin(), chain.begin() + 7);
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(sevenNew), 0U);

    mapArgs["-headerprecheck"] = "0";
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(chain), 0U);
    BOOST_CHECK_EQUAL(CountMemoised(chain, 0, chain.size()), 0U);
    mapArgs.erase("-headerprecheck");

    SetEquihashMemoEnabled(false);
    BOOST_CHECK_EQUAL(PreverifyHeadersEquihash(chain), 0U);
}

// The pre-pass on or off, a "headers" message gives the same per-header
// results, DoS score and final block index.
BOOST_AUTO_TEST_CASE(same_results_with_and_without_prepass)
{
    const std::vector<CBlockHeader>& chain = ValidChain();
    const uint256 genesis = Params().GenesisBlock().GetHash();

    const HeadersOutcome valid = CheckSameWithAndWithout("valid chain", chain);
    BOOST_CHECK_EQUAL(valid.steps.size(), 40U);
    BOOST_CHECK_EQUAL(valid.steps.back(), "accept");
    BOOST_CHECK_EQUAL(valid.nMisbehavior, 0);
    BOOST_CHECK_EQUAL(valid.index.size(), 41U);
    BOOST_CHECK(valid.bestHeader == chain.back().GetHash());

    const std::vector<CBlockHeader> badPow = MineChain(genesis, 16, SpoilAt({10}, SPOIL_POW));
    const HeadersOutcome pow = CheckSameWithAndWithout("bad PoW at 10", badPow);
    BOOST_CHECK_EQUAL(pow.steps.size(), 11U);
    BOOST_CHECK_EQUAL(pow.steps.back(), "reject high-hash 50");
    BOOST_CHECK_EQUAL(pow.index.size(), 11U);

    // chain[0] known but marked failed, chain[1] known and not failed: the
    // serial loop stops at chain[0] with no score.
    std::function<void()> seedFailed = [&chain]() {
        LOCK(cs_main);
        CValidationState state;
        CBlockIndex* p0 = NULL;
        CBlockIndex* p1 = NULL;
        BOOST_REQUIRE(AcceptBlockHeader(chain[0], state, &p0));
        BOOST_REQUIRE(AcceptBlockHeader(chain[1], state, &p1));
        p0->nStatus |= BLOCK_FAILED_VALID;
    };
    const HeadersOutcome failed = CheckSameWithAndWithout("leading known failed header", chain, seedFailed);
    BOOST_CHECK_EQUAL(failed.steps.size(), 1U);
    BOOST_CHECK_EQUAL(failed.steps.back(), "reject duplicate 0");
    BOOST_CHECK_EQUAL(failed.nMisbehavior, 0);
    BOOST_CHECK_EQUAL(failed.index.size(), 3U);

    const std::vector<CBlockHeader> junk = MineChain(genesis, 16, SpoilAt({5}, SPOIL_JUNK));
    const HeadersOutcome junked = CheckSameWithAndWithout("junk (48,5) solution at 5", junk);
    BOOST_CHECK_EQUAL(junked.steps.size(), 6U);
    BOOST_CHECK_EQUAL(junked.steps.back(), "reject invalid-solution 100");

    const std::vector<CBlockHeader> version = MineChain(genesis, 16, SpoilAt({3}, SPOIL_VERSION));
    const HeadersOutcome old = CheckSameWithAndWithout("version 3 at 3", version);
    BOOST_CHECK_EQUAL(old.steps.size(), 4U);
    BOOST_CHECK_EQUAL(old.steps.back(), "reject version-too-low 100");

    // Bad solutions spread through the message, and a non-continuous one.
    const std::vector<CBlockHeader> spread = MineChain(genesis, 24, SpoilAt({12, 18}, SPOIL_SOLUTION));
    CheckSameWithAndWithout("bad solutions at 12 and 18", spread);
    std::vector<CBlockHeader> gap(chain.begin(), chain.begin() + 20);
    gap.insert(gap.end(), chain.begin() + 21, chain.end());
    const HeadersOutcome broken = CheckSameWithAndWithout("continuity break at 20", gap);
    BOOST_CHECK_EQUAL(broken.steps.back(), "non-continuous");
    BOOST_CHECK_EQUAL(broken.nMisbehavior, 20);

    if (MultiCore())
        BOOST_CHECK_EQUAL(valid.nPreverified, 40U);
}

BOOST_AUTO_TEST_SUITE_END()
