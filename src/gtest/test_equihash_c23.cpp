// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Differential tests: zcashd C++ Equihash verifier versus the vendored Z23
// C23 verifier (src/c23/equihash), through the same CheckEquihashSolutionWith
// entry point that block validation uses, on real mainnet headers and on
// mutated solutions, for every batched-BLAKE2b tier the host can run.
//
// Two further tests are DISABLED_ by default and run on demand:
//   ZC23_EQUIHASH_HEADERS=<file> zcash-gtest --gtest_also_run_disabled_tests
//       --gtest_filter=EquihashC23.DISABLED_FullHistoryReplay
//     <file>: one hex-serialized block header per line, height order
//     (getblockheader <hash> false). Optional ZC23_EQUIHASH_THREADS.
//   ZC23_EQUIHASH_BENCH_ITERS=<n> ... --gtest_filter=EquihashC23.DISABLED_Benchmark

#include <gtest/gtest.h>

#include "c23/equihash/zc23_equihash.h"
#include "chainparams.h"
#include "crypto/equihash.h"
#include "pow.h"
#include "primitives/block.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "version.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// Real ZClassic mainnet headers with (192,7) solutions (400 bytes), taken
// from an isolated headers-only node (see the unit report). Heights in the
// comments. Hex is the network serialization (getblockheader <hash> false).
const char* MAINNET_192_7_HEADERS[] = {
#include "gtest/data/equihash_mainnet_192_7.inc"
};

CBlockHeader HeaderFromHex(const std::string& hex)
{
    std::vector<unsigned char> raw = ParseHex(hex);
    CDataStream ss(raw, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader h;
    ss >> h;
    return h;
}

std::vector<CBlockHeader> RealHeaders()
{
    std::vector<CBlockHeader> v;
    CBlockHeader genesis = Params(CBaseChainParams::MAIN).GenesisBlock().GetBlockHeader();
    v.push_back(genesis); // (200,9), height 0
    for (const char* hex : MAINNET_192_7_HEADERS)
        v.push_back(HeaderFromHex(hex));
    return v;
}

unsigned int CollisionBitLength(size_t solSize)
{
    return solSize == 1344 ? 200 / (9 + 1) : 192 / (7 + 1);
}

bool Cpp(const CBlockHeader& h)
{
    return CheckEquihashSolutionWith(&h, Params(), EquihashImpl::CPP);
}

bool C23(const CBlockHeader& h)
{
    return CheckEquihashSolutionWith(&h, Params(), EquihashImpl::C23);
}

// Returns the agreed verdict; records a failure on disagreement.
bool ExpectAgree(const CBlockHeader& h, const std::string& what)
{
    const bool a = Cpp(h);
    const bool b = C23(h);
    EXPECT_EQ(a, b) << what << " hash=" << h.GetHash().GetHex();
    return a;
}

CBlockHeader WithIndices(const CBlockHeader& base, const std::vector<eh_index>& idx)
{
    CBlockHeader h(base);
    h.nSolution = GetMinimalFromIndices(idx, CollisionBitLength(base.nSolution.size()));
    return h;
}

class TierGuard {
public:
    ~TierGuard() { zc23_equihash_select_tier(-1); }
};

std::vector<int> AvailableTiers()
{
    std::vector<int> tiers;
    for (int t = 0; t <= 2; t++) {
        int got = zc23_equihash_select_tier(t);
        if (got == t)
            tiers.push_back(t);
    }
    zc23_equihash_select_tier(-1);
    return tiers;
}

} // namespace

class EquihashC23 : public ::testing::Test {
protected:
    void SetUp() override { SelectParams(CBaseChainParams::MAIN); }
};

TEST_F(EquihashC23, PersonalizationAndParameterSets)
{
    // Both verifiers derive (n,k) from the solution length, and the C23
    // bridge accepts only the four zclassicd parameter sets.
    std::vector<unsigned char> input(140, 0), sol1344(1344, 0), sol400(400, 0);
    EXPECT_EQ(ZC23_EH_INVALID, zc23_equihash_verify(200, 9, input.data(), input.size(), sol1344.data(), sol1344.size()));
    EXPECT_EQ(ZC23_EH_INVALID, zc23_equihash_verify(192, 7, input.data(), input.size(), sol400.data(), sol400.size()));
    // Wrong length for the parameter set.
    EXPECT_EQ(ZC23_EH_INVALID, zc23_equihash_verify(200, 9, input.data(), input.size(), sol400.data(), sol400.size()));
    EXPECT_EQ(ZC23_EH_INVALID, zc23_equihash_verify(192, 7, input.data(), input.size(), sol1344.data(), sol1344.size()));
    // Parameter sets zclassicd never uses.
    EXPECT_EQ(ZC23_EH_UNSUPPORTED, zc23_equihash_verify(96, 3, input.data(), input.size(), sol400.data(), sol400.size()));
    EXPECT_EQ(ZC23_EH_UNSUPPORTED, zc23_equihash_verify(144, 5, input.data(), input.size(), sol400.data(), sol400.size()));
    EXPECT_EQ(ZC23_EH_ERROR, zc23_equihash_verify(200, 9, nullptr, 140, sol1344.data(), sol1344.size()));

    // The C23 verifier with the C++ personalization: the real genesis header
    // verifies through the raw bridge, so "ZcashPoW"||LE32(200)||LE32(9) and
    // the 50-byte digest match crypto/equihash.cpp InitialiseState.
    CBlockHeader g = RealHeaders()[0];
    CEquihashInput I{g};
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << g.nNonce;
    ASSERT_EQ(140U, ss.size());
    EXPECT_EQ(ZC23_EH_VALID, zc23_equihash_verify(200, 9, (const unsigned char*)&ss[0], ss.size(),
                                                  g.nSolution.data(), g.nSolution.size()));
    // Same bytes under the other personalization never verify.
    std::vector<unsigned char> first400(g.nSolution.begin(), g.nSolution.begin() + 400);
    EXPECT_EQ(ZC23_EH_INVALID, zc23_equihash_verify(192, 7, (const unsigned char*)&ss[0], ss.size(),
                                                    first400.data(), first400.size()));
}

TEST_F(EquihashC23, RealMainnetHeadersAllTiers)
{
    TierGuard guard;
    std::vector<CBlockHeader> headers = RealHeaders();
    ASSERT_GE(headers.size(), 2U);
    size_t n200 = 0, n192 = 0;
    for (const CBlockHeader& h : headers) {
        if (h.nSolution.size() == 1344) n200++;
        if (h.nSolution.size() == 400) n192++;
    }
    EXPECT_GE(n200, 1U);
    EXPECT_GE(n192, 1U);
    for (int tier : AvailableTiers()) {
        ASSERT_EQ(tier, zc23_equihash_select_tier(tier));
        for (const CBlockHeader& h : headers) {
            EXPECT_TRUE(Cpp(h)) << h.GetHash().GetHex();
            EXPECT_TRUE(C23(h)) << "tier " << zc23_equihash_tier_name() << " " << h.GetHash().GetHex();
        }
    }
}

TEST_F(EquihashC23, EverySolutionBitFlip)
{
    // Exhaustive single-bit flips of the solution of one header per
    // parameter set, on the default tier and on scalar.
    TierGuard guard;
    std::vector<CBlockHeader> headers = RealHeaders();
    const CBlockHeader* pick[2] = {&headers[0], &headers[1]};
    for (int tier : {-1, 0}) {
        zc23_equihash_select_tier(tier);
        for (const CBlockHeader* base : pick) {
            size_t accepted = 0;
            for (size_t bit = 0; bit < base->nSolution.size() * 8; bit++) {
                CBlockHeader h(*base);
                h.nSolution[bit / 8] ^= (unsigned char)(1u << (bit % 8));
                if (ExpectAgree(h, "solution bit " + std::to_string(bit)))
                    accepted++;
            }
            EXPECT_EQ(0U, accepted);
        }
    }
}

TEST_F(EquihashC23, HeaderFieldMutations)
{
    for (const CBlockHeader& base : RealHeaders()) {
        // Every bit of the 140 committed header bytes, via the fields.
        for (int bit = 0; bit < 32 * 8; bit++) {
            CBlockHeader h(base);
            h.nNonce.begin()[bit / 8] ^= (unsigned char)(1u << (bit % 8));
            EXPECT_FALSE(ExpectAgree(h, "nonce bit"));
            CBlockHeader p(base);
            p.hashPrevBlock.begin()[bit / 8] ^= (unsigned char)(1u << (bit % 8));
            EXPECT_FALSE(ExpectAgree(p, "prev bit"));
            CBlockHeader m(base);
            m.hashMerkleRoot.begin()[bit / 8] ^= (unsigned char)(1u << (bit % 8));
            EXPECT_FALSE(ExpectAgree(m, "merkle bit"));
            CBlockHeader s(base);
            s.hashFinalSaplingRoot.begin()[bit / 8] ^= (unsigned char)(1u << (bit % 8));
            EXPECT_FALSE(ExpectAgree(s, "sapling root bit"));
        }
        for (int bit = 0; bit < 32; bit++) {
            CBlockHeader v(base); v.nVersion ^= (1 << bit);
            EXPECT_FALSE(ExpectAgree(v, "version bit"));
            CBlockHeader t(base); t.nTime ^= (1u << bit);
            EXPECT_FALSE(ExpectAgree(t, "time bit"));
            CBlockHeader b(base); b.nBits ^= (1u << bit);
            EXPECT_FALSE(ExpectAgree(b, "bits bit"));
        }
    }
}

TEST_F(EquihashC23, IndexLevelMutations)
{
    for (const CBlockHeader& base : RealHeaders()) {
        const size_t cbl = CollisionBitLength(base.nSolution.size());
        const std::vector<eh_index> idx = GetIndicesFromMinimal(base.nSolution, cbl);
        const size_t n = idx.size();
        ASSERT_TRUE(n == 512 || n == 128);
        // Round trip is exact.
        ASSERT_TRUE(WithIndices(base, idx).nSolution == base.nSolution);
        EXPECT_TRUE(ExpectAgree(WithIndices(base, idx), "round trip"));

        // Swap the two halves of every subtree at every level (breaks the
        // canonical ordering), and swap single adjacent leaves.
        for (size_t width = 1; width < n; width *= 2) {
            for (size_t start = 0; start + 2 * width <= n; start += 2 * width) {
                std::vector<eh_index> m(idx);
                std::swap_ranges(m.begin() + start, m.begin() + start + width, m.begin() + start + width);
                EXPECT_FALSE(ExpectAgree(WithIndices(base, m), "subtree swap w=" + std::to_string(width)));
            }
        }
        // Duplicate indices: copy one leaf over another at several distances.
        for (size_t i = 0; i < n; i += 7) {
            for (size_t d : {(size_t)1, (size_t)2, (size_t)5, n / 2, n - 1}) {
                std::vector<eh_index> m(idx);
                m[(i + d) % n] = m[i];
                if (m == idx) continue;
                EXPECT_FALSE(ExpectAgree(WithIndices(base, m), "duplicate"));
            }
        }
        // Whole-solution reorderings.
        {
            std::vector<eh_index> m(idx);
            std::sort(m.begin(), m.end());
            EXPECT_FALSE(ExpectAgree(WithIndices(base, m), "sorted"));
            std::reverse(m.begin(), m.end());
            EXPECT_FALSE(ExpectAgree(WithIndices(base, m), "reverse sorted"));
            std::vector<eh_index> r(idx);
            std::reverse(r.begin(), r.end());
            EXPECT_FALSE(ExpectAgree(WithIndices(base, r), "reversed"));
            std::vector<eh_index> rot(idx);
            std::rotate(rot.begin(), rot.begin() + 1, rot.end());
            EXPECT_FALSE(ExpectAgree(WithIndices(base, rot), "rotated"));
        }
        // Extreme and off-by-one index values.
        const eh_index maxIdx = (eh_index)((1u << (cbl + 1)) - 1);
        for (size_t i = 0; i < n; i += 13) {
            for (eh_index v : {(eh_index)0, maxIdx, (eh_index)(idx[i] + 1), (eh_index)(idx[i] - 1), (eh_index)(idx[i] ^ 1)}) {
                std::vector<eh_index> m(idx);
                m[i] = v & maxIdx;
                if (m == idx) continue;
                EXPECT_FALSE(ExpectAgree(WithIndices(base, m), "index value"));
            }
        }
        // All-zero and all-equal solutions.
        EXPECT_FALSE(ExpectAgree(WithIndices(base, std::vector<eh_index>(n, 0)), "all zero"));
        EXPECT_FALSE(ExpectAgree(WithIndices(base, std::vector<eh_index>(n, idx[0])), "all equal"));
    }
}

TEST_F(EquihashC23, WrongLengthsAndRandomSolutions)
{
    std::vector<CBlockHeader> headers = RealHeaders();
    for (const CBlockHeader& base : headers) {
        for (size_t len : {(size_t)0, (size_t)1, (size_t)35, (size_t)36, (size_t)37, (size_t)67, (size_t)68,
                           (size_t)399, (size_t)400, (size_t)401, (size_t)1343, (size_t)1344, (size_t)1345, (size_t)2688}) {
            CBlockHeader h(base);
            std::vector<unsigned char> sol(base.nSolution);
            sol.resize(len, 0);
            h.nSolution = sol;
            if (h.nSolution == base.nSolution) continue;
            EXPECT_FALSE(ExpectAgree(h, "length " + std::to_string(len)));
        }
    }
    // Pseudo-random solutions (deterministic LCG).
    uint64_t s = 0x2545F4914F6CDD1DULL;
    for (int i = 0; i < 200; i++) {
        for (const CBlockHeader& base : headers) {
            CBlockHeader h(base);
            for (unsigned char& c : h.nSolution) {
                s = s * 6364136223846793005ULL + 1442695040888963407ULL;
                c = (unsigned char)(s >> 56);
            }
            EXPECT_FALSE(ExpectAgree(h, "random"));
        }
    }
}

TEST_F(EquihashC23, ConcurrentVerification)
{
    std::vector<CBlockHeader> headers = RealHeaders();
    std::atomic<int> wrong{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; t++) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < 20; i++) {
                const CBlockHeader& h = headers[(t + i) % headers.size()];
                if (!C23(h)) wrong++;
                CBlockHeader bad(h);
                bad.nSolution[(t * 31 + i) % bad.nSolution.size()] ^= 0x40;
                if (C23(bad)) wrong++;
            }
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(0, wrong.load());
}

TEST_F(EquihashC23, DISABLED_FullHistoryReplay)
{
    const char* path = getenv("ZC23_EQUIHASH_HEADERS");
    ASSERT_TRUE(path != nullptr) << "set ZC23_EQUIHASH_HEADERS";
    std::ifstream in(path);
    ASSERT_TRUE(in.good()) << path;
    std::vector<std::string> lines;
    for (std::string line; std::getline(in, line);)
        if (!line.empty()) lines.push_back(line);
    ASSERT_FALSE(lines.empty());

    unsigned nThreads = 4;
    if (const char* t = getenv("ZC23_EQUIHASH_THREADS")) nThreads = std::max(1, atoi(t));

    std::atomic<uint64_t> n200{0}, n192{0}, nOther{0}, cppValid{0}, c23Valid{0};
    std::atomic<uint64_t> disagreeReal{0}, disagreeMut{0}, mutAccepted{0}, linkBreaks{0};
    std::atomic<size_t> next{0};
    std::mutex logMutex;
    auto worker = [&]() {
        for (;;) {
            size_t i = next.fetch_add(1);
            if (i >= lines.size()) return;
            CBlockHeader h = HeaderFromHex(lines[i]);
            if (i > 0) {
                CBlockHeader prev = HeaderFromHex(lines[i - 1]);
                if (h.hashPrevBlock != prev.GetHash()) linkBreaks++;
            }
            if (h.nSolution.size() == 1344) n200++; else if (h.nSolution.size() == 400) n192++; else nOther++;
            const bool a = Cpp(h), b = C23(h);
            if (a) cppValid++;
            if (b) c23Valid++;
            if (a != b) {
                disagreeReal++;
                std::lock_guard<std::mutex> l(logMutex);
                fprintf(stderr, "DISAGREE real height=%zu hash=%s cpp=%d c23=%d\n", i, h.GetHash().GetHex().c_str(), a, b);
            }
            // One deterministic single-bit mutation per header.
            CBlockHeader m(h);
            size_t bit = (i * 2654435761u) % (m.nSolution.size() * 8);
            m.nSolution[bit / 8] ^= (unsigned char)(1u << (bit % 8));
            const bool ma = Cpp(m), mb = C23(m);
            if (ma) mutAccepted++;
            if (ma != mb) {
                disagreeMut++;
                std::lock_guard<std::mutex> l(logMutex);
                fprintf(stderr, "DISAGREE mutated height=%zu bit=%zu cpp=%d c23=%d\n", i, bit, ma, mb);
            }
            if (i % 250000 == 0) {
                std::lock_guard<std::mutex> l(logMutex);
                fprintf(stderr, "replay: %zu / %zu\n", i, lines.size());
            }
        }
    };
    auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> threads;
    for (unsigned t = 0; t < nThreads; t++) threads.emplace_back(worker);
    for (auto& th : threads) th.join();
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    printf("FullHistoryReplay: headers=%zu (200,9)=%llu (192,7)=%llu other=%llu cpp_valid=%llu c23_valid=%llu "
           "disagree_real=%llu mutated=%zu mutated_accepted=%llu disagree_mutated=%llu link_breaks=%llu threads=%u secs=%.1f\n",
           lines.size(), (unsigned long long)n200, (unsigned long long)n192, (unsigned long long)nOther,
           (unsigned long long)cppValid, (unsigned long long)c23Valid, (unsigned long long)disagreeReal,
           lines.size(), (unsigned long long)mutAccepted, (unsigned long long)disagreeMut,
           (unsigned long long)linkBreaks, nThreads, secs);
    EXPECT_EQ(0U, disagreeReal.load());
    EXPECT_EQ(0U, disagreeMut.load());
    EXPECT_EQ(lines.size(), cppValid.load());
    EXPECT_EQ(0U, mutAccepted.load());
    EXPECT_EQ(0U, linkBreaks.load());
}

namespace {
double MedianNs(std::vector<double> v)
{
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}
double PctNs(std::vector<double> v, double p)
{
    std::sort(v.begin(), v.end());
    return v[std::min(v.size() - 1, (size_t)(p * v.size()))];
}
std::string LoadAvg()
{
    std::ifstream f("/proc/loadavg");
    std::string s;
    std::getline(f, s);
    return s;
}
} // namespace

TEST_F(EquihashC23, DISABLED_Benchmark)
{
    TierGuard guard;
    int iters = 200;
    if (const char* e = getenv("ZC23_EQUIHASH_BENCH_ITERS")) iters = std::max(5, atoi(e));
    std::vector<CBlockHeader> headers = RealHeaders();
    printf("Benchmark: iters=%d loadavg_start=\"%s\"\n", iters, LoadAvg().c_str());
    for (const CBlockHeader* h : {&headers[0], &headers[1]}) {
        const char* ps = h->nSolution.size() == 1344 ? "(200,9)" : "(192,7)";
        auto run = [&](const char* name, std::function<bool()> f) {
            std::vector<double> ns;
            for (int w = 0; w < 5; w++) ASSERT_TRUE(f());
            for (int i = 0; i < iters; i++) {
                auto t0 = std::chrono::steady_clock::now();
                bool ok = f();
                auto t1 = std::chrono::steady_clock::now();
                ASSERT_TRUE(ok);
                ns.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count());
            }
            printf("Benchmark %s %-22s median_us=%9.1f p10_us=%9.1f p90_us=%9.1f\n", ps, name,
                   MedianNs(ns) / 1000.0, PctNs(ns, 0.10) / 1000.0, PctNs(ns, 0.90) / 1000.0);
        };
        run("cpp", [&]() { return Cpp(*h); });
        for (int tier : AvailableTiers()) {
            zc23_equihash_select_tier(tier);
            std::string name = std::string("c23 ") + zc23_equihash_tier_name();
            run(name.c_str(), [&]() { return C23(*h); });
        }
        zc23_equihash_select_tier(-1);
    }
    printf("Benchmark: loadavg_end=\"%s\"\n", LoadAvg().c_str());
}
