// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Block-index entries loaded from the block tree keep their Equihash solution on
// disk (fSolutionOnDisk): headers built from them read it back, a rewrite of a
// dirty entry keeps the stored bytes, and a missing record is a loud failure.

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "pow.h"
#include "txdb.h"
#include "test/test_bitcoin.h"

#include <deque>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

std::vector<unsigned char> MakeSolution(size_t size, uint32_t seed)
{
    std::vector<unsigned char> sol(size);
    for (size_t i = 0; i < size; i++)
        sol[i] = (unsigned char)((seed * 131u + i * 7u + (i >> 8)) & 0xff);
    return sol;
}

CBlockHeader MakeHeader(const uint256& prev, uint32_t n, size_t solSize, bool fMine)
{
    CBlockHeader h;
    h.nVersion = 4;
    h.hashPrevBlock = prev;
    h.hashMerkleRoot = ArithToUint256(arith_uint256(n + 1));
    h.nTime = 1600000000 + n;
    h.nBits = UintToArith256(Params().GetConsensus().powLimit).GetCompact();
    h.nSolution = MakeSolution(solSize, n);
    for (uint64_t nonce = 0; fMine; nonce++) {
        h.nNonce = ArithToUint256(arith_uint256(nonce));
        if (CheckProofOfWork(h.GetHash(), h.nBits, Params().GetConsensus()))
            break;
    }
    return h;
}

// Owns block-index entries built from headers (phashBlock needs stable storage).
struct Entries {
    std::deque<uint256> hashes;
    std::vector<std::unique_ptr<CBlockIndex> > owned;
    std::vector<std::vector<unsigned char> > solutions;

    CBlockIndex* Add(const CBlockHeader& h, CBlockIndex* pprev)
    {
        hashes.push_back(h.GetHash());
        owned.emplace_back(new CBlockIndex(h));
        CBlockIndex* p = owned.back().get();
        p->phashBlock = &hashes.back();
        p->pprev = pprev;
        p->nHeight = pprev ? pprev->nHeight + 1 : 1;
        p->nStatus = BLOCK_VALID_TREE;
        solutions.push_back(h.nSolution);
        return p;
    }

    std::vector<const CBlockIndex*> All() const
    {
        std::vector<const CBlockIndex*> v;
        for (const auto& p : owned)
            v.push_back(p.get());
        return v;
    }
};

bool WriteEntries(const std::vector<const CBlockIndex*>& v)
{
    int nLastFile = 0;
    pblocktree->ReadLastBlockFile(nLastFile);
    return pblocktree->WriteBatchSync(std::vector<std::pair<int, const CBlockFileInfo*> >(), nLastFile, v);
}

CBlockIndex* Loaded(const uint256& hash)
{
    BlockMap::iterator it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? NULL : it->second;
}

struct RegtestSetup : public TestingSetup {
    RegtestSetup()
    {
        SelectParams(CBaseChainParams::REGTEST);
        ClearBlockIndexSolutionCacheForTest();
    }
    ~RegtestSetup()
    {
        ClearBlockIndexSolutionCacheForTest();
        SelectParams(CBaseChainParams::MAIN);
    }
};

// Writes a 50-entry chain (1344 and 400 byte solutions) and loads it back.
void WriteAndLoadChain(Entries& chain)
{
    CBlockIndex* prev = NULL;
    for (uint32_t i = 0; i < 50; i++) {
        CBlockHeader h = MakeHeader(prev ? prev->GetBlockHash() : uint256(), i, i % 2 ? 400 : 1344, true);
        prev = chain.Add(h, prev);
    }
    BOOST_REQUIRE(WriteEntries(chain.All()));
    BOOST_REQUIRE(pblocktree->LoadBlockIndexGuts());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(blockindex_solution_tests, RegtestSetup)

BOOST_AUTO_TEST_CASE(loaded_entries_keep_solutions_on_disk)
{
    Entries chain;
    WriteAndLoadChain(chain);
    for (size_t i = 0; i < chain.hashes.size(); i++) {
        CBlockIndex* p = Loaded(chain.hashes[i]);
        BOOST_REQUIRE(p != NULL);
        BOOST_CHECK(p->nSolution.empty());
        BOOST_CHECK(p->fSolutionOnDisk);
        CBlockHeader h = p->GetBlockHeader();
        BOOST_CHECK(h.GetHash() == p->GetBlockHash());
        BOOST_CHECK(h.nSolution == chain.solutions[i]);
    }
    // Entries built in memory keep their own solution.
    BOOST_CHECK(!chain.owned[0]->fSolutionOnDisk);
    BOOST_CHECK(chain.owned[0]->nSolution == chain.solutions[0]);
}

BOOST_AUTO_TEST_CASE(dirty_rewrite_keeps_stored_solution)
{
    Entries chain;
    WriteAndLoadChain(chain);
    CBlockIndex* p = Loaded(chain.hashes[7]);
    BOOST_REQUIRE(p != NULL && p->fSolutionOnDisk);
    p->nStatus = BLOCK_VALID_TREE | BLOCK_FAILED_VALID;
    BOOST_REQUIRE(WriteEntries(std::vector<const CBlockIndex*>(1, p)));

    CDiskBlockIndex disk;
    BOOST_REQUIRE(pblocktree->ReadDiskBlockIndex(chain.hashes[7], disk));
    BOOST_CHECK(disk.nSolution == chain.solutions[7]);
    BOOST_CHECK_EQUAL((unsigned int)disk.nStatus, (unsigned int)(BLOCK_VALID_TREE | BLOCK_FAILED_VALID));
    BOOST_CHECK(disk.GetBlockHash() == chain.hashes[7]);
    BOOST_CHECK(p->nSolution.empty());
}

BOOST_AUTO_TEST_CASE(get_solution_reads_once_then_hits_cache)
{
    Entries chain;
    WriteAndLoadChain(chain);
    ClearBlockIndexSolutionCacheForTest();
    CBlockIndex* p = Loaded(chain.hashes[3]);
    BOOST_REQUIRE(p != NULL);

    std::vector<unsigned char> sol;
    BOOST_REQUIRE(p->GetSolution(sol));
    BOOST_CHECK(sol == chain.solutions[3]);
    BlockIndexSolutionCacheStats s = GetBlockIndexSolutionCacheStats();
    BOOST_CHECK_EQUAL(s.hits, 0u);
    BOOST_CHECK_EQUAL(s.misses, 1u);

    sol.clear();
    BOOST_REQUIRE(p->GetSolution(sol));
    BOOST_CHECK(sol == chain.solutions[3]);
    s = GetBlockIndexSolutionCacheStats();
    BOOST_CHECK_EQUAL(s.hits, 1u);
    BOOST_CHECK_EQUAL(s.misses, 1u);
    BOOST_CHECK_EQUAL(s.entries, 1u);
}

BOOST_AUTO_TEST_CASE(cache_is_bounded)
{
    BOOST_CHECK_EQUAL(BLOCK_INDEX_SOLUTION_CACHE_SIZE, 4096u);
    Entries many;
    for (uint32_t i = 0; i < 5000; i++)
        many.Add(MakeHeader(uint256(), 100000 + i, 400, false), NULL);
    BOOST_REQUIRE(WriteEntries(many.All()));
    ClearBlockIndexSolutionCacheForTest();

    std::vector<unsigned char> sol;
    for (size_t i = 0; i < many.hashes.size(); i++) {
        BOOST_REQUIRE(ReadBlockIndexSolution(many.hashes[i], sol));
        BOOST_REQUIRE(sol == many.solutions[i]);
    }
    BlockIndexSolutionCacheStats s = GetBlockIndexSolutionCacheStats();
    BOOST_CHECK_EQUAL(s.entries, BLOCK_INDEX_SOLUTION_CACHE_SIZE);
    BOOST_CHECK_EQUAL(s.misses, 5000u);
    BOOST_CHECK_EQUAL(s.hits, 0u);

    // The most recent entry is cached; the oldest was evicted.
    BOOST_REQUIRE(ReadBlockIndexSolution(many.hashes.back(), sol));
    BOOST_REQUIRE(ReadBlockIndexSolution(many.hashes.front(), sol));
    s = GetBlockIndexSolutionCacheStats();
    BOOST_CHECK_EQUAL(s.hits, 1u);
    BOOST_CHECK_EQUAL(s.misses, 5001u);
    BOOST_CHECK_EQUAL(s.entries, BLOCK_INDEX_SOLUTION_CACHE_SIZE);
    BOOST_CHECK(pblocktree->EraseBatchSync(many.All()));
}

BOOST_AUTO_TEST_CASE(missing_record_is_loud)
{
    Entries chain;
    WriteAndLoadChain(chain);
    CBlockIndex* p = Loaded(chain.hashes[11]);
    BOOST_REQUIRE(p != NULL && p->fSolutionOnDisk);
    const std::vector<const CBlockIndex*> one(1, p);
    BOOST_REQUIRE(pblocktree->EraseBatchSync(one));
    ClearBlockIndexSolutionCacheForTest();

    std::vector<unsigned char> sol;
    BOOST_CHECK(!p->GetSolution(sol));
    BOOST_CHECK(!ReadBlockIndexSolution(chain.hashes[11], sol));
    BOOST_CHECK_THROW(p->GetBlockHeader(), std::runtime_error);
    p->nStatus = BLOCK_VALID_TREE | BLOCK_FAILED_VALID;
    BOOST_CHECK(!WriteEntries(one));
    CDiskBlockIndex disk;
    BOOST_CHECK(!pblocktree->ReadDiskBlockIndex(chain.hashes[11], disk));
}

// Validation must never read a solution from a CBlockIndex: after a restart it is
// empty there. Equihash is checked on the CBlockHeader in hand (pow.cpp).
BOOST_AUTO_TEST_CASE(validation_reads_no_index_solution)
{
    const std::string self(__FILE__);
    const std::string::size_type cut = self.rfind("test/blockindex_solution_tests.cpp");
    if (cut == std::string::npos)
        return;
    const char* files[] = {"main.cpp", "pow.cpp"};
    const char* banned[] = {"pindex->nSolution", "pindexNew->nSolution", "pindexPrev->nSolution",
                            "blockindex->nSolution", "Tip()->nSolution"};
    for (const char* name : files) {
        std::ifstream in(self.substr(0, cut) + name);
        if (!in) {
            BOOST_TEST_MESSAGE("source not found, skipping " << name);
            continue;
        }
        std::string line;
        for (int n = 1; std::getline(in, line); n++)
            for (const char* b : banned)
                BOOST_CHECK_MESSAGE(line.find(b) == std::string::npos, name << ":" << n << " reads " << b);
    }
}

BOOST_AUTO_TEST_SUITE_END()
