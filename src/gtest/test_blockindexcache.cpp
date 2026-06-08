// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the BOOT-SPEEDUP block-index snapshot cache (txdb.cpp:
// CBlockTreeDB::WriteBlockIndexCache / LoadBlockIndexFromCache).
//
// These prove the load-bearing safety contract WITHOUT a real chain:
//   * round-trip: write cache -> clear -> load -> byte-identical in-memory index;
//   * authoritative tip + record count present and correct;
//   * corruption (flipped body byte) => rejected, mapBlockIndex left EMPTY (clean fallback);
//   * staleness (cache tip != requested best block) => rejected;
//   * a bad magic / missing file => rejected.
//
// The chain is synthetic; on regtest the PoW target is loose, so each block's nNonce is
// ground until CheckProofOfWork passes (the same check the cache loader runs per record).

#include <gtest/gtest.h>

#include "chain.h"
#include "chainparams.h"
#include "main.h"        // mapBlockIndex, InsertBlockIndex, UnloadBlockIndex
#include "pow.h"
#include "txdb.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <boost/filesystem.hpp>
#include <fstream>
#include <vector>

namespace {

// Fresh, isolated regtest datadir for one test (so GetDataDir()/blocks/ is writable + private).
struct CacheTestEnv {
    boost::filesystem::path dir;
    CacheTestEnv() {
        fPrintToConsole = true;   // surface WriteBlockIndexCache/Load error() reasons to stderr
        SelectParams(CBaseChainParams::REGTEST);
        dir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
        // GetDataDir() returns "" unless the -datadir already EXISTS as a directory, so the
        // base dir MUST be created BEFORE pointing -datadir at it.
        boost::filesystem::create_directories(dir);
        mapArgs["-datadir"] = dir.string();
        ClearDatadirCache();
        // GetDataDir() now resolves to dir/<network> (regtest), which it auto-creates; the cache
        // lives at GetDataDir()/blocks/blockindex.dat, so create that blocks/ subdir.
        boost::filesystem::create_directories(GetDataDir() / "blocks");
    }
    ~CacheTestEnv() {
        UnloadBlockIndex();                 // delete all mapBlockIndex entries + reset globals
        mapArgs.erase("-datadir");
        ClearDatadirCache();
        boost::system::error_code ec;
        boost::filesystem::remove_all(dir, ec);
    }
    boost::filesystem::path cacheFile() const { return GetDataDir() / "blocks" / "blockindex.dat"; }
};

// Build a synthetic block index of `n` blocks (genesis + n-1 children) in the GLOBAL
// mapBlockIndex, each passing regtest CheckProofOfWork. Returns them in height order.
static std::vector<CBlockIndex*> BuildChain(size_t n) {
    const Consensus::Params& consensus = Params().GetConsensus();
    const arith_uint256 target = UintToArith256(consensus.powLimit);
    const uint32_t nBits = target.GetCompact();

    std::vector<CBlockIndex*> chain;
    CBlockIndex* prev = NULL;
    for (size_t h = 0; h < n; ++h) {
        CBlockIndex* idx = new CBlockIndex();
        idx->pprev = prev;
        idx->nHeight = (int)h;
        idx->nVersion = 4;
        idx->hashMerkleRoot = GetRandHash();
        idx->hashFinalSaplingRoot = GetRandHash();
        idx->hashSproutAnchor = GetRandHash();
        idx->nTime = 1500000000 + (uint32_t)h;
        idx->nBits = nBits;
        idx->nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
        idx->nTx = 1;
        idx->nFile = 0;
        idx->nDataPos = (unsigned int)(8 + h * 100);
        idx->nUndoPos = (unsigned int)(8 + h * 40);
        idx->nSolution = std::vector<unsigned char>(16, (unsigned char)h);  // arbitrary, self-describing
        if (idx->pprev)
            idx->phashBlock = NULL;   // recomputed below via GetBlockHeader()

        // Grind nNonce until the header hash meets the (loose, regtest) target.
        for (uint32_t n2 = 0; ; ++n2) {
            idx->nNonce = ArithToUint256(arith_uint256(n2));
            if (UintToArith256(idx->GetBlockHeader().GetHash()) <= target)
                break;
        }
        uint256 hash = idx->GetBlockHeader().GetHash();
        BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, idx)).first;
        idx->phashBlock = &((*mi).first);
        chain.push_back(idx);
        prev = idx;
    }
    return chain;
}

// Persist `chain` into the (in-memory) block tree DB so the cache loader's authoritative
// tip cross-check (ReadDiskBlockIndex) has something to read.
static void PersistToDb(CBlockTreeDB& db, const std::vector<CBlockIndex*>& chain) {
    std::vector<const CBlockIndex*> blockinfo(chain.begin(), chain.end());
    std::vector<std::pair<int, const CBlockFileInfo*> > fileInfo;   // none needed for these tests
    ASSERT_TRUE(db.WriteBatchSync(fileInfo, 0, blockinfo));
}

static void ClearGlobalIndex() {
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); ++it)
        delete it->second;
    mapBlockIndex.clear();
}

} // namespace

TEST(blockindexcache, roundtrip_identity) {
    CacheTestEnv env;
    CBlockTreeDB db(1 << 20, true /*fMemory*/);

    const size_t N = 50;
    std::vector<CBlockIndex*> chain = BuildChain(N);
    const uint256 tip = chain.back()->GetBlockHash();
    const int tipHeight = chain.back()->nHeight;
    PersistToDb(db, chain);

    // Snapshot the fields we will compare after a clear + cache reload.
    struct Snap { uint256 hash, merkle, sapling, sprout; int height; uint32_t bits; uint32_t status; unsigned int dataPos; };
    std::vector<Snap> expect;
    for (CBlockIndex* p : chain)
        expect.push_back({p->GetBlockHash(), p->hashMerkleRoot, p->hashFinalSaplingRoot,
                          p->hashSproutAnchor, p->nHeight, (uint32_t)p->nBits, p->nStatus, p->nDataPos});

    ASSERT_TRUE(db.WriteBlockIndexCache(tip, tipHeight));
    ASSERT_TRUE(boost::filesystem::exists(env.cacheFile()));

    ClearGlobalIndex();
    ASSERT_EQ(mapBlockIndex.size(), 0u);

    ASSERT_TRUE(db.LoadBlockIndexFromCache(tip));
    EXPECT_EQ(mapBlockIndex.size(), N);
    ASSERT_TRUE(mapBlockIndex.count(tip) == 1);

    for (const Snap& s : expect) {
        BlockMap::iterator it = mapBlockIndex.find(s.hash);
        ASSERT_TRUE(it != mapBlockIndex.end());
        CBlockIndex* p = it->second;
        EXPECT_EQ(p->nHeight, s.height);
        EXPECT_EQ((uint32_t)p->nBits, s.bits);
        EXPECT_EQ(p->nStatus, s.status);
        EXPECT_EQ(p->nDataPos, s.dataPos);
        EXPECT_TRUE(p->hashMerkleRoot == s.merkle);
        EXPECT_TRUE(p->hashFinalSaplingRoot == s.sapling);
        EXPECT_TRUE(p->hashSproutAnchor == s.sprout);
        // pprev recovered by hash: every non-genesis block links to height-1.
        if (s.height > 0) {
            ASSERT_TRUE(p->pprev != NULL);
            EXPECT_EQ(p->pprev->nHeight, s.height - 1);
        } else {
            EXPECT_TRUE(p->pprev == NULL);
        }
    }
}

TEST(blockindexcache, corruption_rejected_clean) {
    CacheTestEnv env;
    CBlockTreeDB db(1 << 20, true);
    std::vector<CBlockIndex*> chain = BuildChain(30);
    const uint256 tip = chain.back()->GetBlockHash();
    PersistToDb(db, chain);
    ASSERT_TRUE(db.WriteBlockIndexCache(tip, chain.back()->nHeight));
    ClearGlobalIndex();

    // Flip a byte in the middle of the file (a record body) -> checksum/PoW must reject it.
    {
        boost::filesystem::path f = env.cacheFile();
        std::fstream fs(f.string().c_str(), std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(fs.good());
        uint64_t sz = (uint64_t)boost::filesystem::file_size(f);
        fs.seekp((std::streamoff)(sz / 2));
        char b = 0; fs.read(&b, 1); fs.seekp((std::streamoff)(sz / 2)); b = (char)(b ^ 0xFF); fs.write(&b, 1);
        fs.close();
    }

    EXPECT_FALSE(db.LoadBlockIndexFromCache(tip));
    EXPECT_EQ(mapBlockIndex.size(), 0u);   // partial state wiped -> clean leveldb fallback
}

TEST(blockindexcache, staleness_rejected) {
    CacheTestEnv env;
    CBlockTreeDB db(1 << 20, true);
    std::vector<CBlockIndex*> chain = BuildChain(20);
    const uint256 tip = chain.back()->GetBlockHash();
    PersistToDb(db, chain);
    ASSERT_TRUE(db.WriteBlockIndexCache(tip, chain.back()->nHeight));
    ClearGlobalIndex();

    // Ask for a DIFFERENT best block than the cache was written at (simulates a reorg/tip move
    // since shutdown). G5 must reject.
    EXPECT_FALSE(db.LoadBlockIndexFromCache(GetRandHash()));
    EXPECT_EQ(mapBlockIndex.size(), 0u);
}

TEST(blockindexcache, missing_and_badmagic_rejected) {
    CacheTestEnv env;
    CBlockTreeDB db(1 << 20, true);
    std::vector<CBlockIndex*> chain = BuildChain(10);
    const uint256 tip = chain.back()->GetBlockHash();
    PersistToDb(db, chain);

    // No cache file yet -> miss (false), nothing touched.
    EXPECT_FALSE(db.LoadBlockIndexFromCache(tip));

    // Write one, then clobber the 4-byte magic header -> rejected.
    ASSERT_TRUE(db.WriteBlockIndexCache(tip, chain.back()->nHeight));
    ClearGlobalIndex();
    {
        std::fstream fs(env.cacheFile().string().c_str(), std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(fs.good());
        fs.seekp(0); const char junk[4] = {0,0,0,0}; fs.write(junk, 4); fs.close();
    }
    EXPECT_FALSE(db.LoadBlockIndexFromCache(tip));
    EXPECT_EQ(mapBlockIndex.size(), 0u);
}
