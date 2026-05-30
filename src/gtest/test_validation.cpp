#include <gtest/gtest.h>

#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "main.h"
#include "pow.h"
#include "utiltest.h"

extern ZCJoinSplit* params;

extern bool ReceivedBlockTransactions(const CBlock &block, CValidationState& state, CBlockIndex *pindexNew, const CDiskBlockPos& pos);

void ExpectOptionalAmount(CAmount expected, boost::optional<CAmount> actual) {
    EXPECT_TRUE((bool)actual);
    if (actual) {
        EXPECT_EQ(expected, *actual);
    }
}

// Fake an empty view
class FakeCoinsViewDB : public CCoinsView {
public:
    FakeCoinsViewDB() {}

    bool GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const {
        return false;
    }

    bool GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const {
        return false;
    }

    bool GetNullifier(const uint256 &nf, ShieldedType type) const {
        return false;
    }

    bool GetCoins(const uint256 &txid, CCoins &coins) const {
        return false;
    }

    bool HaveCoins(const uint256 &txid) const {
        return false;
    }

    uint256 GetBestBlock() const {
        uint256 a;
        return a;
    }

    uint256 GetBestAnchor(ShieldedType type) const {
        uint256 a;
        return a;
    }

    bool BatchWrite(CCoinsMap &mapCoins,
                    const uint256 &hashBlock,
                    const uint256 &hashSproutAnchor,
                    const uint256 &hashSaplingAnchor,
                    CAnchorsSproutMap &mapSproutAnchors,
                    CAnchorsSaplingMap &mapSaplingAnchors,
                    CNullifiersMap &mapSproutNullifiers,
                    CNullifiersMap saplingNullifiersMap) {
        return false;
    }

    bool GetStats(CCoinsStats &stats) const {
        return false;
    }
};

TEST(Validation, ContextualCheckInputsPassesWithCoinbase) {
    // Create fake coinbase transaction
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    CTransaction tx(mtx);
    ASSERT_TRUE(tx.IsCoinBase());

    // Fake an empty view
    FakeCoinsViewDB fakeDB;
    CCoinsViewCache view(&fakeDB);

    for (int idx = Consensus::BASE_SPROUT; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
        auto consensusBranchId = NetworkUpgradeInfo[idx].nBranchId;
        CValidationState state;
        PrecomputedTransactionData txdata(tx);
        EXPECT_TRUE(ContextualCheckInputs(tx, state, view, false, 0, false, txdata, Params(CBaseChainParams::MAIN).GetConsensus(), consensusBranchId));
    }
}

TEST(Validation, ReceivedBlockTransactions) {
    auto sk = libzcash::SproutSpendingKey::random();

    // Create a fake genesis block
    CBlock block1;
    block1.vtx.push_back(GetValidSproutReceive(*params, sk, 5, true));
    block1.hashMerkleRoot = block1.BuildMerkleTree();
    CBlockIndex fakeIndex1 {block1};

    // Create a fake child block
    CBlock block2;
    block2.hashPrevBlock = block1.GetHash();
    block2.vtx.push_back(GetValidSproutReceive(*params, sk, 10, true));
    block2.hashMerkleRoot = block2.BuildMerkleTree();
    CBlockIndex fakeIndex2 {block2};
    fakeIndex2.pprev = &fakeIndex1;

    CDiskBlockPos pos1;
    CDiskBlockPos pos2;

    // Set initial state of indices
    ASSERT_TRUE(fakeIndex1.RaiseValidity(BLOCK_VALID_TREE));
    ASSERT_TRUE(fakeIndex2.RaiseValidity(BLOCK_VALID_TREE));
    EXPECT_TRUE(fakeIndex1.IsValid(BLOCK_VALID_TREE));
    EXPECT_TRUE(fakeIndex2.IsValid(BLOCK_VALID_TREE));
    EXPECT_FALSE(fakeIndex1.IsValid(BLOCK_VALID_TRANSACTIONS));
    EXPECT_FALSE(fakeIndex2.IsValid(BLOCK_VALID_TRANSACTIONS));

    // Sprout pool values should not be set
    EXPECT_FALSE((bool)fakeIndex1.nSproutValue);
    EXPECT_FALSE((bool)fakeIndex1.nChainSproutValue);
    EXPECT_FALSE((bool)fakeIndex2.nSproutValue);
    EXPECT_FALSE((bool)fakeIndex2.nChainSproutValue);

    // Mark the second block's transactions as received first
    CValidationState state;
    EXPECT_TRUE(ReceivedBlockTransactions(block2, state, &fakeIndex2, pos2));
    EXPECT_FALSE(fakeIndex1.IsValid(BLOCK_VALID_TRANSACTIONS));
    EXPECT_TRUE(fakeIndex2.IsValid(BLOCK_VALID_TRANSACTIONS));

    // Sprout pool value delta should now be set for the second block,
    // but not any chain totals
    EXPECT_FALSE((bool)fakeIndex1.nSproutValue);
    EXPECT_FALSE((bool)fakeIndex1.nChainSproutValue);
    {
        SCOPED_TRACE("ExpectOptionalAmount call");
        ExpectOptionalAmount(20, fakeIndex2.nSproutValue);
    }
    EXPECT_FALSE((bool)fakeIndex2.nChainSproutValue);

    // Now mark the first block's transactions as received
    EXPECT_TRUE(ReceivedBlockTransactions(block1, state, &fakeIndex1, pos1));
    EXPECT_TRUE(fakeIndex1.IsValid(BLOCK_VALID_TRANSACTIONS));
    EXPECT_TRUE(fakeIndex2.IsValid(BLOCK_VALID_TRANSACTIONS));

    // Sprout pool values should now be set for both blocks
    {
        SCOPED_TRACE("ExpectOptionalAmount call");
        ExpectOptionalAmount(10, fakeIndex1.nSproutValue);
    }
    {
        SCOPED_TRACE("ExpectOptionalAmount call");
        ExpectOptionalAmount(10, fakeIndex1.nChainSproutValue);
    }
    {
        SCOPED_TRACE("ExpectOptionalAmount call");
        ExpectOptionalAmount(20, fakeIndex2.nSproutValue);
    }
    {
        SCOPED_TRACE("ExpectOptionalAmount call");
        ExpectOptionalAmount(30, fakeIndex2.nChainSproutValue);
    }
}

// SEC-2 / growable-v3 forward-connect: the load-bearing anti-forgery rule.
//
// The growable-v3 bootstrap import connects the server-supplied post-anchor blocks via
// ConnectTip WITHOUT routing them through AcceptBlockHeader, so the difficulty-RETARGET
// rule (block.nBits == GetNextWorkRequired) -- which on the live header path lives ONLY
// in ContextualCheckBlockHeader -- would be skipped, letting a malicious server bundle a
// forged low-difficulty post-anchor fork that the context-free PoW check (which validates
// against the block's own CLAIMED nBits) would happily accept. main.cpp:3320-3332 closes
// that gap by re-running ContextualCheckBlockHeader on every above-checkpoint imported
// block while CBootstrapForwardConnectGuard is armed. This test pins the exact rule that
// re-check re-applies: a header claiming an easier-than-required difficulty is rejected
// with "bad-diffbits", while the honestly-retargeted header at the same height passes.
TEST(Validation, BootstrapForwardConnectRejectsForgedLowDifficulty) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus();

    // Build a synthetic, evenly-spaced chain long enough for the averaging-window
    // retarget to have a full history to work from (mirrors test_pow.cpp).
    const size_t lastBlk = 2 * params.nPowAveragingWindow;
    std::vector<CBlockIndex> blocks(lastBlk + 1);
    for (size_t i = 0; i <= lastBlk; i++) {
        blocks[i].pprev   = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime   = i ? blocks[i - 1].nTime + params.PoWTargetSpacing(i) : 1269211443;
        blocks[i].nBits   = 0x1e7fffff;
    }
    CBlockIndex* pprev = &blocks[lastBlk];

    // The difficulty the network actually requires for the next block here.
    CBlockHeader probe;
    probe.nTime = pprev->nTime + params.PoWTargetSpacing(pprev->nHeight + 1);
    const uint32_t requiredBits = GetNextWorkRequired(pprev, &probe, params);

    // A forged "low difficulty" claim: a 4x-looser target (easier to mine), which a
    // context-free PoW check against its OWN nBits would accept, but the retarget rule
    // must reject.
    arith_uint256 forgedTarget;
    forgedTarget.SetCompact(requiredBits);
    forgedTarget *= 4;
    const uint32_t forgedBits = forgedTarget.GetCompact();
    ASSERT_NE(forgedBits, requiredBits);

    // Isolate the difficulty rule from the unrelated "older than last checkpoint" guard,
    // which the synthetic low-height chain would otherwise trip.
    const bool savedCheckpoints = fCheckpointsEnabled;
    fCheckpointsEnabled = false;

    auto makeHeader = [&](uint32_t nBits) {
        CBlockHeader h;
        h.nVersion     = 4;            // ContextualCheckBlockHeader rejects nVersion < 4
        h.hashPrevBlock = uint256();   // unused by ContextualCheckBlockHeader
        h.nTime        = probe.nTime;  // strictly after pprev's median-time-past
        h.nBits        = nBits;
        // nSolution left empty -> the equihash solution-size precheck is skipped
        return h;
    };

    // Forged easy header: rejected, and specifically for the difficulty bits.
    {
        CBlockHeader forged = makeHeader(forgedBits);
        CValidationState state;
        EXPECT_FALSE(ContextualCheckBlockHeader(forged, state, pprev));
        EXPECT_EQ("bad-diffbits", state.GetRejectReason());
    }

    // Honest header at the required difficulty: passes the same re-check. This proves the
    // forged header was rejected for its difficulty and not some incidental reason, i.e.
    // that the guard's re-check is exactly what stands between an imported forged-easy
    // block and acceptance.
    {
        CBlockHeader honest = makeHeader(requiredBits);
        CValidationState state;
        EXPECT_TRUE(ContextualCheckBlockHeader(honest, state, pprev));
    }

    fCheckpointsEnabled = savedCheckpoints;
}

// Step-6 safety invariant. ReadBlockFromDisk skips re-verifying the Equihash solution
// for a block pinned by the checkpoint hash-chain, relying on the GetHash()==index
// check to detect on-disk tampering instead. That substitution is sound ONLY because a
// block's hash binds its nSolution: any change to the solution changes GetHash(). Pin
// that invariant so the optimization can never silently accept a tampered solution.
TEST(Validation, BlockHashBindsEquihashSolution) {
    SelectParams(CBaseChainParams::MAIN);
    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = uint256S("0x01");
    block.hashMerkleRoot = uint256S("0x02");
    block.hashFinalSaplingRoot = uint256S("0x03");
    block.nTime = 1500000000;
    block.nBits = 0x1e7fffff;
    block.nNonce = uint256S("0x04");
    block.nSolution = std::vector<unsigned char>(1344, 0x00);

    const uint256 h1 = block.GetHash();
    // Flip one byte of the Equihash solution -> the block hash MUST change, so a pinned
    // block whose on-disk solution was tampered with fails the GetHash()==index check.
    block.nSolution[42] ^= 0xff;
    EXPECT_NE(h1, block.GetHash());
    // Restoring the solution restores the hash (the hash is a faithful function of it).
    block.nSolution[42] ^= 0xff;
    EXPECT_EQ(h1, block.GetHash());
}
