#include <gtest/gtest.h>

#include "checkqueue.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "main.h"
#include "pow.h"
#include "script/interpreter.h"
#include "txdb.h"
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

// The bootstrap fast-sync anchor commits to CCoinsStats::hashSerializedFull. This test
// pins the property that makes that commitment safe for a shielded chain: the full
// commitment binds the Sprout/Sapling nullifier set, whereas the transparent-only
// hashSerialized does not. Without this, a malicious snapshot could ship honest
// transparent coins (matching hashSerialized) with a dropped nullifier — enabling a
// shielded double-spend — and still pass verification.
TEST(Validation, ChainstateCommitmentBindsShieldedState)
{
    // In-memory chainstate (MemEnv: no disk, path is just a label).
    CCoinsViewDB db(boost::filesystem::path("mem-chainstate-test"),
                    1 << 20, /*fMemory=*/true, /*fWipe=*/false);

    // Seed one transparent coin and a best block so the transparent commitment is
    // non-trivial and stable across the two snapshots below.
    const uint256 best = uint256S("0x99");
    {
        CCoinsMap mapCoins;
        CCoinsCacheEntry& e = mapCoins[uint256S("0x01")];
        e.coins.fCoinBase = false;
        e.coins.nVersion = 1;
        e.coins.nHeight = 1;
        e.coins.vout.resize(1);
        e.coins.vout[0].nValue = 10 * COIN;
        e.flags = CCoinsCacheEntry::DIRTY;
        CAnchorsSproutMap aS; CAnchorsSaplingMap aZ;
        CNullifiersMap nS, nZ;
        ASSERT_TRUE(db.BatchWrite(mapCoins, best, uint256(), uint256(), aS, aZ, nS, nZ));
    }

    CCoinsStats before;
    ASSERT_TRUE(db.GetStats(before));

    // Add a single Sprout nullifier — shielded state only; no coin is added or removed,
    // and the best block is left unchanged (BatchWrite skips a null hashBlock).
    {
        CCoinsMap noCoins;
        CAnchorsSproutMap aS; CAnchorsSaplingMap aZ;
        CNullifiersMap sproutN, saplingN;
        CNullifiersCacheEntry& ne = sproutN[uint256S("0x5150")];
        ne.entered = true;
        ne.flags = CNullifiersCacheEntry::DIRTY;
        ASSERT_TRUE(db.BatchWrite(noCoins, uint256(), uint256(), uint256(), aS, aZ, sproutN, saplingN));
    }

    CCoinsStats after;
    ASSERT_TRUE(db.GetStats(after));

    // The transparent UTXO set is identical, so the transparent-only commitment is
    // UNCHANGED — i.e. it is blind to the shielded mutation (the gap being fixed).
    EXPECT_EQ(before.hashSerialized, after.hashSerialized);
    // The full-chainstate commitment MUST change: the nullifier set is now bound.
    EXPECT_NE(before.hashSerializedFull, after.hashSerializedFull);
    // And the two commitments are distinct (full folds in shielded state beyond UTXOs).
    EXPECT_NE(after.hashSerialized, after.hashSerializedFull);
}

// Companion to the shielded test for the TRANSPARENT side: the full commitment must
// bind each coin's consensus metadata (creation height + coinbase flag + version),
// not just its output value/script. CheckInputs reads coins.nHeight/fCoinBase verbatim
// from an imported UTXO set for the COINBASE_MATURITY rule, so if the commitment were
// blind to them a malicious snapshot could ship coins that match hashSerialized but
// carry forged maturity metadata — a no-hashpower consensus partition. hashSerialized
// (transparent outputs only) must stay blind to these flips; hashSerializedFull must not.
TEST(Validation, ChainstateCommitmentBindsCoinMetadata)
{
    CCoinsViewDB db(boost::filesystem::path("mem-chainstate-meta-test"),
                    1 << 20, /*fMemory=*/true, /*fWipe=*/false);
    const uint256 best = uint256S("0x99");

    // Re-write the SAME coin (same outputs) with chosen metadata each time.
    auto writeCoin = [&](bool fCoinBase, int nHeight) {
        CCoinsMap mapCoins;
        CCoinsCacheEntry& e = mapCoins[uint256S("0x01")];
        e.coins.fCoinBase = fCoinBase;
        e.coins.nVersion = 1;
        e.coins.nHeight = nHeight;
        e.coins.vout.resize(1);
        e.coins.vout[0].nValue = 10 * COIN; // OUTPUT identical across every write
        e.flags = CCoinsCacheEntry::DIRTY;
        CAnchorsSproutMap aS; CAnchorsSaplingMap aZ;
        CNullifiersMap nS, nZ;
        ASSERT_TRUE(db.BatchWrite(mapCoins, best, uint256(), uint256(), aS, aZ, nS, nZ));
    };

    writeCoin(/*fCoinBase=*/false, /*nHeight=*/1);
    CCoinsStats base;
    ASSERT_TRUE(db.GetStats(base));

    // Flip ONLY the coinbase flag (outputs unchanged): mislabelling a coinbase as
    // non-coinbase bypasses COINBASE_MATURITY at spend time.
    writeCoin(/*fCoinBase=*/true, /*nHeight=*/1);
    CCoinsStats flipCoinBase;
    ASSERT_TRUE(db.GetStats(flipCoinBase));
    EXPECT_EQ(base.hashSerialized, flipCoinBase.hashSerialized);
    EXPECT_NE(base.hashSerializedFull, flipCoinBase.hashSerializedFull);

    // Change ONLY the creation height (outputs + coinbase flag unchanged): a forged
    // nHeight shifts the maturity window. Same invariant.
    writeCoin(/*fCoinBase=*/false, /*nHeight=*/500000);
    CCoinsStats bumpHeight;
    ASSERT_TRUE(db.GetStats(bumpHeight));
    EXPECT_EQ(base.hashSerialized, bumpHeight.hashSerialized);
    EXPECT_NE(base.hashSerializedFull, bumpHeight.hashSerializedFull);
}

// Regression guard for the CVE-2024-52911-parity use-after-free in ConnectBlock.
//
// In ConnectBlock, queued CScriptChecks hold a raw PrecomputedTransactionData*
// into a local `txdata` vector, and ~CCheckQueueControl() calls Wait() on every
// (including early) return. Crucially, Wait() drains any still-queued checks ON
// THE CALLING THREAD (the "master" in CCheckQueue::Loop). So if `txdata` is
// declared AFTER `control`, reverse-order destruction frees txdata BEFORE
// ~control's Wait() runs the queued check that dereferences it -> heap UAF.
//
// The check below mirrors CScriptCheck: it holds a PrecomputedTransactionData*
// and dereferences it when run. Because no background worker threads are started,
// the queued check is guaranteed to execute inside ~control's Wait() on this
// thread -> the reproduction is DETERMINISTIC, not racy.
//
//  * EXPECT_TRUE(ran) deterministically guards the property the fix depends on:
//    ~CCheckQueueControl drains queued checks. If that contract regresses, the
//    fix becomes a silent no-op and this fails WITHOUT needing a sanitizer.
//  * Under AddressSanitizer, swapping the declaration order of `txdata` and
//    `control` below makes the drained check read freed memory -> ASan reports
//    heap-use-after-free. Build with: ./configure --with-sanitizers=address
//
// NOTE: this guards the lifetime *mechanism*; the exact declaration order inside
// ConnectBlock itself is guarded by the inline comment there + code review.
struct LifetimeCheck {
    const PrecomputedTransactionData* pdata;
    uint256* sink;
    bool* ran;
    LifetimeCheck() : pdata(nullptr), sink(nullptr), ran(nullptr) {}
    LifetimeCheck(const PrecomputedTransactionData* pdataIn, uint256* sinkIn, bool* ranIn)
        : pdata(pdataIn), sink(sinkIn), ran(ranIn) {}
    bool operator()() {
        // Dereference pdata exactly as CScriptCheck dereferences its txdata.
        if (pdata != nullptr && sink != nullptr) {
            *sink = pdata->hashPrevouts;
        }
        if (ran != nullptr) {
            *ran = true;
        }
        return true;
    }
    void swap(LifetimeCheck& other) {
        std::swap(pdata, other.pdata);
        std::swap(sink, other.sink);
        std::swap(ran, other.ran);
    }
};

TEST(Validation, CheckQueueControlDrainsQueuedCheckBeforeTxdataDestroyed) {
    CCheckQueue<LifetimeCheck> queue(128);
    uint256 sink;
    bool ran = false;
    {
        // ConnectBlock's FIXED ordering: txdata declared BEFORE control, so
        // ~control's Wait() (which drains the queued check on this thread) runs
        // BEFORE txdata is destroyed. Swapping these two lines reproduces the
        // use-after-free under AddressSanitizer.
        std::vector<PrecomputedTransactionData> txdata;
        txdata.reserve(1);
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        txdata.emplace_back(CTransaction(mtx));

        CCheckQueueControl<LifetimeCheck> control(&queue);

        std::vector<LifetimeCheck> vChecks;
        vChecks.emplace_back(&txdata[0], &sink, &ran);
        control.Add(vChecks);

        // Simulate an early consensus-failure return (coinbase overpay / bad
        // Sapling root): leave scope WITHOUT calling control.Wait().
    }
    // ~control must have drained the queued check on this thread while txdata
    // was still alive. If it did not, the fix is void.
    EXPECT_TRUE(ran);
}
