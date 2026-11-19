// Crash consistency of the wallet's persisted note state.
//
// wallet.dat holds, per note transaction, the witness cache, the witness height and the
// nullifier. Those are written at checkpoints (CWallet::SetBestChain, together with the
// best-block locator) and whenever a transaction is added or re-added, so after a crash,
// a reindex or a chain that was rolled back behind the wallet the record on disk can be
// ahead of, behind, or on another branch than the chain, or can carry a witness without
// its nullifier (which makes a spent note read as unspent for good).
//
// This file tests the pieces that keep that state trustworthy:
//   - SetBestChainINTERNAL writes every note transaction and the witness cache size
//     before the locator, in one database transaction, and never commits after a failed
//     write (driven through a recording database);
//   - re-adding a note transaction keeps its nullifier together with its witnesses;
//   - CWallet::ReconcileNoteState cuts a witness cache that is ahead of the chain back to
//     the tip, drops one that is not on the chain, lowers the rescan start for one that is
//     behind, and derives a missing nullifier.

#include <gtest/gtest.h>

#include "chain.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "util.h"
#include "utiltest.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "zcash/Note.hpp"
#include "zcash/NoteEncryption.hpp"
#include "zcash/zip32.h"

#include <boost/filesystem.hpp>

#include <deque>
#include <random>
#include <string>
#include <vector>

namespace {

uint256 SeededHash(std::mt19937_64& rng)
{
    uint256 h;
    unsigned char* p = h.begin();
    for (size_t i = 0; i < 32; i += 8) {
        uint64_t v = rng();
        for (size_t k = 0; k < 8; k++) p[i + k] = (unsigned char)(v >> (8 * k));
    }
    return h;
}

CMutableTransaction BaseTx(std::mt19937_64& rng)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.vin.push_back(CTxIn(COutPoint(SeededHash(rng), 0)));
    return mtx;
}

OutputDescription SaplingOutputTo(std::mt19937_64& rng, const libzcash::SaplingPaymentAddress& pa, CAmount value)
{
    uint256 r = SeededHash(rng);
    *(r.begin() + 31) = 0;
    libzcash::SaplingNote note(pa.d, pa.pk_d, value, r);
    libzcash::SaplingNotePlaintext pt(note, std::array<unsigned char, ZC_MEMO_SIZE>());
    auto res = pt.encrypt(note.pk_d);
    assert(res);
    OutputDescription od;
    od.cm = note.cm().get();
    od.ephemeralKey = res.get().second.get_epk();
    od.encCiphertext = res.get().first;
    return od;
}

/** A wallet that exposes the checkpoint write for a recording database. */
class StateWallet : public CWallet {
public:
    explicit StateWallet(const std::string& file) : CWallet(file) { }
    template <typename DB>
    void Checkpoint(DB& db, const CBlockLocator& loc) { SetBestChainINTERNAL(db, loc); }
};

/** Records the order of database operations; can fail the n-th write. */
struct RecordingDB {
    std::vector<std::string> ops;
    int failAt = -1; //!< fail the write with this 0-based index among tx/size/locator writes
    int writes = 0;
    bool inTxn = false;
    bool committed = false;
    bool aborted = false;
    bool WriteStep(const std::string& what) {
        ops.push_back(what);
        return writes++ != failAt;
    }
    bool TxnBegin() { inTxn = true; ops.push_back("begin"); return true; }
    bool TxnCommit() { inTxn = false; committed = true; ops.push_back("commit"); return true; }
    bool TxnAbort() { inTxn = false; aborted = true; ops.push_back("abort"); return true; }
    bool WriteTx(uint256, const CWalletTx&) { return WriteStep("tx"); }
    bool WriteWitnessCacheSize(int64_t) { return WriteStep("cachesize"); }
    bool WriteBestBlock(const CBlockLocator&) { return WriteStep("locator"); }
};

/** A chain of blocks that carry Sapling outputs and the wallet's view of it. */
struct SimChain {
    std::deque<CBlockIndex> index;
    std::vector<uint256> hashes;
    SproutMerkleTree sprout;
    SaplingMerkleTree sapling;
    std::vector<CBlock> blocks;

    void Connect(StateWallet& wallet, CBlock& block, bool fNotifyWallet = true) {
        block.hashPrevBlock = hashes.empty() ? uint256() : hashes.back();
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nTime = 1500000000 + (uint32_t)index.size() * 150;
        uint256 hash = block.GetHash();

        index.emplace_back();
        CBlockIndex& bi = index.back();
        bi.nHeight = (int)index.size() - 1;
        bi.pprev = bi.nHeight ? &index[bi.nHeight - 1] : nullptr;
        bi.nTime = block.nTime;
        bi.hashMerkleRoot = block.hashMerkleRoot;
        bi.BuildSkip();
        auto mi = mapBlockIndex.insert(std::make_pair(hash, &bi)).first;
        bi.phashBlock = &mi->first;
        hashes.push_back(hash);
        blocks.push_back(block);

        LOCK2(cs_main, wallet.cs_wallet);
        chainActive.SetTip(&bi);
        if (fNotifyWallet) {
            for (const CTransaction& tx : block.vtx) wallet.SyncTransaction(tx, &block);
            wallet.ChainTip(&bi, &block, sprout, sapling, true);
        }
        for (const CTransaction& tx : block.vtx) {
            for (const OutputDescription& od : tx.vShieldedOutput) sapling.append(od.cm);
        }
        bi.hashFinalSaplingRoot = sapling.root();
        bi.hashFinalSproutRoot = sprout.root();
    }

    void Clear() {
        chainActive.SetTip(nullptr);
        for (const uint256& h : hashes) mapBlockIndex.erase(h);
        hashes.clear();
    }
};

struct StateFixture : public ::testing::Test {
    boost::filesystem::path dir;
    std::unique_ptr<StateWallet> wallet;
    libzcash::SaplingPaymentAddress addr;
    std::mt19937_64 rng{20261118};
    SimChain chain;

    void SetUp() override {
        RegtestActivateSapling();
        dir = boost::filesystem::temp_directory_path() / UniquePath("wns-%%%%-%%%%");
        boost::filesystem::create_directories(dir);
        mapArgs["-datadir"] = dir.string();
        ClearDatadirCache();
        bitdb.MakeMock();
        wallet.reset(new StateWallet("wallet.dat"));
        bool fFirstRun = true;
        ASSERT_EQ(DB_LOAD_OK, wallet->LoadWallet(fFirstRun));
        auto master = GetTestMasterSaplingSpendingKey();
        auto sk = master.Derive(0 | ZIP32_HARDENED_KEY_LIMIT);
        addr = sk.DefaultAddress();
        LOCK(wallet->cs_wallet);
        ASSERT_TRUE(wallet->AddSaplingZKey(sk, addr));
    }
    void TearDown() override {
        chain.Clear();
        wallet.reset();
        bitdb.Flush(true);
        bitdb.Reset();
        RegtestDeactivateSapling();
        boost::filesystem::remove_all(dir);
    }

    // one block: a stand-in coinbase and, if value > 0, one transaction paying the wallet
    uint256 Mine(CAmount value) {
        CBlock block;
        block.vtx.push_back(CTransaction(BaseTx(rng)));
        uint256 txid;
        if (value > 0) {
            CMutableTransaction mtx = BaseTx(rng);
            mtx.vShieldedOutput.push_back(SaplingOutputTo(rng, addr, value));
            block.vtx.push_back(CTransaction(mtx));
            txid = block.vtx.back().GetHash();
        }
        chain.Connect(*wallet, block);
        return txid;
    }
    CWalletTx& Tx(const uint256& h) { return wallet->mapWallet.at(h); }
    SaplingNoteData& Note(const uint256& h) { return Tx(h).mapSaplingNoteData.begin()->second; }
};

} // namespace

// ---- the checkpoint write order ------------------------------------------------

TEST_F(StateFixture, CheckpointWritesLocatorLastInOneTransaction)
{
    uint256 t1 = Mine(1000); Mine(0); uint256 t2 = Mine(2000);
    (void)t1; (void)t2;
    CBlockLocator loc;
    { LOCK(cs_main); loc = chainActive.GetLocator(); }
    RecordingDB db;
    wallet->Checkpoint(db, loc);
    // begin, one write per note transaction, the cache size, the locator, commit
    std::vector<std::string> want = {"begin", "tx", "tx", "cachesize", "locator", "commit"};
    EXPECT_EQ(want, db.ops);
    EXPECT_TRUE(db.committed);
    EXPECT_FALSE(db.aborted);
}

TEST_F(StateFixture, CheckpointNeverCommitsAfterAFailedWrite)
{
    Mine(1000); Mine(2000);
    CBlockLocator loc;
    { LOCK(cs_main); loc = chainActive.GetLocator(); }
    // fail each of the four writes (2 transactions, cache size, locator) in turn
    for (int fail = 0; fail < 4; fail++) {
        RecordingDB db;
        db.failAt = fail;
        wallet->Checkpoint(db, loc);
        EXPECT_FALSE(db.committed) << "failed write " << fail;
        EXPECT_TRUE(db.aborted) << "failed write " << fail;
        // the locator is only attempted once everything it implies was written
        bool locatorSeen = false;
        for (const std::string& op : db.ops) {
            if (op == "locator") locatorSeen = true;
        }
        if (fail < 3) EXPECT_FALSE(locatorSeen) << "locator written after failed write " << fail;
        EXPECT_NE("commit", db.ops.back());
    }
}

// ---- re-adding a note transaction ----------------------------------------------

TEST_F(StateFixture, ReaddedNoteTransactionKeepsItsNullifier)
{
    uint256 t = Mine(1000); Mine(0); Mine(0);
    ASSERT_TRUE(Note(t).nullifier);
    uint256 nf = *Note(t).nullifier;
    ASSERT_FALSE(Note(t).witnesses.empty());

    // A block reconnected after a rollback or a reindex, or a transaction announced again
    // after a disconnect: the wallet sees the same transaction once more.
    {
        LOCK2(cs_main, wallet->cs_wallet);
        wallet->SyncTransaction(Tx(t), &chain.blocks[chain.index[0].nHeight + 1]);
        wallet->SyncTransaction(Tx(t), nullptr);
    }
    ASSERT_FALSE(Note(t).witnesses.empty());
    ASSERT_TRUE(Note(t).nullifier) << "the witness is kept, the nullifier must be too";
    EXPECT_EQ(nf, *Note(t).nullifier);

    // and the record that goes to wallet.dat has both
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << Tx(t);
    CWalletTx back;
    ss >> back;
    ASSERT_EQ(1u, back.mapSaplingNoteData.size());
    EXPECT_TRUE(back.mapSaplingNoteData.begin()->second.nullifier);
    EXPECT_FALSE(back.mapSaplingNoteData.begin()->second.witnesses.empty());
}

// ---- startup reconciliation ----------------------------------------------------

TEST_F(StateFixture, ReconcileLeavesAConsistentWalletAlone)
{
    uint256 t = Mine(1000); Mine(0); Mine(0);
    LOCK2(cs_main, wallet->cs_wallet);
    CBlockIndex* tip = chainActive.Tip();
    CBlockIndex* pindexRescan = tip;
    size_t sz = Note(t).witnesses.size();
    EXPECT_FALSE(wallet->ReconcileNoteState(pindexRescan));
    EXPECT_EQ(tip, pindexRescan);
    EXPECT_EQ(sz, Note(t).witnesses.size());
    EXPECT_EQ(tip->nHeight, Note(t).witnessHeight);
}

TEST_F(StateFixture, ReconcileDerivesAMissingNullifier)
{
    uint256 t = Mine(1000); Mine(0);
    uint256 nf = *Note(t).nullifier;
    Note(t).nullifier = boost::none; // what an older build could leave in wallet.dat
    LOCK2(cs_main, wallet->cs_wallet);
    CBlockIndex* pindexRescan = chainActive.Tip();
    EXPECT_TRUE(wallet->ReconcileNoteState(pindexRescan));
    ASSERT_TRUE(Note(t).nullifier);
    EXPECT_EQ(nf, *Note(t).nullifier);
    EXPECT_EQ(chainActive.Tip(), pindexRescan);
}

TEST_F(StateFixture, ReconcileCutsAWitnessCacheBackToAChainThatWasRolledBack)
{
    uint256 t = Mine(1000);
    for (int i = 0; i < 5; i++) Mine(0);
    LOCK2(cs_main, wallet->cs_wallet);
    int nTipHeight = chainActive.Height();
    ASSERT_EQ(nTipHeight, Note(t).witnessHeight);
    size_t before = Note(t).witnesses.size();

    // the chain state was flushed three blocks ago and the node was killed: the chain is
    // behind the wallet
    chainActive.SetTip(&chain.index[nTipHeight - 3]);
    CBlockIndex* pindexRescan = chainActive.Tip();
    EXPECT_TRUE(wallet->ReconcileNoteState(pindexRescan));
    EXPECT_EQ(nTipHeight - 3, Note(t).witnessHeight);
    EXPECT_EQ(before - 3, Note(t).witnesses.size());
    EXPECT_EQ(chainActive.Tip()->hashFinalSaplingRoot, Note(t).witnesses.front().root());
    EXPECT_EQ(chainActive.Tip(), pindexRescan);
    // the nullifier is untouched
    EXPECT_TRUE(Note(t).nullifier);
}

TEST_F(StateFixture, ReconcileDropsAWitnessCacheThatIsNotOnTheChain)
{
    uint256 t = Mine(1000);
    for (int i = 0; i < 4; i++) Mine(0);
    LOCK2(cs_main, wallet->cs_wallet);
    int nTipHeight = chainActive.Height();
    // The locator shares block 2 with the chain; above that the wallet's cache follows another
    // branch: the chain has a different tree at the height the cache claims.
    chain.index[nTipHeight].hashFinalSaplingRoot = SeededHash(rng);
    CBlockIndex* pindexRescan = &chain.index[2];
    EXPECT_TRUE(wallet->ReconcileNoteState(pindexRescan));
    EXPECT_TRUE(Note(t).witnesses.empty());
    EXPECT_EQ(-1, Note(t).witnessHeight);
    // the block that holds the note (the first one) is where the rescan has to begin
    ASSERT_NE(nullptr, pindexRescan);
    EXPECT_EQ(0, pindexRescan->nHeight);
}

TEST_F(StateFixture, ReconcileStartsTheRescanWhereALaggingCacheEnds)
{
    uint256 t = Mine(1000);
    for (int i = 0; i < 6; i++) Mine(0);
    LOCK2(cs_main, wallet->cs_wallet);
    int nTipHeight = chainActive.Height();
    // a record written while the node was reconnecting blocks: the cache ends 4 blocks
    // before the locator, and is a valid cache for that height
    for (int i = 0; i < 4; i++) Note(t).witnesses.pop_front();
    Note(t).witnessHeight = nTipHeight - 4;
    CBlockIndex* pindexRescan = chainActive.Tip();
    EXPECT_TRUE(wallet->ReconcileNoteState(pindexRescan));
    EXPECT_EQ(nTipHeight - 4, Note(t).witnessHeight); // kept: it matches the chain
    EXPECT_FALSE(Note(t).witnesses.empty());
    ASSERT_NE(nullptr, pindexRescan);
    EXPECT_EQ(nTipHeight - 4, pindexRescan->nHeight);
}

TEST_F(StateFixture, ReconcileRebuildsAConfirmedNoteWithoutAWitness)
{
    uint256 t = Mine(1000); Mine(0); Mine(0);
    LOCK2(cs_main, wallet->cs_wallet);
    Note(t).witnesses.clear();
    Note(t).witnessHeight = chainActive.Height(); // the claim is there, the witness is not
    Note(t).nullifier = boost::none;
    CBlockIndex* pindexRescan = chainActive.Tip();
    EXPECT_TRUE(wallet->ReconcileNoteState(pindexRescan));
    EXPECT_EQ(-1, Note(t).witnessHeight);
    ASSERT_NE(nullptr, pindexRescan);
    EXPECT_EQ(0, pindexRescan->nHeight);
}

TEST_F(StateFixture, ReconcileLeavesAnUnconfirmedNoteAlone)
{
    Mine(0);
    // a transaction that paid the wallet and is still in the mempool: no block, no witness
    CMutableTransaction mtx = BaseTx(rng);
    mtx.vShieldedOutput.push_back(SaplingOutputTo(rng, addr, 5000));
    CTransaction tx(mtx);
    {
        LOCK2(cs_main, wallet->cs_wallet);
        wallet->SyncTransaction(tx, nullptr);
    }
    Mine(0); Mine(0); // blocks without it: the wallet moves the witness height of every note forward
    LOCK2(cs_main, wallet->cs_wallet);
    ASSERT_EQ(1u, wallet->mapWallet.count(tx.GetHash()));
    ASSERT_TRUE(Note(tx.GetHash()).witnesses.empty());
    int h = Note(tx.GetHash()).witnessHeight;
    CBlockIndex* pindexRescan = chainActive.Tip();
    EXPECT_FALSE(wallet->ReconcileNoteState(pindexRescan)) << "nothing was wrong";
    EXPECT_EQ(h, Note(tx.GetHash()).witnessHeight);
    EXPECT_EQ(chainActive.Tip(), pindexRescan);
}

TEST_F(StateFixture, ReconcileResetsAnUnconfirmedNoteWhoseHeightLagsTheChain)
{
    Mine(0);
    CMutableTransaction mtx = BaseTx(rng);
    mtx.vShieldedOutput.push_back(SaplingOutputTo(rng, addr, 5000));
    CTransaction tx(mtx);
    {
        LOCK2(cs_main, wallet->cs_wallet);
        wallet->SyncTransaction(tx, nullptr);
    }
    for (int i = 0; i < 4; i++) Mine(0);
    LOCK2(cs_main, wallet->cs_wallet);
    // A record written when the chain was three blocks shorter, read back after a crash: no
    // witness, and a height that is neither -1 nor the tip. The next block that is connected or
    // disconnected asserts on it.
    Note(tx.GetHash()).witnessHeight = chainActive.Height() - 3;
    CBlockIndex* pindexRescan = chainActive.Tip();
    EXPECT_TRUE(wallet->ReconcileNoteState(pindexRescan));
    EXPECT_EQ(-1, Note(tx.GetHash()).witnessHeight);
    EXPECT_EQ(chainActive.Tip(), pindexRescan);
}
