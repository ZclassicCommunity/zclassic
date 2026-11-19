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
#include "zcash/JoinSplit.hpp"
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
    bool WitnessesLost() const { return fNoteWitnessesLost; }
    size_t LiveNoteTxs() const { return setNoteTxIndex.size(); }
    size_t RetiredNoteTxs() const { return setNoteTxRetired.size(); }
    void CollectLive(std::vector<CWalletTx*>& out) { CollectNoteTxs(out); }
    void CollectAll(std::vector<CWalletTx*>& out) { CollectNoteTxs(out, true); }
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
    bool TxnCommit() { inTxn = false; ops.push_back("commit"); if (failCommit) return false; committed = true; return true; }
    bool TxnAbort() { inTxn = false; aborted = true; ops.push_back("abort"); return true; }
    std::vector<uint256> written;
    bool failCommit = false;
    bool WriteTx(uint256 h, const CWalletTx&) { written.push_back(h); return WriteStep("tx"); }
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
            for (const JSDescription& jsdesc : tx.vjoinsplit) {
                for (const uint256& cm : jsdesc.commitments) sprout.append(cm);
            }
        }
        bi.hashFinalSaplingRoot = sapling.root();
        bi.hashFinalSproutRoot = sprout.root();
    }

    /** Disconnect the tip the way DisconnectTip does (the block index stays known). */
    void Disconnect(StateWallet& wallet) {
        LOCK2(cs_main, wallet.cs_wallet);
        CBlockIndex* pindex = chainActive.Tip();
        ASSERT_TRUE(pindex != nullptr);
        const CBlock& block = blocks[pindex->nHeight];
        chainActive.SetTip(pindex->pprev);
        for (const CTransaction& tx : block.vtx) wallet.SyncTransaction(tx, nullptr);
        wallet.ChainTip(pindex, &block, sprout, sapling, false);
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
    // one block: a stand-in coinbase and a transaction that spends the Sapling note of tx t
    uint256 MineSpendOf(const uint256& t) {
        CBlock block;
        block.vtx.push_back(CTransaction(BaseTx(rng)));
        CMutableTransaction mtx = BaseTx(rng);
        SpendDescription sd;
        sd.nullifier = *wallet->mapWallet.at(t).mapSaplingNoteData.begin()->second.nullifier;
        mtx.vShieldedSpend.push_back(sd);
        block.vtx.push_back(CTransaction(mtx));
        uint256 txid = block.vtx.back().GetHash();
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

// ---- retiring the notes of buried spends -----------------------------------------------------

extern ZCJoinSplit* params;

namespace {

struct RetireFixture : public StateFixture {
    void MineN(int n) { for (int i = 0; i < n; i++) Mine(0); }
    int Depth(const uint256& txid) {
        LOCK2(cs_main, wallet->cs_wallet);
        return Tx(txid).GetDepthInMainChain();
    }
    // mine until the spending block has the given depth
    void MineToDepth(const uint256& spender, int depth) {
        while (Depth(spender) < depth) Mine(0);
        ASSERT_EQ(depth, Depth(spender));
    }
    int TipHeight() { LOCK(cs_main); return chainActive.Height(); }
    /** What LoadWallet does with a record read back from wallet.dat. */
    void Reload(const uint256& txid, int nWitnessHeightOnDisk = -2) {
        LOCK2(cs_main, wallet->cs_wallet);
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << Tx(txid);
        CWalletTx copy;
        ss >> copy;
        if (nWitnessHeightOnDisk != -2) {
            for (auto& item : copy.mapSaplingNoteData) item.second.witnessHeight = nWitnessHeightOnDisk;
        }
        wallet->AddToWallet(copy, true, nullptr);
    }
};

} // namespace

TEST_F(RetireFixture, ASpendBuriedDeeperThanTheWitnessCacheRetiresTheNote)
{
    uint256 a = Mine(1000), b = Mine(2000); Mine(0);
    uint256 nf = *Note(a).nullifier;
    uint256 sp = MineSpendOf(a);

    MineToDepth(sp, (int)WITNESS_CACHE_SIZE); // exactly 100: not yet
    {
        LOCK2(cs_main, wallet->cs_wallet);
        EXPECT_EQ(0u, wallet->RetireSpentNotes());
        EXPECT_FALSE(Note(a).fRetired);
        EXPECT_FALSE(Note(a).witnesses.empty());
        EXPECT_TRUE(wallet->IsSaplingSpent(nf));
        EXPECT_EQ(0u, wallet->CountRetiredNotes());
    }
    Mine(0); // depth 101
    {
        LOCK2(cs_main, wallet->cs_wallet);
        ASSERT_EQ((int)WITNESS_CACHE_SIZE + 1, Tx(sp).GetDepthInMainChain());
        wallet->RetireSpentNotes();
        EXPECT_TRUE(Note(a).fRetired);
        EXPECT_TRUE(Note(a).witnesses.empty());
        EXPECT_EQ(-1, Note(a).witnessHeight);
        ASSERT_TRUE(Note(a).nullifier) << "the nullifier is what keeps the note spent";
        EXPECT_EQ(nf, *Note(a).nullifier);
        EXPECT_TRUE(wallet->IsSaplingSpent(nf));
        EXPECT_EQ(1u, wallet->CountRetiredNotes());
        EXPECT_EQ(1u, wallet->RetiredNoteTxs());
        EXPECT_EQ(1u, wallet->LiveNoteTxs());
        // the unspent note is untouched
        EXPECT_FALSE(Note(b).fRetired);
        EXPECT_EQ(chainActive.Height(), Note(b).witnessHeight);
        EXPECT_FALSE(Note(b).witnesses.empty());
    }
    // later blocks leave the retired record alone and keep witnessing the other note
    MineN(5);
    LOCK2(cs_main, wallet->cs_wallet);
    EXPECT_TRUE(Note(a).witnesses.empty());
    EXPECT_EQ(-1, Note(a).witnessHeight);
    EXPECT_EQ(chainActive.Height(), Note(b).witnessHeight);
    EXPECT_EQ(chainActive.Tip()->hashFinalSaplingRoot, Note(b).witnesses.front().root());
    std::vector<CWalletTx*> live, all;
    wallet->CollectLive(live);
    wallet->CollectAll(all);
    EXPECT_EQ(1u, live.size()) << "the block updates only see the transaction with a live note";
    EXPECT_EQ(2u, all.size());
}

TEST_F(RetireFixture, TheBlockUpdatesRetireByThemselves)
{
    uint256 a = Mine(1000); Mine(0);
    uint256 sp = MineSpendOf(a);
    // no explicit call: the periodic sweep of the block updates finds it
    MineToDepth(sp, (int)WITNESS_CACHE_SIZE + 1 + (int)RETIRE_SWEEP_INTERVAL);
    LOCK2(cs_main, wallet->cs_wallet);
    EXPECT_TRUE(Note(a).fRetired);
    EXPECT_TRUE(Note(a).witnesses.empty());
    EXPECT_EQ(-1, Note(a).witnessHeight);
}

TEST_F(RetireFixture, AnUnspentOrRecentlySpentNoteIsNeverRetired)
{
    uint256 a = Mine(1000), b = Mine(2000);
    MineSpendOf(a);
    MineN(60);
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->RetireSpentNotes();
    EXPECT_FALSE(Note(a).fRetired); // spent 61 deep
    EXPECT_FALSE(Note(b).fRetired); // never spent
    EXPECT_FALSE(Note(a).witnesses.empty());
    EXPECT_FALSE(Note(b).witnesses.empty());
}

TEST_F(RetireFixture, ReconcileDoesNotAskForARescanForARetiredNote)
{
    uint256 a = Mine(1000); Mine(0);
    uint256 sp = MineSpendOf(a);
    MineToDepth(sp, (int)WITNESS_CACHE_SIZE + 1);
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->RetireSpentNotes();
    ASSERT_TRUE(Note(a).witnesses.empty());
    CBlockIndex* pindexRescan = chainActive.Tip();
    EXPECT_FALSE(wallet->ReconcileNoteState(pindexRescan)) << "a retired note has no witness on purpose";
    EXPECT_EQ(chainActive.Tip(), pindexRescan);
    EXPECT_EQ(-1, Note(a).witnessHeight);
}

TEST_F(RetireFixture, ALoadedRetiredRecordIsRetiredAgainWithoutARescan)
{
    uint256 a = Mine(1000); uint256 b = Mine(2000);
    uint256 sp = MineSpendOf(a);
    MineToDepth(sp, (int)WITNESS_CACHE_SIZE + 1);
    { LOCK2(cs_main, wallet->cs_wallet); wallet->RetireSpentNotes(); }
    Reload(a); // wallet.dat holds witnesses={} height -1, the memory-only flag is gone
    LOCK2(cs_main, wallet->cs_wallet);
    ASSERT_FALSE(Note(a).fRetired);
    CBlockIndex* pindexRescan = chainActive.Tip();
    EXPECT_FALSE(wallet->ReconcileNoteState(pindexRescan)) << "the stored record was already in the retired form";
    EXPECT_TRUE(Note(a).fRetired);
    EXPECT_EQ(chainActive.Tip(), pindexRescan);
    EXPECT_FALSE(Note(b).fRetired);
}

TEST_F(RetireFixture, ARetiredRecordAnOlderBinaryRewroteIsPutBack)
{
    uint256 a = Mine(1000); Mine(0);
    uint256 sp = MineSpendOf(a);
    MineToDepth(sp, (int)WITNESS_CACHE_SIZE + 1);
    { LOCK2(cs_main, wallet->cs_wallet); wallet->RetireSpentNotes(); }
    int nTip = TipHeight();
    // the previous release moves the height of every note forward, witness or not
    Reload(a, nTip);
    LOCK2(cs_main, wallet->cs_wallet);
    ASSERT_EQ(nTip, Note(a).witnessHeight);
    CBlockIndex* pindexRescan = chainActive.Tip();
    EXPECT_TRUE(wallet->ReconcileNoteState(pindexRescan)) << "the record changes, so it is written back";
    EXPECT_TRUE(Note(a).fRetired);
    EXPECT_EQ(-1, Note(a).witnessHeight);
    EXPECT_EQ(chainActive.Tip(), pindexRescan) << "no rescan";
}

TEST_F(RetireFixture, ARetiredRecordPassesTheInvariantOfThePreviousRelease)
{
    uint256 a = Mine(1000); Mine(0);
    uint256 sp = MineSpendOf(a);
    MineToDepth(sp, (int)WITNESS_CACHE_SIZE + 1);
    { LOCK2(cs_main, wallet->cs_wallet); wallet->RetireSpentNotes(); }
    // the record as wallet.dat holds it
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    { LOCK2(cs_main, wallet->cs_wallet); ss << Tx(a); }
    CWalletTx back;
    ss >> back;
    ASSERT_EQ(1u, back.mapSaplingNoteData.size());
    SaplingNoteData rec = back.mapSaplingNoteData.begin()->second;
    EXPECT_TRUE(rec.witnesses.empty());
    EXPECT_EQ(-1, rec.witnessHeight);
    EXPECT_TRUE(rec.nullifier);
    EXPECT_FALSE(rec.fRetired) << "the flag is memory only";

    // The previous release's per-block logic (CopyPreviousWitnesses, UpdateWitnessHeights and
    // DecrementNoteWitnesses, unchanged from before this change), with its asserts as expectations.
    int nHeight = TipHeight();
    for (int i = 1; i <= 5; i++) {
        const int indexHeight = nHeight + i;
        if (rec.witnessHeight < indexHeight) {
            EXPECT_TRUE(rec.witnessHeight == -1 || rec.witnessHeight == indexHeight - 1) << "assert in CopyPreviousWitnesses";
            if (rec.witnesses.size() > 0) rec.witnesses.push_front(rec.witnesses.front());
        }
        if (rec.witnessHeight < indexHeight) rec.witnessHeight = indexHeight; // UpdateWitnessHeights
    }
    for (int i = 5; i >= 1; i--) {
        const int indexHeight = nHeight + i;
        bool fLost = false;
        if (rec.witnessHeight <= indexHeight) {
            const bool fHad = !rec.witnesses.empty();
            if (fHad && rec.witnessHeight != -1 && rec.witnessHeight != indexHeight) fLost = true;
            else if (fHad) rec.witnesses.pop_front();
            rec.witnessHeight = indexHeight - 1;
        }
        EXPECT_FALSE(fLost);
    }
    EXPECT_TRUE(rec.witnesses.empty());
    EXPECT_EQ(nHeight, rec.witnessHeight);
}

TEST_F(RetireFixture, AnUnwindThatReachesTheSpendBringsTheNoteBack)
{
    uint256 a = Mine(1000); Mine(0); // the only note: its witness is the one the unwind has to bring back
    uint256 nf = *Note(a).nullifier;
    uint256 sp = MineSpendOf(a);
    const int nSpendHeight = TipHeight();
    MineToDepth(sp, (int)WITNESS_CACHE_SIZE + 1 + (int)RETIRE_SWEEP_INTERVAL);
    { LOCK2(cs_main, wallet->cs_wallet); ASSERT_TRUE(Note(a).fRetired); }

    // an operator invalidateblock/parkblock goes as deep as it likes: unwind to just above the spend
    while (TipHeight() >= nSpendHeight) {
        chain.Disconnect(*wallet);
        LOCK2(cs_main, wallet->cs_wallet);
        if (chainActive.Height() >= nSpendHeight) {
            EXPECT_TRUE(Note(a).fRetired) << "at height " << chainActive.Height();
            EXPECT_FALSE(wallet->WitnessesLost());
            EXPECT_TRUE(wallet->IsSaplingSpent(nf));
        }
    }
    // the last block the loop disconnected was the one with the spend
    LOCK2(cs_main, wallet->cs_wallet);
    EXPECT_FALSE(Note(a).fRetired);
    EXPECT_TRUE(wallet->WitnessesLost()) << "the rebuild that restores the witness is armed";
    EXPECT_FALSE(wallet->IsSaplingSpent(nf)) << "the spend is gone: the note is unspent again";
    ASSERT_TRUE(Note(a).nullifier);
    EXPECT_EQ(nf, *Note(a).nullifier);
    EXPECT_EQ(1u, wallet->LiveNoteTxs());
    EXPECT_EQ(0u, wallet->RetiredNoteTxs());
    EXPECT_EQ(0u, wallet->CountRetiredNotes());
}

TEST_F(RetireFixture, AReorgOfTwentyFiveBlocksStillUnspendsARecentSpend)
{
    uint256 a = Mine(1000); Mine(0);
    uint256 nf = *Note(a).nullifier;
    MineN(30);
    uint256 sp = MineSpendOf(a);
    MineN(20);
    ASSERT_EQ(21, Depth(sp));
    for (int i = 0; i < 25; i++) chain.Disconnect(*wallet); // 20 blocks above the spend, the spend, 4 below
    LOCK2(cs_main, wallet->cs_wallet);
    EXPECT_FALSE(wallet->IsSaplingSpent(nf));
    EXPECT_FALSE(Note(a).fRetired);
    EXPECT_FALSE(wallet->WitnessesLost()) << "a witness cache of 100 rolls back 25 blocks";
    ASSERT_FALSE(Note(a).witnesses.empty());
    EXPECT_EQ(chainActive.Height(), Note(a).witnessHeight);
    EXPECT_EQ(chainActive.Tip()->hashFinalSaplingRoot, Note(a).witnesses.front().root());
}

TEST_F(RetireFixture, ASproutNoteIsRetiredToo)
{
    auto sk = libzcash::SproutSpendingKey::random();
    {
        LOCK(wallet->cs_wallet);
        ASSERT_TRUE(wallet->AddSproutSpendingKey(sk));
    }
    CWalletTx recv = GetValidSproutReceive(*params, sk, 10, true);
    CWalletTx other = GetValidSproutReceive(*params, sk, 20, true);
    uint256 rh = recv.GetHash(), oh = other.GetHash();
    for (const CWalletTx* w : {&recv, &other}) {
        CBlock block;
        block.vtx.push_back(CTransaction(BaseTx(rng)));
        block.vtx.push_back(CTransaction(*w));
        chain.Connect(*wallet, block);
    }
    Mine(0);
    JSOutPoint op {rh, 0, 1};
    uint256 nf;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        ASSERT_EQ(1u, wallet->mapWallet.at(rh).mapSproutNoteData.count(op));
        SproutNoteData& nd = wallet->mapWallet.at(rh).mapSproutNoteData.at(op);
        ASSERT_TRUE(nd.nullifier);
        ASSERT_FALSE(nd.witnesses.empty());
        nf = *nd.nullifier;
    }
    auto note = GetSproutNote(*params, sk, recv, 0, 1);
    CWalletTx spend = GetValidSproutSpend(*params, sk, note, 5);
    uint256 sp = spend.GetHash();
    {
        CBlock block;
        block.vtx.push_back(CTransaction(BaseTx(rng)));
        block.vtx.push_back(CTransaction(spend));
        chain.Connect(*wallet, block);
    }
    MineToDepth(sp, (int)WITNESS_CACHE_SIZE + 1 + (int)RETIRE_SWEEP_INTERVAL);
    LOCK2(cs_main, wallet->cs_wallet);
    SproutNoteData& nd = wallet->mapWallet.at(rh).mapSproutNoteData.at(op);
    EXPECT_TRUE(nd.fRetired);
    EXPECT_TRUE(nd.witnesses.empty());
    EXPECT_EQ(-1, nd.witnessHeight);
    EXPECT_TRUE(wallet->IsSproutSpent(nf));
    // the other Sprout note keeps its witness
    SproutNoteData& od = wallet->mapWallet.at(oh).mapSproutNoteData.begin()->second;
    EXPECT_FALSE(od.fRetired);
    EXPECT_FALSE(od.witnesses.empty());
    EXPECT_EQ(chainActive.Height(), od.witnessHeight);
}

// ---- the checkpoint writes only the note transactions that changed ----------------------------

namespace {

struct CheckpointFixture : public RetireFixture {
    CBlockLocator Loc() { LOCK(cs_main); return chainActive.GetLocator(); }
    /** One checkpoint into a recording database; returns what it wrote. */
    std::vector<uint256> Checkpoint(RecordingDB& db) {
        LOCK2(cs_main, wallet->cs_wallet);
        wallet->Checkpoint(db, chainActive.GetLocator());
        return db.written;
    }
    std::vector<uint256> Checkpoint() { RecordingDB db; return Checkpoint(db); }
    static std::vector<uint256> Sorted(std::vector<uint256> v) { std::sort(v.begin(), v.end()); return v; }
};

} // namespace

TEST_F(CheckpointFixture, AnUnchangedWalletWritesNoTransaction)
{
    uint256 a = Mine(1000), b = Mine(2000); Mine(0);
    EXPECT_EQ(Sorted({a, b}), Sorted(Checkpoint())) << "the first checkpoint writes what the blocks changed";
    RecordingDB db;
    EXPECT_TRUE(Checkpoint(db).empty()) << "nothing changed since";
    // the cache size and the locator still go in one database transaction
    std::vector<std::string> want = {"begin", "cachesize", "locator", "commit"};
    EXPECT_EQ(want, db.ops);
    EXPECT_TRUE(db.committed);
    {
        LOCK(wallet->cs_wallet);
        EXPECT_EQ(0u, wallet->CountDirtyNoteTxs());
    }
}

TEST_F(CheckpointFixture, ABlockMarksEveryLiveNoteTransaction)
{
    uint256 a = Mine(1000), b = Mine(2000); Mine(0);
    Checkpoint();
    Mine(0);
    EXPECT_EQ(Sorted({a, b}), Sorted(Checkpoint())) << "every witness moved";
    EXPECT_TRUE(Checkpoint().empty());
}

TEST_F(CheckpointFixture, ADisconnectMarksEveryLiveNoteTransaction)
{
    uint256 a = Mine(1000), b = Mine(2000); Mine(0); Mine(0);
    Checkpoint();
    chain.Disconnect(*wallet);
    EXPECT_EQ(Sorted({a, b}), Sorted(Checkpoint()));
    EXPECT_TRUE(Checkpoint().empty());
}

TEST_F(CheckpointFixture, ARetiredNoteIsWrittenOnceAndThenLeftOut)
{
    uint256 a = Mine(1000), b = Mine(2000); Mine(0);
    uint256 sp = MineSpendOf(a);
    MineToDepth(sp, (int)WITNESS_CACHE_SIZE);
    EXPECT_EQ(Sorted({a, b}), Sorted(Checkpoint())) << "spent but not yet deep: both are live";
    MineToDepth(sp, (int)WITNESS_CACHE_SIZE + 1 + (int)RETIRE_SWEEP_INTERVAL);
    {
        LOCK2(cs_main, wallet->cs_wallet);
        ASSERT_TRUE(Note(a).fRetired);
    }
    // the retiring block changed both: a (emptied) and b (moved)
    EXPECT_EQ(Sorted({a, b}), Sorted(Checkpoint()));
    Mine(0);
    EXPECT_EQ(std::vector<uint256>({b}), Checkpoint()) << "only the unspent note moves";
    Mine(0); Mine(0);
    EXPECT_EQ(std::vector<uint256>({b}), Checkpoint());
}

TEST_F(CheckpointFixture, AFailedCheckpointLeavesTheRecordsMarked)
{
    uint256 a = Mine(1000), b = Mine(2000); Mine(0);
    {
        RecordingDB db;
        db.failAt = 1; // the second transaction
        Checkpoint(db);
        EXPECT_TRUE(db.aborted);
        EXPECT_FALSE(db.committed);
    }
    {
        RecordingDB db;
        db.failAt = 2; // the cache size
        Checkpoint(db);
        EXPECT_TRUE(db.aborted);
    }
    {
        RecordingDB db;
        db.failCommit = true;
        EXPECT_EQ(2u, Checkpoint(db).size());
        EXPECT_FALSE(db.committed);
    }
    EXPECT_EQ(Sorted({a, b}), Sorted(Checkpoint())) << "still written once a checkpoint goes through";
    EXPECT_TRUE(Checkpoint().empty());
}

TEST_F(CheckpointFixture, ReconcileMarksTheRecordsItRepairs)
{
    uint256 a = Mine(1000), b = Mine(2000); Mine(0);
    Checkpoint();
    {
        LOCK2(cs_main, wallet->cs_wallet);
        Note(a).nullifier = boost::none; // what an older build could leave in wallet.dat
        CBlockIndex* pindexRescan = chainActive.Tip();
        ASSERT_TRUE(wallet->ReconcileNoteState(pindexRescan));
    }
    EXPECT_EQ(std::vector<uint256>({a}), Checkpoint()) << "only the repaired record";
    {
        // a cache that is ahead of the chain is cut back: only that note
        LOCK2(cs_main, wallet->cs_wallet);
        int nTip = chainActive.Height();
        chainActive.SetTip(&chain.index[nTip - 1]);
        CBlockIndex* pindexRescan = chainActive.Tip();
        ASSERT_TRUE(wallet->ReconcileNoteState(pindexRescan));
    }
    EXPECT_EQ(Sorted({a, b}), Sorted(Checkpoint()));
}

TEST_F(CheckpointFixture, ClearingTheWitnessCacheMarksEveryNoteTransaction)
{
    uint256 a = Mine(1000), b = Mine(2000); Mine(0);
    Checkpoint();
    { LOCK(wallet->cs_wallet); wallet->ClearNoteWitnessCache(); }
    EXPECT_EQ(Sorted({a, b}), Sorted(Checkpoint()));
}

TEST_F(CheckpointFixture, ANewNoteTransactionAndAMergedOneAreMarked)
{
    uint256 a = Mine(1000); Mine(0);
    Checkpoint();
    // a note that arrives unconfirmed (AddToWallet inserts it)
    CMutableTransaction mtx = BaseTx(rng);
    mtx.vShieldedOutput.push_back(SaplingOutputTo(rng, addr, 5000));
    CTransaction tx(mtx);
    {
        LOCK2(cs_main, wallet->cs_wallet);
        wallet->SyncTransaction(tx, nullptr);
    }
    EXPECT_EQ(std::vector<uint256>({tx.GetHash()}), Checkpoint());
    // and the block that confirms it (merge: hashBlock, merkle branch, witness)
    CBlock block;
    block.vtx.push_back(CTransaction(BaseTx(rng)));
    block.vtx.push_back(tx);
    chain.Connect(*wallet, block);
    EXPECT_EQ(Sorted({a, tx.GetHash()}), Sorted(Checkpoint()));
}

TEST_F(CheckpointFixture, ATransactionThatLeavesTheWalletIsNotWritten)
{
    uint256 a = Mine(1000), b = Mine(2000); Mine(0);
    {
        LOCK2(cs_main, wallet->cs_wallet);
        wallet->MarkNoteTxDirty(GetRandHash()); // a hash the wallet does not hold
    }
    EXPECT_EQ(Sorted({a, b}), Sorted(Checkpoint()));
    EXPECT_TRUE(Checkpoint().empty());
    LOCK(wallet->cs_wallet);
    EXPECT_EQ(0u, wallet->CountDirtyNoteTxs());
}
