// The wallet health report behind getwalletinfo "health" and the wallet transaction "status".
//
// CWallet::GetHealth counts, per pool, notes that are spent and unspent and the witness state of
// the unspent ones; counts the wallet's own unmined sends; and reports the rebuild flag, the
// witness cache size and the checkpoint height. CWallet::TxStatus names a wallet transaction's
// state. Both are read-only passes over mapWallet; the last test measures one on 100000
// transactions.

#include <gtest/gtest.h>

#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "txmempool.h"
#include "util.h"
#include "utiltest.h"
#include "wallet/wallet.h"

#include <chrono>
#include <random>

namespace {

class HealthWallet : public CWallet {
public:
    HealthWallet() : CWallet() { }
    void SetLost(bool f) { fNoteWitnessesLost = f; }
    void SetCacheSize(int64_t n) { nWitnessCacheSize = n; }
    void SetCheckpoint(int h) { nCheckpointHeight = h; }
};

uint256 Seeded(std::mt19937_64& rng)
{
    uint256 h;
    for (size_t i = 0; i < 32; i += 8) {
        uint64_t v = rng();
        for (size_t k = 0; k < 8; k++) *(h.begin() + i + k) = (unsigned char)(v >> (8 * k));
    }
    return h;
}

CMutableTransaction BaseTx(std::mt19937_64& rng, uint32_t expiry = 0)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.nExpiryHeight = expiry;
    mtx.vin.push_back(CTxIn(COutPoint(Seeded(rng), 0)));
    mtx.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    return mtx;
}

SaplingWitness OneWitness()
{
    SaplingMerkleTree t;
    t.append(uint256S("01"));
    return t.witness();
}

/** A tip at height nHeight that wallet transactions can claim to be in. */
struct FakeChain {
    CBlock block;
    CBlockIndex index;
    uint256 hash;
    explicit FakeChain(int nHeight) {
        block.nVersion = 4;
        block.hashMerkleRoot = uint256S("77");
        index = CBlockIndex(block);
        index.nHeight = nHeight;
        hash = block.GetHash();
        mapBlockIndex.insert(std::make_pair(hash, &index));
        index.phashBlock = &mapBlockIndex.find(hash)->first;
        chainActive.SetTip(&index);
    }
    ~FakeChain() {
        chainActive.SetTip(NULL);
        mapBlockIndex.erase(hash);
    }
    void Mine(CWalletTx& wtx) {
        wtx.hashBlock = hash;
        wtx.nIndex = 0;
        wtx.fMerkleVerified = true;
    }
};

} // namespace

TEST(WalletHealth, EmptyWalletAndFlags) {
    HealthWallet wallet;
    LOCK2(cs_main, wallet.cs_wallet);
    CWallet::Health h;
    wallet.GetHealth(h);
    EXPECT_EQ(-1, h.nTipHeight);
    EXPECT_EQ(-1, h.nCheckpointHeight);
    EXPECT_EQ(0, h.nWitnessCacheSize);
    EXPECT_FALSE(h.fWitnessRebuildPending);
    EXPECT_EQ(0u, h.sapling.nUnspent + h.sapling.nSpent + h.sprout.nUnspent + h.sprout.nSpent);

    wallet.SetLost(true);
    wallet.SetCacheSize(57);
    wallet.SetCheckpoint(12);
    wallet.GetHealth(h);
    EXPECT_TRUE(h.fWitnessRebuildPending);
    EXPECT_EQ(57, h.nWitnessCacheSize);
    EXPECT_EQ(12, h.nCheckpointHeight);
    wallet.SetLost(false);
    wallet.GetHealth(h);
    EXPECT_FALSE(h.fWitnessRebuildPending);
}

TEST(WalletHealth, FailedCheckpointIsReported) {
    HealthWallet wallet;
    CWallet::Health h;
    {
        LOCK2(cs_main, wallet.cs_wallet);
        wallet.GetHealth(h);
    }
    EXPECT_FALSE(h.fCheckpointFailed);
    EXPECT_EQ(0, h.nCheckpointFailures);
    wallet.NoteCheckpointResult(false);
    wallet.NoteCheckpointResult(false);
    {
        LOCK2(cs_main, wallet.cs_wallet);
        wallet.GetHealth(h);
    }
    EXPECT_TRUE(h.fCheckpointFailed);
    EXPECT_EQ(2, h.nCheckpointFailures);
    // A later success clears the flag; the count of failures since start stays.
    wallet.NoteCheckpointResult(true);
    {
        LOCK2(cs_main, wallet.cs_wallet);
        wallet.GetHealth(h);
    }
    EXPECT_FALSE(h.fCheckpointFailed);
    EXPECT_EQ(2, h.nCheckpointFailures);
}

TEST(WalletHealth, SaplingNoteStates) {
    RegtestActivateSapling();
    {
        std::mt19937_64 rng(5);
        HealthWallet wallet;
        FakeChain chain(10);
        LOCK2(cs_main, wallet.cs_wallet);

        // one mined transaction holding five notes: ready, missing, stale, spent, spent-with-witness
        CMutableTransaction m = BaseTx(rng);
        CWalletTx wtx(&wallet, CTransaction(m));
        uint256 id = wtx.GetHash();
        uint256 nf[5];
        for (int i = 0; i < 5; i++) nf[i] = Seeded(rng);
        SaplingNoteData nd;
        nd.nullifier = nf[0]; nd.witnesses.push_back(OneWitness()); nd.witnessHeight = 10;
        wtx.mapSaplingNoteData[SaplingOutPoint(id, 0)] = nd;
        nd = SaplingNoteData(); nd.nullifier = nf[1];
        wtx.mapSaplingNoteData[SaplingOutPoint(id, 1)] = nd;
        nd = SaplingNoteData(); nd.nullifier = nf[2]; nd.witnesses.push_back(OneWitness()); nd.witnessHeight = 7;
        wtx.mapSaplingNoteData[SaplingOutPoint(id, 2)] = nd;
        nd = SaplingNoteData(); nd.nullifier = nf[3]; nd.witnesses.push_back(OneWitness()); nd.witnessHeight = 10;
        wtx.mapSaplingNoteData[SaplingOutPoint(id, 3)] = nd;
        nd = SaplingNoteData(); nd.nullifier = nf[4];
        wtx.mapSaplingNoteData[SaplingOutPoint(id, 4)] = nd;
        chain.Mine(wtx);
        ASSERT_TRUE(wallet.AddToWallet(wtx, true, NULL));

        // a mined transaction that spends notes 3 and 4
        CMutableTransaction s = BaseTx(rng);
        for (int i = 3; i < 5; i++) {
            SpendDescription sd;
            sd.nullifier = nf[i];
            s.vShieldedSpend.push_back(sd);
        }
        CWalletTx spender(&wallet, CTransaction(s));
        chain.Mine(spender);
        ASSERT_TRUE(wallet.AddToWallet(spender, true, NULL));

        // a transaction with one note that is in neither the chain nor the mempool
        CMutableTransaction u = BaseTx(rng);
        CWalletTx unconf(&wallet, CTransaction(u));
        nd = SaplingNoteData(); nd.nullifier = Seeded(rng);
        unconf.mapSaplingNoteData[SaplingOutPoint(unconf.GetHash(), 0)] = nd;
        ASSERT_TRUE(wallet.AddToWallet(unconf, true, NULL));

        CWallet::Health h;
        wallet.GetHealth(h);
        EXPECT_EQ(10, h.nTipHeight);
        EXPECT_EQ(3u, h.sapling.nUnspent);   // 0, 1 and 2
        EXPECT_EQ(2u, h.sapling.nSpent);
        EXPECT_EQ(1u, h.sapling.nReady);
        EXPECT_EQ(1u, h.sapling.nMissing);
        EXPECT_EQ(1u, h.sapling.nStale);
        EXPECT_EQ(0u, h.sapling.nUnconfirmed);
        EXPECT_EQ(1u, h.sapling.nDead);    // the note of a transaction in neither chain nor mempool
        EXPECT_EQ(2u, h.sapling.nWitnessEntries);       // notes 0 and 2
        EXPECT_EQ(1u, h.sapling.nSpentWitnessEntries);  // note 3
        EXPECT_EQ(0u, h.sprout.nUnspent + h.sprout.nSpent);
    }
    RegtestDeactivateSapling();
}

TEST(WalletHealth, PendingSendsAndStatus) {
    RegtestActivateSapling();
    {
        std::mt19937_64 rng(9);
        HealthWallet wallet;
        FakeChain chain(10);              // the next block is 11
        LOCK2(cs_main, wallet.cs_wallet);

        auto add = [&](uint32_t expiry, bool fromMe, bool mined) {
            CMutableTransaction m = BaseTx(rng, expiry);
            CWalletTx w(&wallet, CTransaction(m));
            w.fFromMe = fromMe;
            if (mined) chain.Mine(w);
            EXPECT_TRUE(wallet.AddToWallet(w, true, NULL));
            return w.GetHash();
        };
        uint256 mined = add(0, true, true);
        uint256 pending = add(100, true, false);
        uint256 soon = add(12, true, false);     // 11 + 3 > 12 and 11 <= 12
        uint256 expired = add(5, true, false);   // 11 > 5
        uint256 foreign = add(5, false, false);  // an unmined receive is not a send of ours
        // a transaction that spends the same input as a mined one
        CMutableTransaction c = BaseTx(rng, 100);
        c.vin[0].prevout = wallet.mapWallet[mined].vin[0].prevout;
        CWalletTx cw(&wallet, CTransaction(c));
        cw.fFromMe = true;
        ASSERT_TRUE(wallet.AddToWallet(cw, true, NULL));
        uint256 conflicted = cw.GetHash();

        EXPECT_STREQ("mined", wallet.TxStatus(wallet.mapWallet[mined]));
        EXPECT_STREQ("pending", wallet.TxStatus(wallet.mapWallet[pending]));
        EXPECT_STREQ("expiringsoon", wallet.TxStatus(wallet.mapWallet[soon]));
        EXPECT_STREQ("expired", wallet.TxStatus(wallet.mapWallet[expired]));
        EXPECT_STREQ("conflicted", wallet.TxStatus(wallet.mapWallet[conflicted]));
        (void)foreign;

        CWallet::Health h;
        wallet.GetHealth(h);
        EXPECT_EQ(0u, h.nPendingInMempool);      // none of them is in the (empty) mempool
        EXPECT_EQ(2u, h.nPendingNotInMempool);   // pending and expiring soon
        EXPECT_EQ(1u, h.nExpiringSoon);
        EXPECT_EQ(1u, h.nExpired);
        EXPECT_EQ(1u, h.nConflicted);
    }
    RegtestDeactivateSapling();
}

TEST(WalletHealth, CostOnHundredThousandTransactions) {
    RegtestActivateSapling();
    {
        std::mt19937_64 rng(3);
        HealthWallet wallet;
        FakeChain chain(500000);
        LOCK2(cs_main, wallet.cs_wallet);
        const size_t N = 100000;
        for (size_t i = 0; i < N; i++) {
            CMutableTransaction m = BaseTx(rng);
            CWalletTx w(&wallet, CTransaction(m));
            chain.Mine(w);
            if (i % 10 == 0) {   // every tenth transaction holds a Sapling note, a third of them spent
                SaplingNoteData nd;
                nd.nullifier = Seeded(rng);
                nd.witnesses.push_back(OneWitness());
                nd.witnessHeight = 500000;
                w.mapSaplingNoteData[SaplingOutPoint(w.GetHash(), 0)] = nd;
            }
            ASSERT_TRUE(wallet.AddToWallet(w, true, NULL));
        }
        ASSERT_EQ(N, wallet.mapWallet.size());
        CWallet::Health h;
        auto t0 = std::chrono::steady_clock::now();
        wallet.GetHealth(h);
        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        printf("[ cost ] GetHealth over %zu wallet transactions (%zu notes): %.1f ms\n", N, h.sapling.nUnspent, ms);
        EXPECT_EQ(N / 10, h.sapling.nUnspent);
        EXPECT_EQ(N / 10, h.sapling.nReady);
        // The pass must stay far below a second (it holds cs_main and cs_wallet).
        EXPECT_LT(ms, 1000.0);
    }
    RegtestDeactivateSapling();
}
