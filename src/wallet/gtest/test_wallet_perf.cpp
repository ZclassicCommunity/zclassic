// Wallet hot-path benchmark. Not a correctness test: it is disabled by
// default and prints wall-clock timings for the wallet paths that scale with
// wallet size. Run it alone, in a fresh process:
//
//   ./zcash-gtest --gtest_also_run_disabled_tests \
//       --gtest_filter=WalletPerf.DISABLED_Bench
//
// Sizes are set with environment variables (defaults in parentheses):
//   WPERF_NOTES (2000) Sapling notes owned by the wallet, one per tx
//   WPERF_SPROUT (50)  Sprout notes owned by the wallet, one per tx
//   WPERF_TTX (10000)  transparent wallet transactions
//   WPERF_IVKS (20)    Sapling keys in the wallet
//   WPERF_BLOCKS (120) foreign blocks connected after the wallet is filled
//   WPERF_OUTS (20)    foreign Sapling outputs per foreign block
//   WPERF_PREFILL (30000) commitments in the Sapling tree before the first note
//   WPERF_READ_REPS (3) repetitions of the read paths
//
// It also prints a digest of the observable wallet state (per-note witness
// bytes, heights, nullifiers, values, balances) keyed by note commitment, so
// two builds can be compared: the Sapling part of the digest depends only on
// the fixed seed, not on the random keys or ciphertexts.

#include <gtest/gtest.h>

#include "chain.h"
#include "chainparams.h"
#include "crypto/sha256.h"
#include "key.h"
#include "main.h"
#include "primitives/block.h"
#include "script/standard.h"
#include "streams.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltest.h"
#include "utiltime.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "zcash/Note.hpp"
#include "zcash/NoteEncryption.hpp"
#include "zcash/zip32.h"

#include <boost/filesystem.hpp>

#include <cstdio>
#include <cstdlib>
#include <deque>
#include <map>
#include <random>
#include <string>
#include <vector>

extern ZCJoinSplit* params;

namespace {

int EnvInt(const char* name, int def)
{
    const char* v = getenv(name);
    return v ? atoi(v) : def;
}

struct Timer {
    std::map<std::string, std::pair<int64_t, int64_t>> acc; // name -> (micros, calls)
    std::vector<std::string> order;
    void Add(const std::string& name, int64_t micros) {
        if (!acc.count(name)) order.push_back(name);
        acc[name].first += micros;
        acc[name].second += 1;
    }
    void Print() const {
        for (const std::string& name : order) {
            const auto& e = acc.at(name);
            printf("[wperf] %-34s total %10.3f ms  calls %6lld  avg %10.3f ms\n",
                   name.c_str(), e.first / 1000.0, (long long)e.second,
                   e.first / 1000.0 / e.second);
        }
        fflush(stdout);
    }
};

#define WPERF_TIME(timer, name, stmt) \
    do { int64_t t0_ = GetTimeMicros(); stmt; (timer).Add(name, GetTimeMicros() - t0_); } while (0)

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

class PerfWallet : public CWallet {
public:
    explicit PerfWallet(const std::string& file) : CWallet(file) { }
};

CMutableTransaction BaseTx(std::mt19937_64& rng)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.vin.push_back(CTxIn(COutPoint(SeededHash(rng), 0)));
    return mtx;
}

// A Sapling output that decrypts with pa's ivk. No proof: the wallet never
// checks one. The commitment depends only on the seeded rcm.
OutputDescription SaplingOutputTo(std::mt19937_64& rng, const libzcash::SaplingPaymentAddress& pa, CAmount value)
{
    uint256 r = SeededHash(rng);
    *(r.begin() + 31) = 0; // keep it below the Jubjub scalar modulus
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

struct Chain {
    std::deque<CBlockIndex> index;
    std::vector<uint256> hashes;
    SproutMerkleTree sprout;
    SaplingMerkleTree sapling;

    // Connects the block the way ConnectTip does: SyncTransaction for every
    // tx, then ChainTip with the trees as they were before the block.
    void Connect(PerfWallet& wallet, CBlock& block, Timer& timer, const std::string& tag) {
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

        LOCK2(cs_main, wallet.cs_wallet);
        chainActive.SetTip(&bi);
        WPERF_TIME(timer, tag + " SyncTransaction", {
            for (const CTransaction& tx : block.vtx) wallet.SyncTransaction(tx, &block);
        });
        WPERF_TIME(timer, tag + " ChainTip", wallet.ChainTip(&bi, &block, sprout, sapling, true));
        for (const CTransaction& tx : block.vtx) {
            for (const JSDescription& js : tx.vjoinsplit)
                for (const uint256& cm : js.commitments) sprout.append(cm);
            for (const OutputDescription& od : tx.vShieldedOutput) sapling.append(od.cm);
        }
    }

    void Clear() {
        chainActive.SetTip(nullptr);
        for (const uint256& h : hashes) mapBlockIndex.erase(h);
    }
};

// Digest of the observable Sapling note state, keyed by note commitment.
std::string StateDigest(PerfWallet& wallet, std::vector<SaplingNoteEntry>& saplingEntries, CAmount extra)
{
    std::map<uint256, std::string> byCm;
    for (const auto& item : wallet.mapWallet) {
        const CWalletTx& wtx = item.second;
        for (const auto& nd : wtx.mapSaplingNoteData) {
            CDataStream ss(SER_DISK, CLIENT_VERSION);
            ss << nd.second.witnesses << nd.second.witnessHeight << nd.second.nullifier;
            ss << (nd.second.value ? *nd.second.value : (CAmount)-1);
            byCm[wtx.vShieldedOutput[nd.first.n].cm] = std::string(ss.begin(), ss.end());
        }
    }
    std::map<uint256, std::string> entries;
    for (const SaplingNoteEntry& e : saplingEntries) {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << (uint64_t)e.note.value() << e.note.r << e.confirmations;
        entries[e.note.cm().get()] = std::string(ss.begin(), ss.end());
    }
    CSHA256 h;
    for (const auto& kv : byCm) {
        h.Write(kv.first.begin(), 32);
        h.Write((const unsigned char*)kv.second.data(), kv.second.size());
    }
    for (const auto& kv : entries) {
        h.Write(kv.first.begin(), 32);
        h.Write((const unsigned char*)kv.second.data(), kv.second.size());
    }
    int64_t tail[2] = { wallet.nWitnessCacheSize, extra };
    h.Write((const unsigned char*)tail, sizeof(tail));
    unsigned char out[32];
    h.Finalize(out);
    return HexStr(out, out + 32);
}

} // namespace

TEST(WalletPerf, DISABLED_Bench)
{
    const int nNotes = EnvInt("WPERF_NOTES", 2000);
    const int nSprout = EnvInt("WPERF_SPROUT", 50);
    const int nTtx = EnvInt("WPERF_TTX", 10000);
    const int nIvks = std::max(1, EnvInt("WPERF_IVKS", 20));
    const int nBlocks = EnvInt("WPERF_BLOCKS", 120);
    const int nOuts = EnvInt("WPERF_OUTS", 20);
    const int nPrefill = EnvInt("WPERF_PREFILL", 30000);
    const int nFillBlocks = 20;

    RegtestActivateSapling();
    boost::filesystem::path dir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("wperf-%%%%-%%%%-%%%%");
    boost::filesystem::create_directories(dir);
    mapArgs["-datadir"] = dir.string();
    ClearDatadirCache();
    ASSERT_TRUE(bitdb.Open(dir)) << "run this benchmark alone, in a fresh process";

    Timer timer;
    std::mt19937_64 rng(20261116);
    Chain chain;
    CAmount nExpectSapling = 0, nExpectTransparent = 0;
    std::string digest;
    {
        PerfWallet wallet("wallet.dat");
        bool fFirstRun = true;
        ASSERT_EQ(DB_LOAD_OK, wallet.LoadWallet(fFirstRun));

        // Keys.
        auto master = GetTestMasterSaplingSpendingKey();
        std::vector<libzcash::SaplingPaymentAddress> addrs;
        for (int i = 0; i < nIvks; i++) {
            auto sk = master.Derive(i | ZIP32_HARDENED_KEY_LIMIT);
            addrs.push_back(sk.DefaultAddress());
            LOCK(wallet.cs_wallet);
            ASSERT_TRUE(wallet.AddSaplingZKey(sk, addrs.back()));
        }
        auto sproutSk = libzcash::SproutSpendingKey::random();
        CKey tkey;
        tkey.MakeNewKey(true);
        {
            LOCK(wallet.cs_wallet);
            ASSERT_TRUE(wallet.AddSproutZKey(sproutSk));
            ASSERT_TRUE(wallet.AddKeyPubKey(tkey, tkey.GetPubKey()));
        }
        CScript tscript = GetScriptForDestination(tkey.GetPubKey().GetID());

        for (int i = 0; i < nPrefill; i++) chain.sapling.append(SeededHash(rng));

        // Fill blocks: every wallet transaction arrives mined.
        for (int b = 0; b < nFillBlocks; b++) {
            CBlock block;
            block.vtx.push_back(CTransaction(BaseTx(rng))); // stand-in for the coinbase
            for (int i = b; i < nNotes; i += nFillBlocks) {
                CMutableTransaction mtx = BaseTx(rng);
                CAmount v = 1000 + i;
                mtx.vShieldedOutput.push_back(SaplingOutputTo(rng, addrs[i % nIvks], v));
                nExpectSapling += v;
                block.vtx.push_back(CTransaction(mtx));
            }
            for (int i = b; i < nSprout; i += nFillBlocks) {
                block.vtx.push_back(GetValidSproutReceive(*params, sproutSk, 10, true, 4));
            }
            for (int i = b; i < nTtx; i += nFillBlocks) {
                CMutableTransaction mtx = BaseTx(rng);
                CAmount v = 5000 + i;
                mtx.vout.push_back(CTxOut(v, tscript));
                nExpectTransparent += v;
                block.vtx.push_back(CTransaction(mtx));
            }
            chain.Connect(wallet, block, timer, "fill");
        }

        // Foreign blocks: nothing in them is ours.
        auto foreign = master.Derive(0x7fffffff | ZIP32_HARDENED_KEY_LIMIT).DefaultAddress();
        for (int b = 0; b < nBlocks; b++) {
            CBlock block;
            block.vtx.push_back(CTransaction(BaseTx(rng)));
            CMutableTransaction mtx = BaseTx(rng);
            for (int i = 0; i < nOuts; i++) mtx.vShieldedOutput.push_back(SaplingOutputTo(rng, foreign, 1));
            block.vtx.push_back(CTransaction(mtx));
            chain.Connect(wallet, block, timer, "foreign");
            if (b % 40 == 39) {
                CBlockLocator loc;
                { LOCK(cs_main); loc = chainActive.GetLocator(); }
                WPERF_TIME(timer, "SetBestChain", wallet.SetBestChain(loc));
            }
        }

        // Reorg: disconnect and reconnect the last five blocks.
        {
            LOCK2(cs_main, wallet.cs_wallet);
            for (int k = 0; k < 5; k++) {
                CBlockIndex* tip = &chain.index[chain.index.size() - 1 - k];
                CBlock empty;
                WPERF_TIME(timer, "ChainTip disconnect", wallet.ChainTip(tip, &empty, chain.sprout, chain.sapling, false));
            }
        }

        // Read paths.
        std::vector<CSproutNotePlaintextEntry> sproutEntries;
        std::vector<SaplingNoteEntry> saplingEntries;
        CAmount nSaplingCached = 0, nSproutCached = 0, nBalance = 0;
        const int nReadReps = EnvInt("WPERF_READ_REPS", 3);
        for (int rep = 0; rep < nReadReps; rep++) {
            sproutEntries.clear();
            saplingEntries.clear();
            WPERF_TIME(timer, "GetFilteredNotes (all)", wallet.GetFilteredNotes(sproutEntries, saplingEntries, "", 1));
            std::vector<CSproutNotePlaintextEntry> s1;
            std::vector<SaplingNoteEntry> s2;
            std::set<libzcash::PaymentAddress> filter;
            filter.insert(addrs[0]);
            WPERF_TIME(timer, "GetFilteredNotes (one address)", wallet.GetFilteredNotes(s1, s2, filter, 1, INT_MAX, true, true, true));
            {
                LOCK2(cs_main, wallet.cs_wallet);
                WPERF_TIME(timer, "GetSaplingBalanceCached", nSaplingCached = wallet.GetSaplingBalanceCached(1));
                WPERF_TIME(timer, "GetSproutBalanceCached", nSproutCached = wallet.GetSproutBalanceCached(1));
                WPERF_TIME(timer, "GetBalance", nBalance = wallet.GetBalance());
                std::vector<COutput> vCoins;
                WPERF_TIME(timer, "AvailableCoins", wallet.AvailableCoins(vCoins, false, NULL, true));
                EXPECT_EQ((size_t)nTtx, vCoins.size());
            }
        }
        EXPECT_EQ((size_t)nNotes, saplingEntries.size());
        EXPECT_EQ((size_t)nSprout * 2, sproutEntries.size());
        EXPECT_EQ(nExpectSapling, nSaplingCached);
        EXPECT_EQ((CAmount)nSprout * 20, nSproutCached);
        EXPECT_EQ(nExpectTransparent, nBalance);
        digest = StateDigest(wallet, saplingEntries, nSaplingCached + nSproutCached + nBalance);
    }

    // Reload what was written. LoadWallet checks Sprout proofs, which the
    // benchmark does not make, so this needs WPERF_SPROUT=0.
    bitdb.Flush(false);
    if (nSprout == 0) {
        PerfWallet reloaded("wallet.dat");
        bool fFirstRun = false;
        DBErrors err = DB_LOAD_OK;
        WPERF_TIME(timer, "LoadWallet", err = reloaded.LoadWallet(fFirstRun));
        EXPECT_EQ(DB_LOAD_OK, err);
        EXPECT_EQ((size_t)(nNotes + nSprout + nTtx), reloaded.mapWallet.size());
    }

    printf("[wperf] notes=%d sprout=%d ttx=%d ivks=%d blocks=%d outs=%d prefill=%d\n",
           nNotes, nSprout, nTtx, nIvks, nBlocks, nOuts, nPrefill);
    timer.Print();
    printf("[wperf] wallet.dat bytes %llu\n", (unsigned long long)boost::filesystem::file_size(dir / "wallet.dat"));
    printf("[wperf] state digest %s\n", digest.c_str());

    chain.Clear();
    bitdb.Flush(true);
    bitdb.Reset();
    if (!getenv("WPERF_KEEP")) boost::filesystem::remove_all(dir);
    else printf("[wperf] kept datadir %s\n", dir.string().c_str());
    RegtestDeactivateSapling();
}
