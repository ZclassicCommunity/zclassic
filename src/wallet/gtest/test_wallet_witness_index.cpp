// Differential test for the wallet note-witness index (report 03, C1).
//
// The production CWallet now walks only the wallet transactions that carry
// Sprout or Sapling note data, and skips the per-block witness work entirely
// when there are none. This file keeps the original full-mapWallet-walk
// implementation (copied verbatim from wallet.cpp before the change) as the
// reference, drives a production wallet and a reference wallet through the
// same randomized chain history, and requires byte-identical serialized note
// data (witness lists and witness heights) and an identical nWitnessCacheSize
// after every step.

#include <gtest/gtest.h>

#include "chain.h"
#include "chainparamsbase.h"
#include "clientversion.h"
#include "util.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "streams.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "zcash/IncrementalMerkleTree.hpp"

#include <boost/filesystem.hpp>

#include <chrono>
#include <cstdio>
#include <memory>
#include <random>
#include <stdexcept>
#include <vector>

namespace witness_ref {

// ---- Reference: the pre-index implementation, verbatim apart from names ----

template<typename NoteDataMap>
void CopyPreviousWitnesses(NoteDataMap& noteDataMap, int indexHeight, int64_t nWitnessCacheSize)
{
    for (auto& item : noteDataMap) {
        auto* nd = &(item.second);
        if (nd->witnessHeight < indexHeight) {
            assert(nWitnessCacheSize >= nd->witnesses.size());
            assert((nd->witnessHeight == -1) || (nd->witnessHeight == indexHeight - 1));
            if (nd->witnesses.size() > 0) {
                nd->witnesses.push_front(nd->witnesses.front());
            }
            if (nd->witnesses.size() > WITNESS_CACHE_SIZE) {
                nd->witnesses.pop_back();
            }
        }
    }
}

template<typename NoteDataMap>
void AppendNoteCommitment(NoteDataMap& noteDataMap, int indexHeight, int64_t nWitnessCacheSize, const uint256& note_commitment)
{
    for (auto& item : noteDataMap) {
        auto* nd = &(item.second);
        if (nd->witnessHeight < indexHeight && nd->witnesses.size() > 0) {
            assert(nWitnessCacheSize >= nd->witnesses.size());
            nd->witnesses.front().append(note_commitment);
        }
    }
}

template<typename OutPoint, typename NoteData, typename Witness>
void WitnessNoteIfMine(std::map<OutPoint, NoteData>& noteDataMap, int indexHeight, int64_t nWitnessCacheSize, const OutPoint& key, const Witness& witness)
{
    if (noteDataMap.count(key) && noteDataMap[key].witnessHeight < indexHeight) {
        auto* nd = &(noteDataMap[key]);
        if (nd->witnesses.size() > 0) {
            nd->witnesses.clear();
        }
        nd->witnesses.push_front(witness);
        nd->witnessHeight = indexHeight - 1;
        assert(nWitnessCacheSize >= nd->witnesses.size());
    }
}

template<typename NoteDataMap>
void UpdateWitnessHeights(NoteDataMap& noteDataMap, int indexHeight, int64_t nWitnessCacheSize)
{
    for (auto& item : noteDataMap) {
        auto* nd = &(item.second);
        if (nd->witnessHeight < indexHeight) {
            nd->witnessHeight = indexHeight;
            assert(nWitnessCacheSize >= nd->witnesses.size());
        }
    }
}

void IncrementNoteWitnesses(CWallet& w,
                            const CBlockIndex* pindex,
                            const CBlock* pblock,
                            SproutMerkleTree& sproutTree,
                            SaplingMerkleTree& saplingTree)
{
    LOCK(w.cs_wallet);
    auto& mapWallet = w.mapWallet;
    auto& nWitnessCacheSize = w.nWitnessCacheSize;
    for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
       CopyPreviousWitnesses(wtxItem.second.mapSproutNoteData, pindex->nHeight, nWitnessCacheSize);
       CopyPreviousWitnesses(wtxItem.second.mapSaplingNoteData, pindex->nHeight, nWitnessCacheSize);
    }

    if (nWitnessCacheSize < WITNESS_CACHE_SIZE) {
        nWitnessCacheSize += 1;
    }

    assert(pblock != nullptr);

    for (const CTransaction& tx : pblock->vtx) {
        auto hash = tx.GetHash();
        bool txIsOurs = mapWallet.count(hash);
        for (size_t i = 0; i < tx.vjoinsplit.size(); i++) {
            const JSDescription& jsdesc = tx.vjoinsplit[i];
            for (uint8_t j = 0; j < jsdesc.commitments.size(); j++) {
                const uint256& note_commitment = jsdesc.commitments[j];
                sproutTree.append(note_commitment);
                for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
                    AppendNoteCommitment(wtxItem.second.mapSproutNoteData, pindex->nHeight, nWitnessCacheSize, note_commitment);
                }
                if (txIsOurs) {
                    JSOutPoint jsoutpt {hash, i, j};
                    WitnessNoteIfMine(mapWallet[hash].mapSproutNoteData, pindex->nHeight, nWitnessCacheSize, jsoutpt, sproutTree.witness());
                }
            }
        }
        for (uint32_t i = 0; i < tx.vShieldedOutput.size(); i++) {
            const uint256& note_commitment = tx.vShieldedOutput[i].cm;
            saplingTree.append(note_commitment);
            for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
                AppendNoteCommitment(wtxItem.second.mapSaplingNoteData, pindex->nHeight, nWitnessCacheSize, note_commitment);
            }
            if (txIsOurs) {
                SaplingOutPoint outPoint {hash, i};
                WitnessNoteIfMine(mapWallet[hash].mapSaplingNoteData, pindex->nHeight, nWitnessCacheSize, outPoint, saplingTree.witness());
            }
        }
    }

    for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
        UpdateWitnessHeights(wtxItem.second.mapSproutNoteData, pindex->nHeight, nWitnessCacheSize);
        UpdateWitnessHeights(wtxItem.second.mapSaplingNoteData, pindex->nHeight, nWitnessCacheSize);
    }
}

template<typename NoteDataMap>
void DecrementNoteWitnesses(NoteDataMap& noteDataMap, int indexHeight, int64_t nWitnessCacheSize)
{
    for (auto& item : noteDataMap) {
        auto* nd = &(item.second);
        if (nd->witnessHeight <= indexHeight) {
            assert(nWitnessCacheSize >= nd->witnesses.size());
            assert((nd->witnessHeight == -1) || (nd->witnessHeight == indexHeight));
            if (nd->witnesses.size() > 0) {
                nd->witnesses.pop_front();
            }
            nd->witnessHeight = indexHeight - 1;
        }
        if (nd->witnessHeight < indexHeight) {
            assert((nWitnessCacheSize - 1) >= nd->witnesses.size());
        }
    }
}

void DecrementNoteWitnesses(CWallet& w, const CBlockIndex* pindex)
{
    LOCK(w.cs_wallet);
    for (std::pair<const uint256, CWalletTx>& wtxItem : w.mapWallet) {
        DecrementNoteWitnesses(wtxItem.second.mapSproutNoteData, pindex->nHeight, w.nWitnessCacheSize);
        DecrementNoteWitnesses(wtxItem.second.mapSaplingNoteData, pindex->nHeight, w.nWitnessCacheSize);
    }
    w.nWitnessCacheSize -= 1;
    assert(w.nWitnessCacheSize > 0);
}

// The witness half of the original CWallet::ChainTip (trees by const reference).
void ChainTip(CWallet& w, const CBlockIndex* pindex, const CBlock* pblock,
              SproutMerkleTree sproutTree, SaplingMerkleTree saplingTree, bool added)
{
    if (added) {
        IncrementNoteWitnesses(w, pindex, pblock, sproutTree, saplingTree);
    } else {
        DecrementNoteWitnesses(w, pindex);
    }
}

} // namespace witness_ref

namespace {

class IndexedWallet : public CWallet {
public:
    explicit IndexedWallet(const std::string& file) : CWallet(file) { }

    // The witness half of the production CWallet::ChainTip (trees by const reference).
    void ChainTipWitness(const CBlockIndex* pindex, const CBlock* pblock,
                         const SproutMerkleTree& sproutTree, const SaplingMerkleTree& saplingTree, bool added) {
        WitnessChainTip(pindex, pblock, sproutTree, saplingTree, added);
    }
    size_t IndexSize() const { return setNoteTxIndex.size(); }
    bool IndexCovers(const uint256& hash) const { return setNoteTxIndex.count(hash) > 0; }
};

class RefWallet : public CWallet {
public:
    explicit RefWallet(const std::string& file) : CWallet(file) { }
};

uint256 RandHash(std::mt19937_64& rng)
{
    uint256 h;
    unsigned char* p = h.begin();
    for (size_t i = 0; i < 32; i += 8) {
        uint64_t v = rng();
        for (size_t k = 0; k < 8; k++) {
            p[i + k] = (unsigned char)(v >> (8 * k));
        }
    }
    return h;
}

CTransaction RandomTx(std::mt19937_64& rng, int nJoinSplits, int nOutputs)
{
    CMutableTransaction mtx;
    mtx.fOverwintered = true;
    mtx.nVersion = SAPLING_TX_VERSION;
    mtx.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    mtx.vin.push_back(CTxIn(COutPoint(RandHash(rng), (uint32_t)(rng() & 3))));
    mtx.vout.push_back(CTxOut(1000 + (CAmount)(rng() & 0xffff), CScript() << OP_TRUE));
    for (int i = 0; i < nJoinSplits; i++) {
        JSDescription js;
        js.proof = libzcash::GrothProof();
        for (size_t k = 0; k < js.commitments.size(); k++) {
            js.commitments[k] = RandHash(rng);
        }
        for (size_t k = 0; k < js.nullifiers.size(); k++) {
            js.nullifiers[k] = RandHash(rng);
        }
        mtx.vjoinsplit.push_back(js);
    }
    for (int i = 0; i < nOutputs; i++) {
        OutputDescription od;
        od.cm = RandHash(rng);
        mtx.vShieldedOutput.push_back(od);
    }
    return CTransaction(mtx);
}

// Attach note data for a random subset (possibly none) of the outputs.
// `keep` lists notes that must stay (UpdatedNoteData requires the incoming
// note map to contain every note the wallet already holds for the tx).
void AttachNotes(std::mt19937_64& rng, CWalletTx& wtx, int pctOwned,
                 const mapSproutNoteData_t* keepSprout = nullptr,
                 const mapSaplingNoteData_t* keepSapling = nullptr)
{
    uint256 hash = wtx.GetHash();
    mapSproutNoteData_t sproutNotes;
    mapSaplingNoteData_t saplingNotes;
    if (keepSprout) sproutNotes = *keepSprout;
    if (keepSapling) saplingNotes = *keepSapling;
    for (size_t js = 0; js < wtx.vjoinsplit.size(); js++) {
        for (uint8_t n = 0; n < wtx.vjoinsplit[js].commitments.size(); n++) {
            JSOutPoint op {hash, js, n};
            if (!sproutNotes.count(op) && (int)(rng() % 100) < pctOwned) {
                SproutNoteData nd;
                nd.nullifier = RandHash(rng);
                sproutNotes[op] = nd;
            }
        }
    }
    for (uint32_t i = 0; i < wtx.vShieldedOutput.size(); i++) {
        SaplingOutPoint op {hash, i};
        if (!saplingNotes.count(op) && (int)(rng() % 100) < pctOwned) {
            SaplingNoteData nd;
            nd.nullifier = RandHash(rng);
            saplingNotes[op] = nd;
        }
    }
    wtx.SetSproutNoteData(sproutNotes);
    wtx.SetSaplingNoteData(saplingNotes);
}

std::string SerializeNotes(const CWalletTx& wtx)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << wtx.mapSproutNoteData;
    ss << wtx.mapSaplingNoteData;
    return std::string(ss.begin(), ss.end());
}

bool HasNotes(const CWalletTx& wtx)
{
    return !wtx.mapSproutNoteData.empty() || !wtx.mapSaplingNoteData.empty();
}

// Byte-identical serialized note data (witness lists and witness heights)
// for every wallet entry, identical cache size, and the index invariant.
void ExpectSameWitnessState(IndexedWallet& a, RefWallet& b, const std::string& where)
{
    LOCK2(a.cs_wallet, b.cs_wallet);
    ASSERT_EQ(a.nWitnessCacheSize, b.nWitnessCacheSize) << where;
    ASSERT_EQ(a.mapWallet.size(), b.mapWallet.size()) << where;
    auto ia = a.mapWallet.begin();
    auto ib = b.mapWallet.begin();
    for (; ia != a.mapWallet.end(); ++ia, ++ib) {
        ASSERT_EQ(ia->first, ib->first) << where;
        const CWalletTx& wa = ia->second;
        const CWalletTx& wb = ib->second;
        ASSERT_EQ(SerializeNotes(wa), SerializeNotes(wb)) << where << " tx " << ia->first.GetHex();
        // Heights are inside the serialization; check them directly too so a
        // failure names the field.
        ASSERT_EQ(wa.mapSproutNoteData.size(), wb.mapSproutNoteData.size()) << where;
        for (auto x = wa.mapSproutNoteData.begin(), y = wb.mapSproutNoteData.begin();
             x != wa.mapSproutNoteData.end(); ++x, ++y) {
            ASSERT_EQ(x->second.witnessHeight, y->second.witnessHeight) << where;
            ASSERT_EQ(x->second.witnesses.size(), y->second.witnesses.size()) << where;
        }
        ASSERT_EQ(wa.mapSaplingNoteData.size(), wb.mapSaplingNoteData.size()) << where;
        for (auto x = wa.mapSaplingNoteData.begin(), y = wb.mapSaplingNoteData.begin();
             x != wa.mapSaplingNoteData.end(); ++x, ++y) {
            ASSERT_EQ(x->second.witnessHeight, y->second.witnessHeight) << where;
            ASSERT_EQ(x->second.witnesses.size(), y->second.witnesses.size()) << where;
        }
        if (HasNotes(wa)) {
            ASSERT_TRUE(a.IndexCovers(ia->first)) << where << " index misses " << ia->first.GetHex();
        }
    }
}

// Berkeley DB environment for the live AddToWallet path (it writes the tx
// and the order position). Uses an in-memory mock environment unless another
// test already opened the environment, in which case that one is reused.
struct DbEnvGuard {
    bool fMock = false;
    DbEnvGuard() {
        // CDB evaluates GetDataDir() even for a mock environment, and
        // GetDataDir() creates the directory. Never let it fall back to the
        // user's default datadir: point it at a fresh temporary directory
        // unless an earlier test already did.
        if (!AreBaseParamsConfigured()) {
            SelectBaseParams(CBaseChainParams::REGTEST);
        }
        if (!mapArgs.count("-datadir")) {
            boost::filesystem::path pathTemp = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
            boost::filesystem::create_directories(pathTemp);
            mapArgs["-datadir"] = pathTemp.string();
            ClearDatadirCache();
        }
        try {
            bitdb.MakeMock();
            fMock = true;
        } catch (const std::runtime_error&) {
            fMock = false;
        }
    }
    ~DbEnvGuard() {
        if (fMock) {
            bitdb.Flush(true);
            bitdb.Reset();
        }
    }
};

struct SimBlock {
    CBlock block;
    std::unique_ptr<CBlockIndex> index;
    SproutMerkleTree sproutBefore;
    SaplingMerkleTree saplingBefore;
};

class WitnessSim {
public:
    WitnessSim(uint64_t seed, const std::string& tag)
        : rng(seed),
          a("witidx_a_" + tag + ".dat"),
          b("witidx_b_" + tag + ".dat") { }

    std::mt19937_64 rng;
    IndexedWallet a;
    RefWallet b;
    std::vector<SimBlock> chain;            // chain[k] is at height k + 1
    SproutMerkleTree sproutTip;
    SaplingMerkleTree saplingTip;
    std::vector<uint256> pending;           // wallet txs not yet mined
    std::vector<uint256> mined;             // wallet txs seen in a block
    std::map<uint256, CTransaction> txs;    // every wallet tx by hash
    int pctOwned = 0;                       // share of outputs that are ours
    int stats[8] = {0};

    int Height() const { return (int)chain.size(); }

    void AddToBoth(const CWalletTx& wtx, bool live) {
        if (live) {
            CWalletDB dba(a.strWalletFile, "cr+");
            CWalletDB dbb(b.strWalletFile, "cr+");
            ASSERT_TRUE(a.AddToWallet(wtx, false, &dba));
            ASSERT_TRUE(b.AddToWallet(wtx, false, &dbb));
        } else {
            ASSERT_TRUE(a.AddToWallet(wtx, true, nullptr));
            ASSERT_TRUE(b.AddToWallet(wtx, true, nullptr));
        }
    }

    CTransaction NewShapedTx() {
        int kind = rng() % 100;
        int js = 0, outs = 0;
        if (kind < 40) {
            // transparent only
        } else if (kind < 60) {
            js = 1 + rng() % 2;
        } else if (kind < 85) {
            outs = 1 + rng() % 3;
        } else {
            js = 1;
            outs = 1 + rng() % 2;
        }
        return RandomTx(rng, js, outs);
    }

    void NewWalletTx(const CTransaction& tx, bool live) {
        CWalletTx wtx(nullptr, tx);
        AttachNotes(rng, wtx, pctOwned);
        txs[tx.GetHash()] = tx;
        AddToBoth(wtx, live);
    }

    void Connect() {
        SimBlock sb;
        sb.index.reset(new CBlockIndex());
        sb.index->nHeight = Height() + 1;
        sb.sproutBefore = sproutTip;
        sb.saplingBefore = saplingTip;
        int ntx = rng() % 6;
        for (int t = 0; t < ntx; t++) {
            CTransaction tx = NewShapedTx();
            sb.block.vtx.push_back(tx);
            if ((int)(rng() % 100) < 30) {
                // Ours: in the wallet before ChainTip, as SyncTransaction does.
                NewWalletTx(tx, rng() % 2 == 0);
                mined.push_back(tx.GetHash());
            }
        }
        if (!pending.empty() && rng() % 100 < 25) {
            size_t k = rng() % pending.size();
            sb.block.vtx.push_back(txs.at(pending[k]));
            mined.push_back(pending[k]);
            pending.erase(pending.begin() + k);
            stats[0]++;
        }
        if (!mined.empty() && rng() % 100 < 4) {
            // A wallet tx seen again (the inconsistent-cache path in
            // WitnessNoteIfMine), sometimes twice in one block.
            const uint256& h = mined[rng() % mined.size()];
            if (txs.count(h)) {
                sb.block.vtx.push_back(txs.at(h));
                if (rng() % 2) sb.block.vtx.push_back(txs.at(h));
                stats[1]++;
            }
        }
        for (const CTransaction& tx : sb.block.vtx) {
            for (const JSDescription& js : tx.vjoinsplit) {
                for (const uint256& cm : js.commitments) sproutTip.append(cm);
            }
            for (const OutputDescription& od : tx.vShieldedOutput) saplingTip.append(od.cm);
        }
        a.ChainTipWitness(sb.index.get(), &sb.block, sb.sproutBefore, sb.saplingBefore, true);
        witness_ref::ChainTip(b, sb.index.get(), &sb.block, sb.sproutBefore, sb.saplingBefore, true);
        chain.push_back(std::move(sb));
        stats[2]++;
    }

    void Disconnect(int depth) {
        for (int d = 0; d < depth; d++) {
            SimBlock& sb = chain.back();
            a.ChainTipWitness(sb.index.get(), &sb.block, sproutTip, saplingTip, false);
            witness_ref::ChainTip(b, sb.index.get(), &sb.block, sproutTip, saplingTip, false);
            sproutTip = sb.sproutBefore;
            saplingTip = sb.saplingBefore;
            // The block's wallet txs stay in the wallet; they may be mined
            // again later, as after a real reorg.
            for (const CTransaction& tx : sb.block.vtx) {
                if (txs.count(tx.GetHash())) pending.push_back(tx.GetHash());
            }
            chain.pop_back();
        }
        stats[3]++;
    }

    void AddPending() {
        CTransaction tx = RandomTx(rng, rng() % 2, 1 + rng() % 2);
        NewWalletTx(tx, rng() % 2 == 0);
        pending.push_back(tx.GetHash());
        stats[4]++;
    }

    // A wallet tx gains note data later (key import, rescan): merge on the
    // live path, or a wholesale reload on the load path.
    void GainNotes() {
        if (txs.empty()) return;
        auto it = txs.begin();
        std::advance(it, rng() % txs.size());
        const uint256 hash = it->first;
        mapSproutNoteData_t keepSprout;
        mapSaplingNoteData_t keepSapling;
        {
            LOCK(a.cs_wallet);
            auto mi = a.mapWallet.find(hash);
            if (mi == a.mapWallet.end()) return;
            keepSprout = mi->second.mapSproutNoteData;
            keepSapling = mi->second.mapSaplingNoteData;
        }
        CWalletTx wtx(nullptr, it->second);
        bool live = rng() % 2 == 0;
        AttachNotes(rng, wtx, 60, &keepSprout, &keepSapling);
        AddToBoth(wtx, live);
        stats[5]++;
    }

    void EraseOne() {
        if (txs.empty()) return;
        auto it = txs.begin();
        std::advance(it, rng() % txs.size());
        a.EraseFromWallet(it->first);
        b.EraseFromWallet(it->first);
        stats[6]++;
    }

    // mapWallet grows outside AddToWallet (operator[] on a missing hash, as
    // some RPC read paths do); the index must notice and rebuild.
    void UnhookedInsert() {
        uint256 h = RandHash(rng);
        LOCK2(a.cs_wallet, b.cs_wallet);
        a.mapWallet[h];
        b.mapWallet[h];
        stats[7]++;
    }
};

void RunSim(uint64_t seed, int steps, const std::string& tag)
{
    WitnessSim sim(seed, tag);
    for (int step = 0; step < steps; step++) {
        // Phases: a transparent-only stretch first (fast path), then notes,
        // then a stretch where most new outputs are foreign again.
        if (step < steps / 5) {
            sim.pctOwned = 0;
        } else if (step < (4 * steps) / 5) {
            sim.pctOwned = 50;
        } else {
            sim.pctOwned = 10;
        }
        int r = sim.rng() % 100;
        int64_t cache = sim.a.nWitnessCacheSize;
        if (r < 66 || sim.Height() == 0 || cache < 2) {
            sim.Connect();
        } else if (r < 72) {
            int maxDepth = std::min<int>(sim.Height(), (int)cache - 1);
            maxDepth = std::min(maxDepth, (sim.rng() % 4 == 0) ? 25 : 3);
            int depth = 1 + (int)(sim.rng() % maxDepth);
            sim.Disconnect(depth);
        } else if (r < 82) {
            sim.AddPending();
        } else if (r < 92) {
            sim.GainNotes();
        } else if (r < 97) {
            sim.EraseOne();
        } else {
            sim.UnhookedInsert();
        }
        std::string where = "seed " + std::to_string(seed) + " step " + std::to_string(step);
        ExpectSameWitnessState(sim.a, sim.b, where);
        if (::testing::Test::HasFatalFailure()) return;
    }
    size_t withNotes = 0;
    {
        LOCK(sim.a.cs_wallet);
        for (const auto& item : sim.a.mapWallet) withNotes += HasNotes(item.second) ? 1 : 0;
    }
    std::printf("[witness-index] seed %llu: %d steps, height %d, cache %lld, wallet %zu txs (%zu with notes, index %zu); "
                "connects %d, reorgs %d, pending mined %d, replays %d, pending added %d, note gains %d, erases %d, unhooked %d\n",
                (unsigned long long)seed, steps, sim.Height(), (long long)sim.a.nWitnessCacheSize,
                sim.a.mapWallet.size(), withNotes, sim.a.IndexSize(),
                sim.stats[2], sim.stats[3], sim.stats[0], sim.stats[1], sim.stats[4], sim.stats[5], sim.stats[6], sim.stats[7]);
}

} // namespace

TEST(WalletWitnessIndex, DifferentialRandomChains)
{
    DbEnvGuard env;
    const uint64_t seeds[] = {1, 2, 3, 0x5eed, 0xc0ffee, 20261116};
    int i = 0;
    for (uint64_t seed : seeds) {
        RunSim(seed, 800, std::to_string(i++));
        if (HasFatalFailure()) return;
    }
}

// The witness cache saturates at WITNESS_CACHE_SIZE and each note's list is
// capped at the same size; a long chain with a note-holding wallet crosses it.
TEST(WalletWitnessIndex, CacheWraparound)
{
    DbEnvGuard env;
    WitnessSim sim(77, "wrap");
    sim.pctOwned = 60;
    for (int h = 0; h < (int)WITNESS_CACHE_SIZE + 60; h++) {
        sim.Connect();
        ExpectSameWitnessState(sim.a, sim.b, "wrap connect " + std::to_string(h));
        if (HasFatalFailure()) return;
        if (h % 37 == 36) {
            sim.Disconnect(1 + (int)(sim.rng() % 20));
            ExpectSameWitnessState(sim.a, sim.b, "wrap reorg " + std::to_string(h));
            if (HasFatalFailure()) return;
        }
    }
    EXPECT_EQ((int64_t)WITNESS_CACHE_SIZE, sim.a.nWitnessCacheSize);
}

// A wallet with no notes takes the fast path: only nWitnessCacheSize moves.
TEST(WalletWitnessIndex, NoNotesFastPath)
{
    DbEnvGuard env;
    WitnessSim sim(9, "nonotes");
    sim.pctOwned = 0;
    for (int h = 0; h < 30; h++) {
        sim.Connect();
        ExpectSameWitnessState(sim.a, sim.b, "nonotes " + std::to_string(h));
        if (HasFatalFailure()) return;
    }
    EXPECT_EQ(0u, sim.a.IndexSize());
    EXPECT_EQ(30, sim.a.nWitnessCacheSize);
}

// Per-block witness cost, original full walk vs indexed path. Timing is
// printed, never asserted.
TEST(WalletWitnessIndex, PerBlockCost)
{
    struct Case { int nTransparent; int nNoteTxs; bool shielded; };
    const Case cases[] = {
        {0, 0, true}, {100, 0, true}, {10000, 0, true},
        {0, 0, false}, {100, 0, false}, {10000, 0, false},
        {10000, 20, true},
    };
    const int nBlocks = 200;
    for (const Case& c : cases) {
        std::mt19937_64 rng(4242);
        IndexedWallet a("witidx_bench_a.dat");
        RefWallet b("witidx_bench_b.dat");
        for (int i = 0; i < c.nTransparent; i++) {
            CWalletTx wtx(nullptr, RandomTx(rng, 0, 0));
            ASSERT_TRUE(a.AddToWallet(wtx, true, nullptr));
            ASSERT_TRUE(b.AddToWallet(wtx, true, nullptr));
        }
        // Blocks: 3 foreign transparent txs, plus (if shielded) one foreign
        // tx with a JoinSplit and two Sapling outputs. The first nNoteTxs
        // blocks also carry one wallet tx whose outputs are all ours.
        std::vector<CBlock> blocks(nBlocks);
        std::vector<CBlockIndex> idx(nBlocks);
        std::vector<CWalletTx> ours;
        for (int h = 0; h < nBlocks; h++) {
            idx[h].nHeight = h + 1;
            for (int t = 0; t < 3; t++) blocks[h].vtx.push_back(RandomTx(rng, 0, 0));
            if (c.shielded) blocks[h].vtx.push_back(RandomTx(rng, 1, 2));
            if (h < c.nNoteTxs) {
                CTransaction tx = RandomTx(rng, 1, 2);
                blocks[h].vtx.push_back(tx);
                CWalletTx wtx(nullptr, tx);
                AttachNotes(rng, wtx, 100);
                ours.push_back(wtx);
            }
        }
        double total[2] = {0, 0};
        for (int pass = 0; pass < 2; pass++) {
            SproutMerkleTree sprout;
            SaplingMerkleTree sapling;
            for (int h = 0; h < nBlocks; h++) {
                if (h < c.nNoteTxs) {
                    if (pass == 0) ASSERT_TRUE(a.AddToWallet(ours[h], true, nullptr));
                    else ASSERT_TRUE(b.AddToWallet(ours[h], true, nullptr));
                }
                auto t0 = std::chrono::steady_clock::now();
                if (pass == 0) {
                    a.ChainTipWitness(&idx[h], &blocks[h], sprout, sapling, true);
                } else {
                    witness_ref::ChainTip(b, &idx[h], &blocks[h], sprout, sapling, true);
                }
                auto t1 = std::chrono::steady_clock::now();
                total[pass] += std::chrono::duration<double, std::micro>(t1 - t0).count();
                for (const CTransaction& tx : blocks[h].vtx) {
                    for (const JSDescription& js : tx.vjoinsplit)
                        for (const uint256& cm : js.commitments) sprout.append(cm);
                    for (const OutputDescription& od : tx.vShieldedOutput) sapling.append(od.cm);
                }
            }
        }
        ExpectSameWitnessState(a, b, "bench");
        if (HasFatalFailure()) return;
        std::printf("[witness-bench] transparent=%d noteTxs=%d shieldedBlocks=%s: original %.2f us/block, indexed %.2f us/block (%d blocks, trees passed by value in both)\n",
                    c.nTransparent, c.nNoteTxs, c.shielded ? "yes" : "no",
                    total[1] / nBlocks, total[0] / nBlocks, nBlocks);
    }
}
