// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdb.h"

#include "chainparams.h"
#include "hash.h"
#include "main.h"
#include "pow.h"
#include "ui_interface.h"
#include "uint256.h"

#include <stdint.h>

#include <boost/thread.hpp>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <exception>
#include <future>
#include <list>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

using namespace std;

// NOTE: Per issue #3277, do not use the prefix 'X' or 'x' as they were
// previously used by DB_SAPLING_ANCHOR and DB_BEST_SAPLING_ANCHOR.
static const char DB_SPROUT_ANCHOR = 'A';
static const char DB_SAPLING_ANCHOR = 'Z';
static const char DB_NULLIFIER = 's';
static const char DB_SAPLING_NULLIFIER = 'S';
static const char DB_COINS = 'c';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BLOCK_INDEX = 'b';

static const char DB_BEST_BLOCK = 'B';
static const char DB_BEST_SPROUT_ANCHOR = 'a';
static const char DB_BEST_SAPLING_ANCHOR = 'z';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';


CCoinsViewDB::CCoinsViewDB(std::string dbName, size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / dbName, nCacheSize, fMemory, fWipe) {
}

CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe)
{
}

CCoinsViewDB::CCoinsViewDB(const boost::filesystem::path& path, size_t nCacheSize, bool fMemory, bool fWipe) : db(path, nCacheSize, fMemory, fWipe)
{
}


bool CCoinsViewDB::GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const {
    if (rt == SproutMerkleTree::empty_root()) {
        SproutMerkleTree new_tree;
        tree = new_tree;
        return true;
    }

    bool read = db.Read(make_pair(DB_SPROUT_ANCHOR, rt), tree);

    return read;
}

bool CCoinsViewDB::GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const {
    if (rt == SaplingMerkleTree::empty_root()) {
        SaplingMerkleTree new_tree;
        tree = new_tree;
        return true;
    }

    bool read = db.Read(make_pair(DB_SAPLING_ANCHOR, rt), tree);

    return read;
}

bool CCoinsViewDB::GetNullifier(const uint256 &nf, ShieldedType type) const {
    bool spent = false;
    char dbChar;
    switch (type) {
        case SPROUT:
            dbChar = DB_NULLIFIER;
            break;
        case SAPLING:
            dbChar = DB_SAPLING_NULLIFIER;
            break;
        default:
            throw runtime_error("Unknown shielded type");
    }
    return db.Read(make_pair(dbChar, nf), spent);
}

bool CCoinsViewDB::GetCoins(const uint256 &txid, CCoins &coins) const {
    return db.Read(make_pair(DB_COINS, txid), coins);
}

bool CCoinsViewDB::HaveCoins(const uint256 &txid) const {
    return db.Exists(make_pair(DB_COINS, txid));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!db.Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

uint256 CCoinsViewDB::GetBestAnchor(ShieldedType type) const {
    uint256 hashBestAnchor;
    
    switch (type) {
        case SPROUT:
            if (!db.Read(DB_BEST_SPROUT_ANCHOR, hashBestAnchor))
                return SproutMerkleTree::empty_root();
            break;
        case SAPLING:
            if (!db.Read(DB_BEST_SAPLING_ANCHOR, hashBestAnchor))
                return SaplingMerkleTree::empty_root();
            break;
        default:
            throw runtime_error("Unknown shielded type");
    }

    return hashBestAnchor;
}

void BatchWriteNullifiers(CDBBatch& batch, CNullifiersMap& mapToUse, const char& dbChar)
{
    for (CNullifiersMap::iterator it = mapToUse.begin(); it != mapToUse.end();) {
        if (it->second.flags & CNullifiersCacheEntry::DIRTY) {
            if (!it->second.entered)
                batch.Erase(make_pair(dbChar, it->first));
            else
                batch.Write(make_pair(dbChar, it->first), true);
            // TODO: changed++? ... See comment in CCoinsViewDB::BatchWrite. If this is needed we could return an int
        }
        CNullifiersMap::iterator itOld = it++;
        mapToUse.erase(itOld);
    }
}

template<typename Map, typename MapIterator, typename MapEntry, typename Tree>
void BatchWriteAnchors(CDBBatch& batch, Map& mapToUse, const char& dbChar)
{
    for (MapIterator it = mapToUse.begin(); it != mapToUse.end();) {
        if (it->second.flags & MapEntry::DIRTY) {
            if (!it->second.entered)
                batch.Erase(make_pair(dbChar, it->first));
            else {
                if (it->first != Tree::empty_root()) {
                    batch.Write(make_pair(dbChar, it->first), it->second.tree);
                }
            }
            // TODO: changed++?
        }
        MapIterator itOld = it++;
        mapToUse.erase(itOld);
    }
}

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins,
                              const uint256 &hashBlock,
                              const uint256 &hashSproutAnchor,
                              const uint256 &hashSaplingAnchor,
                              CAnchorsSproutMap &mapSproutAnchors,
                              CAnchorsSaplingMap &mapSaplingAnchors,
                              CNullifiersMap &mapSproutNullifiers,
                              CNullifiersMap &mapSaplingNullifiers) {
    CDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            if (it->second.coins.IsPruned())
                batch.Erase(make_pair(DB_COINS, it->first));
            else
                batch.Write(make_pair(DB_COINS, it->first), it->second.coins);
            changed++;
        }
        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
    }

    ::BatchWriteAnchors<CAnchorsSproutMap, CAnchorsSproutMap::iterator, CAnchorsSproutCacheEntry, SproutMerkleTree>(batch, mapSproutAnchors, DB_SPROUT_ANCHOR);
    ::BatchWriteAnchors<CAnchorsSaplingMap, CAnchorsSaplingMap::iterator, CAnchorsSaplingCacheEntry, SaplingMerkleTree>(batch, mapSaplingAnchors, DB_SAPLING_ANCHOR);

    ::BatchWriteNullifiers(batch, mapSproutNullifiers, DB_NULLIFIER);
    ::BatchWriteNullifiers(batch, mapSaplingNullifiers, DB_SAPLING_NULLIFIER);

    if (!hashBlock.IsNull())
        batch.Write(DB_BEST_BLOCK, hashBlock);
    if (!hashSproutAnchor.IsNull())
        batch.Write(DB_BEST_SPROUT_ANCHOR, hashSproutAnchor);
    if (!hashSaplingAnchor.IsNull())
        batch.Write(DB_BEST_SAPLING_ANCHOR, hashSaplingAnchor);

    LogPrint("coindb", "Committing %u changed transactions (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return db.WriteBatch(batch);
}

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "blocks" / "index", nCacheSize, fMemory, fWipe) {
}

CBlockTreeDB::CBlockTreeDB(const boost::filesystem::path& path, size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(path, nCacheSize, fMemory, fWipe) {
}

bool CBlockTreeDB::ReadDiskBlockIndex(const uint256& hash, CDiskBlockIndex& diskindex) {
    return Read(make_pair(DB_BLOCK_INDEX, hash), diskindex);
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo &info) {
    return Read(make_pair(DB_BLOCK_FILES, nFile), info);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing) {
    // Setting the flag is synced: -reindex has just wiped the block index, and only the
    // flag tells the next start so. Lost in a power cut, that start would find an empty
    // index next to full block files and write new blocks over them. Clearing it needs
    // no sync: a lost clear only runs the reindex once more.
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1', true);
    else
        return Erase(DB_REINDEX_FLAG);
}

bool CBlockTreeDB::ReadReindexing(bool &fReindexing) {
    fReindexing = Exists(DB_REINDEX_FLAG);
    return true;
}

bool CBlockTreeDB::ReadLastBlockFile(int &nFile) {
    return Read(DB_LAST_BLOCK, nFile);
}

bool CCoinsViewDB::GetStats(CCoinsStats &stats) const {
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    boost::scoped_ptr<CDBIterator> pcursor(const_cast<CDBWrapper*>(&db)->NewIterator());
    pcursor->Seek(DB_COINS);

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBlock = GetBestBlock();
    ss << stats.hashBlock;
    CAmount nTotalAmount = 0;
    // Per-coin consensus metadata (creation height, coinbase flag, tx version)
    // accumulated separately so it can be folded into hashSerializedFull WITHOUT
    // changing hashSerialized (which stays transparent-output-only for RPC/tool
    // back-compat). hashSerialized binds only nValue+scriptPubKey, but CheckInputs
    // reads nHeight/fCoinBase verbatim from an imported UTXO set for the
    // COINBASE_MATURITY rule, so an unbound metadata field lets a bootstrap snapshot
    // ship forged coinbase-maturity metadata that hashes identically to the honest
    // set — a consensus partition with no attacker hashpower. Bind it here.
    CHashWriter ssMeta(SER_GETHASH, PROTOCOL_VERSION);
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        CCoins coins;
        if (pcursor->GetKey(key) && key.first == DB_COINS) {
            if (pcursor->GetValue(coins)) {
                stats.nTransactions++;
                // Fold the consensus-relevant per-coin metadata (once per CCoins
                // entry, in leveldb sorted-key order so it is identical on every
                // node holding the same chainstate). nHeight is always >= 0; the tx
                // version is a small non-negative value in this chain.
                ssMeta << VARINT(coins.nHeight);
                ssMeta << static_cast<uint8_t>(coins.fCoinBase ? 1 : 0);
                ssMeta << VARINT(static_cast<uint32_t>(coins.nVersion));
                for (unsigned int i=0; i<coins.vout.size(); i++) {
                    const CTxOut &out = coins.vout[i];
                    if (!out.IsNull()) {
                        stats.nTransactionOutputs++;
                        ss << VARINT(i+1);
                        ss << out;
                        nTotalAmount += out.nValue;
                    }
                }
                stats.nSerializedSize += 32 + pcursor->GetValueSize();
                ss << VARINT(0);
            } else {
                return error("CCoinsViewDB::GetStats() : unable to read value");
            }
        } else {
            break;
        }
        pcursor->Next();
    }
    {
        LOCK(cs_main);
        // Defensive: a scratch / frozen-copy chainstate (option B) can carry a
        // best block this node's index does not (yet) hold. Leave nHeight at its
        // default rather than dereference end(); the normal chainstate's best
        // block is always present, so gettxoutsetinfo is unaffected.
        BlockMap::const_iterator it = mapBlockIndex.find(stats.hashBlock);
        if (it != mapBlockIndex.end() && it->second)
            stats.nHeight = it->second->nHeight;
    }
    stats.hashSerialized = ss.GetHash();

    // Full-chainstate commitment: fold the transparent commitment together with the
    // shielded state so the bootstrap anchor binds the Sprout/Sapling note-commitment
    // tree anchors and the nullifier sets, not just the transparent UTXO set. Without
    // this, a snapshot could ship honest transparent coins (matching hashSerialized)
    // alongside a tampered nullifier set or forged anchor and still pass verification —
    // enabling, e.g., a shielded double-spend on a bootstrapped node.
    //
    // We hash the best-anchor roots (the current Sprout/Sapling tree tips) plus the
    // KEYS of every stored anchor and nullifier. The keys are roots/nullifiers (32-byte
    // cryptographic commitments), so binding them binds set membership and the accepted
    // tree tips cheaply, without re-hashing the (large) serialized tree blobs: a tampered
    // tree stored under an honest root would produce a divergent next-block anchor, which
    // is itself bound here for the following block. leveldb iterates each key prefix in
    // sorted order, so this digest is identical on every node holding the same chainstate.
    CHashWriter ssFull(SER_GETHASH, PROTOCOL_VERSION);
    ssFull << stats.hashSerialized;
    // Bind the per-coin consensus metadata digest (height/coinbase-flag/version)
    // accumulated above, so the bootstrap anchor commitment covers coinbase-maturity
    // inputs, not just transparent output value+script.
    ssFull << ssMeta.GetHash();
    ssFull << GetBestAnchor(SPROUT);
    ssFull << GetBestAnchor(SAPLING);
    const char shieldedPrefixes[] = { DB_SPROUT_ANCHOR, DB_SAPLING_ANCHOR,
                                      DB_NULLIFIER, DB_SAPLING_NULLIFIER };
    for (size_t p = 0; p < sizeof(shieldedPrefixes); p++) {
        const char prefix = shieldedPrefixes[p];
        boost::scoped_ptr<CDBIterator> it2(const_cast<CDBWrapper*>(&db)->NewIterator());
        for (it2->Seek(make_pair(prefix, uint256())); it2->Valid(); it2->Next()) {
            boost::this_thread::interruption_point();
            std::pair<char, uint256> key2;
            if (!it2->GetKey(key2) || key2.first != prefix)
                break;
            ssFull << key2.second;
        }
    }
    stats.hashSerializedFull = ssFull.GetHash();

    stats.nTotalAmount = nTotalAmount;
    return true;
}

// An entry loaded from disk holds no solution in memory; a rewrite (its status
// changed) copies the stored one, so a record never loses its solution. Fails,
// failing the whole batch, rather than write an empty solution.
static bool AttachStoredSolution(CBlockTreeDB& db, const CBlockIndex* pindex, CDiskBlockIndex& di)
{
    if (!pindex->fSolutionOnDisk)
        return true;
    const uint256 hash = pindex->GetBlockHash();
    CDiskBlockIndex stored;
    if (!db.ReadDiskBlockIndex(hash, stored) || stored.nSolution.empty())
        return error("WriteBatchSync: stored solution of block %s unreadable; index entry not rewritten", hash.ToString());
    di.nSolution.swap(stored.nSolution);
    return true;
}

bool CBlockTreeDB::WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBlockFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }
    batch.Write(DB_LAST_BLOCK, nLastFile);
    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        CDiskBlockIndex di(*it);
        if (!AttachStoredSolution(*this, *it, di))
            return false;
        batch.Write(make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), di);
    }
    return WriteBatch(batch, true);
}

namespace {

// Bounded LRU of solutions by block hash. A block hash commits to its solution,
// so an entry can never go stale. The mutex is never held across a database read.
class SolutionCache
{
public:
    bool Get(const uint256& hash, std::vector<unsigned char>& out)
    {
        std::lock_guard<std::mutex> lock(cs);
        auto it = index.find(hash);
        if (it == index.end()) {
            misses++;
            return false;
        }
        order.splice(order.begin(), order, it->second);
        out = it->second->second;
        hits++;
        return true;
    }

    void Put(const uint256& hash, const std::vector<unsigned char>& solution)
    {
        std::lock_guard<std::mutex> lock(cs);
        if (index.count(hash))
            return;
        order.emplace_front(hash, solution);
        index[hash] = order.begin();
        if (order.size() > BLOCK_INDEX_SOLUTION_CACHE_SIZE) {
            index.erase(order.back().first);
            order.pop_back();
        }
    }

    BlockIndexSolutionCacheStats Stats()
    {
        std::lock_guard<std::mutex> lock(cs);
        return BlockIndexSolutionCacheStats{hits, misses, order.size()};
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lock(cs);
        order.clear();
        index.clear();
        hits = misses = 0;
    }

private:
    typedef std::list<std::pair<uint256, std::vector<unsigned char> > > Order;
    std::mutex cs;
    Order order;
    std::map<uint256, Order::iterator> index;
    uint64_t hits = 0;
    uint64_t misses = 0;
};

SolutionCache& TheSolutionCache()
{
    static SolutionCache cache;
    return cache;
}

} // namespace

bool ReadBlockIndexSolution(const uint256& hash, std::vector<unsigned char>& out)
{
    if (TheSolutionCache().Get(hash, out))
        return true;
    if (pblocktree == NULL)
        return error("%s: block tree not open; solution of %s unavailable", __func__, hash.ToString());
    CDiskBlockIndex disk;
    try {
        if (!pblocktree->ReadDiskBlockIndex(hash, disk))
            return error("%s: no block index record for %s", __func__, hash.ToString());
    } catch (const std::exception& e) {
        return error("%s: reading block index record %s: %s", __func__, hash.ToString(), e.what());
    }
    if (disk.nSolution.empty() || disk.GetBlockHash() != hash)
        return error("%s: block index record %s holds no matching solution", __func__, hash.ToString());
    TheSolutionCache().Put(hash, disk.nSolution);
    out.swap(disk.nSolution);
    return true;
}

BlockIndexSolutionCacheStats GetBlockIndexSolutionCacheStats()
{
    return TheSolutionCache().Stats();
}

void ClearBlockIndexSolutionCacheForTest()
{
    TheSolutionCache().Clear();
}

bool CBlockTreeDB::EraseBatchSync(const std::vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        batch.Erase(make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()));
    }
    return WriteBatch(batch, true);
}

bool CBlockTreeDB::ReadTxIndex(const uint256 &txid, CDiskTxPos &pos) {
    return Read(make_pair(DB_TXINDEX, txid), pos);
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<uint256,CDiskTxPos> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::WriteFlag(const std::string &name, bool fValue) {
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CBlockTreeDB::ReadFlag(const std::string &name, bool &fValue) {
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

namespace {

// A run of consecutive block-index values copied out of leveldb.
struct RawIndexBatch {
    std::vector<char> data;
    std::vector<size_t> end; // end[i] = offset one past record i in data
    size_t size() const { return end.size(); }
};

// What a worker derives from a RawIndexBatch. Nothing here touches shared state.
struct ParsedIndexBatch {
    std::vector<CDiskBlockIndex> disk;
    std::vector<uint256> hash;
    std::vector<char> parsed; // record deserialized
    std::vector<char> powOk;  // CheckProofOfWork() on the block hash passed
};

ParsedIndexBatch ParseIndexBatch(const RawIndexBatch& raw, const Consensus::Params& consensus)
{
    ParsedIndexBatch out;
    const size_t n = raw.size();
    out.disk.resize(n);
    out.hash.resize(n);
    out.parsed.assign(n, 0);
    out.powOk.assign(n, 0);
    size_t begin = 0;
    for (size_t i = 0; i < n; i++) {
        const char* p = raw.data.data() + begin;
        const char* e = raw.data.data() + raw.end[i];
        begin = raw.end[i];
        try {
            CDataStream ssValue(p, e, SER_DISK, CLIENT_VERSION);
            ssValue >> out.disk[i];
        } catch (const std::exception&) {
            continue; // reported, in record order, by the consumer
        }
        out.parsed[i] = 1;
        out.hash[i] = out.disk[i].GetBlockHash();
        out.powOk[i] = CheckProofOfWork(out.hash[i], out.disk[i].nBits, consensus);
        // The index keeps no solution (fSolutionOnDisk): free it here, on the worker,
        // not when the consumer drops the batch (3.3 M frees on the load thread).
        std::vector<unsigned char>().swap(out.disk[i].nSolution);
    }
    return out;
}

} // namespace

bool CBlockTreeDB::LoadBlockIndexGuts()
{
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(make_pair(DB_BLOCK_INDEX, uint256()));

    int64_t nLoaded = 0;

    // The block index holds millions of records. Reading them is a pipeline:
    // this thread walks leveldb in key order and copies the raw values into
    // batches; worker threads deserialize each record, double-SHA256 its header
    // and check its proof of work (all pure functions of the record); this thread
    // then inserts the results into mapBlockIndex strictly in key order, so the
    // result, and the first error if any, are exactly those of the one-record-
    // at-a-time loop this replaces.
    const Consensus::Params& consensus = Params().GetConsensus();
    const unsigned int nHardware = std::thread::hardware_concurrency();
    const size_t nMaxPending = nHardware > 1 ? std::min<unsigned int>(nHardware, 8) : 0;
    static const size_t BATCH_RECORDS = 2048;


    // Insert one parsed batch. Returns false after reporting an error.
    auto consume = [&nLoaded](ParsedIndexBatch& pb) -> bool {
        for (size_t i = 0; i < pb.disk.size(); i++) {
            boost::this_thread::interruption_point();
            if (!pb.parsed[i])
                return error("LoadBlockIndex() : failed to read value");
            CDiskBlockIndex& diskindex = pb.disk[i];

            // Construct block index object
            CBlockIndex* pindexNew = InsertBlockIndex(pb.hash[i]);
            pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);
            pindexNew->nHeight        = diskindex.nHeight;
            pindexNew->nFile          = diskindex.nFile;
            pindexNew->nDataPos       = diskindex.nDataPos;
            pindexNew->nUndoPos       = diskindex.nUndoPos;
            pindexNew->hashSproutAnchor     = diskindex.hashSproutAnchor;
            pindexNew->nVersion       = diskindex.nVersion;
            pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
            pindexNew->hashFinalSaplingRoot   = diskindex.hashFinalSaplingRoot;
            pindexNew->nTime          = diskindex.nTime;
            pindexNew->nBits          = diskindex.nBits;
            pindexNew->nNonce         = diskindex.nNonce;
            // The solution stays on disk (millions of 400-1344 byte vectors);
            // GetSolution() reads it back by hash when a header is served.
            std::vector<unsigned char>().swap(pindexNew->nSolution);
            pindexNew->fSolutionOnDisk = true;
            pindexNew->nStatus        = diskindex.nStatus;
            pindexNew->nCachedBranchId = diskindex.nCachedBranchId;
            pindexNew->nTx            = diskindex.nTx;
            pindexNew->nSproutValue   = diskindex.nSproutValue;
            pindexNew->nSaplingValue  = diskindex.nSaplingValue;

            // Consistency check.
            //
            // pb.hash[i] is the double-SHA256 of the header that was just
            // deserialized, and is the key this entry was inserted under; the
            // fields above are copied verbatim from the same record, so
            // recomputing the header hash from pindexNew would compare a value
            // with itself (the former `header.GetHash() != GetBlockHash()`
            // check could never fail). The proof-of-work check consumes the same
            // hash; a worker evaluated it, and it is reported here at the same
            // point in record order as before.
            if (!pb.powOk[i])
                return error("LoadBlockIndex(): CheckProofOfWork failed: %s", pindexNew->ToString());

            // The block index holds millions of records; scanning it is the
            // longest phase of an otherwise-synced startup. Emit a periodic
            // progress message so neither the console nor a GUI looks frozen.
            // InitMessage is wired to SetRPCWarmupStatus (init.cpp), so the
            // climbing count also reaches GUI wallets polling over RPC during
            // warmup. Trailing "..." matches the wallet's dot-animation. Purely
            // cosmetic -- it does not change what is loaded.
            if ((++nLoaded % 50000) == 0)
                uiInterface.InitMessage(strprintf(_("Loading block index %d..."), nLoaded));
        }
        return true;
    };

    // Copy the next run of records out of leveldb. Returns false at the end of
    // the block-index key range (or an unparsable key), after which no more
    // records follow.
    auto readBatch = [&pcursor](RawIndexBatch& raw) -> bool {
        while (raw.size() < BATCH_RECORDS) {
            if (!pcursor->Valid())
                return false;
            std::pair<char, uint256> key;
            if (!(pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX))
                return false;
            const std::pair<const char*, size_t> value = pcursor->GetRawValue();
            raw.data.insert(raw.data.end(), value.first, value.first + value.second);
            raw.end.push_back(raw.data.size());
            pcursor->Next();
        }
        return true;
    };

    if (nHardware <= 1) {
        // One CPU: nothing to overlap.
        for (bool fMore = true; fMore;) {
            boost::this_thread::interruption_point();
            RawIndexBatch raw;
            fMore = readBatch(raw);
            ParsedIndexBatch pb = ParseIndexBatch(raw, consensus);
            if (!consume(pb))
                return false;
        }
        return true;
    }

    // A reader thread owns the leveldb iterator from here on and hands parse
    // tasks over in key order through a bounded queue; this thread consumes them
    // in that order. The guard stops and joins the reader on every exit path
    // (including a boost interruption thrown from consume()).
    struct Pipeline {
        std::mutex mtx;
        std::condition_variable cvSpace, cvItem;
        std::deque<std::future<ParsedIndexBatch>> queue;
        bool fDone = false;
        bool fStop = false;
        std::exception_ptr error;
        std::thread reader;
        ~Pipeline()
        {
            {
                std::lock_guard<std::mutex> lock(mtx);
                fStop = true;
            }
            cvSpace.notify_all();
            if (reader.joinable())
                reader.join();
        }
    } pipe;

    pipe.reader = std::thread([&pipe, &readBatch, &consensus, nMaxPending]() {
        try {
            for (bool fMore = true; fMore;) {
                RawIndexBatch raw;
                fMore = readBatch(raw);
                if (raw.size() == 0)
                    continue;
                std::future<ParsedIndexBatch> fut = std::async(std::launch::async,
                    [raw = std::move(raw), &consensus]() { return ParseIndexBatch(raw, consensus); });
                std::unique_lock<std::mutex> lock(pipe.mtx);
                pipe.cvSpace.wait(lock, [&] { return pipe.fStop || pipe.queue.size() < nMaxPending; });
                if (pipe.fStop)
                    break;
                pipe.queue.push_back(std::move(fut));
                pipe.cvItem.notify_one();
            }
        } catch (...) {
            std::lock_guard<std::mutex> lock(pipe.mtx);
            pipe.error = std::current_exception();
        }
        std::lock_guard<std::mutex> lock(pipe.mtx);
        pipe.fDone = true;
        pipe.cvItem.notify_one();
    });

    for (;;) {
        std::future<ParsedIndexBatch> fut;
        {
            std::unique_lock<std::mutex> lock(pipe.mtx);
            pipe.cvItem.wait(lock, [&] { return !pipe.queue.empty() || pipe.fDone; });
            if (pipe.queue.empty()) {
                if (pipe.error)
                    std::rethrow_exception(pipe.error);
                break;
            }
            fut = std::move(pipe.queue.front());
            pipe.queue.pop_front();
        }
        pipe.cvSpace.notify_one();
        ParsedIndexBatch pb = fut.get();
        if (!consume(pb))
            return false;
    }

    return true;
}
