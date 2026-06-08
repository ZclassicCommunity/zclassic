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
#include "util.h"          // GetDataDir, FileCommit, RenameOver
#include "utiltime.h"      // GetTimeMicros (block-index cache timing)
#include "streams.h"       // CAutoFile (block-index cache I/O)
#include "clientversion.h" // CLIENT_VERSION (cache schema pinning)

#include <algorithm>
#include <stdint.h>

#include <boost/filesystem.hpp>   // exists / file_size / remove for the block-index cache

#include <boost/thread.hpp>

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
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1');
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

bool CBlockTreeDB::WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBlockFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }
    batch.Write(DB_LAST_BLOCK, nLastFile);
    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        batch.Write(make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), CDiskBlockIndex(*it));
    }
    return WriteBatch(batch, true);
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

// ============================================================================
// BOOT SPEEDUP — block-index snapshot cache.  See txdb.h for the safety contract.
// ============================================================================

// File header for blocks/blockindex.dat. Serialized with the SAME stream as the body so the
// whole-file checksum covers it. Fixed-width fields via the stream operators (little-endian
// normalized by serialize.h) — NO raw struct dump, so it is portable across same-CLIENT_VERSION
// builds; nPtrSize is a cheap arch sanity tag.
static const uint32_t BLOCKINDEX_CACHE_MAGIC   = 0x5A434249; // 'Z','C','B','I'
static const uint32_t BLOCKINDEX_CACHE_VERSION = 1;          // bump to invalidate all old caches

namespace {
struct BlockIndexCacheHeader {
    uint32_t nMagic;
    uint32_t nFormatVersion;
    int32_t  nClientVersion;
    uint8_t  nPtrSize;
    uint256  hashGenesis;
    uint256  hashTip;
    int32_t  nTipHeight;
    uint64_t nCount;

    BlockIndexCacheHeader()
        : nMagic(0), nFormatVersion(0), nClientVersion(0), nPtrSize(0),
          nTipHeight(0), nCount(0) {}

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nMagic);
        READWRITE(nFormatVersion);
        READWRITE(nClientVersion);
        READWRITE(nPtrSize);
        READWRITE(hashGenesis);
        READWRITE(hashTip);
        READWRITE(nTipHeight);
        READWRITE(nCount);
    }
};
} // namespace

// Rehydrate ONE on-disk record into the in-memory mapBlockIndex, IDENTICALLY for the leveldb
// scan and the cache load (single source of truth, so the two paths can never drift). Returns
// the new/updated index, or NULL if the record fails CheckProofOfWork (the existing
// LoadBlockIndexGuts behaviour — the caller turns NULL into an error/fallback). pprev is
// recovered by hash via InsertBlockIndex, so records may be applied in any order.
static CBlockIndex* ApplyDiskBlockIndex(const CDiskBlockIndex& diskindex)
{
    CBlockIndex* pindexNew      = InsertBlockIndex(diskindex.GetBlockHash());
    pindexNew->pprev            = InsertBlockIndex(diskindex.hashPrev);
    pindexNew->nHeight          = diskindex.nHeight;
    pindexNew->nFile            = diskindex.nFile;
    pindexNew->nDataPos         = diskindex.nDataPos;
    pindexNew->nUndoPos         = diskindex.nUndoPos;
    pindexNew->hashSproutAnchor = diskindex.hashSproutAnchor;
    pindexNew->nVersion         = diskindex.nVersion;
    pindexNew->hashMerkleRoot   = diskindex.hashMerkleRoot;
    pindexNew->hashFinalSaplingRoot = diskindex.hashFinalSaplingRoot;
    pindexNew->nTime            = diskindex.nTime;
    pindexNew->nBits            = diskindex.nBits;
    pindexNew->nNonce           = diskindex.nNonce;
    pindexNew->nSolution        = diskindex.nSolution;
    pindexNew->nStatus          = diskindex.nStatus;
    pindexNew->nCachedBranchId  = diskindex.nCachedBranchId;
    pindexNew->nTx              = diskindex.nTx;
    pindexNew->nSproutValue     = diskindex.nSproutValue;
    pindexNew->nSaplingValue    = diskindex.nSaplingValue;

    if (!CheckProofOfWork(pindexNew->GetBlockHash(), pindexNew->nBits, Params().GetConsensus()))
        return NULL;
    return pindexNew;
}

bool CBlockTreeDB::LoadBlockIndexGuts()
{
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(make_pair(DB_BLOCK_INDEX, uint256()));

    int64_t nLoaded = 0;

    // Load mapBlockIndex
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex)) {
                // Construct the in-memory block index object from the on-disk record. This is
                // the SHARED per-record path (ApplyDiskBlockIndex), also used by the snapshot-
                // cache loader, so the two can never drift. It copies the persisted fields and
                // runs CheckProofOfWork (the old duplicate header re-hash was removed: it
                // compared a recompute against a recompute of identical inputs and could never
                // fail, doubling the per-record hashing cost across millions of records; the PoW
                // check consumes the same already-computed hash). NULL == PoW failed.
                CBlockIndex* pindexNew = ApplyDiskBlockIndex(diskindex);
                if (!pindexNew)
                    return error("LoadBlockIndex(): CheckProofOfWork failed: %s",
                                 diskindex.GetBlockHash().ToString());

                pcursor->Next();

                // The block index holds millions of records; scanning it is the
                // longest phase of an otherwise-synced startup. Emit a periodic
                // progress message so neither the console nor a GUI looks frozen.
                // InitMessage is wired to SetRPCWarmupStatus (init.cpp), so the
                // climbing count also reaches GUI wallets polling over RPC during
                // warmup. Trailing "..." matches the wallet's dot-animation. Purely
                // cosmetic -- it does not change what is loaded.
                if ((++nLoaded % 50000) == 0)
                    uiInterface.InitMessage(strprintf(_("Loading block index %d..."), nLoaded));
            } else {
                return error("LoadBlockIndex() : failed to read value");
            }
        } else {
            break;
        }
    }

    return true;
}

// Write the in-memory block index to blocks/blockindex.dat on a CLEAN shutdown. Best-effort:
// any error logs a warning and returns false; it NEVER blocks or fails shutdown. Mirrors the
// proven CAddrDB write idiom (temp file + fsync + atomic rename) but streams records so a
// multi-GB index is not held in RAM. hashTip MUST be the durable coins-DB best block captured
// by the caller while pcoinsTip is still valid (the same anchor the next-boot loader checks).
bool CBlockTreeDB::WriteBlockIndexCache(const uint256& hashTip, int nTipHeight)
{
    if (hashTip.IsNull() || mapBlockIndex.empty())
        return false;   // nothing durable to cache yet

    // Never cache a tree that is mid-(persisted)-reindex: it is not a faithful full index.
    bool fReindexing = false;
    if (ReadReindexing(fReindexing) && fReindexing)
        return false;

    boost::filesystem::path pathTmp   = GetDataDir() / "blocks" / "blockindex.dat.new";
    boost::filesystem::path pathFinal = GetDataDir() / "blocks" / "blockindex.dat";
    try {
        // Snapshot the pointers under the (caller-held) cs_main, sorted by height for
        // sequential locality + parents-before-children (correctness does not depend on order;
        // pprev is recovered by hash on load).
        std::vector<const CBlockIndex*> vByHeight;
        vByHeight.reserve(mapBlockIndex.size());
        for (BlockMap::const_iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); ++it)
            vByHeight.push_back(it->second);
        std::sort(vByHeight.begin(), vByHeight.end(),
                  [](const CBlockIndex* a, const CBlockIndex* b) { return a->nHeight < b->nHeight; });

        // Refuse on a near-full disk (the file is comparable in size to blocks/index).
        const uint64_t nEst = (uint64_t)vByHeight.size() * 1500ull + 4096;
        if (!CheckDiskSpace(nEst))
            return error("%s: insufficient disk for block-index cache (need ~%uMB)",
                         __func__, (unsigned)(nEst >> 20));

        CAutoFile fileout(fopen(pathTmp.string().c_str(), "wb"), SER_DISK, CLIENT_VERSION);
        if (fileout.IsNull())
            return error("%s: failed to open %s", __func__, pathTmp.string());

        CHashWriter hasher(SER_DISK, CLIENT_VERSION);
        BlockIndexCacheHeader hdr;
        hdr.nMagic         = BLOCKINDEX_CACHE_MAGIC;
        hdr.nFormatVersion = BLOCKINDEX_CACHE_VERSION;
        hdr.nClientVersion = CLIENT_VERSION;
        hdr.nPtrSize       = (uint8_t)sizeof(void*);
        hdr.hashGenesis    = Params().GetConsensus().hashGenesisBlock;
        hdr.hashTip        = hashTip;
        hdr.nTipHeight     = nTipHeight;
        hdr.nCount         = vByHeight.size();
        fileout << hdr;
        hasher  << hdr;

        for (size_t i = 0; i < vByHeight.size(); ++i) {
            CDiskBlockIndex di(vByHeight[i]);
            fileout << di;   // exactly the bytes leveldb stores as the record value
            hasher  << di;   // checksum the identical serialization (manual tee)
        }
        fileout << hasher.GetHash();   // trailing whole-file checksum

        FileCommit(fileout.Get());     // fsync before the rename
        fileout.fclose();
        if (!RenameOver(pathTmp, pathFinal))
            return error("%s: atomic rename into place failed", __func__);

        LogPrintf("%s: wrote %u block-index records (tip %s height %d)\n",
                  __func__, (unsigned)hdr.nCount, hashTip.ToString(), nTipHeight);
        return true;
    } catch (const std::exception& e) {
        LogPrintf("%s: block-index cache write failed (%s); continuing\n", __func__, e.what());
        try { boost::filesystem::remove(pathTmp); } catch (...) {}
        return false;
    }
}

// Rehydrate mapBlockIndex from blocks/blockindex.dat INSTEAD of the full leveldb scan, but only
// when the cache is provably current + intact + complete. Returns true on a verified hit (caller
// skips LoadBlockIndexGuts); false on any miss/mismatch/corruption (caller runs the leveldb scan).
// On any mid-load failure we UnloadBlockIndex() first so no partial state can leak into the
// fallback. leveldb stays authoritative; this can only ever be a faster equivalent or be ignored.
bool CBlockTreeDB::LoadBlockIndexFromCache(const uint256& hashBestChain)
{
    if (hashBestChain.IsNull())
        return false;   // empty/fresh datadir -> nothing to accelerate

    // A persisted (interrupted) reindex must rebuild from leveldb, NOT from a cache that
    // predates it (the readHook only sees the cmdline flags; the durable flag is read later).
    bool fReindexing = false;
    if (ReadReindexing(fReindexing) && fReindexing)
        return false;

    boost::filesystem::path pathCache = GetDataDir() / "blocks" / "blockindex.dat";
    if (!boost::filesystem::exists(pathCache))
        return false;

    const int64_t t0 = GetTimeMicros();
    bool ok = false;
    uint64_t nLoaded = 0;
    try {
        const uint64_t fileSize = (uint64_t)boost::filesystem::file_size(pathCache);
        CAutoFile filein(fopen(pathCache.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION);
        if (filein.IsNull())
            return false;

        CHashWriter hasher(SER_DISK, CLIENT_VERSION);
        BlockIndexCacheHeader hdr;
        filein >> hdr;
        hasher << hdr;

        // ---- header guards (cheap; reject before any record work) ----
        if (hdr.nMagic != BLOCKINDEX_CACHE_MAGIC)            return false;  // G2 not our file
        if (hdr.nFormatVersion != BLOCKINDEX_CACHE_VERSION)  return false;  // G2 schema bump
        if (hdr.nClientVersion != CLIENT_VERSION)            return false;  // G3 record-encoding pin
        if (hdr.nPtrSize != (uint8_t)sizeof(void*))          return false;  // arch sanity (MF-6)
        if (hdr.hashGenesis != Params().GetConsensus().hashGenesisBlock)
            return false;                                                   // G4 wrong network/datadir
        if (hdr.hashTip != hashBestChain)                    return false;  // G5 staleness anchor
        // Bound nCount against the file so a corrupt header cannot drive an absurd loop/alloc.
        // Each record is at least a few dozen bytes; require room for that many.
        const uint64_t kMinRecBytes = 40;
        if (hdr.nCount == 0 || hdr.nCount > (fileSize / kMinRecBytes) + 1)
            return false;

        // ---- bulk load (streaming; PoW-checked per record exactly as leveldb) ----
        for (uint64_t i = 0; i < hdr.nCount; ++i) {
            CDiskBlockIndex diskindex;
            filein >> diskindex;          // throws on short/corrupt -> caught -> fallback
            hasher << diskindex;          // recompute the whole-file checksum
            if (!ApplyDiskBlockIndex(diskindex))   // G7 PoW; byte-identical to leveldb path
                throw std::runtime_error("record failed proof-of-work");
            ++nLoaded;
        }

        // ---- whole-file integrity (bit-rot / truncation guard) ----
        uint256 storedChecksum;
        filein >> storedChecksum;
        if (hasher.GetHash() != storedChecksum)            // G6
            throw std::runtime_error("checksum mismatch");

        // ---- structural / completeness guards ----
        // G8b: a complete index has every parent present, so InsertBlockIndex created NO stub
        // parents -> mapBlockIndex holds exactly nCount entries. A mismatch means a dangling
        // parent (corrupt/forged/partial) -> reject (also blocks the injected-fork boot-loop).
        if ((uint64_t)mapBlockIndex.size() != hdr.nCount)
            throw std::runtime_error("dangling parent / record-set incomplete");
        // G9: the authoritative tip must actually be present (else the later SetTip path errors).
        BlockMap::iterator tipIt = mapBlockIndex.find(hdr.hashTip);
        if (tipIt == mapBlockIndex.end())
            throw std::runtime_error("tip record absent");
        // Cross-check the single most-consequential record against authoritative leveldb (one
        // cheap point-read): a forged-but-checksum-valid tip record cannot be trusted.
        CDiskBlockIndex tipDisk;
        if (!ReadDiskBlockIndex(hdr.hashTip, tipDisk))
            throw std::runtime_error("tip record missing from leveldb");
        CBlockIndex* tip = tipIt->second;
        if (tipDisk.GetBlockHash() != hdr.hashTip || tipDisk.nHeight != tip->nHeight ||
            tipDisk.nBits != tip->nBits || tipDisk.nStatus != tip->nStatus)
            throw std::runtime_error("tip record disagrees with leveldb");

        ok = true;
    } catch (const std::exception& e) {
        LogPrintf("LoadBlockIndexFromCache: ignoring block-index cache (%s); using leveldb\n", e.what());
        ok = false;
    }

    if (!ok) {
        UnloadBlockIndex();   // wipe any partial state -> clean slate for the leveldb fallback
        return false;
    }
    LogPrintf("LoadBlockIndexFromCache: block-index cache HIT (%u records in %.2fs)\n",
              (unsigned)nLoaded, (GetTimeMicros() - t0) * 1e-6);
    return true;
}
