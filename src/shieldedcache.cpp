// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "shieldedcache.h"

#include "crypto/common.h"
#include "crypto/sha256.h"
#include "random.h"
#include "util.h"

#include <boost/thread.hpp>
#include <boost/unordered_set.hpp>

namespace {

/** Entries already carry a per-process random nonce, so no further blinding
 *  is needed in the set hash (as in sigcache.cpp). */
class CShieldedVerdictHasher
{
public:
    size_t operator()(const uint256& key) const {
        return key.GetCheapHash();
    }
};

class CShieldedVerdictCache
{
private:
    //! Entries are SHA256(nonce || txid || branchId as 4 bytes LE).
    uint256 nonce;
    typedef boost::unordered_set<uint256, CShieldedVerdictHasher> map_type;
    map_type setValid;
    size_t nMaxEntries;
    boost::shared_mutex cs_shieldedcache;

    static size_t ReadMaxEntries()
    {
        int64_t nMiB = GetArg("-maxshieldedcachesize", DEFAULT_MAX_SHIELDED_CACHE_SIZE);
        if (nMiB <= 0)
            return 0;
        if (nMiB > 16384)
            nMiB = 16384; // 16 GiB: keeps the product below in range everywhere
        return (size_t)(((uint64_t)nMiB << 20) / 64);
    }

public:
    CShieldedVerdictCache() : nMaxEntries(ReadMaxEntries())
    {
        GetRandBytes(nonce.begin(), 32);
    }

    void ComputeEntry(uint256& entry, const uint256& txid, uint32_t branchId) const
    {
        unsigned char le[4];
        WriteLE32(le, branchId);
        CSHA256().Write(nonce.begin(), 32).Write(txid.begin(), 32).Write(le, 4).Finalize(entry.begin());
    }

    bool Contains(const uint256& txid, uint32_t branchId)
    {
        uint256 entry;
        ComputeEntry(entry, txid, branchId);
        boost::shared_lock<boost::shared_mutex> lock(cs_shieldedcache);
        if (nMaxEntries == 0)
            return false;
        return setValid.count(entry) != 0;
    }

    void Insert(const uint256& txid, uint32_t branchId)
    {
        uint256 entry;
        ComputeEntry(entry, txid, branchId);
        boost::unique_lock<boost::shared_mutex> lock(cs_shieldedcache);
        if (nMaxEntries == 0)
            return;
        if (setValid.count(entry))
            return;
        // Same random-bucket eviction as the signature cache.
        while (setValid.size() >= nMaxEntries) {
            map_type::size_type s = GetRand(setValid.bucket_count());
            map_type::local_iterator it = setValid.begin(s);
            if (it != setValid.end(s)) {
                setValid.erase(*it);
            }
        }
        setValid.insert(entry);
    }

    void ClearForTest()
    {
        boost::unique_lock<boost::shared_mutex> lock(cs_shieldedcache);
        setValid.clear();
        nMaxEntries = ReadMaxEntries();
    }

    size_t Size()
    {
        boost::shared_lock<boost::shared_mutex> lock(cs_shieldedcache);
        return setValid.size();
    }

    size_t MaxEntries()
    {
        boost::shared_lock<boost::shared_mutex> lock(cs_shieldedcache);
        return nMaxEntries;
    }
};

CShieldedVerdictCache& GetShieldedVerdictCache()
{
    // Constructed on first use (thread-safe since C++11); -maxshieldedcachesize
    // is read once at that point.
    static CShieldedVerdictCache cache;
    return cache;
}

} // namespace

bool ShieldedVerdictContains(const uint256& txid, uint32_t branchId)
{
    return GetShieldedVerdictCache().Contains(txid, branchId);
}

void ShieldedVerdictInsert(const uint256& txid, uint32_t branchId)
{
    GetShieldedVerdictCache().Insert(txid, branchId);
}

void ShieldedVerdictClearForTest()
{
    GetShieldedVerdictCache().ClearForTest();
}

size_t ShieldedVerdictSizeForTest()
{
    return GetShieldedVerdictCache().Size();
}

size_t ShieldedVerdictMaxEntriesForTest()
{
    return GetShieldedVerdictCache().MaxEntries();
}
