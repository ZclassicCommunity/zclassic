// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "equihashmemo.h"

#include "random.h"

#include <string.h>

#include <algorithm>

static size_t RoundUpPow2(size_t n)
{
    size_t p = 1;
    while (p < n && p < (((size_t)1) << (sizeof(size_t) * 8 - 2)))
        p <<= 1;
    return p;
}

CEquihashMemo::CEquihashMemo(size_t nMaxEntries)
{
    size_t entries = RoundUpPow2(nMaxEntries < WAYS ? WAYS : nMaxEntries);
    nSets = entries / WAYS;
    slots.assign(nSets * WAYS, uint256());
    used.assign(nSets * WAYS, 0);
    nUsed = 0;
    GetRandBytes(salt.begin(), salt.size());
    memset(&stats, 0, sizeof(stats));
}

size_t CEquihashMemo::SetIndex(const uint256& hash) const
{
    // nSets is a power of two.
    return (size_t)(hash.GetHash(salt) & (uint64_t)(nSets - 1));
}

bool CEquihashMemo::Contains(const uint256& hash) const
{
    const size_t base = SetIndex(hash) * WAYS;
    std::lock_guard<std::mutex> lock(cs);
    stats.lookups++;
    for (size_t w = 0; w < WAYS; w++) {
        if (used[base + w] && slots[base + w] == hash) {
            stats.hits++;
            return true;
        }
    }
    return false;
}

void CEquihashMemo::Insert(const uint256& hash)
{
    const size_t base = SetIndex(hash) * WAYS;
    std::lock_guard<std::mutex> lock(cs);
    for (size_t w = 0; w < WAYS; w++) {
        if (used[base + w] && slots[base + w] == hash)
            return; // already present
    }
    // Insert at way 0 and shift the set down (FIFO within the set); the
    // entry in the last way, if any, is evicted.
    if (used[base + WAYS - 1])
        stats.evictions++;
    else
        nUsed++;
    for (size_t w = WAYS - 1; w > 0; w--) {
        slots[base + w] = slots[base + w - 1];
        used[base + w] = used[base + w - 1];
    }
    slots[base] = hash;
    used[base] = 1;
    stats.inserts++;
}

void CEquihashMemo::Clear()
{
    std::lock_guard<std::mutex> lock(cs);
    std::fill(used.begin(), used.end(), 0);
    std::fill(slots.begin(), slots.end(), uint256());
    nUsed = 0;
}

size_t CEquihashMemo::Size() const
{
    std::lock_guard<std::mutex> lock(cs);
    return nUsed;
}

CEquihashMemo::Stats CEquihashMemo::GetStats() const
{
    std::lock_guard<std::mutex> lock(cs);
    return stats;
}

CEquihashMemo& GetEquihashMemo()
{
    // Constructed on first use (thread-safe static initialisation), after
    // the RNG is available; never destroyed before other statics that may
    // still validate headers during shutdown.
    static CEquihashMemo* memo = new CEquihashMemo(DEFAULT_EQUIHASH_MEMO_ENTRIES);
    return *memo;
}
