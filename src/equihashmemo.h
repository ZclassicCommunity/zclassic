// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCLASSIC_EQUIHASHMEMO_H
#define ZCLASSIC_EQUIHASHMEMO_H

#include "uint256.h"

#include <stddef.h>
#include <stdint.h>

#include <mutex>
#include <vector>

/** Default number of block hashes the process-wide Equihash memo holds
 *  (32 bytes each, so 1 MiB). Sized to cover the 1024-block download window
 *  plus the headers that arrive alongside it many times over. */
static const size_t DEFAULT_EQUIHASH_MEMO_ENTRIES = 32768;

/**
 * Bounded, thread-safe set of block hashes whose Equihash solution has
 * already been verified VALID in this process.
 *
 * Soundness argument (why a hit may skip the verifier):
 *  - The key is the block hash, SHA256d over the whole serialized header,
 *    which covers every byte CheckEquihashSolution reads: the CEquihashInput
 *    fields, nNonce and nSolution (and therefore the (n,k) derived from the
 *    solution size). The verifier is a pure function of those bytes.
 *  - Only TRUE results are inserted. A miss always runs the full verifier,
 *    so the first evaluation of any header, its reject reason and its DoS
 *    score are exactly what they were without the memo, and an invalid
 *    solution can never be accepted because of it.
 *  - Eviction only turns a future hit into a miss (a re-verification).
 *
 * Layout: 4-way set-associative table indexed by a salted hash of the key
 * (the salt is random per process, so peers cannot aim headers at one set).
 * Memory is fixed at construction.
 */
class CEquihashMemo
{
public:
    static const size_t WAYS = 4;

    struct Stats {
        uint64_t lookups;
        uint64_t hits;
        uint64_t inserts;
        uint64_t evictions;
    };

    /** nMaxEntries is rounded up to a power of two and to at least WAYS. */
    explicit CEquihashMemo(size_t nMaxEntries = DEFAULT_EQUIHASH_MEMO_ENTRIES);

    /** True iff hash was inserted and has not been evicted since. */
    bool Contains(const uint256& hash) const;

    /** Record that the header with this hash has a VALID Equihash solution.
     *  Callers must only pass a hash whose verification just returned true. */
    void Insert(const uint256& hash);

    void Clear();

    size_t Capacity() const { return nSets * WAYS; }
    size_t Size() const;
    Stats GetStats() const;

private:
    size_t SetIndex(const uint256& hash) const;

    mutable std::mutex cs;
    size_t nSets;
    uint256 salt;
    std::vector<uint256> slots;   // nSets * WAYS keys
    std::vector<uint8_t> used;    // nSets * WAYS flags
    size_t nUsed;
    mutable Stats stats;
};

/** The process-wide memo used by CheckEquihashSolutionMemo (pow.cpp). */
CEquihashMemo& GetEquihashMemo();

#endif // ZCLASSIC_EQUIHASHMEMO_H
