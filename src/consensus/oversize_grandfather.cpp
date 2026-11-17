// Copyright (c) 2026 Rhett Creighton
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The table in z23/oversize_grandfather_table.inc is copied byte for byte from
// the Z23 repository (zclassic23), Apache License 2.0, Copyright 2026 Rhett
// Creighton (full text in src/c23/LICENSE.z23; see also src/c23/NOTICE):
//
//   Z23 path:   core/consensus/src/oversize_grandfather_table.inc
//   Z23 commit: 03a8b1d4c9ff43f47215c5d493585641cf86c3d0
//               (identical blob at origin/main 76ffcc4885843f63df1f69fc8c531911ba5f1181)
//   git blob:   1deee007953f53931b5736498c13b1436d64fde3
//   sha3-256:   443a7deeae3a1239bce85df59e19cb374529cbaaa9895e0ebdda21777f509d35
//               (Z23 core/MANIFEST.sha3)
//
// Do not edit the .inc. contrib/devtools/check-oversize-grandfather.sh verifies
// the blob hash, the entry count, the sort order and the uniqueness. Provenance
// and the rule: doc/oversize-grandfather.md.

#include "consensus/oversize_grandfather.h"

#include <string.h>

#include "consensus/consensus.h"

// The included table defines struct oversize_grandfather_entry (internal
// uint256 byte order, ascending memcmp order), OVERSIZE_GRANDFATHER_COUNT and
// g_oversize_grandfather[].
namespace {
#include "consensus/z23/oversize_grandfather_table.inc"
static_assert(OVERSIZE_GRANDFATHER_COUNT == 413u, "the table holds the 413 historical oversize transactions");
static_assert(sizeof(oversize_grandfather_entry::txid) == 32, "txid is 32 bytes");
} // namespace

size_t OversizeGrandfatherCount()
{
    return OVERSIZE_GRANDFATHER_COUNT;
}

bool OversizeGrandfatherEntry(size_t i, uint256& txid, uint32_t& nSize)
{
    if (i >= OVERSIZE_GRANDFATHER_COUNT)
        return false;
    memcpy(txid.begin(), g_oversize_grandfather[i].txid, 32);
    nSize = g_oversize_grandfather[i].size;
    return true;
}

bool IsOversizeGrandfathered(const uint256& txid, size_t nSize)
{
    if (nSize > MAX_TX_SIZE_GRANDFATHER_CEILING)
        return false;
    size_t lo = 0, hi = OVERSIZE_GRANDFATHER_COUNT;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(txid.begin(), g_oversize_grandfather[mid].txid, 32);
        if (c == 0)
            return nSize == (size_t)g_oversize_grandfather[mid].size;
        if (c < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return false;
}
