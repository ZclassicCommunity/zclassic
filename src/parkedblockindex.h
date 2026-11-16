// Distributed under the MIT software license; see COPYING.
#ifndef ZCLASSIC_PARKEDBLOCKINDEX_H
#define ZCLASSIC_PARKEDBLOCKINDEX_H

#include "chain.h"
#include <set>

// Derived, memory-only index of nonzero parked flags. Its owner holds cs_main
// and updates it whenever those flags change, after loading, and before deletion.
// It does not decide whether a block is valid or eligible for unparking.
class ParkedBlockIndex {
    std::set<CBlockIndex*> entries;
public:
    void Update(CBlockIndex* block) {
        if (block->nStatus & BLOCK_PARKED_MASK) entries.insert(block);
        else entries.erase(block);
    }
    void Erase(const CBlockIndex* block) { entries.erase(const_cast<CBlockIndex*>(block)); }
    void Clear() { entries.clear(); }
    size_t Size() const { return entries.size(); }
    bool Contains(const CBlockIndex* block) const {
        return entries.count(const_cast<CBlockIndex*>(block)) != 0;
    }

    // Equivalent to the old full-map descendant pass and full ancestor walk.
    // Notify only changed nodes, distinguishing descendants (including target)
    // from ancestors because only descendants refresh the candidate set.
    template<typename Changed>
    void Unpark(CBlockIndex* target, bool clearChildren, Changed changed) {
        for (auto it = entries.begin(); it != entries.end();) {
            CBlockIndex* block = *it++;
            bool descendant = false;
            unsigned int mask;
            if (block->nHeight >= target->nHeight &&
                block->GetAncestor(target->nHeight) == target) {
                descendant = true;
                mask = (clearChildren || block == target) ? BLOCK_PARKED_MASK : BLOCK_PARKED_PARENT_FLAG;
            } else if (block->nHeight < target->nHeight &&
                       target->GetAncestor(block->nHeight) == block) {
                mask = BLOCK_PARKED_MASK;
            } else {
                continue;
            }
            const unsigned int status = block->nStatus & ~mask;
            if (status == block->nStatus) continue;
            block->nStatus = status;
            if (!(status & BLOCK_PARKED_MASK)) entries.erase(block);
            changed(block, descendant);
        }
    }
};
#endif
