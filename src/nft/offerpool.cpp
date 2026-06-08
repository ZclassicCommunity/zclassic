// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// NFT marketplace — RAM-only offerpool implementation (MARKETPLACE_DESIGN.md
// §3.3, §5, §12). See offerpool.h for the contract. NON-consensus, RAM-only,
// hard-capped, thread-safe (cs_pool). No cs_main is taken here — chain liveness
// is supplied by the caller's injected EvictStale callback.

// ENABLE_WALLET comes from bitcoin-config.h and MUST be defined before the
// wallet-guarded offerpool.h is included, or this TU compiles to nothing and
// every COfferPool method becomes an undefined reference at link.
#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "nft/offerpool.h"

#ifdef ENABLE_WALLET

#include <algorithm>

// The single global instance (mirrors the in-tree singleton style, e.g. mempool).
COfferPool g_offerPool;

bool COfferPool::Insert(const CNftOfferBlob& blob, const uint256& advertisedId,
                        size_t serializedBytes, int height, std::string& reason)
{
    // ANTI-GRIND (§5): the advertised hash MUST equal the content hash of the
    // blob actually delivered. A peer that announces one offerId and ships a
    // different blob is caught HERE, before anything is stored. Recompute from
    // the blob — never trust the caller's claim that they already matched.
    uint256 trueHash = blob.OfferHash();
    if (advertisedId != trueHash) {
        reason = "advertised offerId does not match blob OfferHash (anti-grind)";
        return false;
    }

    // Single-offer size cap (§5): reject an oversize entry before it can count
    // against the pool. (The §5 body bound is 4 KiB; this leaves headroom.)
    if (serializedBytes > OFFERPOOL_MAX_OFFER_BYTES) {
        reason = "offer exceeds per-offer byte cap";
        return false;
    }

    LOCK(cs_pool);

    // Dedup: an already-present hash is a no-op success. Leave the stored entry
    // (and all accounting) untouched.
    std::map<uint256, COfferPoolEntry>::iterator it = mapOffers.find(trueHash);
    if (it != mapOffers.end())
        return true;

    // Total-offers cap (reject-new when full).
    if (mapOffers.size() >= OFFERPOOL_MAX_OFFERS) {
        reason = "offerpool is full (max offers)";
        return false;
    }

    // Total-bytes cap (reject-new when this entry would push us over).
    if (nTotalBytes + serializedBytes > OFFERPOOL_MAX_BYTES) {
        reason = "offerpool is full (max bytes)";
        return false;
    }

    // Per-token cap: one NFT cannot flood the pool with price variants (§3.3).
    std::map<uint256, size_t>::iterator pt = mapPerToken.find(blob.tokenId);
    size_t curPerToken = (pt == mapPerToken.end()) ? 0 : pt->second;
    if (curPerToken >= OFFERPOOL_MAX_PER_TOKEN) {
        reason = "per-token offer cap reached for this NFT";
        return false;
    }

    // Accept. Cache the scalars so Browse/sort never re-deserialize.
    COfferPoolEntry e;
    e.blob            = blob;
    e.offerHash       = trueHash;
    e.serializedBytes = serializedBytes;
    e.firstSeenHeight = height;
    e.live            = true;
    e.priceZat        = blob.priceZat;
    e.tokenId         = blob.tokenId;
    e.expiryHeight    = blob.expiryHeight;

    mapOffers[trueHash] = e;
    mapPerToken[blob.tokenId] = curPerToken + 1;
    nTotalBytes += serializedBytes;
    return true;
}

bool COfferPool::Get(const uint256& hash, CNftOfferBlob& out) const
{
    LOCK(cs_pool);
    std::map<uint256, COfferPoolEntry>::const_iterator it = mapOffers.find(hash);
    if (it == mapOffers.end())
        return false;
    out = it->second.blob;
    return true;
}

bool COfferPool::Has(const uint256& hash) const
{
    LOCK(cs_pool);
    return mapOffers.count(hash) != 0;
}

// Assumes cs_pool held. Removes the entry and rolls back its per-token + byte
// accounting. Safe to call from inside an iteration as long as the caller does
// not keep an iterator to the erased key (EvictStale collects keys first).
void COfferPool::EraseLocked(const uint256& hash)
{
    AssertLockHeld(cs_pool);
    std::map<uint256, COfferPoolEntry>::iterator it = mapOffers.find(hash);
    if (it == mapOffers.end())
        return;

    // Byte accounting.
    if (nTotalBytes >= it->second.serializedBytes)
        nTotalBytes -= it->second.serializedBytes;
    else
        nTotalBytes = 0; // defensive; should never underflow

    // Per-token accounting.
    std::map<uint256, size_t>::iterator pt = mapPerToken.find(it->second.tokenId);
    if (pt != mapPerToken.end()) {
        if (pt->second <= 1)
            mapPerToken.erase(pt);
        else
            pt->second -= 1;
    }

    mapOffers.erase(it);
}

void COfferPool::EvictByHash(const uint256& hash)
{
    LOCK(cs_pool);
    EraseLocked(hash);
}

size_t COfferPool::EvictStale(std::function<bool(const CNftOfferBlob&)> isStillLive,
                              int tipHeight)
{
    LOCK(cs_pool);

    // Collect doomed keys first, then erase, so we never invalidate the iterator
    // we are walking and never call a (potentially cs_main-taking) callback while
    // mutating the map.
    std::vector<uint256> doomed;
    for (std::map<uint256, COfferPoolEntry>::iterator it = mapOffers.begin();
         it != mapOffers.end(); ++it) {
        const COfferPoolEntry& e = it->second;

        // Expiry: an offer with an expiry that has reached/passed the tip is dead.
        // (expiryHeight == 0 means "no expiry" — never expires on this axis.)
        bool expired = (e.expiryHeight != 0 &&
                        (int)e.expiryHeight <= tipHeight);

        // Liveness: ask the injected oracle (the chain) whether vin[0] is still
        // an unspent, owned NFT UTXO. Spent/filled => dead.
        bool dead = expired;
        if (!dead && isStillLive) {
            if (!isStillLive(e.blob))
                dead = true;
        }

        if (dead)
            doomed.push_back(it->first);
    }

    for (size_t i = 0; i < doomed.size(); ++i)
        EraseLocked(doomed[i]);

    return doomed.size();
}

namespace {
// Strict weak ordering: price ascending, then offerHash for a stable tiebreak.
bool EntryPriceLess(const COfferPoolEntry& a, const COfferPoolEntry& b)
{
    if (a.priceZat != b.priceZat)
        return a.priceZat < b.priceZat;
    return a.offerHash < b.offerHash;
}
} // namespace

std::vector<COfferPoolEntry> COfferPool::Browse(const COfferPoolFilter& filter) const
{
    LOCK(cs_pool);

    std::vector<COfferPoolEntry> hits;
    for (std::map<uint256, COfferPoolEntry>::const_iterator it = mapOffers.begin();
         it != mapOffers.end(); ++it) {
        const COfferPoolEntry& e = it->second;

        if (filter.hasTokenId && e.tokenId != filter.tokenId)
            continue;
        if (filter.hasMaxPriceZat && e.priceZat > filter.maxPriceZat)
            continue;
        if (filter.hasMinExpiry) {
            // An offer satisfies a minExpiry floor if it has no expiry (0) or its
            // expiry is at/after the requested floor.
            if (e.expiryHeight != 0 && (int)e.expiryHeight < filter.minExpiry)
                continue;
        }
        hits.push_back(e);
    }

    // Floor first.
    std::sort(hits.begin(), hits.end(), EntryPriceLess);

    // Pagination (after sort). `from` past the end => empty; count == 0 => all
    // remaining from `from`. Compute the take count with OVERFLOW-SAFE clamping:
    // `from` and `count` come (eventually) from an RPC caller, so `from + count`
    // could wrap size_t and slip past a naive `< hits.size()` guard, yielding an
    // out-of-bounds end iterator (UB). `avail` is safe (from < hits.size() here).
    if (filter.from >= hits.size())
        return std::vector<COfferPoolEntry>();

    size_t avail = hits.size() - filter.from;
    size_t take  = (filter.count == 0) ? avail : std::min(filter.count, avail);
    std::vector<COfferPoolEntry>::iterator beginIt = hits.begin() + filter.from;
    std::vector<COfferPoolEntry>::iterator endIt   = beginIt + take;
    return std::vector<COfferPoolEntry>(beginIt, endIt);
}

std::vector<uint256> COfferPool::AllHashes(size_t max) const
{
    LOCK(cs_pool);
    std::vector<uint256> out;
    out.reserve(max != 0 && max < mapOffers.size() ? max : mapOffers.size());
    for (std::map<uint256, COfferPoolEntry>::const_iterator it = mapOffers.begin();
         it != mapOffers.end(); ++it) {
        if (max != 0 && out.size() >= max)
            break;
        out.push_back(it->first);
    }
    return out;
}

size_t COfferPool::Count() const
{
    LOCK(cs_pool);
    return mapOffers.size();
}

size_t COfferPool::Bytes() const
{
    LOCK(cs_pool);
    return nTotalBytes;
}

std::vector<COfferPoolFloor> COfferPool::FloorByToken() const
{
    LOCK(cs_pool);

    // Aggregate min-price + count per token.
    std::map<uint256, COfferPoolFloor> agg;
    for (std::map<uint256, COfferPoolEntry>::const_iterator it = mapOffers.begin();
         it != mapOffers.end(); ++it) {
        const COfferPoolEntry& e = it->second;
        std::map<uint256, COfferPoolFloor>::iterator f = agg.find(e.tokenId);
        if (f == agg.end()) {
            COfferPoolFloor nf;
            nf.tokenId       = e.tokenId;
            nf.floorPriceZat = e.priceZat;
            nf.offerCount    = 1;
            agg[e.tokenId]   = nf;
        } else {
            if (e.priceZat < f->second.floorPriceZat)
                f->second.floorPriceZat = e.priceZat;
            f->second.offerCount += 1;
        }
    }

    std::vector<COfferPoolFloor> out;
    out.reserve(agg.size());
    for (std::map<uint256, COfferPoolFloor>::const_iterator it = agg.begin();
         it != agg.end(); ++it)
        out.push_back(it->second);
    return out;
}

void COfferPool::Clear()
{
    LOCK(cs_pool);
    mapOffers.clear();
    mapPerToken.clear();
    nTotalBytes = 0;
}

#endif // ENABLE_WALLET
