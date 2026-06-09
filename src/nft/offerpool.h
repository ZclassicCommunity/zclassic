// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// NFT marketplace — RAM-only offerpool (MARKETPLACE_DESIGN.md §3.3, P2).
//
// A hard-bounded, in-memory map of already-verified NFT sale offers, keyed by
// the FULL 32-byte CNftOfferBlob::OfferHash() (NOT the collision-weak 8-byte
// display OfferId — see nftoffer.h §3.7 / §5). It is the discovery-layer cache
// that the gossip transport (P3) fills on receipt and the marketplace RPCs (P4,
// nft_browseoffers / nft_offerpoolinfo) read.
//
// Design properties (release-gating, §1):
//   * NON-consensus. Touches no CheckBlock / ConnectBlock / pow / script-verify.
//   * RAM-only. Never persists to disk; lost on restart (re-floods via getnftinv).
//   * Hard-capped on every axis an adversary controls: total offers, total bytes,
//     per-token variants, and per-offer size (§5, §12). Insert REJECTS when full
//     (reject-new, the safest policy for an adversarial pool — see Insert()).
//   * Anti-grind: Insert demands advertisedId == blob.OfferHash() before storing,
//     so a peer cannot announce one hash and deliver a different blob.
//   * Self-evicting: EvictStale re-checks each offer's liveness via an INJECTED
//     callback (so it is unit-testable WITHOUT a live chain) and drops anything
//     spent/filled/expired. The real P3 caller passes a lambda doing the
//     pcoinsTip vin[0] check under cs_main (mirrors nft_listoffers' live recompute).
//
// THREAD-SAFETY: every public method takes cs_pool internally. No public method
// assumes cs_main; all chain work happens inside the caller-supplied EvictStale
// callback (which the caller invokes already holding whatever lock it needs).
//
// The pool stores ONLY the CNftOfferBlob plus small cached scalars (price, token,
// expiry, size). It NEVER stores decoded images or any larger blob.

#ifndef BITCOIN_NFT_OFFERPOOL_H
#define BITCOIN_NFT_OFFERPOOL_H

#ifdef ENABLE_WALLET

#include "rpc/nftoffer.h"   // CNftOfferBlob
#include "sync.h"
#include "uint256.h"

#include <functional>
#include <map>
#include <string>
#include <vector>

// ── caps (MARKETPLACE_DESIGN.md §12 — start conservative, finalize from soak) ──
//
// These bound the worst-case RAM an adversarial gossip flood can pin. They are
// all enforced at Insert() time; none can be exceeded.
static const size_t OFFERPOOL_MAX_OFFERS     = 5000;       //!< total distinct offers
static const size_t OFFERPOOL_MAX_BYTES      = 32u << 20;  //!< 32 MiB total serialized
static const size_t OFFERPOOL_MAX_PER_TOKEN  = 16;         //!< price-variants per NFT
// A single offer's serialized size. The §5 body bound is 4 KiB (NFT_OFFER_MAX_HEX
// is 4096 for offerHex alone); 8192 leaves headroom for the addresses + framing
// while still rejecting any oversize entry well before it can bloat the pool.
static const size_t OFFERPOOL_MAX_OFFER_BYTES = 8192;

/** One stored, already-verified offer plus its cached scalars for fast browse. */
struct COfferPoolEntry
{
    CNftOfferBlob blob;        //!< the verified offer (the ONLY large field)
    uint256       offerHash;   //!< == blob.OfferHash() (the map key)
    size_t        serializedBytes; //!< wire size that counted against the byte cap
    int           firstSeenHeight; //!< chain height when first inserted (diagnostics)
    bool          live;        //!< last-known liveness (set false by EvictStale path)

    // Cached from the verified blob so Browse/sort never re-deserialize.
    int64_t       priceZat;    //!< == blob.priceZat (sort/filter key; floor = min)
    uint256       tokenId;     //!< == blob.tokenId  (filter key)
    uint32_t      expiryHeight;//!< == blob.expiryHeight (0 = no expiry)

    COfferPoolEntry()
        : serializedBytes(0), firstSeenHeight(0), live(true),
          priceZat(0), expiryHeight(0)
    { offerHash.SetNull(); tokenId.SetNull(); }
};

/** Optional, defaulted filter for Browse() (§7 nft_browseoffers). */
struct COfferPoolFilter
{
    bool     hasTokenId;     //!< if true, only offers for `tokenId`
    uint256  tokenId;
    bool     hasMaxPriceZat; //!< if true, only priceZat <= maxPriceZat
    int64_t  maxPriceZat;
    bool     hasMinExpiry;   //!< if true, only expiryHeight == 0 OR >= minExpiry
    int      minExpiry;
    size_t   from;           //!< pagination offset (after sort)
    size_t   count;          //!< pagination limit (0 = "no explicit limit")

    COfferPoolFilter()
        : hasTokenId(false), hasMaxPriceZat(false), maxPriceZat(0),
          hasMinExpiry(false), minExpiry(0), from(0), count(0)
    { tokenId.SetNull(); }
};

/** Per-collection (here: per-token) floor price, for nft_offerpoolinfo. */
struct COfferPoolFloor
{
    uint256 tokenId;
    int64_t floorPriceZat; //!< lowest live priceZat for this token
    size_t  offerCount;    //!< number of live offers for this token
    COfferPoolFloor() : floorPriceZat(0), offerCount(0) { tokenId.SetNull(); }
};

/**
 * The RAM-only NFT offerpool. A single global instance `g_offerPool` is defined
 * in offerpool.cpp (mirroring the in-tree singleton style). Thread-safe.
 */
class COfferPool
{
public:
    COfferPool() : nTotalBytes(0) {}

    /**
     * Insert an already-verified offer. REJECTS (returns false + fills `reason`,
     * NEVER throws) when:
     *   - advertisedId != blob.OfferHash()       (anti-grind / anti-amplification)
     *   - serializedBytes > OFFERPOOL_MAX_OFFER_BYTES (single-offer cap)
     *   - the total-offers cap is already reached  (reject-new)
     *   - the total-bytes cap would be exceeded     (reject-new)
     *   - the per-token cap is already reached       (reject-new)
     *
     * Dedup: re-inserting an already-present hash is a NO-OP success (returns
     * true; the stored entry is left untouched). Caps are checked against the
     * post-insert size so a fresh hash that fits is accepted up to the boundary.
     *
     * Eviction policy when full = REJECT-NEW (no LRU/price eviction). For an
     * adversarial, permissionless pool this is the safe choice: an attacker that
     * fills the pool with valid-but-stale offers cannot then displace honest
     * entries, and the block-driven EvictStale GC reclaims room as offers die.
     */
    bool Insert(const CNftOfferBlob& blob, const uint256& advertisedId,
                size_t serializedBytes, int height, std::string& reason);

    /** Copy out the stored blob for `hash`. False if absent. */
    bool Get(const uint256& hash, CNftOfferBlob& out) const;

    /** True iff `hash` is present. */
    bool Has(const uint256& hash) const;

    /** Drop one offer by hash (no-op if absent). nftabort / cancel accelerator. */
    void EvictByHash(const uint256& hash);

    /**
     * Block-driven GC (§3.3). Removes every entry for which EITHER:
     *   - isStillLive(blob) returns false  (spent / filled — the chain is truth), OR
     *   - the offer has an expiry (expiryHeight != 0) that has passed relative to
     *     `tipHeight` (expiryHeight <= tipHeight).
     * Returns the number of entries removed.
     *
     * `isStillLive` is INJECTED so this method needs no live chain to test. The
     * P3 caller passes a lambda doing the pcoinsTip vin[0] liveness check under
     * cs_main; that lambda is the ONLY place cs_main is touched.
     */
    size_t EvictStale(std::function<bool(const CNftOfferBlob&)> isStillLive,
                      int tipHeight);

    /**
     * Browse the pool, price-ascending (element 0 = the floor). Applies the
     * optional tokenId / maxPriceZat / minExpiry filters, then from/count
     * pagination. Returns copies of the matching entries.
     */
    std::vector<COfferPoolEntry> Browse(const COfferPoolFilter& filter) const;

    /**
     * Enumerate up to `max` stored offer hashes (for the getnftinv -> nftinv
     * digest reply, §3.2). Returns at most `max` keys; if `max` == 0, returns
     * all. Order is the map's (offerHash-ascending) order. Thread-safe.
     */
    std::vector<uint256> AllHashes(size_t max) const;

    /** Number of offers currently held. */
    size_t Count() const;

    /** Total serialized bytes currently held (matches the byte cap accounting). */
    size_t Bytes() const;

    /** Per-token floor prices + counts (for nft_offerpoolinfo floorByCollection). */
    std::vector<COfferPoolFloor> FloorByToken() const;

    /** Drop everything (test/teardown helper). */
    void Clear();

private:
    mutable CCriticalSection cs_pool;

    // hash -> entry. std::map keeps a stable, ordered store; the pool is small
    // (<= OFFERPOOL_MAX_OFFERS) so the ordered-map cost is negligible and it
    // avoids pulling in an unordered_map hasher for uint256.
    std::map<uint256, COfferPoolEntry> mapOffers;

    // tokenId -> count of offers for that token (per-token cap accounting).
    std::map<uint256, size_t> mapPerToken;

    // Running sum of serializedBytes across mapOffers (byte-cap accounting).
    size_t nTotalBytes;

    // Internal, assumes cs_pool already held. Updates the per-token + byte
    // accounting and erases from mapOffers. (Caller iterates safely.)
    void EraseLocked(const uint256& hash);
};

extern COfferPool g_offerPool;

#endif // ENABLE_WALLET

#endif // BITCOIN_NFT_OFFERPOOL_H
