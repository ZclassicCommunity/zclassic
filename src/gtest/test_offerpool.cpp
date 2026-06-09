// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Unit tests for the RAM-only NFT offerpool (src/nft/offerpool.{h,cpp},
// MARKETPLACE_DESIGN.md §3.3 / §5 / §12). The offerpool stores ALREADY-VERIFIED
// CNftOfferBlob's; NftVerify is exercised in test_nftoffer.cpp + the regtest
// harness, so here we construct blobs BY HAND (dummy tokenId/price/expiry/addrs/
// offerHex) and drive every cap, the anti-grind hash gate, the injected-oracle
// liveness GC, expiry GC, and the price-ascending Browse filters/pagination.
//
// Nothing here needs a live chain or pcoinsTip: EvictStale takes its liveness
// notion as a std::function, exactly so it is unit-testable in isolation.

// ENABLE_WALLET comes from bitcoin-config.h — it MUST be included before the
// #ifdef below, or the whole file (the offerpool is ENABLE_WALLET-only) silently
// compiles to ZERO tests. <gtest/gtest.h> does not pull in the config header.
#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <gtest/gtest.h>

#ifdef ENABLE_WALLET

#include "nft/offerpool.h"
#include "rpc/nftoffer.h"
#include "serialize.h"   // SER_NETWORK
#include "streams.h"     // CDataStream
#include "uint256.h"
#include "version.h"     // PROTOCOL_VERSION

#include <functional>
#include <set>
#include <string>
#include <vector>

namespace {

// NOTE: COfferPool holds a CCriticalSection (boost::recursive_mutex) by value,
// so it is NON-copyable / NON-movable. Each test therefore constructs its own
// `COfferPool pool;` directly on the stack (a fresh, isolated instance) rather
// than returning one by value — the g_offerPool global exists for production
// wiring, not the unit, and is intentionally untouched here.

// Build a dummy-but-coherent verified blob. `tokenSeed` selects the NFT, `nonce`
// makes otherwise-identical offers distinct (so their OfferHash differs), and
// `price`/`expiry` drive the browse/expiry tests.
CNftOfferBlob MakeBlob(uint8_t tokenSeed, int64_t price, uint32_t expiry,
                       int nonce = 0)
{
    CNftOfferBlob b;
    std::vector<unsigned char> t(32, 0);
    t[0] = tokenSeed;
    b.tokenId = uint256(t);
    b.priceZat = price;
    b.expiryHeight = expiry;
    b.payoutAddr = "t1PayoutDummyAddress";
    b.buyerNftAddr = "t1BuyerNftDummyAddress";
    // offerHex stands in for the seller partial; vary it by nonce so distinct
    // logical offers hash differently.
    b.offerHex = std::string("deadbeef") + std::to_string(nonce);
    return b;
}

// Like MakeBlob but derives a UNIQUE 32-byte tokenId from a 32-bit index, so a
// large batch never collides on token (keeps the per-token cap from tripping
// before the total-offers / total-bytes caps under test).
CNftOfferBlob MakeBlobUniqueToken(uint32_t idx, int64_t price)
{
    CNftOfferBlob b;
    std::vector<unsigned char> t(32, 0);
    t[0] = (unsigned char)(idx & 0xff);
    t[1] = (unsigned char)((idx >> 8) & 0xff);
    t[2] = (unsigned char)((idx >> 16) & 0xff);
    t[3] = (unsigned char)((idx >> 24) & 0xff);
    b.tokenId = uint256(t);
    b.priceZat = price;
    b.expiryHeight = 0;
    b.payoutAddr = "t1PayoutDummyAddress";
    b.buyerNftAddr = "t1BuyerNftDummyAddress";
    b.offerHex = std::string("deadbeef") + std::to_string(idx);
    return b;
}

// The wire size that the gossip layer would charge against the byte cap.
size_t WireBytes(const CNftOfferBlob& b)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << b;
    return ss.size();
}

// Convenience: insert a blob keyed by its own (correct) OfferHash.
bool InsertGood(COfferPool& pool, const CNftOfferBlob& b, int height,
                std::string& reason)
{
    return pool.Insert(b, b.OfferHash(), WireBytes(b), height, reason);
}

} // namespace

TEST(OfferPool, InsertGetHasRoundTrip)
{
    COfferPool pool;
    CNftOfferBlob b = MakeBlob(1, 1000, 0, 0);
    uint256 h = b.OfferHash();

    std::string reason;
    EXPECT_TRUE(InsertGood(pool, b, 100, reason)) << reason;
    EXPECT_EQ(1u, pool.Count());
    EXPECT_TRUE(pool.Has(h));

    CNftOfferBlob got;
    ASSERT_TRUE(pool.Get(h, got));
    EXPECT_EQ(b.tokenId, got.tokenId);
    EXPECT_EQ(b.priceZat, got.priceZat);
    EXPECT_EQ(b.offerHex, got.offerHex);

    // Absent hash.
    CNftOfferBlob none;
    uint256 nope; nope.SetNull();
    EXPECT_FALSE(pool.Has(nope));
    EXPECT_FALSE(pool.Get(nope, none));
}

TEST(OfferPool, DedupIsNoOpSuccess)
{
    COfferPool pool;
    CNftOfferBlob b = MakeBlob(1, 1000, 0, 0);

    std::string reason;
    EXPECT_TRUE(InsertGood(pool, b, 100, reason)) << reason;
    EXPECT_EQ(1u, pool.Count());
    size_t bytes1 = pool.Bytes();

    // Re-insert the identical blob (same hash): success, no growth.
    EXPECT_TRUE(InsertGood(pool, b, 101, reason)) << reason;
    EXPECT_EQ(1u, pool.Count());
    EXPECT_EQ(bytes1, pool.Bytes());
}

TEST(OfferPool, AdvertisedIdMismatchRejected)
{
    COfferPool pool;
    CNftOfferBlob b = MakeBlob(1, 1000, 0, 0);

    // Advertise a hash that is NOT this blob's content hash (anti-grind).
    uint256 wrong;
    std::vector<unsigned char> w(32, 0xAB);
    wrong = uint256(w);
    ASSERT_NE(wrong, b.OfferHash());

    std::string reason;
    EXPECT_FALSE(pool.Insert(b, wrong, WireBytes(b), 100, reason));
    EXPECT_FALSE(reason.empty());
    EXPECT_EQ(0u, pool.Count());
}

TEST(OfferPool, PerTokenCapRejectsOverflow)
{
    COfferPool pool;
    std::string reason;

    // Fill exactly the per-token cap for tokenSeed 7, varying nonce/price so the
    // hashes differ.
    for (size_t i = 0; i < OFFERPOOL_MAX_PER_TOKEN; ++i) {
        CNftOfferBlob b = MakeBlob(7, 1000 + (int64_t)i, 0, (int)i);
        EXPECT_TRUE(InsertGood(pool, b, 100, reason)) << reason << " i=" << i;
    }
    EXPECT_EQ(OFFERPOOL_MAX_PER_TOKEN, pool.Count());

    // One more for the SAME token: rejected.
    CNftOfferBlob over = MakeBlob(7, 9999, 0, (int)OFFERPOOL_MAX_PER_TOKEN);
    EXPECT_FALSE(InsertGood(pool, over, 100, reason));
    EXPECT_FALSE(reason.empty());
    EXPECT_EQ(OFFERPOOL_MAX_PER_TOKEN, pool.Count());

    // A DIFFERENT token is still accepted (the cap is per-token, not global here).
    CNftOfferBlob other = MakeBlob(8, 1000, 0, 0);
    EXPECT_TRUE(InsertGood(pool, other, 100, reason)) << reason;
    EXPECT_EQ(OFFERPOOL_MAX_PER_TOKEN + 1, pool.Count());
}

TEST(OfferPool, SingleOfferByteCapRejectsOversize)
{
    COfferPool pool;
    CNftOfferBlob b = MakeBlob(1, 1000, 0, 0);

    std::string reason;
    // Claim a serialized size over the per-offer cap (the gossip layer reports
    // the real wire size; we simulate an oversize one).
    EXPECT_FALSE(pool.Insert(b, b.OfferHash(), OFFERPOOL_MAX_OFFER_BYTES + 1,
                             100, reason));
    EXPECT_FALSE(reason.empty());
    EXPECT_EQ(0u, pool.Count());

    // Exactly at the cap is allowed.
    EXPECT_TRUE(pool.Insert(b, b.OfferHash(), OFFERPOOL_MAX_OFFER_BYTES,
                            100, reason)) << reason;
    EXPECT_EQ(1u, pool.Count());
}

TEST(OfferPool, TotalBytesCapRejects)
{
    COfferPool pool;
    std::string reason;

    // Use the per-offer cap as a big-but-legal size so few entries fill the
    // byte budget without hitting the per-token cap. Spread across many tokens.
    const size_t perOffer = OFFERPOOL_MAX_OFFER_BYTES;          // 8192
    const size_t fit = OFFERPOOL_MAX_BYTES / perOffer;          // how many fit
    ASSERT_GT(fit, 0u);

    // The byte budget must be reachable WITHOUT first hitting the offers cap.
    ASSERT_LE(fit, OFFERPOOL_MAX_OFFERS);

    size_t inserted = 0;
    for (size_t i = 0; i < fit; ++i) {
        // A UNIQUE token each time so the per-token cap never trips first.
        CNftOfferBlob b = MakeBlobUniqueToken((uint32_t)i, 1000 + (int64_t)i);
        if (pool.Insert(b, b.OfferHash(), perOffer, 100, reason))
            ++inserted;
    }
    EXPECT_EQ(fit, inserted);
    EXPECT_EQ(fit * perOffer, pool.Bytes());

    // The next full-size offer would push us over the byte cap: rejected.
    CNftOfferBlob over = MakeBlobUniqueToken(99999, 5000);
    EXPECT_FALSE(pool.Insert(over, over.OfferHash(), perOffer, 100, reason));
    EXPECT_FALSE(reason.empty());
}

TEST(OfferPool, TotalOffersCapRejects)
{
    COfferPool pool;
    std::string reason;

    // Tiny per-offer size + unique token per offer, so ONLY the total-offers cap
    // can trip (not the byte cap, not the per-token cap).
    const size_t tiny = 64;
    ASSERT_LE(OFFERPOOL_MAX_OFFERS * tiny, OFFERPOOL_MAX_BYTES);

    for (size_t i = 0; i < OFFERPOOL_MAX_OFFERS; ++i) {
        CNftOfferBlob b = MakeBlobUniqueToken((uint32_t)i, 1000 + (int64_t)i);
        ASSERT_TRUE(pool.Insert(b, b.OfferHash(), tiny, 100, reason))
            << reason << " i=" << i;
    }
    EXPECT_EQ(OFFERPOOL_MAX_OFFERS, pool.Count());

    // One more distinct offer: rejected (offers cap).
    CNftOfferBlob over = MakeBlobUniqueToken(0xCAFE0001, 1);
    EXPECT_FALSE(pool.Insert(over, over.OfferHash(), tiny, 100, reason));
    EXPECT_FALSE(reason.empty());
    EXPECT_EQ(OFFERPOOL_MAX_OFFERS, pool.Count());
}

TEST(OfferPool, EvictByHash)
{
    COfferPool pool;
    CNftOfferBlob a = MakeBlob(1, 1000, 0, 0);
    CNftOfferBlob b = MakeBlob(1, 2000, 0, 1);
    std::string reason;
    ASSERT_TRUE(InsertGood(pool, a, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, b, 100, reason)) << reason;
    EXPECT_EQ(2u, pool.Count());

    pool.EvictByHash(a.OfferHash());
    EXPECT_EQ(1u, pool.Count());
    EXPECT_FALSE(pool.Has(a.OfferHash()));
    EXPECT_TRUE(pool.Has(b.OfferHash()));

    // Evicting an absent hash is a harmless no-op.
    uint256 absent; std::vector<unsigned char> x(32, 0x55); absent = uint256(x);
    pool.EvictByHash(absent);
    EXPECT_EQ(1u, pool.Count());

    // Per-token + byte accounting rolled back: re-inserting `a` works again.
    EXPECT_TRUE(InsertGood(pool, a, 100, reason)) << reason;
    EXPECT_EQ(2u, pool.Count());
}

TEST(OfferPool, EvictStaleByInjectedLiveness)
{
    COfferPool pool;
    std::string reason;

    // Three offers; we'll mark the middle one (price 2000) dead via the oracle.
    CNftOfferBlob a = MakeBlob(1, 1000, 0, 0);
    CNftOfferBlob dead = MakeBlob(1, 2000, 0, 1);
    CNftOfferBlob c = MakeBlob(2, 3000, 0, 2);
    ASSERT_TRUE(InsertGood(pool, a, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, dead, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, c, 100, reason)) << reason;
    EXPECT_EQ(3u, pool.Count());

    uint256 deadHash = dead.OfferHash();
    std::function<bool(const CNftOfferBlob&)> oracle =
        [deadHash](const CNftOfferBlob& blob) -> bool {
            // "Live" iff it is NOT the one we condemned.
            return blob.OfferHash() != deadHash;
        };

    size_t removed = pool.EvictStale(oracle, /*tipHeight=*/100);
    EXPECT_EQ(1u, removed);
    EXPECT_EQ(2u, pool.Count());
    EXPECT_TRUE(pool.Has(a.OfferHash()));
    EXPECT_FALSE(pool.Has(deadHash));
    EXPECT_TRUE(pool.Has(c.OfferHash()));
}

TEST(OfferPool, EvictStaleByExpiry)
{
    COfferPool pool;
    std::string reason;

    // Mix: one no-expiry (0), one expiring at 150, one expiring at 250.
    CNftOfferBlob noexp = MakeBlob(1, 1000, 0, 0);
    CNftOfferBlob exp150 = MakeBlob(1, 2000, 150, 1);
    CNftOfferBlob exp250 = MakeBlob(2, 3000, 250, 2);
    ASSERT_TRUE(InsertGood(pool, noexp, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, exp150, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, exp250, 100, reason)) << reason;
    EXPECT_EQ(3u, pool.Count());

    // Always-live oracle so ONLY expiry drives eviction.
    std::function<bool(const CNftOfferBlob&)> alwaysLive =
        [](const CNftOfferBlob&) -> bool { return true; };

    // At tip 200: exp150 is dead (150 <= 200), exp250 + noexp survive.
    size_t removed = pool.EvictStale(alwaysLive, /*tipHeight=*/200);
    EXPECT_EQ(1u, removed);
    EXPECT_TRUE(pool.Has(noexp.OfferHash()));
    EXPECT_FALSE(pool.Has(exp150.OfferHash()));
    EXPECT_TRUE(pool.Has(exp250.OfferHash()));

    // Advance the tip past 250: exp250 now dies too; noexp persists forever.
    removed = pool.EvictStale(alwaysLive, /*tipHeight=*/300);
    EXPECT_EQ(1u, removed);
    EXPECT_TRUE(pool.Has(noexp.OfferHash()));
    EXPECT_FALSE(pool.Has(exp250.OfferHash()));
    EXPECT_EQ(1u, pool.Count());
}

TEST(OfferPool, BrowsePriceAscendingFloorFirst)
{
    COfferPool pool;
    std::string reason;

    // Insert out of price order.
    CNftOfferBlob p300 = MakeBlob(1, 300, 0, 0);
    CNftOfferBlob p100 = MakeBlob(1, 100, 0, 1);
    CNftOfferBlob p200 = MakeBlob(1, 200, 0, 2);
    ASSERT_TRUE(InsertGood(pool, p300, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, p100, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, p200, 100, reason)) << reason;

    COfferPoolFilter f;
    std::vector<COfferPoolEntry> res = pool.Browse(f);
    ASSERT_EQ(3u, res.size());
    EXPECT_EQ(100, res[0].priceZat);   // floor first
    EXPECT_EQ(200, res[1].priceZat);
    EXPECT_EQ(300, res[2].priceZat);
}

TEST(OfferPool, BrowseTokenIdFilter)
{
    COfferPool pool;
    std::string reason;

    CNftOfferBlob t1a = MakeBlob(1, 100, 0, 0);
    CNftOfferBlob t1b = MakeBlob(1, 200, 0, 1);
    CNftOfferBlob t2a = MakeBlob(2, 150, 0, 0);
    ASSERT_TRUE(InsertGood(pool, t1a, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, t1b, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, t2a, 100, reason)) << reason;

    COfferPoolFilter f;
    f.hasTokenId = true;
    f.tokenId = t1a.tokenId;
    std::vector<COfferPoolEntry> res = pool.Browse(f);
    ASSERT_EQ(2u, res.size());
    EXPECT_EQ(t1a.tokenId, res[0].tokenId);
    EXPECT_EQ(t1a.tokenId, res[1].tokenId);
    EXPECT_EQ(100, res[0].priceZat);
    EXPECT_EQ(200, res[1].priceZat);
}

TEST(OfferPool, BrowseMaxPriceFilter)
{
    COfferPool pool;
    std::string reason;
    for (int i = 0; i < 5; ++i) {
        CNftOfferBlob b = MakeBlob(1, (int64_t)(100 * (i + 1)), 0, i); // 100..500
        ASSERT_TRUE(InsertGood(pool, b, 100, reason)) << reason;
    }

    COfferPoolFilter f;
    f.hasMaxPriceZat = true;
    f.maxPriceZat = 300;
    std::vector<COfferPoolEntry> res = pool.Browse(f);
    ASSERT_EQ(3u, res.size()); // 100, 200, 300
    EXPECT_EQ(100, res[0].priceZat);
    EXPECT_EQ(300, res[2].priceZat);
}

TEST(OfferPool, BrowseMinExpiryFilter)
{
    COfferPool pool;
    std::string reason;

    CNftOfferBlob noexp = MakeBlob(1, 100, 0, 0);    // no expiry: always passes
    CNftOfferBlob soon  = MakeBlob(1, 200, 150, 1);  // expires 150
    CNftOfferBlob late  = MakeBlob(1, 300, 500, 2);  // expires 500
    ASSERT_TRUE(InsertGood(pool, noexp, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, soon, 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, late, 100, reason)) << reason;

    COfferPoolFilter f;
    f.hasMinExpiry = true;
    f.minExpiry = 200; // want offers valid through at least height 200
    std::vector<COfferPoolEntry> res = pool.Browse(f);
    // noexp (0 => passes) + late (500 >= 200); soon (150 < 200) excluded.
    ASSERT_EQ(2u, res.size());
    std::set<int64_t> prices;
    for (size_t i = 0; i < res.size(); ++i) prices.insert(res[i].priceZat);
    EXPECT_TRUE(prices.count(100)); // noexp
    EXPECT_TRUE(prices.count(300)); // late
    EXPECT_FALSE(prices.count(200)); // soon excluded
}

TEST(OfferPool, BrowseFromCountPagination)
{
    COfferPool pool;
    std::string reason;
    for (int i = 0; i < 10; ++i) {
        CNftOfferBlob b = MakeBlob(1, (int64_t)(100 * (i + 1)), 0, i); // 100..1000
        ASSERT_TRUE(InsertGood(pool, b, 100, reason)) << reason;
    }

    // from=2, count=3 over the price-ascending list => prices 300,400,500.
    COfferPoolFilter f;
    f.from = 2;
    f.count = 3;
    std::vector<COfferPoolEntry> page = pool.Browse(f);
    ASSERT_EQ(3u, page.size());
    EXPECT_EQ(300, page[0].priceZat);
    EXPECT_EQ(400, page[1].priceZat);
    EXPECT_EQ(500, page[2].priceZat);

    // from past the end => empty.
    COfferPoolFilter f2;
    f2.from = 100;
    EXPECT_TRUE(pool.Browse(f2).empty());

    // count=0 => all remaining from `from`.
    COfferPoolFilter f3;
    f3.from = 8;
    f3.count = 0;
    std::vector<COfferPoolEntry> rest = pool.Browse(f3);
    ASSERT_EQ(2u, rest.size());
    EXPECT_EQ(900, rest[0].priceZat);
    EXPECT_EQ(1000, rest[1].priceZat);
}

TEST(OfferPool, FloorByToken)
{
    COfferPool pool;
    std::string reason;

    // token1: 300,100,200 (floor 100, count 3); token2: 50 (floor 50, count 1).
    ASSERT_TRUE(InsertGood(pool, MakeBlob(1, 300, 0, 0), 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, MakeBlob(1, 100, 0, 1), 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, MakeBlob(1, 200, 0, 2), 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, MakeBlob(2, 50, 0, 0), 100, reason)) << reason;

    std::vector<COfferPoolFloor> floors = pool.FloorByToken();
    ASSERT_EQ(2u, floors.size());

    std::vector<unsigned char> t1(32, 0); t1[0] = 1; uint256 tok1(t1);
    std::vector<unsigned char> t2(32, 0); t2[0] = 2; uint256 tok2(t2);

    bool sawT1 = false, sawT2 = false;
    for (size_t i = 0; i < floors.size(); ++i) {
        if (floors[i].tokenId == tok1) {
            sawT1 = true;
            EXPECT_EQ(100, floors[i].floorPriceZat);
            EXPECT_EQ(3u, floors[i].offerCount);
        } else if (floors[i].tokenId == tok2) {
            sawT2 = true;
            EXPECT_EQ(50, floors[i].floorPriceZat);
            EXPECT_EQ(1u, floors[i].offerCount);
        }
    }
    EXPECT_TRUE(sawT1);
    EXPECT_TRUE(sawT2);
}

// D1: the search->buy seam. nft_browseoffers emits each offer as
// "znftoffer:"+blob.ToBase64(); nft_takeoffer must be able to decode that exact
// string back into the SAME blob via CNftOfferBlob::FromBase64. This round-trips
// the wire form Browse hands the GUI (strip the "znftoffer:" URI prefix, base64
// is the bare blob) and asserts byte-for-byte field equality — closing the gap
// between what Browse returns and what takeoffer consumes.
TEST(OfferPool, BrowseOfferBlobRoundTripsThroughFromBase64)
{
    COfferPool pool;
    std::string reason;

    CNftOfferBlob orig = MakeBlob(42, 123456789, 654321, 7);
    ASSERT_TRUE(InsertGood(pool, orig, 100, reason)) << reason;

    COfferPoolFilter f;
    std::vector<COfferPoolEntry> res = pool.Browse(f);
    ASSERT_EQ(1u, res.size());
    const COfferPoolEntry& e = res[0];

    // Exactly the field nft_browseoffers emits for "offerBlob".
    const std::string offerBlob = "znftoffer:" + e.blob.ToBase64();

    // The GUI / nft_takeoffer strips the "znftoffer:" prefix, then FromBase64.
    const std::string prefix = "znftoffer:";
    ASSERT_EQ(0u, offerBlob.find(prefix));
    const std::string bare = offerBlob.substr(prefix.size());

    CNftOfferBlob decoded;
    std::string err;
    ASSERT_TRUE(decoded.FromBase64(bare, err)) << err;
    EXPECT_TRUE(err.empty());

    // Byte-for-byte field equality (the seam must not mutate the offer).
    EXPECT_EQ(orig.tokenId, decoded.tokenId);
    EXPECT_EQ(orig.priceZat, decoded.priceZat);
    EXPECT_EQ(orig.payoutAddr, decoded.payoutAddr);
    EXPECT_EQ(orig.buyerNftAddr, decoded.buyerNftAddr);
    EXPECT_EQ(orig.expiryHeight, decoded.expiryHeight);
    EXPECT_EQ(orig.offerHex, decoded.offerHex);

    // And the content hash (the pool key / anti-grind id) is preserved.
    EXPECT_EQ(orig.OfferHash(), decoded.OfferHash());
    EXPECT_EQ(e.offerHash, decoded.OfferHash());

    // A garbage base64 must FAIL to decode (fail-closed), not silently accept.
    CNftOfferBlob bad;
    std::string baderr;
    EXPECT_FALSE(bad.FromBase64("not!valid!base64!!!", baderr));
    EXPECT_FALSE(baderr.empty());
}

TEST(OfferPool, ClearResetsAccounting)
{
    COfferPool pool;
    std::string reason;
    ASSERT_TRUE(InsertGood(pool, MakeBlob(1, 100, 0, 0), 100, reason)) << reason;
    ASSERT_TRUE(InsertGood(pool, MakeBlob(1, 200, 0, 1), 100, reason)) << reason;
    EXPECT_EQ(2u, pool.Count());
    EXPECT_GT(pool.Bytes(), 0u);

    pool.Clear();
    EXPECT_EQ(0u, pool.Count());
    EXPECT_EQ(0u, pool.Bytes());

    // After Clear the per-token accounting is reset too: re-fill to the cap works.
    for (size_t i = 0; i < OFFERPOOL_MAX_PER_TOKEN; ++i) {
        CNftOfferBlob b = MakeBlob(1, 1000 + (int64_t)i, 0, (int)i);
        EXPECT_TRUE(InsertGood(pool, b, 100, reason)) << reason << " i=" << i;
    }
    EXPECT_EQ(OFFERPOOL_MAX_PER_TOKEN, pool.Count());
}

#endif // ENABLE_WALLET
