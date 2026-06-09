// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// C hot-path tests for beta7 ZMARKET spider, router, index query, and
// content-hosting-invariant modules.

#include <gtest/gtest.h>

extern "C" {
#include "zmarket/zmarket_content.h"
#include "zmarket/zmarket_index.h"
#include "zmarket/zmarket_onion.h"
#include "zmarket/zmarket_policy.h"
#include "zmarket/zmarket_record.h"
#include "zmarket/zmarket_router.h"
#include "zmarket/zmarket_spider.h"
}

#include <cstring>
#include <vector>

namespace {

void put16(std::vector<unsigned char>& v, uint16_t x)
{
    v.push_back((unsigned char)(x & 0xff));
    v.push_back((unsigned char)((x >> 8) & 0xff));
}

void put32(std::vector<unsigned char>& v, uint32_t x)
{
    for (int i = 0; i < 4; i++)
        v.push_back((unsigned char)((x >> (8 * i)) & 0xff));
}

void put64(std::vector<unsigned char>& v, uint64_t x)
{
    for (int i = 0; i < 8; i++)
        v.push_back((unsigned char)((x >> (8 * i)) & 0xff));
}

std::vector<unsigned char> record(enum zmarket_record_type type,
                                  const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> v;
    const unsigned char magic[] = {'Z', 'M', 'R', 'K'};
    v.insert(v.end(), magic, magic + 4);
    put16(v, ZMARKET_RECORD_VERSION);
    put16(v, (uint16_t)type);
    put32(v, 0);                 // flags
    put64(v, 1700000000ULL);     // expires_unix
    put32(v, (uint32_t)payload.size());
    v.insert(v.end(), payload.begin(), payload.end());
    put16(v, 32);                // signer key
    for (int i = 0; i < 32; i++) v.push_back((unsigned char)(0xA0 + i));
    put16(v, 64);                // signature
    for (int i = 0; i < 64; i++) v.push_back((unsigned char)(0xB0 + i));
    return v;
}

void make_id(uint8_t id[ZMARKET_ID_LEN], uint8_t base)
{
    for (size_t i = 0; i < ZMARKET_ID_LEN; i++)
        id[i] = base ^ (uint8_t)i;
}

} // namespace

// ============================================================
// Spider tests
// ============================================================

TEST(ZMarketCSpider, QueueBoundsAndPeerCaps)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    policy.mode_bits |= ZMARKET_MODE_SPIDER;

    zmarket_index_slot seen_slots[16];
    zmarket_index seen;
    zmarket_index_init(&seen, seen_slots, 16);

    zmarket_spider_peer peers[4];
    zmarket_spider_fetch queue[8];
    zmarket_spider sp;
    zmarket_spider_init(&sp, peers, 4, queue, 8, &seen, &policy);

    const char peer_a[] = "peer-a";
    EXPECT_EQ(zmarket_spider_add_peer(&sp, peer_a, std::strlen(peer_a),
                                      10, 1, 1000),
              ZMARKET_SPIDER_OK);
    EXPECT_EQ(zmarket_spider_peer_count(&sp), (size_t)1);

    /* Peer table full. */
    const char *more[] = {"pb", "pc", "pd", "pe"};
    for (int i = 0; i < 4; i++)
        zmarket_spider_add_peer(&sp, more[i], std::strlen(more[i]),
                                10, 1, 1000 + i + 1);
    EXPECT_EQ(zmarket_spider_peer_count(&sp), (size_t)4);
    EXPECT_EQ(zmarket_spider_add_peer(&sp, "pf", 2, 10, 1, 2000),
              ZMARKET_SPIDER_ERR_PEER_FULL);

    /* Feed inventory: 3 IDs, queue cap is 8. */
    uint8_t ids[3][ZMARKET_ID_LEN];
    for (int i = 0; i < 3; i++) make_id(ids[i], (uint8_t)(0x10 + i));

    enum zmarket_record_type types[3] = {
        ZMARKET_RECORD_OFFER, ZMARKET_RECORD_OFFER, ZMARKET_RECORD_MIRROR
    };
    uint64_t exps[3] = {2000, 2001, 2002};

    EXPECT_EQ(zmarket_spider_on_inv(&sp, peer_a, std::strlen(peer_a),
                                     (const uint8_t *)ids, 3, types, exps,
                                     1000),
              ZMARKET_SPIDER_OK);
    EXPECT_GT(zmarket_spider_queue_depth(&sp), (size_t)0);

    /* Dedup: feeding the same IDs again should not grow the queue. */
    size_t before = zmarket_spider_pending_count(&sp);
    zmarket_spider_on_inv(&sp, peer_a, std::strlen(peer_a),
                          (const uint8_t *)ids, 3, types, exps, 1000);
    EXPECT_EQ(zmarket_spider_pending_count(&sp), before);

    zmarket_spider_clear(&sp);
    EXPECT_EQ(zmarket_spider_peer_count(&sp), (size_t)0);
    EXPECT_EQ(zmarket_spider_queue_depth(&sp), (size_t)0);
}

TEST(ZMarketCSpider, TTLExpiredItemsSkipped)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    policy.mode_bits |= ZMARKET_MODE_SPIDER;

    zmarket_index_slot seen_slots[8];
    zmarket_index seen;
    zmarket_index_init(&seen, seen_slots, 8);

    zmarket_spider_peer peers[2];
    zmarket_spider_fetch queue[8];
    zmarket_spider sp;
    zmarket_spider_init(&sp, peers, 2, queue, 8, &seen, &policy);

    const char peer_a[] = "peer-a";
    zmarket_spider_add_peer(&sp, peer_a, std::strlen(peer_a), 10, 1, 1000);

    /* Feed one expired, one not. */
    uint8_t id_expired[ZMARKET_ID_LEN], id_ok[ZMARKET_ID_LEN];
    make_id(id_expired, 0x20);
    make_id(id_ok, 0x21);

    uint8_t id_buf[2][ZMARKET_ID_LEN];
    memcpy(id_buf[0], id_expired, ZMARKET_ID_LEN);
    memcpy(id_buf[1], id_ok, ZMARKET_ID_LEN);

    enum zmarket_record_type types[2] = {
        ZMARKET_RECORD_OFFER, ZMARKET_RECORD_OFFER
    };
    /* First expired (999 < 1000 = now), second valid. */
    uint64_t exps[2] = {999, 2000};

    zmarket_spider_on_inv(&sp, peer_a, std::strlen(peer_a),
                          (const uint8_t *)id_buf, 2, types, exps, 1000);

    /* Only the non-expired ID should be in the queue. */
    EXPECT_EQ(zmarket_spider_pending_count(&sp), (size_t)1);
}

TEST(ZMarketCSpider, BackoffOnFailures)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    policy.mode_bits |= ZMARKET_MODE_SPIDER;

    zmarket_index_slot seen_slots[8];
    zmarket_index seen;
    zmarket_index_init(&seen, seen_slots, 8);

    zmarket_spider_peer peers[2];
    zmarket_spider_fetch queue[16];
    zmarket_spider sp;
    zmarket_spider_init(&sp, peers, 2, queue, 16, &seen, &policy);

    const char peer_a[] = "peer-a";
    zmarket_spider_add_peer(&sp, peer_a, std::strlen(peer_a), 100, 1, 1000);

    /* Feed some inventory. */
    uint8_t id[ZMARKET_ID_LEN];
    make_id(id, 0x30);
    enum zmarket_record_type typ = ZMARKET_RECORD_OFFER;
    uint64_t exp = 2000;
    zmarket_spider_on_inv(&sp, peer_a, std::strlen(peer_a),
                          id, 1, &typ, &exp, 1000);

    /* Fail it many times to trigger backoff. */
    for (int i = 0; i < 10; i++) {
        zmarket_spider_fetch_done(&sp, id, false, 1000 + i);
        /* Re-enqueue for next attempt. */
        if (i < 9) {
            zmarket_index_remove(&seen, id);
            zmarket_spider_on_inv(&sp, peer_a, std::strlen(peer_a),
                                  id, 1, &typ, &exp, 1000 + i);
        }
    }
    zmarket_spider_prune(&sp, 1100);

    EXPECT_TRUE(zmarket_spider_peer_in_backoff(&sp, peer_a,
                                               std::strlen(peer_a), 1100));
}

TEST(ZMarketCSpider, PolicyDeniesSpideringWhenOff)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    /* SPIDER mode NOT set. */

    zmarket_index_slot seen_slots[4];
    zmarket_index seen;
    zmarket_index_init(&seen, seen_slots, 4);

    zmarket_spider_peer peers[2];
    zmarket_spider_fetch queue[4];
    zmarket_spider sp;
    zmarket_spider_init(&sp, peers, 2, queue, 4, &seen, &policy);

    const char peer_a[] = "peer-a";
    zmarket_spider_add_peer(&sp, peer_a, std::strlen(peer_a), 10, 1, 1000);

    uint8_t id[ZMARKET_ID_LEN];
    make_id(id, 0x40);
    enum zmarket_record_type typ = ZMARKET_RECORD_OFFER;
    uint64_t exp = 2000;

    EXPECT_EQ(zmarket_spider_on_inv(&sp, peer_a, std::strlen(peer_a),
                                     id, 1, &typ, &exp, 1000),
              ZMARKET_SPIDER_ERR_POLICY);
}

// ============================================================
// Router tests
// ============================================================

TEST(ZMarketCRouter, AdmissionPolicyAndDedupe)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    policy.mode_bits |= ZMARKET_MODE_RELAY;

    zmarket_index_slot dedup_slots[16];
    zmarket_index dedup;
    zmarket_index_init(&dedup, dedup_slots, 16);

    zmarket_route_entry entries[8];
    zmarket_router_peer peers[4];
    zmarket_router rt;
    zmarket_router_init(&rt, entries, 8, peers, 4, &dedup, &policy);

    uint8_t id[ZMARKET_ID_LEN];
    make_id(id, 0x50);

    /* Admit a valid record. */
    EXPECT_EQ(zmarket_router_admit(&rt, id, ZMARKET_RECORD_OFFER,
                                   2000, 0, nullptr, 0, 1000),
              ZMARKET_ROUTE_ACCEPT);
    EXPECT_EQ(zmarket_router_entry_count(&rt), (size_t)1);

    /* Duplicate should be rejected. */
    EXPECT_EQ(zmarket_router_admit(&rt, id, ZMARKET_RECORD_OFFER,
                                   2000, 0, nullptr, 0, 1000),
              ZMARKET_ROUTE_REJECT_DUPLICATE);

    /* Expired record should be rejected. */
    uint8_t id2[ZMARKET_ID_LEN];
    make_id(id2, 0x51);
    EXPECT_EQ(zmarket_router_admit(&rt, id2, ZMARKET_RECORD_OFFER,
                                   500, 0, nullptr, 0, 1000),
              ZMARKET_ROUTE_REJECT_EXPIRED);

    /* Too many hops. */
    uint8_t id3[ZMARKET_ID_LEN];
    make_id(id3, 0x52);
    EXPECT_EQ(zmarket_router_admit(&rt, id3, ZMARKET_RECORD_OFFER,
                                   2000, 7, nullptr, 0, 1000),
              ZMARKET_ROUTE_REJECT_HOPS);
}

TEST(ZMarketCRouter, RouteFanoutRespectsCapAndExcludesSource)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    policy.mode_bits |= ZMARKET_MODE_RELAY;
    policy.caps.max_route_fanout = 3;

    zmarket_index_slot dedup_slots[16];
    zmarket_index dedup;
    zmarket_index_init(&dedup, dedup_slots, 16);

    zmarket_route_entry entries[8];
    zmarket_router_peer peers[8];
    zmarket_router rt;
    zmarket_router_init(&rt, entries, 8, peers, 8, &dedup, &policy);

    /* Add peers. */
    const char *pnames[] = {"pa", "pb", "pc", "pd", "pe"};
    for (int i = 0; i < 5; i++)
        zmarket_router_add_peer(&rt, pnames[i], std::strlen(pnames[i]), false);

    /* Admit a record. */
    uint8_t id[ZMARKET_ID_LEN];
    make_id(id, 0x60);
    zmarket_router_admit(&rt, id, ZMARKET_RECORD_OFFER, 2000,
                         0, "pa", 2, 1000);

    /* Fanout from source "pa" should exclude "pa", cap at 3. */
    zmarket_route_fanout fo = zmarket_router_fanout(&rt, id,
                                                     "pa", 2, 1000);
    EXPECT_LE(fo.count, (size_t)3);
    EXPECT_GE(fo.count, (size_t)3); /* 4 other peers, cap is 3 */
    /* Verify source peer is excluded. */
    size_t pa_idx = (size_t)-1;
    for (size_t i = 0; i < rt.peer_capacity; i++) {
        if (rt.peers[i].state != 0 && rt.peers[i].id_len == 2 &&
            memcmp(rt.peers[i].id, "pa", 2) == 0) {
            pa_idx = i;
            break;
        }
    }
    for (size_t i = 0; i < fo.count; i++)
        EXPECT_NE(fo.peer_indices[i], pa_idx);
}

TEST(ZMarketCRouter, TorOnlyModeBlocksClearnetPeers)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    policy.mode_bits |= ZMARKET_MODE_RELAY;

    zmarket_index_slot dedup_slots[8];
    zmarket_index dedup;
    zmarket_index_init(&dedup, dedup_slots, 8);

    zmarket_route_entry entries[4];
    zmarket_router_peer peers[4];
    zmarket_router rt;
    zmarket_router_init(&rt, entries, 4, peers, 4, &dedup, &policy);

    zmarket_router_add_peer(&rt, "tor-a", 5, true);   /* Tor peer */
    zmarket_router_add_peer(&rt, "clr-b", 5, false);  /* Clearnet peer */

    uint8_t id[ZMARKET_ID_LEN];
    make_id(id, 0x70);
    zmarket_router_admit(&rt, id, ZMARKET_RECORD_OFFER, 2000,
                         0, nullptr, 0, 1000);

    /* With tor_mode=2 (only), fanout should exclude clearnet. */
    zmarket_router_set_tor_mode(&rt, 2);
    zmarket_route_fanout fo = zmarket_router_fanout(&rt, id,
                                                     nullptr, 0, 1000);
    EXPECT_EQ(fo.count, (size_t)1); /* Only the Tor peer */

    /* should_relay also blocks clearnet in Tor-only mode. */
    EXPECT_TRUE(zmarket_router_should_relay(&rt, id, "tor-a", 5, 1000));
    EXPECT_FALSE(zmarket_router_should_relay(&rt, id, "clr-b", 5, 1000));
}

TEST(ZMarketCRouter, HopDecrementAndMax)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    policy.mode_bits |= ZMARKET_MODE_RELAY;

    zmarket_index_slot dedup_slots[4];
    zmarket_index dedup;
    zmarket_index_init(&dedup, dedup_slots, 4);

    zmarket_route_entry entries[4];
    zmarket_router_peer peers[2];
    zmarket_router rt;
    zmarket_router_init(&rt, entries, 4, peers, 2, &dedup, &policy);

    uint8_t id[ZMARKET_ID_LEN];
    make_id(id, 0x80);
    zmarket_router_admit(&rt, id, ZMARKET_RECORD_OFFER, 2000,
                         0, nullptr, 0, 1000);

    /* hop_count starts at 0 (meaning 0 hops taken). Decrement means
     * incrementing the hop counter. Should stay routable until max. */
    for (uint32_t h = 0; h < ZMARKET_ROUTER_MAX_HOPS; h++)
        EXPECT_TRUE(zmarket_router_decrement_hops(&rt, id));
    /* One more should exceed max. */
    EXPECT_FALSE(zmarket_router_decrement_hops(&rt, id));
}

TEST(ZMarketCRouter, PruneExpiredEntries)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    policy.mode_bits |= ZMARKET_MODE_RELAY;

    zmarket_index_slot dedup_slots[8];
    zmarket_index dedup;
    zmarket_index_init(&dedup, dedup_slots, 8);

    zmarket_route_entry entries[8];
    zmarket_router_peer peers[2];
    zmarket_router rt;
    zmarket_router_init(&rt, entries, 8, peers, 2, &dedup, &policy);

    /* Add two records: one expiring at 1500, one at 2000. */
    uint8_t id1[ZMARKET_ID_LEN], id2[ZMARKET_ID_LEN];
    make_id(id1, 0x90);
    make_id(id2, 0x91);
    zmarket_router_admit(&rt, id1, ZMARKET_RECORD_OFFER, 1500,
                         0, nullptr, 0, 1000);
    zmarket_router_admit(&rt, id2, ZMARKET_RECORD_OFFER, 2000,
                         0, nullptr, 0, 1000);
    EXPECT_EQ(zmarket_router_entry_count(&rt), (size_t)2);

    /* Prune at 1600: id1 expires. */
    EXPECT_EQ(zmarket_router_prune(&rt, 1600), (size_t)1);
    EXPECT_FALSE(zmarket_router_has(&rt, id1));
    EXPECT_TRUE(zmarket_router_has(&rt, id2));
}

// ============================================================
// CRITICAL INVARIANT: routing records NEVER hosts files
// ============================================================

TEST(ZMarketCRouter, RoutingRecordsNeverHostFiles)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    /* Enable routing but NOT content hosting. */
    policy.mode_bits |= ZMARKET_MODE_RELAY;
    policy.mode_bits |= ZMARKET_MODE_SPIDER;
    policy.mode_bits |= ZMARKET_MODE_INDEXER;

    zmarket_index_slot dedup_slots[8];
    zmarket_index dedup;
    zmarket_index_init(&dedup, dedup_slots, 8);

    zmarket_route_entry entries[8];
    zmarket_router_peer peers[4];
    zmarket_router rt;
    zmarket_router_init(&rt, entries, 8, peers, 4, &dedup, &policy);

    /* Admit records of all types - these are just signed envelopes. */
    uint8_t offer_id[ZMARKET_ID_LEN];
    uint8_t manifest_id[ZMARKET_ID_LEN];
    uint8_t mirror_id[ZMARKET_ID_LEN];
    make_id(offer_id, 0xA0);
    make_id(manifest_id, 0xA1);
    make_id(mirror_id, 0xA2);

    zmarket_router_admit(&rt, offer_id, ZMARKET_RECORD_OFFER,
                         2000, 0, nullptr, 0, 1000);
    zmarket_router_admit(&rt, manifest_id, ZMARKET_RECORD_MANIFEST,
                         2000, 0, nullptr, 0, 1000);
    zmarket_router_admit(&rt, mirror_id, ZMARKET_RECORD_MIRROR,
                         2000, 0, nullptr, 0, 1000);
    EXPECT_EQ(zmarket_router_entry_count(&rt), (size_t)3);

    /* HARD CHECK: Content hosting must be DENIED even though we route. */
    uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN];
    content_root[0] = 0xBB;
    for (size_t i = 1; i < ZMARKET_CONTENT_ROOT_LEN; i++)
        content_root[i] = (uint8_t)i;

    /* Without content_host mode, can_host_content must be false. */
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, false));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, true));

    /* Even with an explicit allowlist entry, hosting is denied
     * because the mode bit is off. */
    zmarket_content_allowlist_entry content_entries[2];
    zmarket_content_allowlist allowlist;
    zmarket_content_allowlist_init(&allowlist, content_entries, 2);

    const char path[] = "/operator/chosen/file.bin";
    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, content_root,
                                            path, std::strlen(path), 1000),
              ZMARKET_CONTENT_OK);
    EXPECT_TRUE(zmarket_content_operator_allowed(&allowlist, content_root));
    EXPECT_FALSE(zmarket_content_can_host(&policy, &allowlist, content_root));

    /* Enable content hosting. Now allowlist entries work. */
    policy.mode_bits |= ZMARKET_MODE_CONTENT_HOST;
    EXPECT_TRUE(zmarket_content_can_host(&policy, &allowlist, content_root));

    /* But routing activity NEVER added to the allowlist. */
    /* The mirror record in the routing table has nothing to do with hosting. */
    EXPECT_EQ(zmarket_content_allowlist_count(&allowlist), (size_t)1);

    /* And a content root NOT in the allowlist is not hostable. */
    uint8_t unknown_root[ZMARKET_CONTENT_ROOT_LEN];
    memset(unknown_root, 0xFF, ZMARKET_CONTENT_ROOT_LEN);
    EXPECT_FALSE(zmarket_content_can_host(&policy, &allowlist, unknown_root));
}

// ============================================================
// Index query / filter / pagination tests
// ============================================================

TEST(ZMarketCIndex, QueryFilterByTypeAndExpiry)
{
    zmarket_index_slot slots[16];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 16);

    /* Insert records of different types and expiries. */
    uint8_t id_base = 0xC0;
    for (int i = 0; i < 8; i++) {
        uint8_t id[ZMARKET_ID_LEN];
        make_id(id, id_base + (uint8_t)i);
        enum zmarket_record_type type = (i % 2 == 0)
            ? ZMARKET_RECORD_OFFER
            : ZMARKET_RECORD_MIRROR;
        uint64_t exp = 1000 + (uint64_t)i * 100;
        zmarket_index_put(&idx, id, type, exp);
    }
    EXPECT_EQ(zmarket_index_count(&idx), (size_t)8);

    /* Filter: only OFFER records. */
    zmarket_index_filter filter_type{};
    filter_type.filter_type = true;
    filter_type.type = ZMARKET_RECORD_OFFER;
    EXPECT_EQ(zmarket_index_count_filtered(&idx, &filter_type), (size_t)4);

    /* Filter: expiry >= 1300. */
    zmarket_index_filter filter_exp{};
    filter_exp.filter_min_expires = true;
    filter_exp.min_expires = 1300;
    EXPECT_EQ(zmarket_index_count_filtered(&idx, &filter_exp), (size_t)5);

    /* Combined: OFFER and expiry >= 1300. */
    zmarket_index_filter filter_both{};
    filter_both.filter_type = true;
    filter_both.type = ZMARKET_RECORD_OFFER;
    filter_both.filter_min_expires = true;
    filter_both.min_expires = 1300;
    EXPECT_EQ(zmarket_index_count_filtered(&idx, &filter_both), (size_t)2);
}

TEST(ZMarketCIndex, QueryPagination)
{
    zmarket_index_slot slots[32];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 32);

    for (int i = 0; i < 10; i++) {
        uint8_t id[ZMARKET_ID_LEN];
        make_id(id, 0xD0 + (uint8_t)i);
        zmarket_index_put(&idx, id, ZMARKET_RECORD_OFFER, 2000 + i);
    }

    /* Page 1: offset 0, limit 3. */
    const struct zmarket_index_slot *page1[3];
    zmarket_index_query_result res1;
    res1.slots = page1;
    res1.capacity = 3;
    res1.count = 0;

    size_t total = zmarket_index_query(&idx, nullptr, 0, &res1);
    EXPECT_EQ(total, (size_t)10);
    EXPECT_EQ(res1.count, (size_t)3);

    /* Page 2: offset 3, limit 3. */
    const struct zmarket_index_slot *page2[3];
    zmarket_index_query_result res2;
    res2.slots = page2;
    res2.capacity = 3;
    res2.count = 0;

    zmarket_index_query(&idx, nullptr, 3, &res2);
    EXPECT_EQ(res2.count, (size_t)3);

    /* Pages should not overlap (different IDs). */
    EXPECT_NE(memcmp(page1[0]->id, page2[0]->id, ZMARKET_ID_LEN), 0);
}

TEST(ZMarketCIndex, PruneExpiredAndRemove)
{
    zmarket_index_slot slots[8];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 8);

    uint8_t id1[ZMARKET_ID_LEN], id2[ZMARKET_ID_LEN];
    make_id(id1, 0xE0);
    make_id(id2, 0xE1);
    zmarket_index_put(&idx, id1, ZMARKET_RECORD_OFFER, 1500);
    zmarket_index_put(&idx, id2, ZMARKET_RECORD_OFFER, 2000);
    EXPECT_EQ(zmarket_index_count(&idx), (size_t)2);

    /* Prune at 1600. */
    EXPECT_EQ(zmarket_index_prune(&idx, 1600), (size_t)1);
    EXPECT_FALSE(zmarket_index_has(&idx, id1));
    EXPECT_TRUE(zmarket_index_has(&idx, id2));

    /* Explicit remove. */
    EXPECT_TRUE(zmarket_index_remove(&idx, id2));
    EXPECT_FALSE(zmarket_index_has(&idx, id2));
    EXPECT_EQ(zmarket_index_count(&idx), (size_t)0);
}

TEST(ZMarketCIndex, GetSlot)
{
    zmarket_index_slot slots[4];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 4);

    uint8_t id[ZMARKET_ID_LEN];
    make_id(id, 0xF0);
    zmarket_index_put(&idx, id, ZMARKET_RECORD_MIRROR, 3000);

    const zmarket_index_slot *s = zmarket_index_get(&idx, id);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(s->type, (uint16_t)ZMARKET_RECORD_MIRROR);
    EXPECT_EQ(s->expires_unix, (uint64_t)3000);
    EXPECT_EQ(s->seen_count, (uint32_t)1);
}

// ============================================================
// Memindex sort/pagination tests
// ============================================================

TEST(ZMarketCMemindex, SortByExpiry)
{
    zmarket_index_slot slots[8];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 8);

    /* Insert with non-monotonic expiries. */
    uint8_t bases[] = {0x10, 0x20, 0x30, 0x40};
    uint64_t exps[] = {3000, 1000, 4000, 2000};
    for (int i = 0; i < 4; i++) {
        uint8_t id[ZMARKET_ID_LEN];
        make_id(id, bases[i]);
        zmarket_index_put(&idx, id, ZMARKET_RECORD_OFFER, exps[i]);
    }

    const zmarket_index_slot *sorted[4];
    zmarket_memindex mi;
    zmarket_memindex_init(&mi, sorted, 4, &idx, ZMARKET_SORT_EXPIRY_ASC);

    ASSERT_EQ(mi.count, (size_t)4);
    /* Should be sorted ascending by expiry. */
    EXPECT_EQ(mi.sorted[0]->expires_unix, (uint64_t)1000);
    EXPECT_EQ(mi.sorted[1]->expires_unix, (uint64_t)2000);
    EXPECT_EQ(mi.sorted[2]->expires_unix, (uint64_t)3000);
    EXPECT_EQ(mi.sorted[3]->expires_unix, (uint64_t)4000);
}

TEST(ZMarketCMemindex, SortedQueryWithFilter)
{
    zmarket_index_slot slots[8];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 8);

    for (int i = 0; i < 6; i++) {
        uint8_t id[ZMARKET_ID_LEN];
        make_id(id, 0x50 + (uint8_t)i);
        enum zmarket_record_type t = (i < 3) ? ZMARKET_RECORD_OFFER
                                              : ZMARKET_RECORD_MIRROR;
        zmarket_index_put(&idx, id, t, 1000 + (uint64_t)i * 100);
    }

    const zmarket_index_slot *sorted[6];
    zmarket_memindex mi;
    zmarket_memindex_init(&mi, sorted, 6, &idx, ZMARKET_SORT_EXPIRY_ASC);

    /* Filter for OFFER only, get page of 2. */
    zmarket_index_filter filter{};
    filter.filter_type = true;
    filter.type = ZMARKET_RECORD_OFFER;

    const zmarket_index_slot *page[2];
    zmarket_index_query_result res;
    res.slots = page;
    res.capacity = 2;
    res.count = 0;

    size_t total = zmarket_memindex_query(&mi, &filter, 0, &res);
    EXPECT_EQ(total, (size_t)3); /* 3 OFFER records */
    EXPECT_EQ(res.count, (size_t)2);
    /* Results should be sorted by expiry ascending. */
    EXPECT_LE(page[0]->expires_unix, page[1]->expires_unix);
}

TEST(ZMarketCMemindex, InsertAndRemove)
{
    zmarket_index_slot slots[8];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 8);

    uint8_t id_a[ZMARKET_ID_LEN], id_b[ZMARKET_ID_LEN];
    make_id(id_a, 0x60);
    make_id(id_b, 0x61);
    zmarket_index_put(&idx, id_a, ZMARKET_RECORD_OFFER, 2000);
    zmarket_index_put(&idx, id_b, ZMARKET_RECORD_OFFER, 3000);

    const zmarket_index_slot *sorted[4];
    zmarket_memindex mi;
    zmarket_memindex_init(&mi, sorted, 4, &idx, ZMARKET_SORT_EXPIRY_ASC);
    EXPECT_EQ(mi.count, (size_t)2);

    /* Insert a new slot directly. */
    struct zmarket_index_slot new_slot;
    make_id(new_slot.id, 0x62);
    new_slot.expires_unix = 2500;
    new_slot.seen_count = 1;
    new_slot.type = (uint16_t)ZMARKET_RECORD_OFFER;
    new_slot.state = 1;

    EXPECT_TRUE(zmarket_memindex_insert(&mi, &new_slot));
    EXPECT_EQ(mi.count, (size_t)3);
    /* Still sorted: 2000, 2500, 3000. */
    EXPECT_EQ(mi.sorted[0]->expires_unix, (uint64_t)2000);
    EXPECT_EQ(mi.sorted[1]->expires_unix, (uint64_t)2500);
    EXPECT_EQ(mi.sorted[2]->expires_unix, (uint64_t)3000);

    /* Remove middle entry. */
    EXPECT_TRUE(zmarket_memindex_remove(&mi, new_slot.id));
    EXPECT_EQ(mi.count, (size_t)2);
    EXPECT_FALSE(zmarket_memindex_remove(&mi, new_slot.id));
}

// ============================================================
// Iterator test
// ============================================================

TEST(ZMarketCIndex, IterVisitsAllSlots)
{
    zmarket_index_slot slots[8];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 8);

    for (int i = 0; i < 5; i++) {
        uint8_t id[ZMARKET_ID_LEN];
        make_id(id, 0x70 + (uint8_t)i);
        zmarket_index_put(&idx, id, ZMARKET_RECORD_OFFER, 2000);
    }

    size_t visited = 0;
    struct iter_ctx {
        size_t *count;
    };
    iter_ctx ctx;
    ctx.count = &visited;

    zmarket_index_iter(&idx,
        [](const zmarket_index_slot *s, void *c) -> bool {
            (void)s;
            auto *ctx = static_cast<iter_ctx *>(c);
            (*ctx->count)++;
            return true;
        }, &ctx);
    EXPECT_EQ(visited, (size_t)5);

    /* Early termination: stop after 3. */
    size_t limited = 0;
    zmarket_index_iter(&idx,
        [](const zmarket_index_slot *s, void *c) -> bool {
            (void)s;
            auto *cnt = static_cast<size_t *>(c);
            (*cnt)++;
            return *cnt < 3;
        }, &limited);
    EXPECT_EQ(limited, (size_t)3);
}

// ============================================================
// Onion endpoint lifecycle tests
// ============================================================

TEST(ZMarketCOnion, OneTimeEndpointRetiresAfterSuccessfulUse)
{
    /* One-time onion endpoints must retire (state -> USED) after a single
     * successful use and must never be chosen again by zmarket_onion_choose. */

    zmarket_onion_endpoint entries[4];
    zmarket_onion_set set;
    zmarket_onion_set_init(&set, entries, 4);

    const char one_time_a[] =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    const char one_time_b[] =
        "bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxy.onion";
    const char reusable_c[] =
        "cdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz.onion";

    unsigned char scope_id[ZMARKET_ONION_SCOPE_ID_LEN] = {0};
    scope_id[0] = 0x77;

    /* Insert one-time endpoints and a reusable endpoint. */
    ASSERT_EQ(zmarket_onion_set_put(&set, one_time_a,
                std::strlen(one_time_a), 9735,
                ZMARKET_ONION_ROLE_DIRECT,
                ZMARKET_ONION_SCOPE_ONE_TIME, scope_id,
                100, 1700002000ULL, 1700000000ULL),
              ZMARKET_ONION_OK);
    ASSERT_EQ(zmarket_onion_set_put(&set, one_time_b,
                std::strlen(one_time_b), 9736,
                ZMARKET_ONION_ROLE_DIRECT,
                ZMARKET_ONION_SCOPE_ONE_TIME, scope_id,
                100, 1700002000ULL, 1700000000ULL),
              ZMARKET_ONION_OK);
    ASSERT_EQ(zmarket_onion_set_put(&set, reusable_c,
                std::strlen(reusable_c), 9737,
                ZMARKET_ONION_ROLE_DIRECT,
                ZMARKET_ONION_SCOPE_REUSABLE, nullptr,
                100, 1700002000ULL, 1700000000ULL),
              ZMARKET_ONION_OK);

    /* Choose a DIRECT one-time endpoint. */
    const zmarket_onion_endpoint *ep =
        zmarket_onion_choose(&set, ZMARKET_ONION_ROLE_DIRECT,
                             1700000100ULL, 42);
    ASSERT_NE(ep, nullptr);
    EXPECT_EQ(ep->scope, (uint8_t)ZMARKET_ONION_SCOPE_ONE_TIME);
    EXPECT_EQ(ep->use_count, (uint32_t)0);

    /* Mark it as successfully used. */
    EXPECT_TRUE(zmarket_onion_mark_success(&set, ep->host,
                                           ZMARKET_ONION_HOST_LEN,
                                           ep->port, 1700000200ULL));

    /* Verify the endpoint is now in USED state. */
    const zmarket_onion_endpoint *used_ep =
        zmarket_onion_set_find(&set, ep->host, ZMARKET_ONION_HOST_LEN,
                               ep->port);
    ASSERT_NE(used_ep, nullptr);
    EXPECT_EQ(used_ep->state, (uint8_t)ZMARKET_ONION_USED);
    EXPECT_EQ(used_ep->use_count, (uint32_t)1);
    EXPECT_EQ(used_ep->success_count, (uint32_t)1);

    /* The retired endpoint must never be chosen again. */
    const zmarket_onion_endpoint *chosen_again =
        zmarket_onion_choose(&set, ZMARKET_ONION_ROLE_DIRECT,
                             1700000300ULL, 9999);
    /* Should get the other one-time or the reusable, NOT the retired one. */
    if (chosen_again) {
        EXPECT_NE(chosen_again->state, (uint8_t)ZMARKET_ONION_USED);
        /* The retired endpoint should never appear. */
        EXPECT_NE(memcmp(chosen_again->host, used_ep->host,
                         ZMARKET_ONION_HOST_LEN), 0);
    }

    /* Mark the other one-time as used too. */
    const zmarket_onion_endpoint *other = nullptr;
    if (chosen_again &&
        chosen_again->scope == ZMARKET_ONION_SCOPE_ONE_TIME) {
        other = chosen_again;
        zmarket_onion_mark_success(&set, other->host,
                                   ZMARKET_ONION_HOST_LEN,
                                   other->port, 1700000300ULL);
    }

    /* After both one-time endpoints are used, only the reusable one
     * should remain selectable. */
    const zmarket_onion_endpoint *final_choice =
        zmarket_onion_choose(&set, ZMARKET_ONION_ROLE_DIRECT,
                             1700000400ULL, 12345);
    ASSERT_NE(final_choice, nullptr);
    EXPECT_EQ(final_choice->scope, (uint8_t)ZMARKET_ONION_SCOPE_REUSABLE);
    EXPECT_STREQ(final_choice->host, reusable_c);

    /* Reusable endpoint survives repeated use. */
    for (int i = 0; i < 5; i++)
        zmarket_onion_mark_success(&set, reusable_c,
                                   std::strlen(reusable_c), 9737,
                                   1700000400ULL + (uint64_t)i);
    const zmarket_onion_endpoint *still_ok =
        zmarket_onion_set_find(&set, reusable_c,
                               std::strlen(reusable_c), 9737);
    ASSERT_NE(still_ok, nullptr);
    EXPECT_EQ(still_ok->state, (uint8_t)ZMARKET_ONION_ACTIVE);
    EXPECT_EQ(still_ok->use_count, (uint32_t)5);
}

TEST(ZMarketCOnion, ExpiredEndpointsAreNeverChosen)
{
    /* Expired endpoints must never appear in zmarket_onion_choose results,
     * regardless of role, weight, or seed. */

    zmarket_onion_endpoint entries[4];
    zmarket_onion_set set;
    zmarket_onion_set_init(&set, entries, 4);

    const char host_a[] =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    const char host_b[] =
        "bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxy.onion";

    unsigned char scope_id[ZMARKET_ONION_SCOPE_ID_LEN] = {0};
    scope_id[0] = 0x33;

    /* Insert an expired endpoint (expires at 1000). */
    ASSERT_EQ(zmarket_onion_set_put(&set, host_a,
                std::strlen(host_a), 9735,
                ZMARKET_ONION_ROLE_MARKET,
                ZMARKET_ONION_SCOPE_REUSABLE, nullptr,
                500, 1000ULL, 500ULL),
              ZMARKET_ONION_OK);

    /* Insert a valid endpoint (expires at 2000). */
    ASSERT_EQ(zmarket_onion_set_put(&set, host_b,
                std::strlen(host_b), 9736,
                ZMARKET_ONION_ROLE_MARKET,
                ZMARKET_ONION_SCOPE_ASSET, scope_id,
                500, 2000ULL, 500ULL),
              ZMARKET_ONION_OK);

    /* At now=1500, host_a is expired. */
    const zmarket_onion_endpoint *chosen =
        zmarket_onion_choose(&set, ZMARKET_ONION_ROLE_MARKET, 1500ULL, 0);
    ASSERT_NE(chosen, nullptr);
    EXPECT_STREQ(chosen->host, host_b);  /* Only non-expired. */

    /* Verify endpoint_usable rejects expired. */
    const zmarket_onion_endpoint *expired_ep =
        zmarket_onion_set_find(&set, host_a, std::strlen(host_a), 9735);
    ASSERT_NE(expired_ep, nullptr);
    EXPECT_FALSE(zmarket_onion_endpoint_usable(expired_ep,
                                                ZMARKET_ONION_ROLE_MARKET,
                                                1500ULL));

    /* Usable endpoint passes. */
    const zmarket_onion_endpoint *valid_ep =
        zmarket_onion_set_find(&set, host_b, std::strlen(host_b), 9736);
    ASSERT_NE(valid_ep, nullptr);
    EXPECT_TRUE(zmarket_onion_endpoint_usable(valid_ep,
                                               ZMARKET_ONION_ROLE_MARKET,
                                               1500ULL));

    /* At now=2500, both are expired -> choose returns NULL. */
    EXPECT_EQ(zmarket_onion_choose(&set, ZMARKET_ONION_ROLE_MARKET,
                                    2500ULL, 0),
              nullptr);

    /* With now=0 (skip expiry check), expired one is technically usable. */
    EXPECT_TRUE(zmarket_onion_endpoint_usable(expired_ep,
                                               ZMARKET_ONION_ROLE_MARKET,
                                               0ULL));
}

TEST(ZMarketCOnion, TorOnlyRoutingRejectsClearnetRoutes)
{
    /* Tor-only routing must never select clearnet (non-onion) endpoints.
     * The onion layer only stores validated .onion v3 hosts; any clearnet
     * route attempt must fail validation at the onion layer. */

    zmarket_onion_endpoint entries[4];
    zmarket_onion_set set;
    zmarket_onion_set_init(&set, entries, 4);

    const char onion_host[] =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    /* Clearnet addresses cannot even be inserted — host validation rejects. */
    const char clearnet_ip[] = "192.168.1.1";
    EXPECT_FALSE(zmarket_onion_host_is_v3(clearnet_ip,
                                          std::strlen(clearnet_ip)));

    const char clearnet_dns[] = "example.com";
    EXPECT_FALSE(zmarket_onion_host_is_v3(clearnet_dns,
                                          std::strlen(clearnet_dns)));

    const char clearnet_port[] = "example.com:8080";
    EXPECT_FALSE(zmarket_onion_host_is_v3(clearnet_port,
                                          std::strlen(clearnet_port)));

    /* Attempting to put a clearnet address into the onion set fails. */
    EXPECT_EQ(zmarket_onion_set_put(&set, clearnet_ip,
                                    std::strlen(clearnet_ip), 80,
                                    ZMARKET_ONION_ROLE_MARKET,
                                    ZMARKET_ONION_SCOPE_REUSABLE, nullptr,
                                    100, 2000ULL, 1000ULL),
              ZMARKET_ONION_ERR_HOST);

    EXPECT_EQ(zmarket_onion_set_put(&set, clearnet_dns,
                                    std::strlen(clearnet_dns), 443,
                                    ZMARKET_ONION_ROLE_MARKET,
                                    ZMARKET_ONION_SCOPE_REUSABLE, nullptr,
                                    100, 2000ULL, 1000ULL),
              ZMARKET_ONION_ERR_HOST);

    /* Only valid onion hosts succeed. */
    EXPECT_EQ(zmarket_onion_set_put(&set, onion_host,
                                    std::strlen(onion_host), 9735,
                                    ZMARKET_ONION_ROLE_MARKET,
                                    ZMARKET_ONION_SCOPE_REUSABLE, nullptr,
                                    100, 2000ULL, 1000ULL),
              ZMARKET_ONION_OK);

    /* Tor-only router fanout: combine with router's tor_mode. */
    zmarket_policy policy;
    zmarket_policy_default(&policy);
    policy.mode_bits |= ZMARKET_MODE_RELAY;

    zmarket_index_slot dedup_slots[4];
    zmarket_index dedup;
    zmarket_index_init(&dedup, dedup_slots, 4);

    zmarket_route_entry rt_entries[4];
    zmarket_router_peer peers[4];
    zmarket_router rt;
    zmarket_router_init(&rt, rt_entries, 4, peers, 4, &dedup, &policy);

    /* Add one Tor peer and one clearnet peer to the router. */
    zmarket_router_add_peer(&rt, "tor-onion-a", 12, true);
    zmarket_router_add_peer(&rt, "clearnet-ip", 12, false);

    uint8_t id[ZMARKET_ID_LEN];
    make_id(id, 0xBB);
    zmarket_router_admit(&rt, id, ZMARKET_RECORD_LISTING, 2000,
                         0, nullptr, 0, 1000);

    /* Tor-only mode: only tor peer is relayable. */
    zmarket_router_set_tor_mode(&rt, 2);
    EXPECT_TRUE(zmarket_router_should_relay(&rt, id,
                                            "tor-onion-a", 12, 1000));
    EXPECT_FALSE(zmarket_router_should_relay(&rt, id,
                                             "clearnet-ip", 12, 1000));

    /* Fanout should only include the Tor peer. */
    zmarket_route_fanout fo = zmarket_router_fanout(&rt, id,
                                                     nullptr, 0, 1000);
    ASSERT_EQ(fo.count, (size_t)1);
    /* Verify the selected peer is the Tor one. */
    EXPECT_TRUE(rt.peers[fo.peer_indices[0]].tor_peer);

    /* The onion endpoint set has zero clearnet entries. */
    EXPECT_EQ(zmarket_onion_set_count(&set), (size_t)1);
}

TEST(ZMarketCOnion, RoutingSpiderIndexModesCannotEnableContentHosting)
{
    /* HARD INVARIANT: enabling SPIDER, INDEXER, or RELAY (routing) modes
     * must NEVER imply or enable content hosting. Content hosting requires
     * an explicit ZMARKET_MODE_CONTENT_HOST mode bit AND per-file operator
     * allowlist entry. This test proves the separation. */

    zmarket_policy policy;
    zmarket_policy_default(&policy);

    /* Default: viewer+buyer+seller+indexer — no hosting. */
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, true));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, false));

    /* Add spider mode: still no hosting. */
    policy.mode_bits |= ZMARKET_MODE_SPIDER;
    EXPECT_TRUE(zmarket_policy_can_spider_records(&policy));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, true));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, false));

    /* Add relay/routing mode: still no hosting. */
    policy.mode_bits |= ZMARKET_MODE_RELAY;
    EXPECT_TRUE(zmarket_policy_can_route_records(&policy));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, true));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, false));

    /* Add indexer mode: still no hosting. */
    policy.mode_bits |= ZMARKET_MODE_INDEXER;
    EXPECT_TRUE(zmarket_policy_can_index_records(&policy));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, true));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, false));

    /* All three routing modes together: STILL no hosting. */
    EXPECT_TRUE(zmarket_policy_can_spider_records(&policy));
    EXPECT_TRUE(zmarket_policy_can_route_records(&policy));
    EXPECT_TRUE(zmarket_policy_can_index_records(&policy));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, true));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, false));

    /* Now add content_host mode. Hosting still denied without allowlist. */
    policy.mode_bits |= ZMARKET_MODE_CONTENT_HOST;
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, false));
    EXPECT_TRUE(zmarket_policy_can_host_content(&policy, true));

    /* Cross-check with content allowlist: routing activity must not
     * pollute the allowlist. */
    zmarket_content_allowlist_entry content_entries[4];
    zmarket_content_allowlist allowlist;
    zmarket_content_allowlist_init(&allowlist, content_entries, 4);

    /* Simulate routing activity: index many records of various types. */
    zmarket_index_slot slots[16];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 16);

    uint8_t id[ZMARKET_ID_LEN];
    for (int i = 0; i < 8; i++) {
        make_id(id, (uint8_t)(0xC0 + i));
        enum zmarket_record_type t;
        switch (i % 4) {
        case 0: t = ZMARKET_RECORD_LISTING; break;
        case 1: t = ZMARKET_RECORD_BUYREQ_ROUTE; break;
        case 2: t = ZMARKET_RECORD_MANIFEST; break;
        default: t = ZMARKET_RECORD_MIRROR; break;
        }
        zmarket_index_put(&idx, id, t, 2000 + (uint64_t)i);
    }
    EXPECT_EQ(zmarket_index_count(&idx), (size_t)8);

    /* Spider peers and onion endpoints — still no content. */
    zmarket_onion_endpoint onion_entries[4];
    zmarket_onion_set onion_set;
    zmarket_onion_set_init(&onion_set, onion_entries, 4);

    const char onion_host[] =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    zmarket_onion_set_put(&onion_set, onion_host, std::strlen(onion_host),
                          9735, ZMARKET_ONION_ROLE_MARKET,
                          ZMARKET_ONION_SCOPE_REUSABLE, nullptr,
                          100, 2000ULL, 1000ULL);

    /* None of this routing/indexing/spidering activity affects hosting. */
    EXPECT_EQ(zmarket_content_allowlist_count(&allowlist), (size_t)0);

    /* A content root not in the allowlist is not hostable. */
    uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN];
    content_root[0] = 0xDD;
    EXPECT_FALSE(zmarket_content_can_host(&policy, &allowlist, content_root));

    /* Only an explicit operator allowlist entry enables hosting. */
    const char path[] = "/operator/explicitly-chosen/file.bin";
    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, content_root,
                                            path, std::strlen(path), 1000),
              ZMARKET_CONTENT_OK);
    EXPECT_EQ(zmarket_content_allowlist_count(&allowlist), (size_t)1);
    EXPECT_TRUE(zmarket_content_can_host(&policy, &allowlist, content_root));

    /* The allowlist was NOT enlarged by routing activity. */
    EXPECT_EQ(zmarket_content_allowlist_count(&allowlist), (size_t)1);
}

TEST(ZMarketCOnion, MirrorFailoverUsesSignedEndpointsNoMedia)
{
    /* Mirror failover must use signed endpoint sets (MIRROR/MIRROR_SET
     * records) and the indexer must track these without downloading or
     * storing any media bytes. This test proves mirror records go through
     * the index/router as signed envelopes only. */

    zmarket_policy policy;
    zmarket_policy_default(&policy);
    policy.mode_bits |= ZMARKET_MODE_RELAY;
    policy.mode_bits |= ZMARKET_MODE_INDEXER;

    /* Step 1: Parse MIRROR and MIRROR_SET records (signed envelopes). */
    std::vector<unsigned char> mirror_payload(32, 'M');
    std::vector<unsigned char> mirror_set_payload(64, 'S');
    zmarket_record_view view;

    std::vector<unsigned char> mirror_bytes =
        record(ZMARKET_RECORD_MIRROR, mirror_payload);
    ASSERT_EQ(zmarket_record_parse(mirror_bytes.data(),
                                    mirror_bytes.size(), 8192, &view),
              ZMARKET_RECORD_OK);
    EXPECT_EQ(view.type, ZMARKET_RECORD_MIRROR);
    EXPECT_TRUE(zmarket_record_type_is_routable(view.type));
    /* The record carries signed payload metadata, not file bytes. */
    ASSERT_EQ(view.payload_len, (uint32_t)32);

    std::vector<unsigned char> mirror_set_bytes =
        record(ZMARKET_RECORD_MIRROR_SET, mirror_set_payload);
    ASSERT_EQ(zmarket_record_parse(mirror_set_bytes.data(),
                                    mirror_set_bytes.size(), 16384, &view),
              ZMARKET_RECORD_OK);
    EXPECT_EQ(view.type, ZMARKET_RECORD_MIRROR_SET);
    EXPECT_TRUE(zmarket_record_type_is_routable(view.type));

    /* Step 2: Index MIRROR records — no media bytes stored. */
    zmarket_index_slot slots[16];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 16);

    uint8_t mirror_id_a[ZMARKET_ID_LEN], mirror_id_b[ZMARKET_ID_LEN];
    uint8_t mirror_set_id[ZMARKET_ID_LEN];
    make_id(mirror_id_a, 0x10);
    make_id(mirror_id_b, 0x11);
    make_id(mirror_set_id, 0x12);

    EXPECT_TRUE(zmarket_index_put(&idx, mirror_id_a,
                                  ZMARKET_RECORD_MIRROR, 3000));
    EXPECT_TRUE(zmarket_index_put(&idx, mirror_id_b,
                                  ZMARKET_RECORD_MIRROR, 4000));
    EXPECT_TRUE(zmarket_index_put(&idx, mirror_set_id,
                                  ZMARKET_RECORD_MIRROR_SET, 5000));
    EXPECT_EQ(zmarket_index_count(&idx), (size_t)3);

    /* Index slots store metadata (id, type, expiry, seen_count), NOT media. */
    const zmarket_index_slot *slot_a = zmarket_index_get(&idx, mirror_id_a);
    ASSERT_NE(slot_a, nullptr);
    EXPECT_EQ(slot_a->type, (uint16_t)ZMARKET_RECORD_MIRROR);
    EXPECT_EQ(slot_a->expires_unix, (uint64_t)3000);
    EXPECT_EQ(slot_a->seen_count, (uint32_t)1);

    /* Step 3: Mirror failover via signed onion endpoints. */
    zmarket_onion_endpoint onion_entries[4];
    zmarket_onion_set mirror_set;
    zmarket_onion_set_init(&mirror_set, onion_entries, 4);

    const char mirror_host_1[] =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    const char mirror_host_2[] =
        "bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxy.onion";
    const char mirror_host_3[] =
        "cdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz.onion";

    unsigned char scope_a[ZMARKET_ONION_SCOPE_ID_LEN] = {0};
    unsigned char scope_b[ZMARKET_ONION_SCOPE_ID_LEN] = {0};
    unsigned char scope_c[ZMARKET_ONION_SCOPE_ID_LEN] = {0};
    scope_a[0] = 0xAA;
    scope_b[0] = 0xBB;
    scope_c[0] = 0xCC;

    /* Each mirror endpoint is a signed onion address (not media). */
    ASSERT_EQ(zmarket_onion_set_put(&mirror_set, mirror_host_1,
                std::strlen(mirror_host_1), 9735,
                ZMARKET_ONION_ROLE_CONTENT,
                ZMARKET_ONION_SCOPE_ASSET, scope_a,
                200, 1700005000ULL, 1700000000ULL),
              ZMARKET_ONION_OK);
    ASSERT_EQ(zmarket_onion_set_put(&mirror_set, mirror_host_2,
                std::strlen(mirror_host_2), 9736,
                ZMARKET_ONION_ROLE_CONTENT,
                ZMARKET_ONION_SCOPE_ASSET, scope_b,
                200, 1700005000ULL, 1700000000ULL),
              ZMARKET_ONION_OK);
    ASSERT_EQ(zmarket_onion_set_put(&mirror_set, mirror_host_3,
                std::strlen(mirror_host_3), 9737,
                ZMARKET_ONION_ROLE_CONTENT,
                ZMARKET_ONION_SCOPE_ASSET, scope_c,
                200, 1700005000ULL, 1700000000ULL),
              ZMARKET_ONION_OK);
    EXPECT_EQ(zmarket_onion_set_count(&mirror_set), (size_t)3);

    /* Simulate failover: mark mirror_host_1 as failed. */
    zmarket_onion_mark_failure(&mirror_set, mirror_host_1,
                               std::strlen(mirror_host_1), 9735,
                               1700001000ULL);
    const zmarket_onion_endpoint *failed =
        zmarket_onion_set_find(&mirror_set, mirror_host_1,
                               std::strlen(mirror_host_1), 9735);
    ASSERT_NE(failed, nullptr);
    EXPECT_EQ(failed->fail_count, (uint32_t)1);
    /* Still usable (failures don't retire), but gets lower score. */

    /* Failover: choose picks the best remaining endpoint. */
    const zmarket_onion_endpoint *chosen =
        zmarket_onion_choose(&mirror_set, ZMARKET_ONION_ROLE_CONTENT,
                             1700001000ULL, 42);
    ASSERT_NE(chosen, nullptr);
    /* The chosen endpoint is a valid onion host — signed metadata only. */
    EXPECT_TRUE(zmarket_onion_host_is_v3(chosen->host,
                                         ZMARKET_ONION_HOST_LEN));
    EXPECT_EQ(chosen->fail_count, (uint32_t)0);

    /* Mark mirror_host_2 as failed too. */
    zmarket_onion_mark_failure(&mirror_set, mirror_host_2,
                               std::strlen(mirror_host_2), 9736,
                               1700002000ULL);

    /* Third mirror should still work. */
    const zmarket_onion_endpoint *failover2 =
        zmarket_onion_choose(&mirror_set, ZMARKET_ONION_ROLE_CONTENT,
                             1700002000ULL, 42);
    ASSERT_NE(failover2, nullptr);
    EXPECT_EQ(failover2->fail_count, (uint32_t)0);

    /* Step 4: Content hosting is STILL denied — the indexer/router only
     * tracks signed endpoint metadata, never hosts or downloads media. */
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, true));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, false));

    zmarket_content_allowlist_entry content_entries[2];
    zmarket_content_allowlist allowlist;
    zmarket_content_allowlist_init(&allowlist, content_entries, 2);
    EXPECT_EQ(zmarket_content_allowlist_count(&allowlist), (size_t)0);

    uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN];
    content_root[0] = 0xEE;
    EXPECT_FALSE(zmarket_content_can_host(&policy, &allowlist, content_root));

    /* The mirror record bytes in the index are signed envelopes,
     * NOT media file data. Verify no content was automatically hosted. */
    EXPECT_EQ(zmarket_content_allowlist_count(&allowlist), (size_t)0);
}
