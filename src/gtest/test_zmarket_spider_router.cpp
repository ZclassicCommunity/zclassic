// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// C hot-path tests for beta7 ZMARKET spider, router, index query, and
// content-hosting-invariant modules.

#include <gtest/gtest.h>

extern "C" {
#include "zmarket/zmarket_content.h"
#include "zmarket/zmarket_index.h"
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
