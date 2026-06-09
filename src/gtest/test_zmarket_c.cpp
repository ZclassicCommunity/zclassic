// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// C hot-path tests for beta7 ZMARKET spider/router/index scaffolding.

#include <gtest/gtest.h>

extern "C" {
#include "zmarket/zmarket_content.h"
#include "zmarket/zmarket_index.h"
#include "zmarket/zmarket_onion.h"
#include "zmarket/zmarket_policy.h"
#include "zmarket/zmarket_record.h"
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

} // namespace

TEST(ZMarketCPolicy, HostingRequiresModeAndOperatorAllowlist)
{
    zmarket_policy policy;
    zmarket_policy_default(&policy);

    EXPECT_TRUE(zmarket_policy_valid(&policy));
    EXPECT_TRUE(zmarket_policy_can_index_records(&policy));
    EXPECT_FALSE(zmarket_policy_can_route_records(&policy));
    EXPECT_FALSE(zmarket_policy_can_spider_records(&policy));

    // Default node must not host content, even if a remote record asks it to.
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, false));
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, true));

    policy.mode_bits |= ZMARKET_MODE_CONTENT_HOST;
    EXPECT_FALSE(zmarket_policy_can_host_content(&policy, false));
    EXPECT_TRUE(zmarket_policy_can_host_content(&policy, true));
}

TEST(ZMarketCRecord, ParsesBoundedSignedRecord)
{
    std::vector<unsigned char> payload;
    payload.push_back('o');
    payload.push_back('f');
    payload.push_back('f');
    payload.push_back('e');
    payload.push_back('r');
    std::vector<unsigned char> bytes = record(ZMARKET_RECORD_OFFER, payload);

    zmarket_record_view view;
    ASSERT_EQ(zmarket_record_parse(bytes.data(), bytes.size(), 8192, &view),
              ZMARKET_RECORD_OK);
    EXPECT_EQ(view.type, ZMARKET_RECORD_OFFER);
    EXPECT_EQ(view.expires_unix, 1700000000ULL);
    ASSERT_EQ(view.payload_len, payload.size());
    EXPECT_EQ(view.payload[0], 'o');
    EXPECT_EQ(view.signer_key_len, 32);
    EXPECT_EQ(view.signature_len, 64);
}

TEST(ZMarketCRecord, RejectsOversizeAndTrailingBytes)
{
    std::vector<unsigned char> payload(9000, 'x');
    std::vector<unsigned char> bytes = record(ZMARKET_RECORD_OFFER, payload);
    zmarket_record_view view;

    EXPECT_EQ(zmarket_record_parse(bytes.data(), bytes.size(), 65536, &view),
              ZMARKET_RECORD_ERR_SIZE);

    payload.assign(4, 'x');
    bytes = record(ZMARKET_RECORD_MIRROR, payload);
    bytes.push_back(0x00);
    EXPECT_EQ(zmarket_record_parse(bytes.data(), bytes.size(), 8192, &view),
              ZMARKET_RECORD_ERR_TRAILING);
}

TEST(ZMarketCRecord, SupportsRouteAndCancelRecordTypes)
{
    std::vector<unsigned char> route_payload(16, 'r');
    std::vector<unsigned char> cancel_payload(8, 'c');
    zmarket_record_view view;

    std::vector<unsigned char> bytes =
        record(ZMARKET_RECORD_BUYREQ_ROUTE, route_payload);
    ASSERT_EQ(zmarket_record_parse(bytes.data(), bytes.size(), 8192, &view),
              ZMARKET_RECORD_OK);
    EXPECT_EQ(view.type, ZMARKET_RECORD_BUYREQ_ROUTE);
    EXPECT_TRUE(zmarket_record_type_is_routable(view.type));

    bytes = record(ZMARKET_RECORD_SEALED_OFFER_ROUTE, route_payload);
    ASSERT_EQ(zmarket_record_parse(bytes.data(), bytes.size(), 8192, &view),
              ZMARKET_RECORD_OK);
    EXPECT_EQ(view.type, ZMARKET_RECORD_SEALED_OFFER_ROUTE);
    EXPECT_TRUE(zmarket_record_type_is_routable(view.type));

    bytes = record(ZMARKET_RECORD_CANCEL, cancel_payload);
    ASSERT_EQ(zmarket_record_parse(bytes.data(), bytes.size(), 8192, &view),
              ZMARKET_RECORD_OK);
    EXPECT_EQ(view.type, ZMARKET_RECORD_CANCEL);
}

TEST(ZMarketCRecord, EnforcesPerTypePayloadCaps)
{
    std::vector<unsigned char> too_large_cancel(3 * 1024, 'x');
    std::vector<unsigned char> bytes =
        record(ZMARKET_RECORD_CANCEL, too_large_cancel);
    zmarket_record_view view;

    EXPECT_EQ(zmarket_record_parse(bytes.data(), bytes.size(), 8192, &view),
              ZMARKET_RECORD_ERR_SIZE);
}

TEST(ZMarketCIndex, FixedMemoryDedupe)
{
    zmarket_index_slot slots[8];
    zmarket_index idx;
    zmarket_index_init(&idx, slots, 8);

    unsigned char id[ZMARKET_ID_LEN] = {0};
    id[31] = 1;

    EXPECT_FALSE(zmarket_index_has(&idx, id));
    EXPECT_TRUE(zmarket_index_put(&idx, id, ZMARKET_RECORD_OFFER, 1700000000ULL));
    EXPECT_TRUE(zmarket_index_has(&idx, id));
    EXPECT_EQ(zmarket_index_count(&idx), (size_t)1);

    // Re-seeing the same id updates metadata but does not grow the table.
    EXPECT_TRUE(zmarket_index_put(&idx, id, ZMARKET_RECORD_OFFER, 1700000100ULL));
    EXPECT_EQ(zmarket_index_count(&idx), (size_t)1);

    zmarket_index_clear(&idx);
    EXPECT_EQ(zmarket_index_count(&idx), (size_t)0);
    EXPECT_FALSE(zmarket_index_has(&idx, id));
}

TEST(ZMarketCContent, HostingRequiresExplicitAllowlistEntry)
{
    zmarket_content_allowlist_entry entries[2];
    zmarket_content_allowlist allowlist;
    zmarket_content_allowlist_init(&allowlist, entries, 2);

    unsigned char root[ZMARKET_CONTENT_ROOT_LEN] = {0};
    root[0] = 0x11;
    root[31] = 0x99;

    zmarket_policy policy;
    zmarket_policy_default(&policy);

    const char path[] = "/operator/selected/content.bin";
    ASSERT_EQ(zmarket_content_allowlist_put(&allowlist, root, path,
                                            std::strlen(path), 1700000200ULL),
              ZMARKET_CONTENT_OK);

    EXPECT_TRUE(zmarket_content_operator_allowed(&allowlist, root));
    EXPECT_FALSE(zmarket_content_can_host(&policy, &allowlist, root));

    policy.mode_bits |= ZMARKET_MODE_CONTENT_HOST;
    EXPECT_TRUE(zmarket_content_can_host(&policy, &allowlist, root));

    const zmarket_content_allowlist_entry* entry =
        zmarket_content_allowlist_find(&allowlist, root);
    ASSERT_NE(entry, nullptr);
    EXPECT_STREQ(entry->source.path, path);
    EXPECT_EQ(entry->source.path_len, std::strlen(path));
    EXPECT_EQ(entry->source.selected_unix, 1700000200ULL);
}

TEST(ZMarketCContent, RejectsImplicitOrAmbiguousEntries)
{
    zmarket_content_allowlist_entry entries[2];
    zmarket_content_allowlist allowlist;
    zmarket_content_allowlist_init(&allowlist, entries, 2);

    unsigned char zero_root[ZMARKET_CONTENT_ROOT_LEN] = {0};
    unsigned char root[ZMARKET_CONTENT_ROOT_LEN] = {0};
    root[0] = 0x22;

    const char path[] = "/operator/selected/content.bin";
    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, zero_root, path,
                                            std::strlen(path), 1),
              ZMARKET_CONTENT_ERR_ROOT);
    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, root, nullptr, 0, 1),
              ZMARKET_CONTENT_ERR_NULL);
    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, root, path, 0, 1),
              ZMARKET_CONTENT_ERR_PATH);

    const char embedded_nul[] = {'/', 'x', '\0', 'y'};
    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, root, embedded_nul,
                                            sizeof(embedded_nul), 1),
              ZMARKET_CONTENT_ERR_PATH);

    std::vector<char> too_long(ZMARKET_CONTENT_SOURCE_PATH_MAX, 'x');
    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, root, too_long.data(),
                                            too_long.size(), 1),
              ZMARKET_CONTENT_ERR_PATH);

    EXPECT_EQ(zmarket_content_allowlist_count(&allowlist), (size_t)0);
    EXPECT_FALSE(zmarket_content_operator_allowed(&allowlist, root));
}

TEST(ZMarketCContent, BoundedAllowlistUpdatesAndRemoves)
{
    zmarket_content_allowlist_entry entries[1];
    zmarket_content_allowlist allowlist;
    zmarket_content_allowlist_init(&allowlist, entries, 1);

    unsigned char root_a[ZMARKET_CONTENT_ROOT_LEN] = {0};
    unsigned char root_b[ZMARKET_CONTENT_ROOT_LEN] = {0};
    root_a[0] = 0xA0;
    root_b[0] = 0xB0;

    const char path_a[] = "/operator/content-a.dat";
    const char path_a2[] = "/operator/content-a-v2.dat";
    const char path_b[] = "/operator/content-b.dat";

    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, root_a, path_a,
                                            std::strlen(path_a), 10),
              ZMARKET_CONTENT_OK);
    EXPECT_EQ(zmarket_content_allowlist_count(&allowlist), (size_t)1);

    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, root_a, path_a2,
                                            std::strlen(path_a2), 20),
              ZMARKET_CONTENT_OK);
    EXPECT_EQ(zmarket_content_allowlist_count(&allowlist), (size_t)1);
    ASSERT_NE(zmarket_content_allowlist_find(&allowlist, root_a), nullptr);
    EXPECT_STREQ(zmarket_content_allowlist_find(&allowlist, root_a)->source.path,
                 path_a2);

    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, root_b, path_b,
                                            std::strlen(path_b), 30),
              ZMARKET_CONTENT_ERR_FULL);

    EXPECT_TRUE(zmarket_content_allowlist_remove(&allowlist, root_a));
    EXPECT_FALSE(zmarket_content_operator_allowed(&allowlist, root_a));
    EXPECT_EQ(zmarket_content_allowlist_count(&allowlist), (size_t)0);

    EXPECT_EQ(zmarket_content_allowlist_put(&allowlist, root_b, path_b,
                                            std::strlen(path_b), 30),
              ZMARKET_CONTENT_OK);
    EXPECT_TRUE(zmarket_content_operator_allowed(&allowlist, root_b));
}

TEST(ZMarketCOnion, ValidatesCanonicalV3OnionHosts)
{
    const char host[] =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    ASSERT_EQ(std::strlen(host), (size_t)ZMARKET_ONION_HOST_LEN);
    EXPECT_TRUE(zmarket_onion_host_is_v3(host, std::strlen(host)));
    EXPECT_FALSE(zmarket_onion_host_is_v3(host, std::strlen(host) - 1));

    char uppercase[ZMARKET_ONION_HOST_BUF_LEN];
    std::memcpy(uppercase, host, sizeof(host));
    uppercase[0] = 'A';
    EXPECT_FALSE(zmarket_onion_host_is_v3(uppercase, std::strlen(uppercase)));

    const char bad_suffix[] =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.tor";
    EXPECT_FALSE(zmarket_onion_host_is_v3(bad_suffix,
                                          std::strlen(bad_suffix)));
}

TEST(ZMarketCOnion, TracksReusableAndOneTimeEndpoints)
{
    zmarket_onion_endpoint entries[3];
    zmarket_onion_set set;
    zmarket_onion_set_init(&set, entries, 3);

    const char market_host[] =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    const char direct_host[] =
        "bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxy.onion";

    unsigned char scope_id[ZMARKET_ONION_SCOPE_ID_LEN] = {0};
    scope_id[0] = 0x55;
    scope_id[31] = 0xaa;

    EXPECT_EQ(zmarket_onion_set_put(&set, market_host,
                                    std::strlen(market_host), 9735,
                                    ZMARKET_ONION_ROLE_MARKET |
                                        ZMARKET_ONION_ROLE_SOCIAL,
                                    ZMARKET_ONION_SCOPE_REUSABLE, nullptr,
                                    100, 1700001000ULL, 1700000000ULL),
              ZMARKET_ONION_OK);

    EXPECT_EQ(zmarket_onion_set_put(&set, direct_host,
                                    std::strlen(direct_host), 9736,
                                    ZMARKET_ONION_ROLE_DIRECT,
                                    ZMARKET_ONION_SCOPE_ONE_TIME, scope_id,
                                    100, 1700001000ULL, 1700000000ULL),
              ZMARKET_ONION_OK);
    EXPECT_EQ(zmarket_onion_set_count(&set), (size_t)2);

    const zmarket_onion_endpoint* chosen =
        zmarket_onion_choose(&set, ZMARKET_ONION_ROLE_MARKET,
                             1700000100ULL, 1234);
    ASSERT_NE(chosen, nullptr);
    EXPECT_STREQ(chosen->host, market_host);

    chosen = zmarket_onion_choose(&set, ZMARKET_ONION_ROLE_DIRECT,
                                  1700000100ULL, 1234);
    ASSERT_NE(chosen, nullptr);
    EXPECT_STREQ(chosen->host, direct_host);

    EXPECT_TRUE(zmarket_onion_mark_success(&set, direct_host,
                                           std::strlen(direct_host), 9736,
                                           1700000200ULL));
    EXPECT_EQ(zmarket_onion_choose(&set, ZMARKET_ONION_ROLE_DIRECT,
                                   1700000201ULL, 1234),
              nullptr);
}

TEST(ZMarketCOnion, RejectsAmbiguousOrExpiredEndpoints)
{
    zmarket_onion_endpoint entries[1];
    zmarket_onion_set set;
    zmarket_onion_set_init(&set, entries, 1);

    const char host[] =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    unsigned char zero_scope[ZMARKET_ONION_SCOPE_ID_LEN] = {0};
    unsigned char scope_id[ZMARKET_ONION_SCOPE_ID_LEN] = {0};
    scope_id[1] = 0x42;

    EXPECT_EQ(zmarket_onion_set_put(&set, host, std::strlen(host), 0,
                                    ZMARKET_ONION_ROLE_MARKET,
                                    ZMARKET_ONION_SCOPE_REUSABLE, nullptr,
                                    100, 0, 0),
              ZMARKET_ONION_ERR_PORT);
    EXPECT_EQ(zmarket_onion_set_put(&set, host, std::strlen(host), 9735,
                                    0,
                                    ZMARKET_ONION_SCOPE_REUSABLE, nullptr,
                                    100, 0, 0),
              ZMARKET_ONION_ERR_ROLE);
    EXPECT_EQ(zmarket_onion_set_put(&set, host, std::strlen(host), 9735,
                                    ZMARKET_ONION_ROLE_MARKET,
                                    ZMARKET_ONION_SCOPE_ONE_TIME, zero_scope,
                                    100, 0, 0),
              ZMARKET_ONION_ERR_SCOPE);

    EXPECT_EQ(zmarket_onion_set_put(&set, host, std::strlen(host), 9735,
                                    ZMARKET_ONION_ROLE_MARKET,
                                    ZMARKET_ONION_SCOPE_ASSET, scope_id,
                                    100, 1700000100ULL, 1700000000ULL),
              ZMARKET_ONION_OK);
    EXPECT_EQ(zmarket_onion_choose(&set, ZMARKET_ONION_ROLE_MARKET,
                                   1700000200ULL, 1),
              nullptr);
}
