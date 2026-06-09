// Copyright 2026 Rhett Creighton - Apache License 2.0

#include "zmarket/zmarket_policy.h"

#include <string.h>

void zmarket_caps_default(struct zmarket_caps *caps)
{
    if (!caps) return;
    memset(caps, 0, sizeof(*caps));
    caps->max_record_bytes  = 64u * 1024u;
    caps->max_offer_bytes   = 8u * 1024u;
    caps->max_manifest_bytes = 64u * 1024u;
    caps->max_mirror_bytes  = 8u * 1024u;
    caps->max_inventory_ids = 1000u;
    caps->max_spider_queue  = 4096u;
    caps->max_index_records = 50000u;
    caps->max_route_fanout  = 16u;
}

void zmarket_policy_default(struct zmarket_policy *policy)
{
    if (!policy) return;
    memset(policy, 0, sizeof(*policy));
    policy->mode_bits = ZMARKET_MODE_VIEWER |
                        ZMARKET_MODE_BUYER |
                        ZMARKET_MODE_SELLER |
                        ZMARKET_MODE_INDEXER;
    zmarket_caps_default(&policy->caps);
}

bool zmarket_policy_valid(const struct zmarket_policy *policy)
{
    if (!policy) return false;
    if (policy->caps.max_offer_bytes == 0 ||
        policy->caps.max_mirror_bytes == 0 ||
        policy->caps.max_manifest_bytes == 0 ||
        policy->caps.max_record_bytes == 0)
        return false;
    if (policy->caps.max_offer_bytes > policy->caps.max_record_bytes)
        return false;
    if (policy->caps.max_mirror_bytes > policy->caps.max_record_bytes)
        return false;
    if (policy->caps.max_manifest_bytes > policy->caps.max_record_bytes)
        return false;
    if (policy->caps.max_inventory_ids == 0 ||
        policy->caps.max_spider_queue == 0 ||
        policy->caps.max_index_records == 0 ||
        policy->caps.max_route_fanout == 0)
        return false;
    return true;
}

bool zmarket_policy_allows_mode(const struct zmarket_policy *policy,
                                enum zmarket_node_mode mode)
{
    if (!policy) return false;
    return (policy->mode_bits & (uint32_t)mode) != 0;
}

bool zmarket_policy_can_host_content(const struct zmarket_policy *policy,
                                     bool operator_allowed)
{
    if (!operator_allowed) return false;
    return zmarket_policy_allows_mode(policy, ZMARKET_MODE_CONTENT_HOST);
}

bool zmarket_policy_can_route_records(const struct zmarket_policy *policy)
{
    return zmarket_policy_allows_mode(policy, ZMARKET_MODE_RELAY);
}

bool zmarket_policy_can_spider_records(const struct zmarket_policy *policy)
{
    return zmarket_policy_allows_mode(policy, ZMARKET_MODE_SPIDER);
}

bool zmarket_policy_can_index_records(const struct zmarket_policy *policy)
{
    return zmarket_policy_allows_mode(policy, ZMARKET_MODE_INDEXER);
}
