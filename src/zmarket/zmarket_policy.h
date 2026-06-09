// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZMARKET policy primitives. C hot-path code only; daemon/GUI code bridges to
// this layer instead of owning marketplace spider/router/index state.

#ifndef ZCLASSIC_ZMARKET_POLICY_H
#define ZCLASSIC_ZMARKET_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum zmarket_node_mode {
    ZMARKET_MODE_VIEWER           = 1u << 0,
    ZMARKET_MODE_BUYER            = 1u << 1,
    ZMARKET_MODE_SELLER           = 1u << 2,
    ZMARKET_MODE_RELAY            = 1u << 3,
    ZMARKET_MODE_SPIDER           = 1u << 4,
    ZMARKET_MODE_INDEXER          = 1u << 5,
    ZMARKET_MODE_CONTENT_HOST     = 1u << 6,
    ZMARKET_MODE_MIRROR_ANNOUNCER = 1u << 7
};

struct zmarket_caps {
    uint32_t max_record_bytes;
    uint32_t max_offer_bytes;
    uint32_t max_manifest_bytes;
    uint32_t max_mirror_bytes;
    uint32_t max_inventory_ids;
    uint32_t max_spider_queue;
    uint32_t max_index_records;
    uint32_t max_route_fanout;
};

struct zmarket_policy {
    uint32_t mode_bits;
    struct zmarket_caps caps;
};

void zmarket_caps_default(struct zmarket_caps *caps);

/* Market-engine defaults after the daemon has explicitly enabled marketplace
 * mode. Daemon startup must still keep marketplace networking/indexing disabled
 * unless config such as -nftmarket opts in and creates the engine. */
void zmarket_policy_default(struct zmarket_policy *policy);

bool zmarket_policy_valid(const struct zmarket_policy *policy);
bool zmarket_policy_allows_mode(const struct zmarket_policy *policy,
                                enum zmarket_node_mode mode);

/* Hosting is never implicit. `operator_allowed` must come from the local
 * allowlist for the exact content id/file selected by the node operator. */
bool zmarket_policy_can_host_content(const struct zmarket_policy *policy,
                                     bool operator_allowed);

/* Spider/router/index modes move small signed records, never file bytes. */
bool zmarket_policy_can_route_records(const struct zmarket_policy *policy);
bool zmarket_policy_can_spider_records(const struct zmarket_policy *policy);
bool zmarket_policy_can_index_records(const struct zmarket_policy *policy);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZCLASSIC_ZMARKET_POLICY_H */
