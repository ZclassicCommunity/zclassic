// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZMARKET routing engine. C hot-path for inventory dedupe, route scoring,
// relay policy, route fanout, TTL/hop decrement, duplicate suppression,
// and Tor-only/clearnet policy checks.
//
// HARD INVARIANT: routing records NEVER hosts files. The router moves small
// signed record envelopes between peers. It does not fetch, serve, or pin
// content. Enabling routing does not enable content hosting.

#ifndef ZCLASSIC_ZMARKET_ROUTER_H
#define ZCLASSIC_ZMARKET_ROUTER_H

#include "zmarket/zmarket_index.h"
#include "zmarket/zmarket_policy.h"
#include "zmarket/zmarket_record.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum hop count for routed packets. */
#define ZMARKET_ROUTER_MAX_HOPS 6u

/* Route entry represents a known record we may relay. */
struct zmarket_route_entry {
    uint8_t id[ZMARKET_ID_LEN];
    enum zmarket_record_type type;
    uint64_t expires_unix;
    uint64_t first_seen_unix;
    uint64_t last_seen_unix;
    uint32_t hop_count;     /* hops taken to reach us */
    uint32_t relay_count;   /* times we relayed this */
    uint8_t  source_peer;   /* index into peer table, 0xff = local */
    uint8_t  state;         /* 0=empty, 1=active, 2=expired */
};

/* Peer tracking for routing decisions. */
#define ZMARKET_ROUTER_PEER_ID_MAX 64u

struct zmarket_router_peer {
    char id[ZMARKET_ROUTER_PEER_ID_MAX];
    size_t id_len;
    uint64_t last_inv_unix;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint32_t inv_sent;
    uint32_t inv_recv;
    uint32_t rejects;
    bool tor_peer;          /* true if this peer is an onion/Tor peer */
    uint8_t state;          /* 0=empty, 1=active */
};

/* Routing decision codes. */
enum zmarket_route_decision {
    ZMARKET_ROUTE_ACCEPT = 0,
    ZMARKET_ROUTE_REJECT_POLICY,
    ZMARKET_ROUTE_REJECT_EXPIRED,
    ZMARKET_ROUTE_REJECT_DUPLICATE,
    ZMARKET_ROUTE_REJECT_HOPS,
    ZMARKET_ROUTE_REJECT_CAP,
    ZMARKET_ROUTE_REJECT_NOT_FOUND,
    ZMARKET_ROUTE_REJECT_NULL
};

/* Fanout result: which peers should receive this record. */
struct zmarket_route_fanout {
    size_t peer_indices[16]; /* indices into peer table */
    size_t count;
};

/* Router engine. Caller provides all backing memory. */
struct zmarket_router {
    struct zmarket_route_entry *entries;
    size_t entry_capacity;
    size_t entry_count;

    struct zmarket_router_peer *peers;
    size_t peer_capacity;
    size_t peer_count;

    /* Dedup index for fast lookup. */
    struct zmarket_index *dedup;

    /* Policy reference (not owned). */
    const struct zmarket_policy *policy;

    /* Tor routing mode: 0=off, 1=prefer, 2=only. */
    uint8_t tor_mode;
};

/* Lifecycle. */
void zmarket_router_init(struct zmarket_router *rt,
                         struct zmarket_route_entry *entries,
                         size_t entry_capacity,
                         struct zmarket_router_peer *peers,
                         size_t peer_capacity,
                         struct zmarket_index *dedup,
                         const struct zmarket_policy *policy);
void zmarket_router_clear(struct zmarket_router *rt);

/* Set Tor routing mode: 0=off (clearnet ok), 1=prefer, 2=only. */
void zmarket_router_set_tor_mode(struct zmarket_router *rt, uint8_t mode);

/* Register a peer. */
enum zmarket_route_decision zmarket_router_add_peer(
    struct zmarket_router *rt,
    const char *peer_id,
    size_t peer_id_len,
    bool tor_peer);

/* Remove a peer. */
bool zmarket_router_remove_peer(struct zmarket_router *rt,
                                const char *peer_id,
                                size_t peer_id_len);

/* Admit a record into the routing table. Checks policy, TTL, dedup,
 * hop count, and capacity. Records that fail admission are not relayed. */
enum zmarket_route_decision zmarket_router_admit(
    struct zmarket_router *rt,
    const uint8_t id[ZMARKET_ID_LEN],
    enum zmarket_record_type type,
    uint64_t expires_unix,
    uint32_t hop_count,
    const char *source_peer_id,
    size_t source_peer_id_len,
    uint64_t now_unix);

/* Compute fanout: which peers should receive this record?
 * Excludes the source peer. Respects max_route_fanout cap.
 * In Tor-only mode, excludes clearnet peers. */
struct zmarket_route_fanout zmarket_router_fanout(
    struct zmarket_router *rt,
    const uint8_t id[ZMARKET_ID_LEN],
    const char *exclude_peer_id,
    size_t exclude_peer_id_len,
    uint64_t now_unix);

/* Check if we should relay a record to a specific peer.
 * Considers policy, dedup, peer rate limits, and Tor mode. */
bool zmarket_router_should_relay(
    const struct zmarket_router *rt,
    const uint8_t id[ZMARKET_ID_LEN],
    const char *peer_id,
    size_t peer_id_len,
    uint64_t now_unix);

/* Record that we relayed a record to a peer. */
void zmarket_router_relay_done(struct zmarket_router *rt,
                               const uint8_t id[ZMARKET_ID_LEN],
                               const char *peer_id,
                               size_t peer_id_len,
                               size_t bytes);

/* Decrement hop count and check if still routable. */
bool zmarket_router_decrement_hops(struct zmarket_router *rt,
                                   const uint8_t id[ZMARKET_ID_LEN]);

/* Prune expired entries. Returns count pruned. */
size_t zmarket_router_prune(struct zmarket_router *rt, uint64_t now_unix);

/* Check if a record is in the routing table. */
bool zmarket_router_has(const struct zmarket_router *rt,
                        const uint8_t id[ZMARKET_ID_LEN]);

/* Query helpers. */
size_t zmarket_router_entry_count(const struct zmarket_router *rt);
size_t zmarket_router_peer_count(const struct zmarket_router *rt);

/* Get peer stats. */
const struct zmarket_router_peer *zmarket_router_get_peer(
    const struct zmarket_router *rt,
    const char *peer_id,
    size_t peer_id_len);

/* Decision string. */
const char *zmarket_route_decision_string(enum zmarket_route_decision d);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZCLASSIC_ZMARKET_ROUTER_H */
