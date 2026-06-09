// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Bounded ZMARKET spider queue. C hot-path for scheduling peer inventory
// fetches, deduplicating seen ids, per-peer token-bucket rate limiting,
// exponential backoff on failures, reject accounting, and batch selection.
//
// The spider discovers signed record IDs from peers, onion feeds, ZNAM
// endpoints, and operator-added seeds. It never fetches file bytes.
// Spidering stores small signed envelopes only; it does not host content.

#ifndef ZCLASSIC_ZMARKET_SPIDER_H
#define ZCLASSIC_ZMARKET_SPIDER_H

#include "zmarket/zmarket_index.h"
#include "zmarket/zmarket_policy.h"
#include "zmarket/zmarket_record.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Spider peer state. Caller owns the array and passes it at init. */
#define ZMARKET_SPIDER_PEER_ID_MAX 64u

struct zmarket_spider_peer {
    char id[ZMARKET_SPIDER_PEER_ID_MAX];
    size_t id_len;
    /* Token-bucket rate limiter. */
    uint64_t tokens;
    uint64_t max_tokens;
    uint64_t refill_per_sec;
    uint64_t last_refill_unix;
    /* Exponential backoff. */
    uint64_t backoff_until_unix;
    uint32_t consecutive_failures;
    /* Accounting. */
    uint64_t total_fetched;
    uint64_t total_rejected;
    uint64_t total_bytes;
    /* Queue of pending inventory IDs to fetch from this peer. */
    size_t pending_count;
    size_t pending_head;
    uint8_t state; /* 0=empty, 1=active, 2=backoff, 3=dead */
};

/* Pending fetch item: a record ID we want to GET from the peer. */
struct zmarket_spider_fetch {
    uint8_t id[ZMARKET_ID_LEN];
    enum zmarket_record_type type;
    uint64_t expires_unix;
    size_t peer_index;
    uint8_t priority; /* 0=normal, higher=sooner */
    uint8_t state;    /* 0=empty, 1=pending, 2=in-flight, 3=done, 4=failed */
};

/* Spider result codes. */
enum zmarket_spider_error {
    ZMARKET_SPIDER_OK = 0,
    ZMARKET_SPIDER_ERR_NULL,
    ZMARKET_SPIDER_ERR_CAP,
    ZMARKET_SPIDER_ERR_PEER_FULL,
    ZMARKET_SPIDER_ERR_QUEUE_FULL,
    ZMARKET_SPIDER_ERR_NOT_FOUND,
    ZMARKET_SPIDER_ERR_BACKOFF,
    ZMARKET_SPIDER_ERR_POLICY,
    ZMARKET_SPIDER_ERR_DUPLICATE,
    ZMARKET_SPIDER_ERR_EXPIRED
};

/* Spider engine. Caller provides all backing memory. */
struct zmarket_spider {
    struct zmarket_spider_peer *peers;
    size_t peer_capacity;
    size_t peer_count;

    /* Global fetch queue (ring buffer of pending items across all peers). */
    struct zmarket_spider_fetch *queue;
    size_t queue_capacity;
    size_t queue_count;
    size_t queue_head;

    /* Dedup index to avoid fetching already-known IDs. */
    struct zmarket_index *seen;

    /* Policy reference (not owned). */
    const struct zmarket_policy *policy;
};

/* Lifecycle. */
void zmarket_spider_init(struct zmarket_spider *sp,
                         struct zmarket_spider_peer *peers,
                         size_t peer_capacity,
                         struct zmarket_spider_fetch *queue,
                         size_t queue_capacity,
                         struct zmarket_index *seen,
                         const struct zmarket_policy *policy);
void zmarket_spider_clear(struct zmarket_spider *sp);

/* Register a peer. Returns ZMARKET_SPIDER_OK or error. */
enum zmarket_spider_error zmarket_spider_add_peer(
    struct zmarket_spider *sp,
    const char *peer_id,
    size_t peer_id_len,
    uint64_t max_tokens,
    uint64_t refill_per_sec,
    uint64_t now_unix);

/* Remove a peer by id. */
bool zmarket_spider_remove_peer(struct zmarket_spider *sp,
                                const char *peer_id,
                                size_t peer_id_len);

/* Feed inventory items from a peer into the fetch queue. Deduplicates against
 * the seen index. Respects per-peer token bucket and global queue cap. */
enum zmarket_spider_error zmarket_spider_on_inv(
    struct zmarket_spider *sp,
    const char *peer_id,
    size_t peer_id_len,
    const uint8_t *ids,
    size_t id_count,
    const enum zmarket_record_type *types,
    const uint64_t *expires,
    uint64_t now_unix);

/* Select the next batch of IDs to fetch from a specific peer.
 * Returns up to max_out IDs in out_ids. Sets out_count to actual count. */
enum zmarket_spider_error zmarket_spider_next_batch(
    struct zmarket_spider *sp,
    const char *peer_id,
    size_t peer_id_len,
    uint8_t *out_ids,       /* max_out * ZMARKET_ID_LEN bytes */
    size_t max_out,
    size_t *out_count,
    uint64_t now_unix);

/* Mark a fetch as completed (success or failure). */
void zmarket_spider_fetch_done(struct zmarket_spider *sp,
                               const uint8_t id[ZMARKET_ID_LEN],
                               bool success,
                               uint64_t now_unix);

/* Refill peer token buckets based on elapsed time. Call periodically. */
void zmarket_spider_refill(struct zmarket_spider *sp, uint64_t now_unix);

/* Prune expired items from the fetch queue and seen index. */
size_t zmarket_spider_prune(struct zmarket_spider *sp, uint64_t now_unix);

/* Query helpers. */
size_t zmarket_spider_peer_count(const struct zmarket_spider *sp);
size_t zmarket_spider_queue_depth(const struct zmarket_spider *sp);
size_t zmarket_spider_pending_count(const struct zmarket_spider *sp);

/* Check if a peer is in backoff. */
bool zmarket_spider_peer_in_backoff(const struct zmarket_spider *sp,
                                    const char *peer_id,
                                    size_t peer_id_len,
                                    uint64_t now_unix);

/* Get peer stats. Returns NULL if not found. */
const struct zmarket_spider_peer *zmarket_spider_get_peer(
    const struct zmarket_spider *sp,
    const char *peer_id,
    size_t peer_id_len);

/* Error string. */
const char *zmarket_spider_error_string(enum zmarket_spider_error err);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZCLASSIC_ZMARKET_SPIDER_H */
