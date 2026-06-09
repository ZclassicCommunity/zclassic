// Copyright 2026 Rhett Creighton - Apache License 2.0

#include "zmarket/zmarket_spider.h"

#include <string.h>

/* Internal peer states. */
#define SPIDER_PEER_EMPTY  0u
#define SPIDER_PEER_ACTIVE 1u
#define SPIDER_PEER_BACKOFF 2u

/* Internal fetch states. */
#define SPIDER_FETCH_EMPTY    0u
#define SPIDER_FETCH_PENDING  1u
#define SPIDER_FETCH_INFLIGHT 2u
#define SPIDER_FETCH_DONE     3u
#define SPIDER_FETCH_FAILED   4u

/* Backoff parameters: first failure = 2s, doubles each time, max 300s. */
#define SPIDER_BACKOFF_BASE_SEC  2u
#define SPIDER_BACKOFF_MAX_SEC   300u

static uint64_t zmarket_spider_compute_backoff(uint32_t failures)
{
    uint64_t backoff = SPIDER_BACKOFF_BASE_SEC;
    uint32_t i;
    for (i = 1; i < failures && backoff < SPIDER_BACKOFF_MAX_SEC; i++) {
        backoff *= 2u;
    }
    if (backoff > SPIDER_BACKOFF_MAX_SEC)
        backoff = SPIDER_BACKOFF_MAX_SEC;
    return backoff;
}

void zmarket_spider_init(struct zmarket_spider *sp,
                         struct zmarket_spider_peer *peers,
                         size_t peer_capacity,
                         struct zmarket_spider_fetch *queue,
                         size_t queue_capacity,
                         struct zmarket_index *seen,
                         const struct zmarket_policy *policy)
{
    if (!sp) return;
    memset(sp, 0, sizeof(*sp));
    sp->peers = peers;
    sp->peer_capacity = peers ? peer_capacity : 0;
    sp->queue = queue;
    sp->queue_capacity = queue ? queue_capacity : 0;
    sp->seen = seen;
    sp->policy = policy;
    if (peers && peer_capacity)
        memset(peers, 0, peer_capacity * sizeof(peers[0]));
    if (queue && queue_capacity)
        memset(queue, 0, queue_capacity * sizeof(queue[0]));
}

void zmarket_spider_clear(struct zmarket_spider *sp)
{
    if (!sp) return;
    if (sp->peers && sp->peer_capacity)
        memset(sp->peers, 0, sp->peer_capacity * sizeof(sp->peers[0]));
    if (sp->queue && sp->queue_capacity)
        memset(sp->queue, 0, sp->queue_capacity * sizeof(sp->queue[0]));
    sp->peer_count = 0;
    sp->queue_count = 0;
    sp->queue_head = 0;
}

static struct zmarket_spider_peer *zmarket_spider_find_peer(
    struct zmarket_spider *sp,
    const char *peer_id,
    size_t peer_id_len)
{
    size_t i;
    if (!sp || !sp->peers || !peer_id || peer_id_len == 0 ||
        peer_id_len >= ZMARKET_SPIDER_PEER_ID_MAX)
        return NULL;
    for (i = 0; i < sp->peer_capacity; i++) {
        if (sp->peers[i].state == SPIDER_PEER_EMPTY) continue;
        if (sp->peers[i].id_len == peer_id_len &&
            memcmp(sp->peers[i].id, peer_id, peer_id_len) == 0)
            return &sp->peers[i];
    }
    return NULL;
}

static struct zmarket_spider_peer *zmarket_spider_find_empty_peer_slot(
    struct zmarket_spider *sp)
{
    size_t i;
    if (!sp || !sp->peers) return NULL;
    for (i = 0; i < sp->peer_capacity; i++) {
        if (sp->peers[i].state == SPIDER_PEER_EMPTY)
            return &sp->peers[i];
    }
    return NULL;
}

static void zmarket_spider_refill_peer(struct zmarket_spider_peer *peer,
                                       uint64_t now_unix)
{
    uint64_t elapsed;
    uint64_t add;
    if (!peer || peer->state == SPIDER_PEER_EMPTY) return;
    if (now_unix <= peer->last_refill_unix) return;
    elapsed = now_unix - peer->last_refill_unix;
    add = elapsed * peer->refill_per_sec;
    peer->tokens += add;
    if (peer->tokens > peer->max_tokens)
        peer->tokens = peer->max_tokens;
    peer->last_refill_unix = now_unix;
}

enum zmarket_spider_error zmarket_spider_add_peer(
    struct zmarket_spider *sp,
    const char *peer_id,
    size_t peer_id_len,
    uint64_t max_tokens,
    uint64_t refill_per_sec,
    uint64_t now_unix)
{
    struct zmarket_spider_peer *slot;

    if (!sp || !sp->peers || !peer_id)
        return ZMARKET_SPIDER_ERR_NULL;
    if (peer_id_len == 0 || peer_id_len >= ZMARKET_SPIDER_PEER_ID_MAX)
        return ZMARKET_SPIDER_ERR_CAP;

    /* Already exists? */
    if (zmarket_spider_find_peer(sp, peer_id, peer_id_len))
        return ZMARKET_SPIDER_OK;

    slot = zmarket_spider_find_empty_peer_slot(sp);
    if (!slot)
        return ZMARKET_SPIDER_ERR_PEER_FULL;

    memset(slot, 0, sizeof(*slot));
    memcpy(slot->id, peer_id, peer_id_len);
    slot->id_len = peer_id_len;
    slot->tokens = max_tokens;
    slot->max_tokens = max_tokens;
    slot->refill_per_sec = refill_per_sec;
    slot->last_refill_unix = now_unix;
    slot->state = SPIDER_PEER_ACTIVE;
    sp->peer_count++;
    return ZMARKET_SPIDER_OK;
}

bool zmarket_spider_remove_peer(struct zmarket_spider *sp,
                                const char *peer_id,
                                size_t peer_id_len)
{
    struct zmarket_spider_peer *peer =
        zmarket_spider_find_peer(sp, peer_id, peer_id_len);
    if (!peer) return false;
    memset(peer, 0, sizeof(*peer));
    if (sp->peer_count > 0)
        sp->peer_count--;
    return true;
}

enum zmarket_spider_error zmarket_spider_on_inv(
    struct zmarket_spider *sp,
    const char *peer_id,
    size_t peer_id_len,
    const uint8_t *ids,
    size_t id_count,
    const enum zmarket_record_type *types,
    const uint64_t *expires,
    uint64_t now_unix)
{
    struct zmarket_spider_peer *peer;
    size_t peer_index;
    size_t i;
    size_t max_queue;

    if (!sp || !sp->queue || !ids || !sp->seen)
        return ZMARKET_SPIDER_ERR_NULL;

    /* Check policy allows spidering. */
    if (sp->policy && !zmarket_policy_can_spider_records(sp->policy))
        return ZMARKET_SPIDER_ERR_POLICY;

    peer = zmarket_spider_find_peer(sp, peer_id, peer_id_len);
    if (!peer)
        return ZMARKET_SPIDER_ERR_NOT_FOUND;
    peer_index = (size_t)(peer - sp->peers);

    /* Check if peer is in backoff. */
    if (peer->state == SPIDER_PEER_BACKOFF &&
        now_unix < peer->backoff_until_unix)
        return ZMARKET_SPIDER_ERR_BACKOFF;

    /* Clear backoff if expired. */
    if (peer->state == SPIDER_PEER_BACKOFF &&
        now_unix >= peer->backoff_until_unix)
        peer->state = SPIDER_PEER_ACTIVE;

    /* Refill token bucket. */
    zmarket_spider_refill_peer(peer, now_unix);

    /* Check per-inv cap from policy. */
    max_queue = sp->policy ? sp->policy->caps.max_inventory_ids : 1000;
    if (id_count > max_queue)
        id_count = max_queue;

    for (i = 0; i < id_count; i++) {
        const uint8_t *id = ids + i * ZMARKET_ID_LEN;
        enum zmarket_record_type typ = types ? types[i] :
                                       ZMARKET_RECORD_LISTING;
        uint64_t exp = expires ? expires[i] : UINT64_MAX;

        /* Skip if already expired. */
        if (exp <= now_unix)
            continue;

        /* Skip if already seen/indexed. */
        if (zmarket_index_has(sp->seen, id))
            continue;

        /* Skip if already in queue. */
        {
            size_t j;
            bool in_queue = false;
            for (j = 0; j < sp->queue_capacity && !in_queue; j++) {
                if (sp->queue[j].state == SPIDER_FETCH_PENDING ||
                    sp->queue[j].state == SPIDER_FETCH_INFLIGHT) {
                    if (memcmp(sp->queue[j].id, id, ZMARKET_ID_LEN) == 0)
                        in_queue = true;
                }
            }
            if (in_queue) continue;
        }

        /* Check token budget. */
        if (peer->tokens < 1)
            break;
        peer->tokens--;

        /* Find a queue slot. */
        {
            size_t slot_idx;
            bool found = false;
            for (slot_idx = 0; slot_idx < sp->queue_capacity; slot_idx++) {
                if (sp->queue[slot_idx].state == SPIDER_FETCH_DONE ||
                    sp->queue[slot_idx].state == SPIDER_FETCH_FAILED ||
                    sp->queue[slot_idx].state == SPIDER_FETCH_EMPTY) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                /* Queue is full; stop enqueuing. */
                peer->total_rejected += (id_count - i);
                return ZMARKET_SPIDER_ERR_QUEUE_FULL;
            }

            /* Enqueue. */
            memcpy(sp->queue[slot_idx].id, id, ZMARKET_ID_LEN);
            sp->queue[slot_idx].type = typ;
            sp->queue[slot_idx].expires_unix = exp;
            sp->queue[slot_idx].peer_index = peer_index;
            sp->queue[slot_idx].priority = 0;
            sp->queue[slot_idx].state = SPIDER_FETCH_PENDING;
            sp->queue_count++;
        }
    }

    /* Check global queue cap from policy. */
    {
        size_t max_q = sp->policy ? sp->policy->caps.max_spider_queue : 4096;
        if (sp->queue_count > max_q)
            return ZMARKET_SPIDER_ERR_QUEUE_FULL;
    }

    return ZMARKET_SPIDER_OK;
}

enum zmarket_spider_error zmarket_spider_next_batch(
    struct zmarket_spider *sp,
    const char *peer_id,
    size_t peer_id_len,
    uint8_t *out_ids,
    size_t max_out,
    size_t *out_count,
    uint64_t now_unix)
{
    struct zmarket_spider_peer *peer;
    size_t selected = 0;
    size_t i;

    if (!sp || !sp->queue || !out_ids || !out_count)
        return ZMARKET_SPIDER_ERR_NULL;

    *out_count = 0;

    peer = zmarket_spider_find_peer(sp, peer_id, peer_id_len);
    if (!peer)
        return ZMARKET_SPIDER_ERR_NOT_FOUND;

    /* Check backoff. */
    if (peer->state == SPIDER_PEER_BACKOFF &&
        now_unix < peer->backoff_until_unix)
        return ZMARKET_SPIDER_ERR_BACKOFF;

    if (peer->state == SPIDER_PEER_BACKOFF &&
        now_unix >= peer->backoff_until_unix)
        peer->state = SPIDER_PEER_ACTIVE;

    zmarket_spider_refill_peer(peer, now_unix);

    /* Select pending items, prioritized by earliest expiry. */
    for (i = 0; i < sp->queue_capacity && selected < max_out; i++) {
        struct zmarket_spider_fetch *f = &sp->queue[i];
        if (f->state != SPIDER_FETCH_PENDING) continue;
        if (f->expires_unix <= now_unix) {
            /* Already expired; mark done. */
            f->state = SPIDER_FETCH_DONE;
            if (sp->queue_count > 0) sp->queue_count--;
            continue;
        }
        if (peer->tokens < 1) break;
        peer->tokens--;

        memcpy(out_ids + selected * ZMARKET_ID_LEN, f->id, ZMARKET_ID_LEN);
        f->state = SPIDER_FETCH_INFLIGHT;
        selected++;
    }

    *out_count = selected;
    peer->total_fetched += selected;
    return selected > 0 ? ZMARKET_SPIDER_OK : ZMARKET_SPIDER_ERR_NOT_FOUND;
}

void zmarket_spider_fetch_done(struct zmarket_spider *sp,
                               const uint8_t id[ZMARKET_ID_LEN],
                               bool success,
                               uint64_t now_unix)
{
    size_t i;
    if (!sp || !sp->queue) return;
    (void)now_unix;

    for (i = 0; i < sp->queue_capacity; i++) {
        struct zmarket_spider_fetch *f = &sp->queue[i];
        if (f->state != SPIDER_FETCH_PENDING &&
            f->state != SPIDER_FETCH_INFLIGHT)
            continue;
        if (memcmp(f->id, id, ZMARKET_ID_LEN) != 0) continue;

        if (success) {
            f->state = SPIDER_FETCH_DONE;
            /* Add to seen index so we don't re-fetch. */
            if (sp->seen)
                zmarket_index_put(sp->seen, id, f->type, f->expires_unix);
            if (f->peer_index < sp->peer_capacity)
                sp->peers[f->peer_index].consecutive_failures = 0;
        } else {
            if (f->peer_index < sp->peer_capacity) {
                struct zmarket_spider_peer *peer = &sp->peers[f->peer_index];
                if (peer->state != SPIDER_PEER_EMPTY &&
                    peer->consecutive_failures != UINT32_MAX) {
                    peer->consecutive_failures++;
                    if (peer->consecutive_failures >= 10) {
                        peer->state = SPIDER_PEER_BACKOFF;
                        peer->backoff_until_unix = now_unix +
                            zmarket_spider_compute_backoff(
                                peer->consecutive_failures);
                    }
                }
            }
            f->state = SPIDER_FETCH_FAILED;
        }
        if (sp->queue_count > 0) sp->queue_count--;
        return;
    }
}

void zmarket_spider_refill(struct zmarket_spider *sp, uint64_t now_unix)
{
    size_t i;
    if (!sp || !sp->peers) return;
    for (i = 0; i < sp->peer_capacity; i++) {
        if (sp->peers[i].state == SPIDER_PEER_EMPTY) continue;
        zmarket_spider_refill_peer(&sp->peers[i], now_unix);
        /* Clear expired backoffs. */
        if (sp->peers[i].state == SPIDER_PEER_BACKOFF &&
            now_unix >= sp->peers[i].backoff_until_unix)
            sp->peers[i].state = SPIDER_PEER_ACTIVE;
    }
}

size_t zmarket_spider_prune(struct zmarket_spider *sp, uint64_t now_unix)
{
    size_t pruned = 0;
    size_t i;

    if (!sp) return 0;

    /* Prune expired fetch queue items. */
    if (sp->queue) {
        for (i = 0; i < sp->queue_capacity; i++) {
            struct zmarket_spider_fetch *f = &sp->queue[i];
            if (f->state == SPIDER_FETCH_EMPTY) continue;
            if (f->state == SPIDER_FETCH_DONE ||
                f->state == SPIDER_FETCH_FAILED)
                continue;
            if (f->expires_unix <= now_unix) {
                memset(f, 0, sizeof(*f));
                pruned++;
                if (sp->queue_count > 0) sp->queue_count--;
            }
        }
    }

    /* Prune peers that have been in extended backoff (dead). */
    if (sp->peers) {
        for (i = 0; i < sp->peer_capacity; i++) {
            struct zmarket_spider_peer *p = &sp->peers[i];
            if (p->state != SPIDER_PEER_ACTIVE) continue;
            if (p->consecutive_failures >= 10) {
                p->state = SPIDER_PEER_BACKOFF;
                p->backoff_until_unix = now_unix +
                    zmarket_spider_compute_backoff(p->consecutive_failures);
            }
        }
    }

    return pruned;
}

size_t zmarket_spider_peer_count(const struct zmarket_spider *sp)
{
    return sp ? sp->peer_count : 0;
}

size_t zmarket_spider_queue_depth(const struct zmarket_spider *sp)
{
    return sp ? sp->queue_count : 0;
}

size_t zmarket_spider_pending_count(const struct zmarket_spider *sp)
{
    size_t count = 0;
    size_t i;
    if (!sp || !sp->queue) return 0;
    for (i = 0; i < sp->queue_capacity; i++) {
        if (sp->queue[i].state == SPIDER_FETCH_PENDING ||
            sp->queue[i].state == SPIDER_FETCH_INFLIGHT)
            count++;
    }
    return count;
}

bool zmarket_spider_peer_in_backoff(const struct zmarket_spider *sp,
                                    const char *peer_id,
                                    size_t peer_id_len,
                                    uint64_t now_unix)
{
    const struct zmarket_spider_peer *peer =
        zmarket_spider_find_peer((struct zmarket_spider *)sp,
                                 peer_id, peer_id_len);
    if (!peer) return false;
    if (peer->state != SPIDER_PEER_BACKOFF) return false;
    return now_unix < peer->backoff_until_unix;
}

const struct zmarket_spider_peer *zmarket_spider_get_peer(
    const struct zmarket_spider *sp,
    const char *peer_id,
    size_t peer_id_len)
{
    return zmarket_spider_find_peer((struct zmarket_spider *)sp,
                                    peer_id, peer_id_len);
}

const char *zmarket_spider_error_string(enum zmarket_spider_error err)
{
    switch (err) {
    case ZMARKET_SPIDER_OK:           return "ok";
    case ZMARKET_SPIDER_ERR_NULL:     return "null argument";
    case ZMARKET_SPIDER_ERR_CAP:      return "capacity exceeded";
    case ZMARKET_SPIDER_ERR_PEER_FULL:return "peer table full";
    case ZMARKET_SPIDER_ERR_QUEUE_FULL:return "fetch queue full";
    case ZMARKET_SPIDER_ERR_NOT_FOUND:return "not found";
    case ZMARKET_SPIDER_ERR_BACKOFF:  return "peer in backoff";
    case ZMARKET_SPIDER_ERR_POLICY:   return "policy denied";
    case ZMARKET_SPIDER_ERR_DUPLICATE:return "duplicate";
    case ZMARKET_SPIDER_ERR_EXPIRED:  return "expired";
    default:                          return "unknown spider error";
    }
}
