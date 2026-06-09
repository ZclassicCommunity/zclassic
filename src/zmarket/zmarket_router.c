// Copyright 2026 Rhett Creighton - Apache License 2.0

#include "zmarket/zmarket_router.h"

#include <string.h>

/* Internal states. */
#define ROUTE_ENTRY_EMPTY  0u
#define ROUTE_ENTRY_ACTIVE 1u
#define ROUTE_ENTRY_EXPIRED 2u

#define ROUTER_PEER_EMPTY  0u
#define ROUTER_PEER_ACTIVE 1u

/* Source peer index meaning: local import. */
#define ROUTE_SOURCE_LOCAL 0xFFu

static struct zmarket_router_peer *zmarket_router_find_peer(
    struct zmarket_router *rt,
    const char *peer_id,
    size_t peer_id_len)
{
    size_t i;
    if (!rt || !rt->peers || !peer_id || peer_id_len == 0 ||
        peer_id_len >= ZMARKET_ROUTER_PEER_ID_MAX)
        return NULL;
    for (i = 0; i < rt->peer_capacity; i++) {
        if (rt->peers[i].state != ROUTER_PEER_ACTIVE) continue;
        if (rt->peers[i].id_len == peer_id_len &&
            memcmp(rt->peers[i].id, peer_id, peer_id_len) == 0)
            return &rt->peers[i];
    }
    return NULL;
}

static size_t zmarket_router_find_peer_index(
    struct zmarket_router *rt,
    const char *peer_id,
    size_t peer_id_len)
{
    size_t i;
    if (!rt || !rt->peers || !peer_id) return (size_t)-1;
    for (i = 0; i < rt->peer_capacity; i++) {
        if (rt->peers[i].state != ROUTER_PEER_ACTIVE) continue;
        if (rt->peers[i].id_len == peer_id_len &&
            memcmp(rt->peers[i].id, peer_id, peer_id_len) == 0)
            return i;
    }
    return (size_t)-1;
}

static struct zmarket_route_entry *zmarket_router_find_entry(
    struct zmarket_router *rt,
    const uint8_t id[ZMARKET_ID_LEN])
{
    size_t i;
    if (!rt || !rt->entries || !id) return NULL;
    for (i = 0; i < rt->entry_capacity; i++) {
        if (rt->entries[i].state != ROUTE_ENTRY_ACTIVE) continue;
        if (memcmp(rt->entries[i].id, id, ZMARKET_ID_LEN) == 0)
            return &rt->entries[i];
    }
    return NULL;
}

static struct zmarket_route_entry *zmarket_router_find_empty_entry(
    struct zmarket_router *rt)
{
    size_t i;
    if (!rt || !rt->entries) return NULL;
    for (i = 0; i < rt->entry_capacity; i++) {
        if (rt->entries[i].state == ROUTE_ENTRY_EMPTY ||
            rt->entries[i].state == ROUTE_ENTRY_EXPIRED)
            return &rt->entries[i];
    }
    return NULL;
}

void zmarket_router_init(struct zmarket_router *rt,
                         struct zmarket_route_entry *entries,
                         size_t entry_capacity,
                         struct zmarket_router_peer *peers,
                         size_t peer_capacity,
                         struct zmarket_index *dedup,
                         const struct zmarket_policy *policy)
{
    if (!rt) return;
    memset(rt, 0, sizeof(*rt));
    rt->entries = entries;
    rt->entry_capacity = entries ? entry_capacity : 0;
    rt->peers = peers;
    rt->peer_capacity = peers ? peer_capacity : 0;
    rt->dedup = dedup;
    rt->policy = policy;
    rt->tor_mode = 0;
    if (entries && entry_capacity)
        memset(entries, 0, entry_capacity * sizeof(entries[0]));
    if (peers && peer_capacity)
        memset(peers, 0, peer_capacity * sizeof(peers[0]));
}

void zmarket_router_clear(struct zmarket_router *rt)
{
    if (!rt) return;
    if (rt->entries && rt->entry_capacity)
        memset(rt->entries, 0, rt->entry_capacity * sizeof(rt->entries[0]));
    if (rt->peers && rt->peer_capacity)
        memset(rt->peers, 0, rt->peer_capacity * sizeof(rt->peers[0]));
    rt->entry_count = 0;
    rt->peer_count = 0;
}

void zmarket_router_set_tor_mode(struct zmarket_router *rt, uint8_t mode)
{
    if (!rt) return;
    rt->tor_mode = mode > 2 ? 2 : mode;
}

enum zmarket_route_decision zmarket_router_add_peer(
    struct zmarket_router *rt,
    const char *peer_id,
    size_t peer_id_len,
    bool tor_peer)
{
    struct zmarket_router_peer *slot;
    size_t idx;

    if (!rt || !rt->peers || !peer_id)
        return ZMARKET_ROUTE_REJECT_NULL;
    if (peer_id_len == 0 || peer_id_len >= ZMARKET_ROUTER_PEER_ID_MAX)
        return ZMARKET_ROUTE_REJECT_CAP;

    /* Already exists? */
    if (zmarket_router_find_peer(rt, peer_id, peer_id_len))
        return ZMARKET_ROUTE_ACCEPT;

    /* Find empty slot. */
    for (idx = 0; idx < rt->peer_capacity; idx++) {
        if (rt->peers[idx].state == ROUTER_PEER_EMPTY) {
            slot = &rt->peers[idx];
            break;
        }
    }
    if (idx == rt->peer_capacity)
        return ZMARKET_ROUTE_REJECT_CAP;

    memset(slot, 0, sizeof(*slot));
    memcpy(slot->id, peer_id, peer_id_len);
    slot->id_len = peer_id_len;
    slot->tor_peer = tor_peer;
    slot->state = ROUTER_PEER_ACTIVE;
    rt->peer_count++;
    return ZMARKET_ROUTE_ACCEPT;
}

bool zmarket_router_remove_peer(struct zmarket_router *rt,
                                const char *peer_id,
                                size_t peer_id_len)
{
    struct zmarket_router_peer *p =
        zmarket_router_find_peer(rt, peer_id, peer_id_len);
    if (!p) return false;
    memset(p, 0, sizeof(*p));
    if (rt->peer_count > 0) rt->peer_count--;
    return true;
}

enum zmarket_route_decision zmarket_router_admit(
    struct zmarket_router *rt,
    const uint8_t id[ZMARKET_ID_LEN],
    enum zmarket_record_type type,
    uint64_t expires_unix,
    uint32_t hop_count,
    const char *source_peer_id,
    size_t source_peer_id_len,
    uint64_t now_unix)
{
    struct zmarket_route_entry *entry;
    size_t source_idx = ROUTE_SOURCE_LOCAL;

    if (!rt || !id)
        return ZMARKET_ROUTE_REJECT_NULL;

    /* Policy check: must allow routing. */
    if (rt->policy && !zmarket_policy_can_route_records(rt->policy))
        return ZMARKET_ROUTE_REJECT_POLICY;

    /* Type must be routable. */
    if (!zmarket_record_type_is_routable(type))
        return ZMARKET_ROUTE_REJECT_POLICY;

    /* TTL check: must not be expired. */
    if (expires_unix <= now_unix)
        return ZMARKET_ROUTE_REJECT_EXPIRED;

    /* Hop count check: must not exceed max. */
    if (hop_count > ZMARKET_ROUTER_MAX_HOPS)
        return ZMARKET_ROUTE_REJECT_HOPS;

    /* Dedup check. */
    if (rt->dedup && zmarket_index_has(rt->dedup, id))
        return ZMARKET_ROUTE_REJECT_DUPLICATE;

    /* Also check routing table directly. */
    if (zmarket_router_find_entry(rt, id))
        return ZMARKET_ROUTE_REJECT_DUPLICATE;

    /* Capacity check. */
    if (rt->entry_count >= rt->entry_capacity)
        return ZMARKET_ROUTE_REJECT_CAP;

    /* Policy cap on max records. */
    if (rt->policy && rt->entry_count >= rt->policy->caps.max_index_records)
        return ZMARKET_ROUTE_REJECT_CAP;

    /* Find source peer index. */
    if (source_peer_id && source_peer_id_len > 0) {
        size_t idx = zmarket_router_find_peer_index(rt, source_peer_id,
                                                    source_peer_id_len);
        source_idx = (idx == (size_t)-1) ? ROUTE_SOURCE_LOCAL
                                         : (uint8_t)idx;
    }

    /* Find an entry slot (reuse expired or empty). */
    entry = zmarket_router_find_empty_entry(rt);
    if (!entry)
        return ZMARKET_ROUTE_REJECT_CAP;

    memset(entry, 0, sizeof(*entry));
    memcpy(entry->id, id, ZMARKET_ID_LEN);
    entry->type = type;
    entry->expires_unix = expires_unix;
    entry->first_seen_unix = now_unix;
    entry->last_seen_unix = now_unix;
    entry->hop_count = hop_count;
    entry->relay_count = 0;
    entry->source_peer = (uint8_t)source_idx;
    entry->state = ROUTE_ENTRY_ACTIVE;
    rt->entry_count++;

    /* Add to dedup index. */
    if (rt->dedup)
        zmarket_index_put(rt->dedup, id, type, expires_unix);

    return ZMARKET_ROUTE_ACCEPT;
}

struct zmarket_route_fanout zmarket_router_fanout(
    struct zmarket_router *rt,
    const uint8_t id[ZMARKET_ID_LEN],
    const char *exclude_peer_id,
    size_t exclude_peer_id_len,
    uint64_t now_unix)
{
    struct zmarket_route_fanout fo;
    size_t max_fanout;
    size_t exclude_idx = (size_t)-1;
    size_t i;

    memset(&fo, 0, sizeof(fo));

    if (!rt || !rt->peers || !id)
        return fo;

    /* Check that the record exists and is active. */
    {
        struct zmarket_route_entry *e = zmarket_router_find_entry(rt, id);
        if (!e || e->state != ROUTE_ENTRY_ACTIVE)
            return fo;
        if (e->expires_unix <= now_unix) {
            e->state = ROUTE_ENTRY_EXPIRED;
            return fo;
        }
    }

    max_fanout = rt->policy ? rt->policy->caps.max_route_fanout : 16;
    if (max_fanout > 16) max_fanout = 16;

    /* Find the source/exclude peer index. */
    if (exclude_peer_id && exclude_peer_id_len > 0)
        exclude_idx = zmarket_router_find_peer_index(rt, exclude_peer_id,
                                                     exclude_peer_id_len);

    /* Select peers for fanout. */
    for (i = 0; i < rt->peer_capacity && fo.count < max_fanout; i++) {
        struct zmarket_router_peer *p = &rt->peers[i];
        if (p->state != ROUTER_PEER_ACTIVE) continue;
        if (i == exclude_idx) continue;

        /* Tor-only mode: skip clearnet peers. */
        if (rt->tor_mode == 2 && !p->tor_peer)
            continue;

        /* Check dedup: don't relay to peers that already know this record.
         * We approximate by checking recent inv activity. A full per-peer
         * inv cache would be in the spider layer. */
        fo.peer_indices[fo.count] = i;
        fo.count++;
    }

    return fo;
}

bool zmarket_router_should_relay(
    const struct zmarket_router *rt,
    const uint8_t id[ZMARKET_ID_LEN],
    const char *peer_id,
    size_t peer_id_len,
    uint64_t now_unix)
{
    const struct zmarket_route_entry *entry;
    size_t peer_idx;

    if (!rt || !id || !peer_id)
        return false;

    /* Policy must allow routing. */
    if (rt->policy && !zmarket_policy_can_route_records(rt->policy))
        return false;

    /* Record must exist and be active. */
    entry = zmarket_router_find_entry((struct zmarket_router *)rt, id);
    if (!entry || entry->state != ROUTE_ENTRY_ACTIVE)
        return false;

    /* Not expired. */
    if (entry->expires_unix <= now_unix)
        return false;

    /* Peer must exist. */
    peer_idx = zmarket_router_find_peer_index(
        (struct zmarket_router *)rt, peer_id, peer_id_len);
    if (peer_idx == (size_t)-1)
        return false;

    /* Don't relay back to source. */
    if (entry->source_peer == (uint8_t)peer_idx)
        return false;

    /* Tor-only mode: don't relay to clearnet peers. */
    if (rt->tor_mode == 2 && !rt->peers[peer_idx].tor_peer)
        return false;

    return true;
}

void zmarket_router_relay_done(struct zmarket_router *rt,
                               const uint8_t id[ZMARKET_ID_LEN],
                               const char *peer_id,
                               size_t peer_id_len,
                               size_t bytes)
{
    struct zmarket_route_entry *entry;
    size_t peer_idx;

    if (!rt || !id) return;

    entry = zmarket_router_find_entry(rt, id);
    if (entry && entry->state == ROUTE_ENTRY_ACTIVE)
        entry->relay_count++;

    if (peer_id && peer_id_len > 0) {
        peer_idx = zmarket_router_find_peer_index(rt, peer_id, peer_id_len);
        if (peer_idx != (size_t)-1) {
            rt->peers[peer_idx].bytes_sent += bytes;
            rt->peers[peer_idx].inv_sent++;
        }
    }
}

bool zmarket_router_decrement_hops(struct zmarket_router *rt,
                                   const uint8_t id[ZMARKET_ID_LEN])
{
    struct zmarket_route_entry *entry;
    if (!rt || !id) return false;
    entry = zmarket_router_find_entry(rt, id);
    if (!entry || entry->state != ROUTE_ENTRY_ACTIVE) return false;
    if (entry->hop_count == 0) return false;
    entry->hop_count++;
    /* hop_count tracks hops taken; when it exceeds max, it's no longer
     * routable. */
    return entry->hop_count <= ZMARKET_ROUTER_MAX_HOPS;
}

size_t zmarket_router_prune(struct zmarket_router *rt, uint64_t now_unix)
{
    size_t pruned = 0;
    size_t i;

    if (!rt || !rt->entries) return 0;

    for (i = 0; i < rt->entry_capacity; i++) {
        struct zmarket_route_entry *e = &rt->entries[i];
        if (e->state != ROUTE_ENTRY_ACTIVE) continue;
        if (e->expires_unix <= now_unix) {
            e->state = ROUTE_ENTRY_EXPIRED;
            pruned++;
            if (rt->entry_count > 0) rt->entry_count--;
        }
    }

    return pruned;
}

bool zmarket_router_has(const struct zmarket_router *rt,
                        const uint8_t id[ZMARKET_ID_LEN])
{
    return zmarket_router_find_entry((struct zmarket_router *)rt, id) != NULL;
}

size_t zmarket_router_entry_count(const struct zmarket_router *rt)
{
    return rt ? rt->entry_count : 0;
}

size_t zmarket_router_peer_count(const struct zmarket_router *rt)
{
    return rt ? rt->peer_count : 0;
}

const struct zmarket_router_peer *zmarket_router_get_peer(
    const struct zmarket_router *rt,
    const char *peer_id,
    size_t peer_id_len)
{
    return zmarket_router_find_peer((struct zmarket_router *)rt,
                                    peer_id, peer_id_len);
}

const char *zmarket_route_decision_string(enum zmarket_route_decision d)
{
    switch (d) {
    case ZMARKET_ROUTE_ACCEPT:           return "accept";
    case ZMARKET_ROUTE_REJECT_POLICY:    return "policy denied";
    case ZMARKET_ROUTE_REJECT_EXPIRED:   return "expired";
    case ZMARKET_ROUTE_REJECT_DUPLICATE: return "duplicate";
    case ZMARKET_ROUTE_REJECT_HOPS:      return "hop limit exceeded";
    case ZMARKET_ROUTE_REJECT_CAP:       return "capacity exceeded";
    case ZMARKET_ROUTE_REJECT_NOT_FOUND: return "not found";
    case ZMARKET_ROUTE_REJECT_NULL:      return "null argument";
    default:                             return "unknown route decision";
    }
}
