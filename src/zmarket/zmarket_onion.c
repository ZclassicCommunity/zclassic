// Copyright 2026 Rhett Creighton - Apache License 2.0

#include "zmarket/zmarket_onion.h"

#include <string.h>

static bool zmarket_onion_base32_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
}

static bool zmarket_onion_scope_id_nonzero(
    const uint8_t scope_id[ZMARKET_ONION_SCOPE_ID_LEN])
{
    size_t i;
    if (!scope_id) return false;
    for (i = 0; i < ZMARKET_ONION_SCOPE_ID_LEN; i++) {
        if (scope_id[i] != 0)
            return true;
    }
    return false;
}

bool zmarket_onion_host_is_v3(const char *host, size_t host_len)
{
    size_t i;
    if (!host || host_len != ZMARKET_ONION_HOST_LEN)
        return false;
    for (i = 0; i < ZMARKET_ONION_SERVICE_ID_LEN; i++) {
        if (!zmarket_onion_base32_char(host[i]))
            return false;
    }
    return memcmp(host + ZMARKET_ONION_SERVICE_ID_LEN,
                  ZMARKET_ONION_SUFFIX,
                  sizeof(ZMARKET_ONION_SUFFIX) - 1u) == 0;
}

bool zmarket_onion_scope_valid(enum zmarket_onion_scope scope)
{
    return scope == ZMARKET_ONION_SCOPE_REUSABLE ||
           scope == ZMARKET_ONION_SCOPE_ASSET ||
           scope == ZMARKET_ONION_SCOPE_SESSION ||
           scope == ZMARKET_ONION_SCOPE_ONE_TIME;
}

bool zmarket_onion_role_valid(uint32_t role_bits)
{
    uint32_t known = ZMARKET_ONION_ROLE_MARKET |
                     ZMARKET_ONION_ROLE_CONTENT |
                     ZMARKET_ONION_ROLE_SOCIAL |
                     ZMARKET_ONION_ROLE_DIRECT;
    return role_bits != 0 && (role_bits & ~known) == 0;
}

void zmarket_onion_set_init(struct zmarket_onion_set *set,
                            struct zmarket_onion_endpoint *entries,
                            size_t capacity)
{
    if (!set) return;
    set->entries = entries;
    set->capacity = entries ? capacity : 0;
    set->count = 0;
    if (entries && capacity)
        memset(entries, 0, capacity * sizeof(entries[0]));
}

void zmarket_onion_set_clear(struct zmarket_onion_set *set)
{
    if (!set || !set->entries || set->capacity == 0)
        return;
    memset(set->entries, 0, set->capacity * sizeof(set->entries[0]));
    set->count = 0;
}

static bool zmarket_onion_find_slot(const struct zmarket_onion_set *set,
                                    const char *host,
                                    size_t host_len,
                                    uint16_t port,
                                    size_t *slot_out)
{
    size_t i;

    if (!set || !set->entries || set->capacity == 0 ||
        !zmarket_onion_host_is_v3(host, host_len) || port == 0)
        return false;

    for (i = 0; i < set->capacity; i++) {
        const struct zmarket_onion_endpoint *e = &set->entries[i];
        if (e->state == ZMARKET_ONION_EMPTY)
            continue;
        if (e->port == port &&
            memcmp(e->host, host, ZMARKET_ONION_HOST_LEN) == 0) {
            if (slot_out)
                *slot_out = i;
            return true;
        }
    }
    return false;
}

static bool zmarket_onion_find_empty_slot(const struct zmarket_onion_set *set,
                                          size_t *slot_out)
{
    size_t i;

    if (!set || !set->entries || set->capacity == 0)
        return false;
    for (i = 0; i < set->capacity; i++) {
        if (set->entries[i].state == ZMARKET_ONION_EMPTY) {
            if (slot_out)
                *slot_out = i;
            return true;
        }
    }
    return false;
}

static enum zmarket_onion_error zmarket_onion_validate_put(
    const char *host,
    size_t host_len,
    uint16_t port,
    uint32_t role_bits,
    enum zmarket_onion_scope scope,
    const uint8_t scope_id[ZMARKET_ONION_SCOPE_ID_LEN],
    uint16_t weight)
{
    if (!host)
        return ZMARKET_ONION_ERR_NULL;
    if (!zmarket_onion_host_is_v3(host, host_len))
        return ZMARKET_ONION_ERR_HOST;
    if (port == 0)
        return ZMARKET_ONION_ERR_PORT;
    if (!zmarket_onion_role_valid(role_bits))
        return ZMARKET_ONION_ERR_ROLE;
    if (!zmarket_onion_scope_valid(scope))
        return ZMARKET_ONION_ERR_SCOPE;
    if (scope != ZMARKET_ONION_SCOPE_REUSABLE &&
        !zmarket_onion_scope_id_nonzero(scope_id))
        return ZMARKET_ONION_ERR_SCOPE;
    if (weight == 0 || weight > ZMARKET_ONION_WEIGHT_MAX)
        return ZMARKET_ONION_ERR_WEIGHT;
    return ZMARKET_ONION_OK;
}

enum zmarket_onion_error zmarket_onion_set_put(
    struct zmarket_onion_set *set,
    const char *host,
    size_t host_len,
    uint16_t port,
    uint32_t role_bits,
    enum zmarket_onion_scope scope,
    const uint8_t scope_id[ZMARKET_ONION_SCOPE_ID_LEN],
    uint16_t weight,
    uint64_t expires_unix,
    uint64_t seen_unix)
{
    size_t slot = 0;
    struct zmarket_onion_endpoint *e;
    enum zmarket_onion_error err;

    if (!set || !set->entries || set->capacity == 0)
        return ZMARKET_ONION_ERR_NULL;

    err = zmarket_onion_validate_put(host, host_len, port, role_bits, scope,
                                     scope_id, weight);
    if (err != ZMARKET_ONION_OK)
        return err;

    if (!zmarket_onion_find_slot(set, host, host_len, port, &slot)) {
        if (set->count >= set->capacity ||
            !zmarket_onion_find_empty_slot(set, &slot))
            return ZMARKET_ONION_ERR_FULL;
        set->count++;
    }

    e = &set->entries[slot];
    memset(e, 0, sizeof(*e));
    memcpy(e->host, host, ZMARKET_ONION_HOST_LEN);
    e->host[ZMARKET_ONION_HOST_LEN] = '\0';
    if (scope_id)
        memcpy(e->scope_id, scope_id, ZMARKET_ONION_SCOPE_ID_LEN);
    e->expires_unix = expires_unix;
    e->last_seen_unix = seen_unix;
    e->role_bits = role_bits;
    e->port = port;
    e->weight = weight;
    e->scope = (uint8_t)scope;
    e->state = ZMARKET_ONION_ACTIVE;
    return ZMARKET_ONION_OK;
}

bool zmarket_onion_set_remove(struct zmarket_onion_set *set,
                              const char *host,
                              size_t host_len,
                              uint16_t port)
{
    size_t slot = 0;
    if (!zmarket_onion_find_slot(set, host, host_len, port, &slot))
        return false;
    memset(&set->entries[slot], 0, sizeof(set->entries[slot]));
    if (set->count > 0)
        set->count--;
    return true;
}

const struct zmarket_onion_endpoint *zmarket_onion_set_find(
    const struct zmarket_onion_set *set,
    const char *host,
    size_t host_len,
    uint16_t port)
{
    size_t slot = 0;
    if (!zmarket_onion_find_slot(set, host, host_len, port, &slot))
        return NULL;
    return &set->entries[slot];
}

bool zmarket_onion_endpoint_usable(
    const struct zmarket_onion_endpoint *endpoint,
    uint32_t required_role_bits,
    uint64_t now_unix)
{
    if (!endpoint || endpoint->state != ZMARKET_ONION_ACTIVE)
        return false;
    if (!zmarket_onion_role_valid(required_role_bits))
        return false;
    if ((endpoint->role_bits & required_role_bits) != required_role_bits)
        return false;
    if (endpoint->scope == ZMARKET_ONION_SCOPE_ONE_TIME &&
        endpoint->use_count != 0)
        return false;
    if (now_unix != 0 && endpoint->expires_unix != 0 &&
        endpoint->expires_unix <= now_unix)
        return false;
    return true;
}

static uint64_t zmarket_onion_hash_bytes(uint64_t h, const uint8_t *p,
                                         size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t zmarket_onion_score(
    const struct zmarket_onion_endpoint *endpoint,
    uint32_t required_role_bits,
    uint64_t seed)
{
    uint64_t h = 1469598103934665603ULL ^ seed;
    uint64_t penalty;
    uint64_t weighted;
    uint8_t port_le[2];
    uint8_t role_le[4];

    port_le[0] = (uint8_t)(endpoint->port & 0xffu);
    port_le[1] = (uint8_t)((endpoint->port >> 8) & 0xffu);
    role_le[0] = (uint8_t)(required_role_bits & 0xffu);
    role_le[1] = (uint8_t)((required_role_bits >> 8) & 0xffu);
    role_le[2] = (uint8_t)((required_role_bits >> 16) & 0xffu);
    role_le[3] = (uint8_t)((required_role_bits >> 24) & 0xffu);

    h = zmarket_onion_hash_bytes(h, (const uint8_t *)endpoint->host,
                                 ZMARKET_ONION_HOST_LEN);
    h = zmarket_onion_hash_bytes(h, port_le, sizeof(port_le));
    h = zmarket_onion_hash_bytes(h, role_le, sizeof(role_le));
    h = zmarket_onion_hash_bytes(h, endpoint->scope_id,
                                 ZMARKET_ONION_SCOPE_ID_LEN);

    weighted = (h / (uint64_t)ZMARKET_ONION_WEIGHT_MAX) *
               (uint64_t)endpoint->weight;
    penalty = (uint64_t)endpoint->fail_count + 1u;
    return weighted / penalty;
}

const struct zmarket_onion_endpoint *zmarket_onion_choose(
    const struct zmarket_onion_set *set,
    uint32_t required_role_bits,
    uint64_t now_unix,
    uint64_t seed)
{
    const struct zmarket_onion_endpoint *best = NULL;
    uint64_t best_score = 0;
    size_t i;

    if (!set || !set->entries || set->capacity == 0)
        return NULL;

    for (i = 0; i < set->capacity; i++) {
        const struct zmarket_onion_endpoint *e = &set->entries[i];
        uint64_t score;
        if (!zmarket_onion_endpoint_usable(e, required_role_bits, now_unix))
            continue;
        score = zmarket_onion_score(e, required_role_bits, seed);
        if (!best || score > best_score) {
            best = e;
            best_score = score;
        }
    }
    return best;
}

bool zmarket_onion_mark_success(struct zmarket_onion_set *set,
                                const char *host,
                                size_t host_len,
                                uint16_t port,
                                uint64_t seen_unix)
{
    size_t slot = 0;
    struct zmarket_onion_endpoint *e;

    if (!zmarket_onion_find_slot(set, host, host_len, port, &slot))
        return false;
    e = &set->entries[slot];
    if (e->success_count != UINT32_MAX)
        e->success_count++;
    if (e->use_count != UINT32_MAX)
        e->use_count++;
    e->last_seen_unix = seen_unix;
    if (e->scope == ZMARKET_ONION_SCOPE_ONE_TIME)
        e->state = ZMARKET_ONION_USED;
    return true;
}

bool zmarket_onion_mark_failure(struct zmarket_onion_set *set,
                                const char *host,
                                size_t host_len,
                                uint16_t port,
                                uint64_t seen_unix)
{
    size_t slot = 0;
    struct zmarket_onion_endpoint *e;

    if (!zmarket_onion_find_slot(set, host, host_len, port, &slot))
        return false;
    e = &set->entries[slot];
    if (e->fail_count != UINT32_MAX)
        e->fail_count++;
    e->last_seen_unix = seen_unix;
    return true;
}

size_t zmarket_onion_set_count(const struct zmarket_onion_set *set)
{
    return set ? set->count : 0;
}

const char *zmarket_onion_error_string(enum zmarket_onion_error err)
{
    switch (err) {
    case ZMARKET_ONION_OK:         return "ok";
    case ZMARKET_ONION_ERR_NULL:   return "null argument";
    case ZMARKET_ONION_ERR_HOST:   return "invalid onion host";
    case ZMARKET_ONION_ERR_PORT:   return "invalid onion port";
    case ZMARKET_ONION_ERR_ROLE:   return "invalid onion role";
    case ZMARKET_ONION_ERR_SCOPE:  return "invalid onion scope";
    case ZMARKET_ONION_ERR_WEIGHT: return "invalid onion weight";
    case ZMARKET_ONION_ERR_FULL:   return "onion endpoint set full";
    default:                       return "unknown onion error";
    }
}
