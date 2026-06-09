// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Bounded onion endpoint policy/index helpers for ZMARKET. This layer does not
// start Tor, open sockets, fetch media, or serve files. It only tracks signed
// onion route/mirror/social endpoints for the C spider/router/index hot path.

#ifndef ZCLASSIC_ZMARKET_ONION_H
#define ZCLASSIC_ZMARKET_ONION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZMARKET_ONION_SERVICE_ID_LEN 56u
#define ZMARKET_ONION_SUFFIX ".onion"
#define ZMARKET_ONION_HOST_LEN 62u
#define ZMARKET_ONION_HOST_BUF_LEN (ZMARKET_ONION_HOST_LEN + 1u)
#define ZMARKET_ONION_SCOPE_ID_LEN 32u
#define ZMARKET_ONION_WEIGHT_MAX 10000u

enum zmarket_onion_role {
    ZMARKET_ONION_ROLE_MARKET  = 1u << 0,
    ZMARKET_ONION_ROLE_CONTENT = 1u << 1,
    ZMARKET_ONION_ROLE_SOCIAL  = 1u << 2,
    ZMARKET_ONION_ROLE_DIRECT  = 1u << 3
};

enum zmarket_onion_scope {
    ZMARKET_ONION_SCOPE_REUSABLE = 1,
    ZMARKET_ONION_SCOPE_ASSET    = 2,
    ZMARKET_ONION_SCOPE_SESSION  = 3,
    ZMARKET_ONION_SCOPE_ONE_TIME = 4
};

enum zmarket_onion_state {
    ZMARKET_ONION_EMPTY    = 0,
    ZMARKET_ONION_ACTIVE   = 1,
    ZMARKET_ONION_DISABLED = 2,
    ZMARKET_ONION_USED     = 3
};

enum zmarket_onion_error {
    ZMARKET_ONION_OK = 0,
    ZMARKET_ONION_ERR_NULL,
    ZMARKET_ONION_ERR_HOST,
    ZMARKET_ONION_ERR_PORT,
    ZMARKET_ONION_ERR_ROLE,
    ZMARKET_ONION_ERR_SCOPE,
    ZMARKET_ONION_ERR_WEIGHT,
    ZMARKET_ONION_ERR_FULL
};

struct zmarket_onion_endpoint {
    char host[ZMARKET_ONION_HOST_BUF_LEN];
    uint8_t scope_id[ZMARKET_ONION_SCOPE_ID_LEN];
    uint64_t expires_unix;
    uint64_t last_seen_unix;
    uint32_t success_count;
    uint32_t fail_count;
    uint32_t use_count;
    uint32_t role_bits;
    uint16_t port;
    uint16_t weight;
    uint8_t scope;
    uint8_t state;
};

struct zmarket_onion_set {
    struct zmarket_onion_endpoint *entries;
    size_t capacity;
    size_t count;
};

bool zmarket_onion_host_is_v3(const char *host, size_t host_len);
bool zmarket_onion_scope_valid(enum zmarket_onion_scope scope);
bool zmarket_onion_role_valid(uint32_t role_bits);

void zmarket_onion_set_init(struct zmarket_onion_set *set,
                            struct zmarket_onion_endpoint *entries,
                            size_t capacity);
void zmarket_onion_set_clear(struct zmarket_onion_set *set);

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
    uint64_t seen_unix);

bool zmarket_onion_set_remove(struct zmarket_onion_set *set,
                              const char *host,
                              size_t host_len,
                              uint16_t port);

const struct zmarket_onion_endpoint *zmarket_onion_set_find(
    const struct zmarket_onion_set *set,
    const char *host,
    size_t host_len,
    uint16_t port);

bool zmarket_onion_endpoint_usable(
    const struct zmarket_onion_endpoint *endpoint,
    uint32_t required_role_bits,
    uint64_t now_unix);

const struct zmarket_onion_endpoint *zmarket_onion_choose(
    const struct zmarket_onion_set *set,
    uint32_t required_role_bits,
    uint64_t now_unix,
    uint64_t seed);

bool zmarket_onion_mark_success(struct zmarket_onion_set *set,
                                const char *host,
                                size_t host_len,
                                uint16_t port,
                                uint64_t seen_unix);

bool zmarket_onion_mark_failure(struct zmarket_onion_set *set,
                                const char *host,
                                size_t host_len,
                                uint16_t port,
                                uint64_t seen_unix);

size_t zmarket_onion_set_count(const struct zmarket_onion_set *set);
const char *zmarket_onion_error_string(enum zmarket_onion_error err);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZCLASSIC_ZMARKET_ONION_H */
