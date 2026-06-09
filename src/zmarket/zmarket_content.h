// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Operator-managed content hosting allowlist. This layer records exact local
// source paths selected by the operator for a 32-byte content root/hash. It
// does not scan directories, open files, serve network bytes, or put file data
// on-chain.

#ifndef ZCLASSIC_ZMARKET_CONTENT_H
#define ZCLASSIC_ZMARKET_CONTENT_H

#include "zmarket/zmarket_policy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZMARKET_CONTENT_ROOT_LEN 32u
#define ZMARKET_CONTENT_SOURCE_PATH_MAX 4096u

enum zmarket_content_error {
    ZMARKET_CONTENT_OK = 0,
    ZMARKET_CONTENT_ERR_NULL,
    ZMARKET_CONTENT_ERR_ROOT,
    ZMARKET_CONTENT_ERR_PATH,
    ZMARKET_CONTENT_ERR_FULL
};

struct zmarket_content_source {
    char path[ZMARKET_CONTENT_SOURCE_PATH_MAX];
    size_t path_len;
    uint64_t selected_unix;
};

struct zmarket_content_allowlist_entry {
    uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN];
    struct zmarket_content_source source;
    uint8_t state;
};

struct zmarket_content_allowlist {
    struct zmarket_content_allowlist_entry *entries;
    size_t capacity;
    size_t count;
};

void zmarket_content_allowlist_init(
    struct zmarket_content_allowlist *allowlist,
    struct zmarket_content_allowlist_entry *entries,
    size_t capacity);

void zmarket_content_allowlist_clear(
    struct zmarket_content_allowlist *allowlist);

enum zmarket_content_error zmarket_content_allowlist_put(
    struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN],
    const char *source_path,
    size_t source_path_len,
    uint64_t selected_unix);

bool zmarket_content_allowlist_remove(
    struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN]);

const struct zmarket_content_allowlist_entry *zmarket_content_allowlist_find(
    const struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN]);

bool zmarket_content_operator_allowed(
    const struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN]);

bool zmarket_content_can_host(
    const struct zmarket_policy *policy,
    const struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN]);

size_t zmarket_content_allowlist_count(
    const struct zmarket_content_allowlist *allowlist);

const char *zmarket_content_error_string(enum zmarket_content_error err);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZCLASSIC_ZMARKET_CONTENT_H */
