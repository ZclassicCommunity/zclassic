// Copyright 2026 Rhett Creighton - Apache License 2.0

#include "zmarket/zmarket_content.h"

#include <string.h>

#define ZMARKET_CONTENT_EMPTY   0u
#define ZMARKET_CONTENT_ALLOWED 1u

static bool zmarket_content_root_valid(
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN])
{
    size_t i;
    if (!content_root)
        return false;
    for (i = 0; i < ZMARKET_CONTENT_ROOT_LEN; i++) {
        if (content_root[i] != 0)
            return true;
    }
    return false;
}

static bool zmarket_content_path_valid(const char *path, size_t path_len)
{
    if (!path || path_len == 0 ||
        path_len >= ZMARKET_CONTENT_SOURCE_PATH_MAX)
        return false;
    return memchr(path, '\0', path_len) == NULL;
}

static void zmarket_content_set_source(struct zmarket_content_source *source,
                                       const char *path,
                                       size_t path_len,
                                       uint64_t selected_unix)
{
    memset(source, 0, sizeof(*source));
    memcpy(source->path, path, path_len);
    source->path[path_len] = '\0';
    source->path_len = path_len;
    source->selected_unix = selected_unix;
}

static bool zmarket_content_find_slot(
    const struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN],
    size_t *slot_out)
{
    size_t i;

    if (!allowlist || !allowlist->entries || allowlist->capacity == 0 ||
        !zmarket_content_root_valid(content_root))
        return false;

    for (i = 0; i < allowlist->capacity; i++) {
        const struct zmarket_content_allowlist_entry *entry =
            &allowlist->entries[i];
        if (entry->state != ZMARKET_CONTENT_ALLOWED)
            continue;
        if (memcmp(entry->content_root, content_root,
                   ZMARKET_CONTENT_ROOT_LEN) == 0) {
            if (slot_out)
                *slot_out = i;
            return true;
        }
    }
    return false;
}

static bool zmarket_content_find_empty_slot(
    const struct zmarket_content_allowlist *allowlist,
    size_t *slot_out)
{
    size_t i;

    if (!allowlist || !allowlist->entries || allowlist->capacity == 0)
        return false;

    for (i = 0; i < allowlist->capacity; i++) {
        if (allowlist->entries[i].state == ZMARKET_CONTENT_EMPTY) {
            if (slot_out)
                *slot_out = i;
            return true;
        }
    }
    return false;
}

void zmarket_content_allowlist_init(
    struct zmarket_content_allowlist *allowlist,
    struct zmarket_content_allowlist_entry *entries,
    size_t capacity)
{
    if (!allowlist)
        return;
    allowlist->entries = entries;
    allowlist->capacity = entries ? capacity : 0;
    allowlist->count = 0;
    if (entries && capacity)
        memset(entries, 0, capacity * sizeof(entries[0]));
}

void zmarket_content_allowlist_clear(
    struct zmarket_content_allowlist *allowlist)
{
    if (!allowlist || !allowlist->entries || allowlist->capacity == 0)
        return;
    memset(allowlist->entries, 0,
           allowlist->capacity * sizeof(allowlist->entries[0]));
    allowlist->count = 0;
}

enum zmarket_content_error zmarket_content_allowlist_put(
    struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN],
    const char *source_path,
    size_t source_path_len,
    uint64_t selected_unix)
{
    size_t slot = 0;
    struct zmarket_content_allowlist_entry *entry;

    if (!allowlist || !allowlist->entries || allowlist->capacity == 0 ||
        !source_path)
        return ZMARKET_CONTENT_ERR_NULL;
    if (!zmarket_content_root_valid(content_root))
        return ZMARKET_CONTENT_ERR_ROOT;
    if (!zmarket_content_path_valid(source_path, source_path_len))
        return ZMARKET_CONTENT_ERR_PATH;

    if (zmarket_content_find_slot(allowlist, content_root, &slot)) {
        entry = &allowlist->entries[slot];
        zmarket_content_set_source(&entry->source, source_path,
                                   source_path_len, selected_unix);
        return ZMARKET_CONTENT_OK;
    }

    if (allowlist->count >= allowlist->capacity ||
        !zmarket_content_find_empty_slot(allowlist, &slot))
        return ZMARKET_CONTENT_ERR_FULL;

    entry = &allowlist->entries[slot];
    memset(entry, 0, sizeof(*entry));
    memcpy(entry->content_root, content_root, ZMARKET_CONTENT_ROOT_LEN);
    zmarket_content_set_source(&entry->source, source_path, source_path_len,
                               selected_unix);
    entry->state = ZMARKET_CONTENT_ALLOWED;
    allowlist->count++;
    return ZMARKET_CONTENT_OK;
}

bool zmarket_content_allowlist_remove(
    struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN])
{
    size_t slot = 0;

    if (!zmarket_content_find_slot(allowlist, content_root, &slot))
        return false;
    memset(&allowlist->entries[slot], 0, sizeof(allowlist->entries[slot]));
    if (allowlist->count > 0)
        allowlist->count--;
    return true;
}

const struct zmarket_content_allowlist_entry *zmarket_content_allowlist_find(
    const struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN])
{
    size_t slot = 0;

    if (!zmarket_content_find_slot(allowlist, content_root, &slot))
        return NULL;
    return &allowlist->entries[slot];
}

bool zmarket_content_operator_allowed(
    const struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN])
{
    return zmarket_content_allowlist_find(allowlist, content_root) != NULL;
}

bool zmarket_content_can_host(
    const struct zmarket_policy *policy,
    const struct zmarket_content_allowlist *allowlist,
    const uint8_t content_root[ZMARKET_CONTENT_ROOT_LEN])
{
    return zmarket_policy_can_host_content(
        policy, zmarket_content_operator_allowed(allowlist, content_root));
}

size_t zmarket_content_allowlist_count(
    const struct zmarket_content_allowlist *allowlist)
{
    return allowlist ? allowlist->count : 0;
}

const char *zmarket_content_error_string(enum zmarket_content_error err)
{
    switch (err) {
    case ZMARKET_CONTENT_OK:        return "ok";
    case ZMARKET_CONTENT_ERR_NULL:  return "null argument";
    case ZMARKET_CONTENT_ERR_ROOT:  return "invalid content root";
    case ZMARKET_CONTENT_ERR_PATH:  return "invalid source path";
    case ZMARKET_CONTENT_ERR_FULL:  return "allowlist full";
    default:                       return "unknown content error";
    }
}
