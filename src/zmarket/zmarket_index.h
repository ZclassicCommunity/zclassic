// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Fixed-memory ZMARKET id index. This is the C hot-path dedupe/index primitive
// used by spidering and routing before higher-level C++ code joins chain facts.
//
// Extended with richer query API: filter by type, expiry range, pagination,
// and in-RAM sorted memindex for fast browse/search.

#ifndef ZCLASSIC_ZMARKET_INDEX_H
#define ZCLASSIC_ZMARKET_INDEX_H

#include "zmarket/zmarket_record.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct zmarket_index_slot {
    uint8_t id[ZMARKET_ID_LEN];
    uint64_t expires_unix;
    uint32_t seen_count;
    uint16_t type;
    uint8_t state;
};

struct zmarket_index {
    struct zmarket_index_slot *slots;
    size_t capacity;
    size_t count;
};

/* ---- Original API (unchanged) ---- */

void zmarket_index_init(struct zmarket_index *idx,
                        struct zmarket_index_slot *slots,
                        size_t capacity);
void zmarket_index_clear(struct zmarket_index *idx);
bool zmarket_index_has(const struct zmarket_index *idx,
                       const uint8_t id[ZMARKET_ID_LEN]);
bool zmarket_index_put(struct zmarket_index *idx,
                       const uint8_t id[ZMARKET_ID_LEN],
                       enum zmarket_record_type type,
                       uint64_t expires_unix);
size_t zmarket_index_count(const struct zmarket_index *idx);

/* ---- Extended query API ---- */

/* Get a slot by id. Returns NULL if not found. */
const struct zmarket_index_slot *zmarket_index_get(
    const struct zmarket_index *idx,
    const uint8_t id[ZMARKET_ID_LEN]);

/* Remove a slot by id. Returns true if removed. */
bool zmarket_index_remove(struct zmarket_index *idx,
                          const uint8_t id[ZMARKET_ID_LEN]);

/* Prune expired entries. Returns count of pruned entries. */
size_t zmarket_index_prune(struct zmarket_index *idx, uint64_t now_unix);

/* Filter predicates for query. */
struct zmarket_index_filter {
    bool filter_type;               /* if true, match type exactly */
    enum zmarket_record_type type;
    bool filter_min_expires;        /* if true, expires >= min_expires */
    uint64_t min_expires;
    bool filter_max_expires;        /* if true, expires <= max_expires */
    uint64_t max_expires;
    bool filter_min_seen;           /* if true, seen_count >= min_seen */
    uint32_t min_seen;
};

/* Query result: caller provides the output buffer. */
struct zmarket_index_query_result {
    const struct zmarket_index_slot **slots; /* array of pointers into index */
    size_t capacity;
    size_t count;
};

/* Run a filtered query. Results are pointers into the index slots.
 * Set offset/skip for pagination. Returns number of matches found
 * (may exceed out->capacity if there are more results). */
size_t zmarket_index_query(const struct zmarket_index *idx,
                           const struct zmarket_index_filter *filter,
                           size_t offset,
                           struct zmarket_index_query_result *out);

/* Count matching entries without collecting results. */
size_t zmarket_index_count_filtered(const struct zmarket_index *idx,
                                    const struct zmarket_index_filter *filter);

/* Iterate all slots. Callback returns true to continue, false to stop.
 * Returns number of slots visited. */
typedef bool (*zmarket_index_iter_fn)(const struct zmarket_index_slot *slot,
                                      void *ctx);
size_t zmarket_index_iter(const struct zmarket_index *idx,
                          zmarket_index_iter_fn fn,
                          void *ctx);

/* ---- In-RAM sorted memindex ---- */

/* Sort key for memindex entries. */
enum zmarket_sort_field {
    ZMARKET_SORT_EXPIRY_ASC = 0,
    ZMARKET_SORT_EXPIRY_DESC,
    ZMARKET_SORT_SEEN_ASC,
    ZMARKET_SORT_SEEN_DESC,
    ZMARKET_SORT_TYPE_ASC
};

/* A memindex holds pointers into an existing zmarket_index, sorted by a key.
 * Caller provides the pointer array. */
struct zmarket_memindex {
    const struct zmarket_index_slot **sorted;
    size_t capacity;
    size_t count;
    enum zmarket_sort_field sort_field;
};

/* Initialize a memindex over an existing index. Sorts the entries. */
void zmarket_memindex_init(struct zmarket_memindex *mi,
                           const struct zmarket_index_slot **sorted,
                           size_t capacity,
                           const struct zmarket_index *idx,
                           enum zmarket_sort_field sort_field);

/* Rebuild the sorted array from the index. Call after index changes. */
void zmarket_memindex_rebuild(struct zmarket_memindex *mi,
                              const struct zmarket_index *idx);

/* Insert a single slot into the sorted position. Faster than full rebuild
 * for incremental updates. */
bool zmarket_memindex_insert(struct zmarket_memindex *mi,
                             const struct zmarket_index_slot *slot);

/* Remove a slot by id from the sorted array. */
bool zmarket_memindex_remove(struct zmarket_memindex *mi,
                             const uint8_t id[ZMARKET_ID_LEN]);

/* Paginated query: returns up to out->capacity results starting at offset. */
size_t zmarket_memindex_query(const struct zmarket_memindex *mi,
                              const struct zmarket_index_filter *filter,
                              size_t offset,
                              struct zmarket_index_query_result *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZCLASSIC_ZMARKET_INDEX_H */
