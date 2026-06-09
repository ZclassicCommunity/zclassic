// Copyright 2026 Rhett Creighton - Apache License 2.0

#include "zmarket/zmarket_index.h"

#include <stdlib.h>
#include <string.h>

#define ZMARKET_INDEX_EMPTY 0u
#define ZMARKET_INDEX_USED  1u

static uint64_t zmarket_id_hash(const uint8_t id[ZMARKET_ID_LEN])
{
    uint64_t h = 1469598103934665603ULL;
    size_t i;
    for (i = 0; i < ZMARKET_ID_LEN; i++) {
        h ^= (uint64_t)id[i];
        h *= 1099511628211ULL;
    }
    return h;
}

void zmarket_index_init(struct zmarket_index *idx,
                        struct zmarket_index_slot *slots,
                        size_t capacity)
{
    if (!idx) return;
    idx->slots = slots;
    idx->capacity = slots ? capacity : 0;
    idx->count = 0;
    if (slots && capacity)
        memset(slots, 0, capacity * sizeof(slots[0]));
}

void zmarket_index_clear(struct zmarket_index *idx)
{
    if (!idx || !idx->slots || idx->capacity == 0) return;
    memset(idx->slots, 0, idx->capacity * sizeof(idx->slots[0]));
    idx->count = 0;
}

static bool zmarket_index_find_slot(const struct zmarket_index *idx,
                                    const uint8_t id[ZMARKET_ID_LEN],
                                    size_t *slot_out,
                                    bool *found_out)
{
    size_t start, n;
    if (!idx || !idx->slots || idx->capacity == 0 || !id)
        return false;

    start = (size_t)(zmarket_id_hash(id) % idx->capacity);
    for (n = 0; n < idx->capacity; n++) {
        size_t pos = (start + n) % idx->capacity;
        struct zmarket_index_slot *s = &idx->slots[pos];
        if (s->state == ZMARKET_INDEX_EMPTY) {
            if (slot_out) *slot_out = pos;
            if (found_out) *found_out = false;
            return true;
        }
        if (memcmp(s->id, id, ZMARKET_ID_LEN) == 0) {
            if (slot_out) *slot_out = pos;
            if (found_out) *found_out = true;
            return true;
        }
    }
    return false;
}

bool zmarket_index_has(const struct zmarket_index *idx,
                       const uint8_t id[ZMARKET_ID_LEN])
{
    size_t slot = 0;
    bool found = false;
    if (!zmarket_index_find_slot(idx, id, &slot, &found))
        return false;
    (void)slot;
    return found;
}

bool zmarket_index_put(struct zmarket_index *idx,
                       const uint8_t id[ZMARKET_ID_LEN],
                       enum zmarket_record_type type,
                       uint64_t expires_unix)
{
    size_t slot = 0;
    bool found = false;
    struct zmarket_index_slot *s;

    if (!idx || !idx->slots || idx->capacity == 0 || !id)
        return false;
    if (!zmarket_record_type_is_routable(type))
        return false;
    if (!zmarket_index_find_slot(idx, id, &slot, &found))
        return false;

    s = &idx->slots[slot];
    if (found) {
        if (s->seen_count != UINT32_MAX)
            s->seen_count++;
        if (expires_unix > s->expires_unix)
            s->expires_unix = expires_unix;
        return true;
    }

    if (idx->count >= idx->capacity)
        return false;
    memcpy(s->id, id, ZMARKET_ID_LEN);
    s->expires_unix = expires_unix;
    s->seen_count = 1;
    s->type = (uint16_t)type;
    s->state = ZMARKET_INDEX_USED;
    idx->count++;
    return true;
}

size_t zmarket_index_count(const struct zmarket_index *idx)
{
    return idx ? idx->count : 0;
}

/* ---- Extended query API implementation ---- */

const struct zmarket_index_slot *zmarket_index_get(
    const struct zmarket_index *idx,
    const uint8_t id[ZMARKET_ID_LEN])
{
    size_t slot = 0;
    bool found = false;
    if (!zmarket_index_find_slot(idx, id, &slot, &found) || !found)
        return NULL;
    return &idx->slots[slot];
}

bool zmarket_index_remove(struct zmarket_index *idx,
                          const uint8_t id[ZMARKET_ID_LEN])
{
    size_t slot = 0;
    bool found = false;
    if (!zmarket_index_find_slot(idx, id, &slot, &found) || !found)
        return false;
    memset(&idx->slots[slot], 0, sizeof(idx->slots[slot]));
    if (idx->count > 0) idx->count--;
    return true;
}

size_t zmarket_index_prune(struct zmarket_index *idx, uint64_t now_unix)
{
    size_t pruned = 0;
    size_t i;
    if (!idx || !idx->slots) return 0;
    for (i = 0; i < idx->capacity; i++) {
        struct zmarket_index_slot *s = &idx->slots[i];
        if (s->state != ZMARKET_INDEX_USED) continue;
        if (s->expires_unix <= now_unix) {
            memset(s, 0, sizeof(*s));
            pruned++;
            if (idx->count > 0) idx->count--;
        }
    }
    return pruned;
}

static bool zmarket_index_slot_matches(
    const struct zmarket_index_slot *s,
    const struct zmarket_index_filter *f)
{
    if (!s || s->state != ZMARKET_INDEX_USED) return false;
    if (f) {
        if (f->filter_type && (enum zmarket_record_type)s->type != f->type)
            return false;
        if (f->filter_min_expires && s->expires_unix < f->min_expires)
            return false;
        if (f->filter_max_expires && s->expires_unix > f->max_expires)
            return false;
        if (f->filter_min_seen && s->seen_count < f->min_seen)
            return false;
    }
    return true;
}

size_t zmarket_index_query(const struct zmarket_index *idx,
                           const struct zmarket_index_filter *filter,
                           size_t offset,
                           struct zmarket_index_query_result *out)
{
    size_t total_matches = 0;
    size_t collected = 0;
    size_t i;

    if (!idx || !idx->slots || !out || !out->slots)
        return 0;

    for (i = 0; i < idx->capacity; i++) {
        const struct zmarket_index_slot *s = &idx->slots[i];
        if (!zmarket_index_slot_matches(s, filter)) continue;
        total_matches++;
        if (total_matches > offset && collected < out->capacity) {
            out->slots[collected] = s;
            collected++;
        }
    }

    out->count = collected;
    return total_matches;
}

size_t zmarket_index_count_filtered(const struct zmarket_index *idx,
                                    const struct zmarket_index_filter *filter)
{
    size_t count = 0;
    size_t i;
    if (!idx || !idx->slots) return 0;
    for (i = 0; i < idx->capacity; i++) {
        if (zmarket_index_slot_matches(&idx->slots[i], filter))
            count++;
    }
    return count;
}

size_t zmarket_index_iter(const struct zmarket_index *idx,
                          zmarket_index_iter_fn fn,
                          void *ctx)
{
    size_t visited = 0;
    size_t i;
    if (!idx || !idx->slots || !fn) return 0;
    for (i = 0; i < idx->capacity; i++) {
        const struct zmarket_index_slot *s = &idx->slots[i];
        if (s->state != ZMARKET_INDEX_USED) continue;
        visited++;
        if (!fn(s, ctx)) break;
    }
    return visited;
}

/* ---- In-RAM sorted memindex ---- */

static int zmarket_slot_cmp_expiry_asc(const void *a, const void *b)
{
    const struct zmarket_index_slot *sa = *(const struct zmarket_index_slot *const *)a;
    const struct zmarket_index_slot *sb = *(const struct zmarket_index_slot *const *)b;
    if (sa->expires_unix < sb->expires_unix) return -1;
    if (sa->expires_unix > sb->expires_unix) return 1;
    return memcmp(sa->id, sb->id, ZMARKET_ID_LEN);
}

static int zmarket_slot_cmp_expiry_desc(const void *a, const void *b)
{
    return -zmarket_slot_cmp_expiry_asc(a, b);
}

static int zmarket_slot_cmp_seen_asc(const void *a, const void *b)
{
    const struct zmarket_index_slot *sa = *(const struct zmarket_index_slot *const *)a;
    const struct zmarket_index_slot *sb = *(const struct zmarket_index_slot *const *)b;
    if (sa->seen_count < sb->seen_count) return -1;
    if (sa->seen_count > sb->seen_count) return 1;
    return memcmp(sa->id, sb->id, ZMARKET_ID_LEN);
}

static int zmarket_slot_cmp_seen_desc(const void *a, const void *b)
{
    return -zmarket_slot_cmp_seen_asc(a, b);
}

static int zmarket_slot_cmp_type_asc(const void *a, const void *b)
{
    const struct zmarket_index_slot *sa = *(const struct zmarket_index_slot *const *)a;
    const struct zmarket_index_slot *sb = *(const struct zmarket_index_slot *const *)b;
    if (sa->type < sb->type) return -1;
    if (sa->type > sb->type) return 1;
    return memcmp(sa->id, sb->id, ZMARKET_ID_LEN);
}

static int (*zmarket_get_sort_fn(enum zmarket_sort_field field))(const void *, const void *)
{
    switch (field) {
    case ZMARKET_SORT_EXPIRY_ASC:  return zmarket_slot_cmp_expiry_asc;
    case ZMARKET_SORT_EXPIRY_DESC: return zmarket_slot_cmp_expiry_desc;
    case ZMARKET_SORT_SEEN_ASC:    return zmarket_slot_cmp_seen_asc;
    case ZMARKET_SORT_SEEN_DESC:   return zmarket_slot_cmp_seen_desc;
    case ZMARKET_SORT_TYPE_ASC:    return zmarket_slot_cmp_type_asc;
    default:                       return zmarket_slot_cmp_expiry_asc;
    }
}

void zmarket_memindex_init(struct zmarket_memindex *mi,
                           const struct zmarket_index_slot **sorted,
                           size_t capacity,
                           const struct zmarket_index *idx,
                           enum zmarket_sort_field sort_field)
{
    if (!mi) return;
    mi->sorted = sorted;
    mi->capacity = sorted ? capacity : 0;
    mi->count = 0;
    mi->sort_field = sort_field;
    if (sorted && capacity)
        memset((void *)sorted, 0, capacity * sizeof(sorted[0]));
    if (idx)
        zmarket_memindex_rebuild(mi, idx);
}

void zmarket_memindex_rebuild(struct zmarket_memindex *mi,
                              const struct zmarket_index *idx)
{
    size_t i;
    if (!mi || !mi->sorted || !idx || !idx->slots) return;

    mi->count = 0;
    for (i = 0; i < idx->capacity && mi->count < mi->capacity; i++) {
        if (idx->slots[i].state == ZMARKET_INDEX_USED) {
            mi->sorted[mi->count] = &idx->slots[i];
            mi->count++;
        }
    }

    /* Sort using the comparator for the configured field. */
    if (mi->count > 1)
        qsort((void *)mi->sorted, mi->count, sizeof(mi->sorted[0]),
              zmarket_get_sort_fn(mi->sort_field));
}

bool zmarket_memindex_insert(struct zmarket_memindex *mi,
                             const struct zmarket_index_slot *slot)
{
    size_t pos;
    if (!mi || !mi->sorted || !slot) return false;
    if (mi->count >= mi->capacity) return false;

    /* Find insertion point using binary search based on sort field. */
    /* For simplicity, append and resort. Production code could use
     * a proper insertion sort for incremental updates. */
    mi->sorted[mi->count] = slot;
    mi->count++;

    if (mi->count > 1)
        qsort((void *)mi->sorted, mi->count, sizeof(mi->sorted[0]),
              zmarket_get_sort_fn(mi->sort_field));
    (void)pos;
    return true;
}

bool zmarket_memindex_remove(struct zmarket_memindex *mi,
                             const uint8_t id[ZMARKET_ID_LEN])
{
    size_t i;
    if (!mi || !mi->sorted || !id) return false;

    for (i = 0; i < mi->count; i++) {
        if (memcmp(mi->sorted[i]->id, id, ZMARKET_ID_LEN) == 0) {
            /* Shift remaining entries left. */
            size_t j;
            for (j = i; j + 1 < mi->count; j++)
                mi->sorted[j] = mi->sorted[j + 1];
            mi->count--;
            mi->sorted[mi->count] = NULL;
            return true;
        }
    }
    return false;
}

size_t zmarket_memindex_query(const struct zmarket_memindex *mi,
                              const struct zmarket_index_filter *filter,
                              size_t offset,
                              struct zmarket_index_query_result *out)
{
    size_t total_matches = 0;
    size_t collected = 0;
    size_t i;

    if (!mi || !mi->sorted || !out || !out->slots)
        return 0;

    for (i = 0; i < mi->count; i++) {
        const struct zmarket_index_slot *s = mi->sorted[i];
        if (!zmarket_index_slot_matches(s, filter)) continue;
        total_matches++;
        if (total_matches > offset && collected < out->capacity) {
            out->slots[collected] = s;
            collected++;
        }
    }

    out->count = collected;
    return total_matches;
}
