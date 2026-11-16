/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_TREE_ROOT_H
#define ZCL_TREE_ROOT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_TREE_MAX_DEPTH 64
/* Canonical frontier, with no borrowed pointers or serialized cache state. */
struct zcl_tree_frontier {
    size_t depth, parents_len;
    uint8_t has_left, has_right;
    uint8_t left[32], right[32];
    uint8_t has_parent[ZCL_TREE_MAX_DEPTH];
    uint8_t parents[ZCL_TREE_MAX_DEPTH][32];
};
struct zcl_tree_root_cache {
    int valid;
    struct zcl_tree_frontier frontier;
    uint8_t root[32];
};
typedef void (*zcl_tree_combine)(const uint8_t *, const uint8_t *, size_t, uint8_t *);
typedef void (*zcl_tree_empty)(size_t, uint8_t *);

/* Sapling's uncommitted leaf: canonical little-endian field element one. */
void zcl_sapling_uncommitted(uint8_t out[32]);

/* Zero-initialize cache before use. It belongs to one thread and one hash
 * algorithm. Returns 0 for invalid
 * arguments without updating the cache. Hash callbacks must not throw. */
int zcl_tree_root(const struct zcl_tree_frontier *tree,
                  struct zcl_tree_root_cache *cache,
                  zcl_tree_combine combine, zcl_tree_empty empty,
                  uint8_t out[32]);
#ifdef __cplusplus
}
#endif
#endif
