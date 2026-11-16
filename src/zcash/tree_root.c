/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Adapted from Z23 core/modules/sapling/src/incremental_merkle_tree.c,
 * incremental_tree_root(). Uses the caller's unchanged consensus hashes.
 * C23-compatible; also builds as C11 for the legacy release toolchains.
 */
#include "tree_root.h"
#include <string.h>

/* Z23 pedersen_hash.c: sapling_uncommitted(), Apache-2.0. */
void zcl_sapling_uncommitted(uint8_t out[32])
{
    memset(out, 0, 32);
    out[0] = 1;
}

static int same_frontier(const struct zcl_tree_frontier *a,
                         const struct zcl_tree_frontier *b)
{
    if (a->depth != b->depth || a->parents_len != b->parents_len ||
        a->has_left != b->has_left || a->has_right != b->has_right)
        return 0;
    if ((a->has_left && memcmp(a->left, b->left, 32)) ||
        (a->has_right && memcmp(a->right, b->right, 32)))
        return 0;
    for (size_t i = 0; i < a->parents_len; ++i) {
        if (a->has_parent[i] != b->has_parent[i] ||
            (a->has_parent[i] && memcmp(a->parents[i], b->parents[i], 32)))
            return 0;
    }
    return 1;
}

int zcl_tree_root(const struct zcl_tree_frontier *tree,
                  struct zcl_tree_root_cache *cache,
                  zcl_tree_combine combine, zcl_tree_empty empty,
                  uint8_t out[32])
{
    if (!tree || !cache || !combine || !empty || !out ||
        tree->depth == 0 || tree->depth > ZCL_TREE_MAX_DEPTH ||
        tree->parents_len >= tree->depth)
        return 0;
    if (cache->valid && same_frontier(tree, &cache->frontier)) {
        memcpy(out, cache->root, 32);
        return 1;
    }
    uint8_t left[32], right[32], root[32], next[32];
    if (tree->has_left) memcpy(left, tree->left, 32);
    else empty(0, left);
    if (tree->has_right) memcpy(right, tree->right, 32);
    else empty(0, right);
    combine(left, right, 0, root);
    size_t d = 1;
    for (size_t i = 0; i < tree->parents_len; ++i, ++d) {
        if (tree->has_parent[i]) combine(tree->parents[i], root, d, next);
        else {
            empty(d, right);
            combine(root, right, d, next);
        }
        memcpy(root, next, 32);
    }
    while (d < tree->depth) {
        empty(d, right);
        combine(root, right, d, next);
        memcpy(root, next, 32);
        ++d;
    }
    cache->frontier = *tree;
    memcpy(cache->root, root, 32);
    cache->valid = 1;
    memcpy(out, root, 32);
    return 1;
}
